const std = @import("std");
const config = @import("../config.zig");
const crypto = @import("../crypto.zig");
const ss_address = @import("../protocol/address.zig");
const dns = @import("../protocol/dns.zig");
const socks5 = @import("../protocol/socks5.zig");
const acl = @import("../security/acl.zig");
const replay = @import("../security/replay.zig");
const fake_dns = @import("fake_dns.zig");
const netio = @import("netio.zig");
const traffic = @import("traffic.zig");

const max_udp_packet_size = 64 * 1024;

const ResponseStyle = enum {
    socks,
    raw,
    redir,
};

const Association = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server_cfg: config.Server,
    local_socket: netio.UdpSocket,
    remote_socket: netio.UdpSocket,
    client_addr: netio.net.IpAddress,
    server_addr: netio.net.IpAddress,
    master_key: [32]u8,
    client_session_id: u64,
    client_packet_id: u64,
    server_replay: replay.ReplayProtector,
    response_style: ResponseStyle,
    response_socket: ?netio.UdpSocket = null,
    timeout_ns: i64,
    last_seen_ns: std.atomic.Value(i64),
    closed: std.atomic.Value(bool) = .init(false),
};

pub fn runLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_cfgs: []const config.Server,
    server_next: *std.atomic.Value(usize),
    local_cfg: config.Local,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
    fake_dns_manager: ?*fake_dns.Manager,
) !void {
    var local_socket = try netio.bindUdp(local_cfg.host, local_cfg.port);
    defer local_socket.close();

    var associations = std.AutoHashMap(u64, *Association).init(allocator);
    defer associations.deinit();
    var retired = std.ArrayList(*Association).empty;
    defer retired.deinit(allocator);

    var buf: [max_udp_packet_size]u8 = undefined;
    while (true) {
        const received = try local_socket.receiveFrom(&buf);
        cleanupLocalAssociations(allocator, io, &associations, &retired, udp_timeout_seconds);
        const packet = buf[0..received.len];

        const parsed = socks5.UdpAssociateHeader.read(packet) catch continue;
        if (parsed.header.frag != 0) continue;

        const key = netio.addressHash(received.from);
        const assoc = associations.get(key) orelse blk: {
            if (udp_max_associations) |capacity| {
                if (associations.count() >= capacity) continue;
            }
            const server_cfg = try selectUdpServer(server_cfgs, server_next);
            const server_addr = try netio.resolveIp(server_cfg.host, server_cfg.port);
            const remote_socket = try netio.openUdp(server_addr);
            errdefer remote_socket.close();

            const assoc = try allocator.create(Association);
            assoc.* = .{
                .allocator = allocator,
                .io = io,
                .server_cfg = server_cfg,
                .local_socket = local_socket,
                .remote_socket = remote_socket,
                .client_addr = received.from,
                .server_addr = server_addr,
                .master_key = [_]u8{0} ** 32,
                .client_session_id = try randomNonZeroU64(io),
                .client_packet_id = 0,
                .server_replay = replay.ReplayProtector.init(allocator, 8192),
                .response_style = .socks,
                .timeout_ns = timeoutNs(udp_timeout_seconds),
                .last_seen_ns = .init(nowNs(io)),
            };
            try crypto.deriveMasterKey(server_cfg.method, server_cfg.password, assoc.master_key[0..server_cfg.method.keyLen()]);
            try associations.put(key, assoc);

            const thread = try std.Thread.spawn(.{}, localResponseLoop, .{assoc});
            thread.detach();
            break :blk assoc;
        };
        assoc.last_seen_ns.store(nowNs(io), .release);

        const target_address = rewriteFakeDnsAddress(fake_dns_manager, io, parsed.header.address);
        const payload = packet[parsed.used..];
        const plain = try makeAddressPayload(allocator, target_address, payload);
        defer allocator.free(plain);
        const encrypted = try encryptClientUdpPacket(allocator, io, assoc, plain);
        defer allocator.free(encrypted);
        _ = try assoc.remote_socket.sendTo(encrypted, assoc.server_addr);
    }
}

pub fn runLocalRedir(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_cfgs: []const config.Server,
    server_next: *std.atomic.Value(usize),
    local_cfg: config.Local,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
) !void {
    var local_socket = try netio.bindUdpRedirListen(local_cfg.host, local_cfg.port, local_cfg.udp_redir);
    defer local_socket.close();

    var associations = std.AutoHashMap(u64, *Association).init(allocator);
    defer associations.deinit();
    var retired = std.ArrayList(*Association).empty;
    defer retired.deinit(allocator);

    var buf: [max_udp_packet_size]u8 = undefined;
    while (true) {
        const received = try local_socket.receiveRedirFrom(&buf);
        cleanupLocalAssociations(allocator, io, &associations, &retired, udp_timeout_seconds);
        const packet = buf[0..received.len];

        const key = addressPairHash(received.from, received.to);
        const assoc = associations.get(key) orelse blk: {
            if (udp_max_associations) |capacity| {
                if (associations.count() >= capacity) continue;
            }
            const server_cfg = try selectUdpServer(server_cfgs, server_next);
            const server_addr = try netio.resolveIp(server_cfg.host, server_cfg.port);
            const remote_socket = try netio.openUdp(server_addr);
            errdefer remote_socket.close();
            const response_socket = try netio.bindUdpRedirResponse(received.to, local_cfg.udp_redir);
            errdefer response_socket.close();

            const assoc = try allocator.create(Association);
            assoc.* = .{
                .allocator = allocator,
                .io = io,
                .server_cfg = server_cfg,
                .local_socket = local_socket,
                .remote_socket = remote_socket,
                .client_addr = received.from,
                .server_addr = server_addr,
                .master_key = [_]u8{0} ** 32,
                .client_session_id = try randomNonZeroU64(io),
                .client_packet_id = 0,
                .server_replay = replay.ReplayProtector.init(allocator, 8192),
                .response_style = .redir,
                .response_socket = response_socket,
                .timeout_ns = timeoutNs(udp_timeout_seconds),
                .last_seen_ns = .init(nowNs(io)),
            };
            try crypto.deriveMasterKey(server_cfg.method, server_cfg.password, assoc.master_key[0..server_cfg.method.keyLen()]);
            try associations.put(key, assoc);

            const thread = try std.Thread.spawn(.{}, localResponseLoop, .{assoc});
            thread.detach();
            break :blk assoc;
        };
        assoc.last_seen_ns.store(nowNs(io), .release);

        const target_address = try netio.ipToShadow(received.to);
        const plain = try makeAddressPayload(allocator, target_address, packet);
        defer allocator.free(plain);
        const encrypted = try encryptClientUdpPacket(allocator, io, assoc, plain);
        defer allocator.free(encrypted);
        _ = try assoc.remote_socket.sendTo(encrypted, assoc.server_addr);
    }
}

pub fn runFakeDnsLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    local_cfg: config.Local,
    manager: *fake_dns.Manager,
) !void {
    _ = allocator;
    var local_socket = try netio.bindUdp(local_cfg.host, local_cfg.port);
    defer local_socket.close();

    var buf: [max_udp_packet_size]u8 = undefined;
    var response_buf: [512]u8 = undefined;
    while (true) {
        const received = try local_socket.receiveFrom(&buf);
        const response_len = fake_dns.writeResponse(io, manager, buf[0..received.len], &response_buf) catch continue;
        _ = try local_socket.sendTo(response_buf[0..response_len], received.from);
    }
}

pub fn runLocalTunnel(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_cfgs: []const config.Server,
    server_next: *std.atomic.Value(usize),
    local_cfg: config.Local,
    forward_address: ss_address.Address,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
) !void {
    var local_socket = try netio.bindUdp(local_cfg.host, local_cfg.port);
    defer local_socket.close();

    var associations = std.AutoHashMap(u64, *Association).init(allocator);
    defer associations.deinit();
    var retired = std.ArrayList(*Association).empty;
    defer retired.deinit(allocator);

    var buf: [max_udp_packet_size]u8 = undefined;
    while (true) {
        const received = try local_socket.receiveFrom(&buf);
        cleanupLocalAssociations(allocator, io, &associations, &retired, udp_timeout_seconds);
        const packet = buf[0..received.len];

        const key = netio.addressHash(received.from);
        const assoc = associations.get(key) orelse blk: {
            if (udp_max_associations) |capacity| {
                if (associations.count() >= capacity) continue;
            }
            const server_cfg = try selectUdpServer(server_cfgs, server_next);
            const server_addr = try netio.resolveIp(server_cfg.host, server_cfg.port);
            const remote_socket = try netio.openUdp(server_addr);
            errdefer remote_socket.close();

            const assoc = try allocator.create(Association);
            assoc.* = .{
                .allocator = allocator,
                .io = io,
                .server_cfg = server_cfg,
                .local_socket = local_socket,
                .remote_socket = remote_socket,
                .client_addr = received.from,
                .server_addr = server_addr,
                .master_key = [_]u8{0} ** 32,
                .client_session_id = try randomNonZeroU64(io),
                .client_packet_id = 0,
                .server_replay = replay.ReplayProtector.init(allocator, 8192),
                .response_style = .raw,
                .timeout_ns = timeoutNs(udp_timeout_seconds),
                .last_seen_ns = .init(nowNs(io)),
            };
            try crypto.deriveMasterKey(server_cfg.method, server_cfg.password, assoc.master_key[0..server_cfg.method.keyLen()]);
            try associations.put(key, assoc);

            const thread = try std.Thread.spawn(.{}, localResponseLoop, .{assoc});
            thread.detach();
            break :blk assoc;
        };
        assoc.last_seen_ns.store(nowNs(io), .release);

        const plain = try makeAddressPayload(allocator, forward_address, packet);
        defer allocator.free(plain);
        const encrypted = try encryptClientUdpPacket(allocator, io, assoc, plain);
        defer allocator.free(encrypted);
        _ = try assoc.remote_socket.sendTo(encrypted, assoc.server_addr);
    }
}

pub fn runDnsLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_cfgs: []const config.Server,
    server_next: *std.atomic.Value(usize),
    local_cfg: config.Local,
    remote_dns_address: ss_address.Address,
    local_dns_address: ?ss_address.Address,
    access_control: ?*const acl.AccessControl,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
) !void {
    var local_socket = try netio.bindUdp(local_cfg.host, local_cfg.port);
    defer local_socket.close();

    var associations = std.AutoHashMap(u64, *Association).init(allocator);
    defer associations.deinit();
    var retired = std.ArrayList(*Association).empty;
    defer retired.deinit(allocator);

    var buf: [max_udp_packet_size]u8 = undefined;
    while (true) {
        const received = try local_socket.receiveFrom(&buf);
        cleanupLocalAssociations(allocator, io, &associations, &retired, udp_timeout_seconds);
        const packet = buf[0..received.len];
        const target_address = dnsTargetAddress(io, packet, remote_dns_address, local_dns_address, access_control);
        if (local_dns_address != null and isSameAddress(target_address, local_dns_address.?)) {
            try directUdpQuery(&local_socket, packet, received.from, target_address);
            continue;
        }

        const key = netio.addressHash(received.from);
        const assoc = associations.get(key) orelse blk: {
            if (udp_max_associations) |capacity| {
                if (associations.count() >= capacity) continue;
            }
            const server_cfg = try selectUdpServer(server_cfgs, server_next);
            const server_addr = try netio.resolveIp(server_cfg.host, server_cfg.port);
            const remote_socket = try netio.openUdp(server_addr);
            errdefer remote_socket.close();

            const assoc = try allocator.create(Association);
            assoc.* = .{
                .allocator = allocator,
                .io = io,
                .server_cfg = server_cfg,
                .local_socket = local_socket,
                .remote_socket = remote_socket,
                .client_addr = received.from,
                .server_addr = server_addr,
                .master_key = [_]u8{0} ** 32,
                .client_session_id = try randomNonZeroU64(io),
                .client_packet_id = 0,
                .server_replay = replay.ReplayProtector.init(allocator, 8192),
                .response_style = .raw,
                .timeout_ns = timeoutNs(udp_timeout_seconds),
                .last_seen_ns = .init(nowNs(io)),
            };
            try crypto.deriveMasterKey(server_cfg.method, server_cfg.password, assoc.master_key[0..server_cfg.method.keyLen()]);
            try associations.put(key, assoc);

            const thread = try std.Thread.spawn(.{}, localResponseLoop, .{assoc});
            thread.detach();
            break :blk assoc;
        };
        assoc.last_seen_ns.store(nowNs(io), .release);

        const plain = try makeAddressPayload(allocator, target_address, packet);
        defer allocator.free(plain);
        const encrypted = try encryptClientUdpPacket(allocator, io, assoc, plain);
        defer allocator.free(encrypted);
        _ = try assoc.remote_socket.sendTo(encrypted, assoc.server_addr);
    }
}

fn selectUdpServer(server_cfgs: []const config.Server, next_index: *std.atomic.Value(usize)) !config.Server {
    if (server_cfgs.len == 0) return error.MissingServer;
    var attempts: usize = 0;
    while (attempts < server_cfgs.len) : (attempts += 1) {
        const index = next_index.fetchAdd(1, .monotonic) % server_cfgs.len;
        const server_cfg = server_cfgs[index];
        if (server_cfg.mode.enableUdp()) return server_cfg;
    }
    return error.UnsupportedCipher;
}

fn directUdpQuery(local_socket: *netio.UdpSocket, packet: []const u8, client_addr: netio.net.IpAddress, target_address: ss_address.Address) !void {
    const target = try netio.shadowToIp(target_address);
    var upstream = try netio.openUdp(target);
    defer upstream.close();
    _ = try upstream.sendTo(packet, target);
    var response_buf: [max_udp_packet_size]u8 = undefined;
    const response = (try upstream.receiveFromTimeout(&response_buf, 5000)) orelse return error.ConnectionTimedOut;
    _ = try local_socket.sendTo(response_buf[0..response.len], client_addr);
}

fn dnsTargetAddress(
    io: std.Io,
    packet: []const u8,
    remote_dns_address: ss_address.Address,
    local_dns_address: ?ss_address.Address,
    access_control: ?*const acl.AccessControl,
) ss_address.Address {
    const local = local_dns_address orelse return remote_dns_address;
    const active_acl = access_control orelse return remote_dns_address;
    var host_buf: [255]u8 = undefined;
    const host = dns.queryHost(packet, &host_buf) catch return remote_dns_address;
    const question_address = ss_address.Address{ .domain = .{ .name = host, .port = 53 } };
    if (active_acl.shouldProxy(io, question_address)) return remote_dns_address;
    return local;
}

fn isSameAddress(a: ss_address.Address, b: ss_address.Address) bool {
    return switch (a) {
        .ipv4 => |a4| switch (b) {
            .ipv4 => |b4| std.mem.eql(u8, &a4.ip, &b4.ip) and a4.port == b4.port,
            else => false,
        },
        .ipv6 => |a6| switch (b) {
            .ipv6 => |b6| std.mem.eql(u8, &a6.ip, &b6.ip) and a6.port == b6.port,
            else => false,
        },
        .domain => |ad| switch (b) {
            .domain => |bd| std.ascii.eqlIgnoreCase(ad.name, bd.name) and ad.port == bd.port,
            else => false,
        },
    };
}

fn rewriteFakeDnsAddress(manager: ?*fake_dns.Manager, io: std.Io, address: ss_address.Address) ss_address.Address {
    const active_manager = manager orelse return address;
    return active_manager.rewriteAddress(io, address) orelse address;
}

pub fn runServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_cfg: config.Server,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
    replay_protector: *replay.ReplayProtector,
    access_control: ?*const acl.AccessControl,
    traffic_counter: *traffic.Counter,
) !void {
    var socket = try netio.bindUdp(server_cfg.host, server_cfg.port);
    defer socket.close();

    var master_key: [32]u8 = undefined;
    try crypto.deriveMasterKey(server_cfg.method, server_cfg.password, master_key[0..server_cfg.method.keyLen()]);

    var target_to_client = std.AutoHashMap(u64, ServerAssociation).init(allocator);
    defer target_to_client.deinit();

    var buf: [max_udp_packet_size]u8 = undefined;
    while (true) {
        const received = try socket.receiveFrom(&buf);
        cleanupServerAssociations(&target_to_client, io, udp_timeout_seconds);
        const packet = buf[0..received.len];

        if (decryptClientUdpPacket(allocator, server_cfg.method, master_key[0..server_cfg.method.keyLen()], packet)) |decrypted| {
            const plain = decrypted.plain;
            defer allocator.free(plain);
            if (decrypted.timestamp) |timestamp| {
                if (!validAead2022Timestamp(io, timestamp)) continue;
            }
            if (clientBlocked(access_control, received.from)) continue;
            if (try replay_protector.checkAndSet(decrypted.replay_key[0..decrypted.replay_key_len])) continue;

            const parsed = ss_address.Address.read(plain) catch continue;
            if (outboundBlocked(access_control, io, parsed.address)) continue;
            const target = netio.shadowToIp(parsed.address) catch continue;
            const target_key = netio.addressHash(target);
            const existing = target_to_client.get(target_key);
            if (!target_to_client.contains(netio.addressHash(target))) {
                if (udp_max_associations) |capacity| {
                    if (capacity == 0) continue;
                    if (target_to_client.count() >= capacity) removeOldestServerAssociation(&target_to_client);
                }
            }
            const server_session_id = if (existing) |assoc| assoc.server_session_id else try randomNonZeroU64(io);
            const server_packet_id = if (existing) |assoc| assoc.server_packet_id else 0;
            try target_to_client.put(target_key, .{
                .client_addr = received.from,
                .last_seen_ns = nowNs(io),
                .client_control = decrypted.control,
                .server_session_id = server_session_id,
                .server_packet_id = server_packet_id,
            });
            const payload = plain[parsed.used..];
            _ = try socket.sendTo(payload, target);
            traffic_counter.add(payload.len);
        } else |_| {
            const assoc = target_to_client.getPtr(netio.addressHash(received.from)) orelse continue;
            try sendTargetResponse(allocator, io, &socket, server_cfg.method, master_key[0..server_cfg.method.keyLen()], assoc, received.from, packet, traffic_counter);
        }
    }
}

fn sendTargetResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: *netio.UdpSocket,
    method: crypto.CipherKind,
    master_key: []const u8,
    assoc: *ServerAssociation,
    source_addr: netio.net.IpAddress,
    payload: []const u8,
    traffic_counter: *traffic.Counter,
) !void {
    assoc.last_seen_ns = nowNs(io);
    const source = netio.ipToShadow(source_addr) catch return;
    const plain = try makeAddressPayload(allocator, source, payload);
    defer allocator.free(plain);
    const encrypted = try encryptServerUdpPacket(allocator, io, method, master_key, assoc, plain);
    defer allocator.free(encrypted);
    _ = try socket.sendTo(encrypted, assoc.client_addr);
    traffic_counter.add(payload.len);
}

fn clientBlocked(access_control: ?*const acl.AccessControl, client_addr: netio.net.IpAddress) bool {
    const active_acl = access_control orelse return false;
    return active_acl.clientBlocked(client_addr);
}

fn outboundBlocked(access_control: ?*const acl.AccessControl, io: std.Io, address: ss_address.Address) bool {
    const active_acl = access_control orelse return false;
    return active_acl.outboundBlocked(io, address);
}

fn encryptClientUdpPacket(
    allocator: std.mem.Allocator,
    io: std.Io,
    assoc: *Association,
    plain: []const u8,
) ![]u8 {
    const method = assoc.server_cfg.method;
    return switch (method.category()) {
        .aead => try crypto.encryptUdpPacket(allocator, io, method, assoc.master_key[0..method.keyLen()], plain),
        .aead2022 => {
            assoc.client_packet_id = assoc.client_packet_id +% 1;
            if (assoc.client_packet_id == 0) {
                assoc.client_session_id = try randomNonZeroU64(io);
                assoc.client_packet_id = 1;
            }
            return try crypto.encryptAead2022UdpPacket(
                allocator,
                io,
                method,
                assoc.master_key[0..method.keyLen()],
                .client,
                .{ .client_session_id = assoc.client_session_id, .packet_id = assoc.client_packet_id },
                plain,
                nowUnixSeconds(io),
            );
        },
        else => error.UnsupportedCipher,
    };
}

fn encryptServerUdpPacket(
    allocator: std.mem.Allocator,
    io: std.Io,
    method: crypto.CipherKind,
    master_key: []const u8,
    assoc: *ServerAssociation,
    plain: []const u8,
) ![]u8 {
    return switch (method.category()) {
        .aead => try crypto.encryptUdpPacket(allocator, io, method, master_key, plain),
        .aead2022 => {
            assoc.server_packet_id = assoc.server_packet_id +% 1;
            if (assoc.server_packet_id == 0) return error.PacketTooLong;
            return try crypto.encryptAead2022UdpPacket(
                allocator,
                io,
                method,
                master_key,
                .server,
                .{
                    .client_session_id = assoc.client_control.client_session_id,
                    .server_session_id = assoc.server_session_id,
                    .packet_id = assoc.server_packet_id,
                },
                plain,
                nowUnixSeconds(io),
            );
        },
        else => error.UnsupportedCipher,
    };
}

fn decryptClientUdpPacket(
    allocator: std.mem.Allocator,
    method: crypto.CipherKind,
    master_key: []const u8,
    packet: []const u8,
) !DecryptedUdpPacket {
    return switch (method.category()) {
        .aead => {
            const plain = try crypto.decryptUdpPacket(allocator, method, master_key, packet);
            errdefer allocator.free(plain);
            var replay_key: [32]u8 = [_]u8{0} ** 32;
            const salt = try crypto.saltFromUdpPacket(method, packet);
            @memcpy(replay_key[0..salt.len], salt);
            return .{ .plain = plain, .replay_key = replay_key, .replay_key_len = salt.len };
        },
        .aead2022 => {
            const decoded = try crypto.decryptAead2022UdpPacket(allocator, method, master_key, packet, .client);
            errdefer allocator.free(decoded.plain);
            return .{
                .plain = decoded.plain,
                .control = decoded.control,
                .timestamp = decoded.timestamp,
                .replay_key = aead2022ReplayKey(decoded.control),
                .replay_key_len = 16,
            };
        },
        else => error.UnsupportedCipher,
    };
}

fn decryptServerUdpPacket(
    allocator: std.mem.Allocator,
    assoc: *Association,
    packet: []const u8,
) !DecryptedUdpPacket {
    const method = assoc.server_cfg.method;
    return switch (method.category()) {
        .aead => {
            const plain = try crypto.decryptUdpPacket(allocator, method, assoc.master_key[0..method.keyLen()], packet);
            return .{ .plain = plain };
        },
        .aead2022 => {
            const decoded = try crypto.decryptAead2022UdpPacket(
                allocator,
                method,
                assoc.master_key[0..method.keyLen()],
                packet,
                .server,
            );
            errdefer allocator.free(decoded.plain);
            return .{
                .plain = decoded.plain,
                .control = decoded.control,
                .timestamp = decoded.timestamp,
                .replay_key = aead2022ReplayKey(decoded.control),
                .replay_key_len = 16,
            };
        },
        else => error.UnsupportedCipher,
    };
}

fn aead2022ReplayKey(control: crypto.Aead2022UdpControl) [32]u8 {
    var key: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, key[0..8], if (control.server_session_id != 0) control.server_session_id else control.client_session_id, .big);
    std.mem.writeInt(u64, key[8..16], control.packet_id, .big);
    return key;
}

fn validAead2022Timestamp(io: std.Io, timestamp: u64) bool {
    const now = nowUnixSeconds(io);
    return if (now >= timestamp)
        now - timestamp <= 30
    else
        timestamp - now <= 30;
}

fn nowUnixSeconds(io: std.Io) u64 {
    return @intCast(std.Io.Clock.real.now(io).toSeconds());
}

fn randomNonZeroU64(io: std.Io) !u64 {
    while (true) {
        var bytes: [8]u8 = undefined;
        try io.randomSecure(&bytes);
        const value = std.mem.readInt(u64, &bytes, .big);
        if (value != 0) return value;
    }
}

fn localResponseLoop(assoc: *Association) void {
    defer assoc.server_replay.deinit();
    var buf: [max_udp_packet_size]u8 = undefined;
    while (true) {
        if (assoc.closed.load(.acquire)) break;
        const now = nowNs(assoc.io);
        const idle_ns = now - assoc.last_seen_ns.load(.acquire);
        if (idle_ns >= assoc.timeout_ns) break;
        const wait_ms: u64 = @intCast(@max(@min(@divTrunc(assoc.timeout_ns - idle_ns, std.time.ns_per_ms), 1000), 1));
        const received = (assoc.remote_socket.receiveFromTimeout(&buf, wait_ms) catch break) orelse continue;
        if (!netio.eqlAddress(received.from, assoc.server_addr)) continue;

        const decrypted = decryptServerUdpPacket(assoc.allocator, assoc, buf[0..received.len]) catch continue;
        if (decrypted.timestamp) |timestamp| {
            if (!validAead2022Timestamp(assoc.io, timestamp)) {
                assoc.allocator.free(decrypted.plain);
                continue;
            }
            if (decrypted.control.client_session_id != assoc.client_session_id) {
                assoc.allocator.free(decrypted.plain);
                continue;
            }
            if (assoc.server_replay.checkAndSet(decrypted.replay_key[0..decrypted.replay_key_len]) catch true) {
                assoc.allocator.free(decrypted.plain);
                continue;
            }
        }
        const plain = decrypted.plain;
        defer assoc.allocator.free(plain);

        const parsed = ss_address.Address.read(plain) catch continue;
        const payload = plain[parsed.used..];
        switch (assoc.response_style) {
            .socks => {
                const response = makeSocksUdpPacket(assoc.allocator, parsed.address, payload) catch continue;
                defer assoc.allocator.free(response);
                _ = assoc.local_socket.sendTo(response, assoc.client_addr) catch break;
            },
            .raw => {
                _ = assoc.local_socket.sendTo(payload, assoc.client_addr) catch break;
            },
            .redir => {
                var response_socket = assoc.response_socket orelse break;
                _ = response_socket.sendTo(payload, assoc.client_addr) catch break;
            },
        }
    }
    if (assoc.response_socket) |response_socket| response_socket.close();
    assoc.remote_socket.close();
    assoc.closed.store(true, .release);
}

const ServerAssociation = struct {
    client_addr: netio.net.IpAddress,
    last_seen_ns: i64,
    client_control: crypto.Aead2022UdpControl = .{},
    server_session_id: u64 = 0,
    server_packet_id: u64 = 0,
};

const DecryptedUdpPacket = struct {
    plain: []u8,
    control: crypto.Aead2022UdpControl = .{},
    timestamp: ?u64 = null,
    replay_key: [32]u8 = [_]u8{0} ** 32,
    replay_key_len: usize = 0,
};

const LocalRemoval = struct {
    key: u64,
};

fn cleanupLocalAssociations(
    allocator: std.mem.Allocator,
    io: std.Io,
    associations: *std.AutoHashMap(u64, *Association),
    retired: *std.ArrayList(*Association),
    udp_timeout_seconds: u64,
) void {
    const now = nowNs(io);
    var removals = std.ArrayList(LocalRemoval).empty;
    defer removals.deinit(allocator);

    var it = associations.iterator();
    while (it.next()) |entry| {
        const assoc = entry.value_ptr.*;
        const expired = now - assoc.last_seen_ns.load(.acquire) >= timeoutNs(udp_timeout_seconds);
        const closed = assoc.closed.load(.acquire);
        if (!expired and !closed) continue;
        removals.append(allocator, .{ .key = entry.key_ptr.* }) catch return;
    }

    for (removals.items) |removal| {
        if (associations.fetchRemove(removal.key)) |removed| {
            retired.append(allocator, removed.value) catch {};
        }
    }

    var i: usize = 0;
    while (i < retired.items.len) {
        const assoc = retired.items[i];
        if (!assoc.closed.load(.acquire)) {
            i += 1;
            continue;
        }
        allocator.destroy(assoc);
        _ = retired.swapRemove(i);
    }
}

fn cleanupServerAssociations(associations: *std.AutoHashMap(u64, ServerAssociation), io: std.Io, udp_timeout_seconds: u64) void {
    const now = nowNs(io);
    const ttl = timeoutNs(udp_timeout_seconds);
    var expired_keys: [64]u64 = undefined;
    var expired_count: usize = 0;

    var it = associations.iterator();
    while (it.next()) |entry| {
        if (now - entry.value_ptr.last_seen_ns >= ttl) {
            expired_keys[expired_count] = entry.key_ptr.*;
            expired_count += 1;
            if (expired_count == expired_keys.len) {
                for (expired_keys[0..expired_count]) |key| _ = associations.remove(key);
                expired_count = 0;
            }
        }
    }

    for (expired_keys[0..expired_count]) |key| _ = associations.remove(key);
}

fn removeOldestServerAssociation(associations: *std.AutoHashMap(u64, ServerAssociation)) void {
    var oldest_key: ?u64 = null;
    var oldest_seen: i64 = std.math.maxInt(i64);
    var it = associations.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.last_seen_ns < oldest_seen) {
            oldest_seen = entry.value_ptr.last_seen_ns;
            oldest_key = entry.key_ptr.*;
        }
    }
    if (oldest_key) |key| _ = associations.remove(key);
}

fn addressPairHash(a: netio.net.IpAddress, b: netio.net.IpAddress) u64 {
    var hasher = std.hash.Wyhash.init(0);
    const a_hash = netio.addressHash(a);
    const b_hash = netio.addressHash(b);
    hasher.update(&std.mem.toBytes(a_hash));
    hasher.update(&std.mem.toBytes(b_hash));
    return hasher.final();
}

fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

fn timeoutNs(seconds: u64) i64 {
    const ns = seconds *| std.time.ns_per_s;
    return std.math.cast(i64, ns) orelse std.math.maxInt(i64);
}

fn makeAddressPayload(allocator: std.mem.Allocator, address: ss_address.Address, payload: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, address.encodedLen() + payload.len);
    errdefer allocator.free(out);
    const used = try address.write(out);
    @memcpy(out[used..], payload);
    return out;
}

fn makeSocksUdpPacket(allocator: std.mem.Allocator, address: ss_address.Address, payload: []const u8) ![]u8 {
    const header = socks5.UdpAssociateHeader{ .frag = 0, .address = address };
    const out = try allocator.alloc(u8, header.encodedLen() + payload.len);
    errdefer allocator.free(out);
    const used = try header.write(out);
    @memcpy(out[used..], payload);
    return out;
}

test "SOCKS UDP packet wraps shadowsocks address and payload" {
    const packet = try makeSocksUdpPacket(
        std.testing.allocator,
        .{ .domain = .{ .name = "example.com", .port = 53 } },
        "dns",
    );
    defer std.testing.allocator.free(packet);

    const parsed = try socks5.UdpAssociateHeader.read(packet);
    try std.testing.expectEqualStrings("example.com", parsed.header.address.domain.name);
    try std.testing.expectEqualStrings("dns", packet[parsed.used..]);
}

test "server UDP associations expire and evict oldest" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = nowNs(io);

    var associations = std.AutoHashMap(u64, ServerAssociation).init(std.testing.allocator);
    defer associations.deinit();

    const fresh = netio.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1001 } };
    const expired = netio.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 1002 } };
    const oldest = netio.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 1003 } };

    try associations.put(netio.addressHash(fresh), .{ .client_addr = fresh, .last_seen_ns = now });
    try associations.put(netio.addressHash(expired), .{ .client_addr = expired, .last_seen_ns = now - timeoutNs(10) });
    cleanupServerAssociations(&associations, io, 5);
    try std.testing.expect(associations.contains(netio.addressHash(fresh)));
    try std.testing.expect(!associations.contains(netio.addressHash(expired)));

    try associations.put(netio.addressHash(oldest), .{ .client_addr = oldest, .last_seen_ns = now - timeoutNs(1) });
    removeOldestServerAssociation(&associations);
    try std.testing.expect(associations.contains(netio.addressHash(fresh)));
    try std.testing.expect(!associations.contains(netio.addressHash(oldest)));
}

test "address pair hash distinguishes redir destinations" {
    const client = netio.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 2000 } };
    const target_a = netio.net.IpAddress{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 80 } };
    const target_b = netio.net.IpAddress{ .ip4 = .{ .bytes = .{ 198, 51, 100, 2 }, .port = 80 } };

    try std.testing.expectEqual(addressPairHash(client, target_a), addressPairHash(client, target_a));
    try std.testing.expect(addressPairHash(client, target_a) != addressPairHash(client, target_b));
}
