const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config.zig");
const crypto = @import("../crypto.zig");
const ss_address = @import("../protocol/address.zig");
const acl = @import("../security/acl.zig");
const replay = @import("../security/replay.zig");
const fake_dns = @import("fake_dns.zig");
const libuv = @import("../deps/libuv.zig");
const netio = @import("netio.zig");

const net = std.Io.net;
const ipv4_header_len = 20;
const ipv6_header_len = 40;
const udp_header_len = 8;
const max_tun_packet_size = 64 * 1024;
const infinite_timeout_ms = std.math.maxInt(u64);

const linux_if_name_size = 16;
const linux_iff_tun: c_short = 0x0001;
const linux_iff_no_pi: c_short = 0x1000;
const linux_tunsetiff: c_ulong = 0x400454ca;

const LinuxIfReq = extern struct {
    ifr_name: [linux_if_name_size]u8 = [_]u8{0} ** linux_if_name_size,
    ifr_flags: c_short = 0,
    _pad: [22]u8 = [_]u8{0} ** 22,
};

pub const IpVersion = enum {
    ipv4,
    ipv6,
};

pub const IpProtocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    icmpv6 = 58,
    other = 255,

    fn fromByte(value: u8) IpProtocol {
        return switch (value) {
            1 => .icmp,
            6 => .tcp,
            17 => .udp,
            58 => .icmpv6,
            else => .other,
        };
    }
};

pub const IpPacket = struct {
    version: IpVersion,
    protocol: IpProtocol,
    protocol_number: u8,
    source: net.IpAddress,
    destination: net.IpAddress,
    payload: []const u8,
};

pub const UdpPacket = struct {
    version: IpVersion,
    source: net.IpAddress,
    destination: net.IpAddress,
    payload: []const u8,
};

pub const Device = struct {
    fd: std.posix.fd_t,
    name: [linux_if_name_size]u8 = [_]u8{0} ** linux_if_name_size,

    pub fn open(local_cfg: config.Local) !Device {
        return switch (builtin.os.tag) {
            .linux => try openLinuxTun(local_cfg.tun_interface_name),
            .macos, .ios => error.TunLocalDarwinDeviceNotImplemented,
            .windows => error.TunLocalWindowsDeviceNotImplemented,
            else => error.TunLocalUnsupportedPlatform,
        };
    }

    pub fn close(self: *Device) void {
        closeFd(self.fd);
        self.* = undefined;
    }

    pub fn read(self: *Device, out: []u8) !usize {
        while (true) {
            if (!try libuv.waitReadable(self.fd, infinite_timeout_ms)) continue;
            return readFd(self.fd, out) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
        }
    }

    pub fn writeAll(self: *Device, packet: []const u8) !void {
        var offset: usize = 0;
        while (offset < packet.len) {
            if (!try libuv.waitWritable(self.fd, infinite_timeout_ms)) continue;
            const written = writeFd(self.fd, packet[offset..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
            if (written == 0) return error.DeviceClosed;
            offset += written;
        }
    }

    pub fn nameSlice(self: *const Device) []const u8 {
        return std.mem.sliceTo(&self.name, 0);
    }
};

pub const UdpAssociation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server_cfg: config.Server,
    client_addr: net.IpAddress,
    master_key: [32]u8,
    client_session_id: u64,
    client_packet_id: u64 = 0,
    server_replay: replay.ReplayProtector,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        server_cfg: config.Server,
        client_addr: net.IpAddress,
    ) !UdpAssociation {
        var self = UdpAssociation{
            .allocator = allocator,
            .io = io,
            .server_cfg = server_cfg,
            .client_addr = client_addr,
            .master_key = [_]u8{0} ** 32,
            .client_session_id = try randomNonZeroU64(io),
            .server_replay = replay.ReplayProtector.init(allocator, 8192),
        };
        try crypto.deriveMasterKey(server_cfg.method, server_cfg.password, self.master_key[0..server_cfg.method.keyLen()]);
        return self;
    }

    pub fn deinit(self: *UdpAssociation) void {
        self.server_replay.deinit();
        self.* = undefined;
    }

    pub fn encryptPacket(self: *UdpAssociation, packet: UdpPacket) ![]u8 {
        const target_address = try netio.ipToShadow(packet.destination);
        const plain = try makeShadowPayload(self.allocator, target_address, packet.payload);
        defer self.allocator.free(plain);
        return try self.encryptPlain(plain);
    }

    pub fn decryptPacket(self: *UdpAssociation, encrypted: []const u8, out: []u8) ![]u8 {
        const decrypted = try self.decryptServerPacket(encrypted);
        defer self.allocator.free(decrypted.plain);
        if (decrypted.timestamp) |timestamp| {
            if (!validAead2022Timestamp(self.io, timestamp)) return error.InvalidTimestamp;
            if (decrypted.control.client_session_id != self.client_session_id) return error.InvalidPacket;
            if (try self.server_replay.checkAndSet(decrypted.replay_key[0..decrypted.replay_key_len])) return error.ReplayedPacket;
        }

        const parsed = try ss_address.Address.read(decrypted.plain);
        const payload = decrypted.plain[parsed.used..];
        const source = try netio.shadowToIp(parsed.address);
        return try buildUdpPacket(out, source, self.client_addr, payload);
    }

    fn encryptPlain(self: *UdpAssociation, plain: []const u8) ![]u8 {
        const method = self.server_cfg.method;
        return switch (method.category()) {
            .stream, .aead => try crypto.encryptUdpPacket(self.allocator, self.io, method, self.master_key[0..method.keyLen()], plain),
            .aead2022 => {
                self.client_packet_id = self.client_packet_id +% 1;
                if (self.client_packet_id == 0) {
                    self.client_session_id = try randomNonZeroU64(self.io);
                    self.client_packet_id = 1;
                }
                return try crypto.encryptAead2022UdpPacket(
                    self.allocator,
                    self.io,
                    method,
                    self.master_key[0..method.keyLen()],
                    .client,
                    .{ .client_session_id = self.client_session_id, .packet_id = self.client_packet_id },
                    plain,
                    nowUnixSeconds(self.io),
                );
            },
            else => error.UnsupportedCipher,
        };
    }

    fn decryptServerPacket(self: *UdpAssociation, encrypted: []const u8) !DecryptedUdpPacket {
        const method = self.server_cfg.method;
        return switch (method.category()) {
            .stream, .aead => {
                const plain = try crypto.decryptUdpPacket(self.allocator, method, self.master_key[0..method.keyLen()], encrypted);
                return .{ .plain = plain };
            },
            .aead2022 => {
                const decoded = try crypto.decryptAead2022UdpPacket(
                    self.allocator,
                    method,
                    self.master_key[0..method.keyLen()],
                    encrypted,
                    .server,
                );
                errdefer self.allocator.free(decoded.plain);
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
};

pub fn runLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    tcp_servers: []const config.Server,
    udp_servers: []const config.Server,
    tcp_next: *std.atomic.Value(usize),
    udp_next: *std.atomic.Value(usize),
    local_cfg: config.Local,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
    access_control: ?*const acl.AccessControl,
    fake_dns_manager: ?*fake_dns.Manager,
) !void {
    _ = tcp_servers;
    _ = udp_servers;
    _ = tcp_next;
    _ = udp_next;
    _ = udp_timeout_seconds;
    _ = udp_max_associations;
    _ = access_control;
    _ = fake_dns_manager;

    return switch (builtin.os.tag) {
        .linux => {
            if (local_cfg.tun_device_fd_from_path != null) return error.TunLocalFdHandoffNotImplemented;
            var device = try Device.open(local_cfg);
            defer device.close();
            return try runDeviceLoop(allocator, io, &device);
        },
        .macos, .ios, .windows => error.TunLocalDeviceNotImplemented,
        else => error.TunLocalUnsupportedPlatform,
    };
}

fn runDeviceLoop(allocator: std.mem.Allocator, io: std.Io, device: *Device) !void {
    _ = allocator;
    _ = io;
    var packet: [max_tun_packet_size]u8 = undefined;
    const n = try device.read(&packet);
    _ = try parseIpPacket(packet[0..n]);
    return error.TunLocalPacketStackNotImplemented;
}

fn openLinuxTun(name: ?[]const u8) !Device {
    var ifreq = try linuxIfReq(name);
    const fd = try std.posix.openat(std.posix.AT.FDCWD, "/dev/net/tun", .{
        .ACCMODE = .RDWR,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0);
    errdefer closeFd(fd);

    switch (std.posix.errno(std.c.ioctl(fd, linux_tunsetiff, &ifreq))) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.AccessDenied,
        .BUSY => return error.DeviceBusy,
        .INVAL => return error.InvalidArgument,
        .NODEV, .NOENT, .NXIO => return error.NoDevice,
        else => |err| return std.posix.unexpectedErrno(err),
    }

    return .{ .fd = fd, .name = ifreq.ifr_name };
}

fn linuxIfReq(name: ?[]const u8) !LinuxIfReq {
    var ifreq = LinuxIfReq{ .ifr_flags = linux_iff_tun | linux_iff_no_pi };
    if (name) |tun_name| {
        if (tun_name.len >= linux_if_name_size) return error.NameTooLong;
        @memcpy(ifreq.ifr_name[0..tun_name.len], tun_name);
    }
    return ifreq;
}

pub fn parseIpPacket(packet: []const u8) !?IpPacket {
    if (packet.len == 0) return null;
    return switch (packet[0] >> 4) {
        4 => try parseIpv4Packet(packet),
        6 => try parseIpv6Packet(packet),
        else => null,
    };
}

pub fn parseUdpPacket(packet: []const u8) !?UdpPacket {
    const ip = (try parseIpPacket(packet)) orelse return null;
    if (ip.protocol != .udp) return null;
    if (ip.payload.len < udp_header_len) return error.InvalidTunPacket;

    const udp_len = std.mem.readInt(u16, ip.payload[4..6], .big);
    if (udp_len < udp_header_len or udp_len > ip.payload.len) return error.InvalidTunPacket;
    const udp_payload = ip.payload[udp_header_len..udp_len];

    var source = ip.source;
    var destination = ip.destination;
    switch (source) {
        .ip4 => |*ip4| ip4.port = std.mem.readInt(u16, ip.payload[0..2], .big),
        .ip6 => |*ip6| ip6.port = std.mem.readInt(u16, ip.payload[0..2], .big),
    }
    switch (destination) {
        .ip4 => |*ip4| ip4.port = std.mem.readInt(u16, ip.payload[2..4], .big),
        .ip6 => |*ip6| ip6.port = std.mem.readInt(u16, ip.payload[2..4], .big),
    }

    const checksum = std.mem.readInt(u16, ip.payload[6..8], .big);
    switch (ip.version) {
        .ipv4 => if (checksum != 0 and udpChecksum(source, destination, ip.payload[0..udp_len]) != 0) return error.InvalidTunPacket,
        .ipv6 => if (checksum == 0 or udpChecksum(source, destination, ip.payload[0..udp_len]) != 0) return error.InvalidTunPacket,
    }

    return .{
        .version = ip.version,
        .source = source,
        .destination = destination,
        .payload = udp_payload,
    };
}

pub fn buildUdpPacket(out: []u8, source: net.IpAddress, destination: net.IpAddress, payload: []const u8) ![]u8 {
    return switch (source) {
        .ip4 => switch (destination) {
            .ip4 => try buildIpv4UdpPacket(out, source, destination, payload),
            .ip6 => error.AddressFamilyMismatch,
        },
        .ip6 => switch (destination) {
            .ip4 => error.AddressFamilyMismatch,
            .ip6 => try buildIpv6UdpPacket(out, source, destination, payload),
        },
    };
}

fn parseIpv4Packet(packet: []const u8) !IpPacket {
    if (packet.len < ipv4_header_len) return error.InvalidTunPacket;
    const header_len = @as(usize, packet[0] & 0x0f) * 4;
    if (header_len < ipv4_header_len or header_len > packet.len) return error.InvalidTunPacket;
    const total_len = std.mem.readInt(u16, packet[2..4], .big);
    if (total_len < header_len or total_len > packet.len) return error.InvalidTunPacket;

    const fragment = std.mem.readInt(u16, packet[6..8], .big);
    if ((fragment & 0x3fff) != 0 or (fragment & 0x2000) != 0) return error.UnsupportedTunFragment;
    if (internetChecksum(packet[0..header_len]) != 0) return error.InvalidTunPacket;

    return .{
        .version = .ipv4,
        .protocol = IpProtocol.fromByte(packet[9]),
        .protocol_number = packet[9],
        .source = .{ .ip4 = .{ .bytes = packet[12..16].*, .port = 0 } },
        .destination = .{ .ip4 = .{ .bytes = packet[16..20].*, .port = 0 } },
        .payload = packet[header_len..total_len],
    };
}

fn parseIpv6Packet(packet: []const u8) !IpPacket {
    if (packet.len < ipv6_header_len) return error.InvalidTunPacket;
    const payload_len = std.mem.readInt(u16, packet[4..6], .big);
    const total_len = ipv6_header_len + @as(usize, payload_len);
    if (total_len > packet.len) return error.InvalidTunPacket;

    return .{
        .version = .ipv6,
        .protocol = IpProtocol.fromByte(packet[6]),
        .protocol_number = packet[6],
        .source = .{ .ip6 = .{ .bytes = packet[8..24].*, .port = 0, .interface = .none } },
        .destination = .{ .ip6 = .{ .bytes = packet[24..40].*, .port = 0, .interface = .none } },
        .payload = packet[ipv6_header_len..total_len],
    };
}

fn buildIpv4UdpPacket(out: []u8, source: net.IpAddress, destination: net.IpAddress, payload: []const u8) ![]u8 {
    const total_len = ipv4_header_len + udp_header_len + payload.len;
    if (total_len > out.len or total_len > std.math.maxInt(u16)) return error.PacketTooLarge;
    const udp_len: u16 = @intCast(udp_header_len + payload.len);
    const ip4_source = source.ip4;
    const ip4_destination = destination.ip4;

    @memset(out[0..total_len], 0);
    out[0] = 0x45;
    std.mem.writeInt(u16, out[2..4], @intCast(total_len), .big);
    out[8] = 64;
    out[9] = @intFromEnum(IpProtocol.udp);
    @memcpy(out[12..16], &ip4_source.bytes);
    @memcpy(out[16..20], &ip4_destination.bytes);
    std.mem.writeInt(u16, out[10..12], internetChecksum(out[0..ipv4_header_len]), .big);

    const udp = out[ipv4_header_len..total_len];
    std.mem.writeInt(u16, udp[0..2], ip4_source.port, .big);
    std.mem.writeInt(u16, udp[2..4], ip4_destination.port, .big);
    std.mem.writeInt(u16, udp[4..6], udp_len, .big);
    @memcpy(udp[udp_header_len..], payload);
    var checksum = udpChecksum(source, destination, udp);
    if (checksum == 0) checksum = 0xffff;
    std.mem.writeInt(u16, udp[6..8], checksum, .big);

    return out[0..total_len];
}

fn buildIpv6UdpPacket(out: []u8, source: net.IpAddress, destination: net.IpAddress, payload: []const u8) ![]u8 {
    const total_len = ipv6_header_len + udp_header_len + payload.len;
    if (total_len > out.len or udp_header_len + payload.len > std.math.maxInt(u16)) return error.PacketTooLarge;
    const udp_len: u16 = @intCast(udp_header_len + payload.len);
    const ip6_source = source.ip6;
    const ip6_destination = destination.ip6;

    @memset(out[0..total_len], 0);
    out[0] = 0x60;
    std.mem.writeInt(u16, out[4..6], udp_len, .big);
    out[6] = @intFromEnum(IpProtocol.udp);
    out[7] = 64;
    @memcpy(out[8..24], &ip6_source.bytes);
    @memcpy(out[24..40], &ip6_destination.bytes);

    const udp = out[ipv6_header_len..total_len];
    std.mem.writeInt(u16, udp[0..2], ip6_source.port, .big);
    std.mem.writeInt(u16, udp[2..4], ip6_destination.port, .big);
    std.mem.writeInt(u16, udp[4..6], udp_len, .big);
    @memcpy(udp[udp_header_len..], payload);
    var checksum = udpChecksum(source, destination, udp);
    if (checksum == 0) checksum = 0xffff;
    std.mem.writeInt(u16, udp[6..8], checksum, .big);

    return out[0..total_len];
}

fn udpChecksum(source: net.IpAddress, destination: net.IpAddress, udp: []const u8) u16 {
    var sum: u32 = 0;
    switch (source) {
        .ip4 => |src| {
            const dst = destination.ip4;
            sum = checksumAdd(sum, &src.bytes);
            sum = checksumAdd(sum, &dst.bytes);
            sum += @intFromEnum(IpProtocol.udp);
            sum += @intCast(udp.len);
        },
        .ip6 => |src| {
            const dst = destination.ip6;
            sum = checksumAdd(sum, &src.bytes);
            sum = checksumAdd(sum, &dst.bytes);
            sum += @intCast((udp.len >> 16) & 0xffff);
            sum += @intCast(udp.len & 0xffff);
            sum += @intFromEnum(IpProtocol.udp);
        },
    }
    sum = checksumAdd(sum, udp);
    return finalizeChecksum(sum);
}

fn internetChecksum(bytes: []const u8) u16 {
    return finalizeChecksum(checksumAdd(0, bytes));
}

fn checksumAdd(initial: u32, bytes: []const u8) u32 {
    var sum = initial;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u16, bytes[i]) << 8) | bytes[i + 1];
    }
    if (i < bytes.len) {
        sum += @as(u16, bytes[i]) << 8;
    }
    return sum;
}

fn finalizeChecksum(initial: u32) u16 {
    var sum = initial;
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @intCast(sum & 0xffff));
}

fn makeShadowPayload(allocator: std.mem.Allocator, address: ss_address.Address, payload: []const u8) ![]u8 {
    const address_len = address.encodedLen();
    const out = try allocator.alloc(u8, address_len + payload.len);
    errdefer allocator.free(out);
    _ = try address.write(out[0..address_len]);
    @memcpy(out[address_len..], payload);
    return out;
}

const DecryptedUdpPacket = struct {
    plain: []u8,
    control: crypto.Aead2022UdpControl = .{},
    timestamp: ?u64 = null,
    replay_key: [32]u8 = [_]u8{0} ** 32,
    replay_key_len: usize = 0,
};

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

fn readFd(fd: std.posix.fd_t, out: []u8) !usize {
    return std.posix.read(fd, out) catch |err| switch (err) {
        error.WouldBlock => error.WouldBlock,
        error.InputOutput => error.InputOutput,
        else => |e| e,
    };
}

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) !usize {
    if (bytes.len == 0) return 0;
    while (true) {
        const rc = std.posix.system.write(fd, bytes.ptr, bytes.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.DeviceClosed,
            .IO => return error.InputOutput,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .NOSPC => return error.NoSpaceLeft,
            .PIPE => return error.BrokenPipe,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn closeFd(fd: std.posix.fd_t) void {
    while (true) {
        switch (std.posix.errno(std.posix.system.close(fd))) {
            .SUCCESS => return,
            .INTR => continue,
            else => return,
        }
    }
}

fn testServerConfig() config.Server {
    return .{
        .host = "127.0.0.1",
        .port = 8388,
        .password = "test-password",
        .method = .aes_256_gcm,
        .mode = .tcp_and_udp,
        .tcp_weight = config.server_weight_scale,
        .udp_weight = config.server_weight_scale,
        .acl_path = null,
        .plugin = null,
        .plugin_opts = null,
        .plugin_args = &.{},
        .plugin_mode = .tcp_only,
    };
}

test "tun parses synthesized IPv4 UDP packet" {
    var buf: [1500]u8 = undefined;
    const source = try net.IpAddress.parse("192.0.2.10", 53000);
    const destination = try net.IpAddress.parse("198.51.100.20", 53);
    const packet = try buildUdpPacket(&buf, source, destination, "hello");

    const ip = (try parseIpPacket(packet)).?;
    try std.testing.expectEqual(IpVersion.ipv4, ip.version);
    try std.testing.expectEqual(IpProtocol.udp, ip.protocol);
    try std.testing.expectEqual(@as(u8, 17), ip.protocol_number);

    const udp = (try parseUdpPacket(packet)).?;
    try std.testing.expectEqual(source, udp.source);
    try std.testing.expectEqual(destination, udp.destination);
    try std.testing.expectEqualStrings("hello", udp.payload);
}

test "tun parses synthesized IPv6 UDP packet" {
    var buf: [1500]u8 = undefined;
    const source = try net.IpAddress.parse("2001:db8::1", 53000);
    const destination = try net.IpAddress.parse("2001:db8::2", 53);
    const packet = try buildUdpPacket(&buf, source, destination, "hello-v6");

    const ip = (try parseIpPacket(packet)).?;
    try std.testing.expectEqual(IpVersion.ipv6, ip.version);
    try std.testing.expectEqual(IpProtocol.udp, ip.protocol);
    try std.testing.expectEqual(@as(u8, 17), ip.protocol_number);

    const udp = (try parseUdpPacket(packet)).?;
    try std.testing.expectEqual(source, udp.source);
    try std.testing.expectEqual(destination, udp.destination);
    try std.testing.expectEqualStrings("hello-v6", udp.payload);
}

test "tun rejects fragmented IPv4 UDP packet" {
    var buf: [1500]u8 = undefined;
    const source = try net.IpAddress.parse("192.0.2.10", 53000);
    const destination = try net.IpAddress.parse("198.51.100.20", 53);
    const packet = try buildUdpPacket(&buf, source, destination, "hello");
    buf[6] = 0x20;
    std.mem.writeInt(u16, buf[10..12], 0, .big);
    std.mem.writeInt(u16, buf[10..12], internetChecksum(packet[0..ipv4_header_len]), .big);

    try std.testing.expectError(error.UnsupportedTunFragment, parseIpPacket(packet));
}

test "tun UDP association encrypts outbound packet with target address" {
    var io = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io.deinit();
    const server_cfg = testServerConfig();
    const client = try net.IpAddress.parse("192.0.2.10", 53000);
    const target = try net.IpAddress.parse("198.51.100.20", 53);
    var assoc = try UdpAssociation.init(std.testing.allocator, io.io(), server_cfg, client);
    defer assoc.deinit();

    const encrypted = try assoc.encryptPacket(.{
        .version = .ipv4,
        .source = client,
        .destination = target,
        .payload = "query",
    });
    defer std.testing.allocator.free(encrypted);

    var master_key: [32]u8 = undefined;
    try crypto.deriveMasterKey(server_cfg.method, server_cfg.password, master_key[0..server_cfg.method.keyLen()]);
    const plain = try crypto.decryptUdpPacket(std.testing.allocator, server_cfg.method, master_key[0..server_cfg.method.keyLen()], encrypted);
    defer std.testing.allocator.free(plain);

    const parsed = try ss_address.Address.read(plain);
    try std.testing.expectEqual(target, try netio.shadowToIp(parsed.address));
    try std.testing.expectEqualStrings("query", plain[parsed.used..]);
}

test "tun UDP association synthesizes inbound response packet" {
    var io = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io.deinit();
    const server_cfg = testServerConfig();
    const client = try net.IpAddress.parse("192.0.2.10", 53000);
    const target = try net.IpAddress.parse("198.51.100.20", 53);
    var assoc = try UdpAssociation.init(std.testing.allocator, io.io(), server_cfg, client);
    defer assoc.deinit();

    var master_key: [32]u8 = undefined;
    try crypto.deriveMasterKey(server_cfg.method, server_cfg.password, master_key[0..server_cfg.method.keyLen()]);
    const plain_response = try makeShadowPayload(std.testing.allocator, try netio.ipToShadow(target), "answer");
    defer std.testing.allocator.free(plain_response);
    const encrypted_response = try crypto.encryptUdpPacket(std.testing.allocator, io.io(), server_cfg.method, master_key[0..server_cfg.method.keyLen()], plain_response);
    defer std.testing.allocator.free(encrypted_response);

    var out: [1500]u8 = undefined;
    const packet = try assoc.decryptPacket(encrypted_response, &out);
    const udp_packet = (try parseUdpPacket(packet)).?;
    try std.testing.expectEqual(target, udp_packet.source);
    try std.testing.expectEqual(client, udp_packet.destination);
    try std.testing.expectEqualStrings("answer", udp_packet.payload);
}

test "tun linux ifreq copies optional interface name" {
    const ifreq = try linuxIfReq("tun123");
    try std.testing.expectEqual(@as(c_short, linux_iff_tun | linux_iff_no_pi), ifreq.ifr_flags);
    try std.testing.expectEqualStrings("tun123", std.mem.sliceTo(&ifreq.ifr_name, 0));
}

test "tun linux ifreq rejects too long interface name" {
    try std.testing.expectError(error.NameTooLong, linuxIfReq("interface-name-too-long"));
}
