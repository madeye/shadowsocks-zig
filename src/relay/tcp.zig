const std = @import("std");
const config = @import("../config.zig");
const crypto = @import("../crypto.zig");
const plugin = @import("../plugin.zig");
const ss_address = @import("../protocol/address.zig");
const dns = @import("../protocol/dns.zig");
const http = @import("../protocol/http.zig");
const acl = @import("../security/acl.zig");
const socks4 = @import("../protocol/socks4.zig");
const socks5 = @import("../protocol/socks5.zig");
const replay = @import("../security/replay.zig");
const fake_dns = @import("fake_dns.zig");
const netio = @import("netio.zig");
const traffic = @import("traffic.zig");
const udp = @import("udp.zig");

pub const max_aead_packet_size: usize = 0x3fff;
const max_aead2022_timestamp_diff: u64 = 30;

pub const StreamType = enum {
    client,
    server,
};

const LocalServerSet = struct {
    tcp_servers: []config.Server,
    udp_servers: []config.Server,
    plugin_processes: []?plugin.Process,

    fn deinit(self: *LocalServerSet, allocator: std.mem.Allocator, io: std.Io) void {
        for (self.plugin_processes) |*maybe_process| {
            if (maybe_process.*) |*process| process.stop(io);
        }
        allocator.free(self.tcp_servers);
        allocator.free(self.udp_servers);
        allocator.free(self.plugin_processes);
        self.* = undefined;
    }
};

const ServerSelector = struct {
    tcp_servers: []const config.Server,
    udp_servers: []const config.Server,
    tcp_next: std.atomic.Value(usize) = .init(0),
    udp_next: std.atomic.Value(usize) = .init(0),

    fn nextTcp(self: *ServerSelector) !config.Server {
        return selectServer(self.tcp_servers, &self.tcp_next, .tcp);
    }
};

const ServerSelectKind = enum {
    tcp,
    udp,
};

fn selectServer(server_cfgs: []const config.Server, next_index: *std.atomic.Value(usize), kind: ServerSelectKind) !config.Server {
    if (server_cfgs.len == 0) return error.MissingServer;
    var attempts: usize = 0;
    while (attempts < server_cfgs.len) : (attempts += 1) {
        const index = next_index.fetchAdd(1, .monotonic) % server_cfgs.len;
        const server_cfg = server_cfgs[index];
        switch (kind) {
            .tcp => if (server_cfg.mode.enableTcp()) return server_cfg,
            .udp => if (server_cfg.mode.enableUdp()) return server_cfg,
        }
    }
    return error.UnsupportedCipher;
}

fn buildLocalServerSet(
    allocator: std.mem.Allocator,
    io: std.Io,
    env_map: *const std.process.Environ.Map,
    servers: []const config.Server,
) !LocalServerSet {
    var tcp_servers = std.ArrayList(config.Server).empty;
    errdefer tcp_servers.deinit(allocator);
    var udp_servers = std.ArrayList(config.Server).empty;
    errdefer udp_servers.deinit(allocator);
    const plugin_processes = try allocator.alloc(?plugin.Process, servers.len);
    errdefer allocator.free(plugin_processes);
    @memset(plugin_processes, null);

    var initialized_process_count: usize = 0;
    errdefer {
        for (plugin_processes[0..initialized_process_count]) |*maybe_process| {
            if (maybe_process.*) |*process| process.stop(io);
        }
    }

    for (servers, 0..) |server_cfg, i| {
        if (!server_cfg.method.isImplemented()) return error.UnsupportedCipher;
        var tcp_server_cfg = server_cfg;
        var udp_server_cfg = server_cfg;
        if (server_cfg.plugin) |plugin_name| {
            const plugin_host = pluginLoopbackHost(server_cfg.host);
            const plugin_port = try netio.reservePort(plugin_host, server_cfg.plugin_mode);
            plugin_processes[i] = try plugin.start(allocator, io, env_map, .{
                .plugin = plugin_name,
                .plugin_opts = server_cfg.plugin_opts,
                .plugin_args = server_cfg.plugin_args,
                .remote = .{ .host = server_cfg.host, .port = server_cfg.port },
                .local = .{ .host = plugin_host, .port = plugin_port },
                .mode = .client,
            });
            initialized_process_count = i + 1;
            if (server_cfg.plugin_mode.enableTcp()) {
                tcp_server_cfg.host = plugin_host;
                tcp_server_cfg.port = plugin_port;
            }
            if (server_cfg.plugin_mode.enableUdp()) {
                udp_server_cfg.host = plugin_host;
                udp_server_cfg.port = plugin_port;
            }
        }
        if (tcp_server_cfg.mode.enableTcp()) try appendWeightedServer(allocator, &tcp_servers, tcp_server_cfg, tcp_server_cfg.tcp_weight);
        if (udp_server_cfg.mode.enableUdp()) try appendWeightedServer(allocator, &udp_servers, udp_server_cfg, udp_server_cfg.udp_weight);
    }

    const tcp_slice = try tcp_servers.toOwnedSlice(allocator);
    errdefer allocator.free(tcp_slice);
    const udp_slice = try udp_servers.toOwnedSlice(allocator);

    return .{
        .tcp_servers = tcp_slice,
        .udp_servers = udp_slice,
        .plugin_processes = plugin_processes,
    };
}

fn appendWeightedServer(
    allocator: std.mem.Allocator,
    servers: *std.ArrayList(config.Server),
    server_cfg: config.Server,
    weight: u16,
) !void {
    var remaining = weight;
    while (remaining > 0) : (remaining -= 1) {
        try servers.append(allocator, server_cfg);
    }
}

pub fn runServer(allocator: std.mem.Allocator, io: std.Io, env_map: *const std.process.Environ.Map, cfg: *const config.Config) !void {
    if (cfg.servers.len == 0) return error.MissingServer;
    for (cfg.servers) |server_cfg| {
        if (!server_cfg.method.isImplemented()) return error.UnsupportedCipher;
    }

    if (cfg.servers.len == 1) {
        return try runServerInstance(allocator, io, env_map, cfg.servers[0], cfg.manager, cfg.udp_timeout_seconds, cfg.udp_max_associations);
    }

    for (cfg.servers[0 .. cfg.servers.len - 1]) |server_cfg| {
        const thread = try std.Thread.spawn(.{}, runServerInstance, .{ allocator, io, env_map, server_cfg, cfg.manager, cfg.udp_timeout_seconds, cfg.udp_max_associations });
        thread.detach();
    }
    const last = cfg.servers[cfg.servers.len - 1];
    return try runServerInstance(allocator, io, env_map, last, cfg.manager, cfg.udp_timeout_seconds, cfg.udp_max_associations);
}

fn runServerInstance(
    allocator: std.mem.Allocator,
    io: std.Io,
    env_map: *const std.process.Environ.Map,
    server_cfg: config.Server,
    manager_cfg: ?config.Manager,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
) !void {
    if (!server_cfg.method.isImplemented()) return error.UnsupportedCipher;
    var replay_protector = replay.ReplayProtector.init(allocator, 500_000);
    defer replay_protector.deinit();
    var traffic_counter = traffic.Counter{};
    if (manager_cfg) |active_manager_cfg| {
        const reporter = try traffic.startReporter(io, active_manager_cfg, server_cfg.port, &traffic_counter);
        reporter.detach();
    }

    var server_acl: ?acl.AccessControl = null;
    if (server_cfg.acl_path) |path| {
        server_acl = try acl.AccessControl.loadFile(allocator, io, path);
    }
    defer if (server_acl) |*access_control| access_control.deinit();
    const acl_ptr: ?*const acl.AccessControl = if (server_acl) |*access_control| access_control else null;

    var tcp_server_cfg = server_cfg;
    var udp_server_cfg = server_cfg;
    var plugin_process: ?plugin.Process = null;
    if (server_cfg.plugin) |plugin_name| {
        const plugin_host = pluginLoopbackHost(server_cfg.host);
        const internal_port = try netio.reservePort(plugin_host, server_cfg.plugin_mode);
        plugin_process = try plugin.start(allocator, io, env_map, .{
            .plugin = plugin_name,
            .plugin_opts = server_cfg.plugin_opts,
            .plugin_args = server_cfg.plugin_args,
            .remote = .{ .host = server_cfg.host, .port = server_cfg.port },
            .local = .{ .host = plugin_host, .port = internal_port },
            .mode = .server,
        });
        if (server_cfg.plugin_mode.enableTcp()) {
            tcp_server_cfg.host = plugin_host;
            tcp_server_cfg.port = internal_port;
        }
        if (server_cfg.plugin_mode.enableUdp()) {
            udp_server_cfg.host = plugin_host;
            udp_server_cfg.port = internal_port;
        }
    }
    defer if (plugin_process) |*process| process.stop(io);

    if (server_cfg.mode.enableUdp()) {
        if (server_cfg.mode.enableTcp()) {
            const udp_thread = try std.Thread.spawn(.{}, udp.runServer, .{ allocator, io, udp_server_cfg, udp_timeout_seconds, udp_max_associations, &replay_protector, acl_ptr, &traffic_counter });
            udp_thread.detach();
        } else {
            return try udp.runServer(allocator, io, udp_server_cfg, udp_timeout_seconds, udp_max_associations, &replay_protector, acl_ptr, &traffic_counter);
        }
    }
    if (!server_cfg.mode.enableTcp()) return;

    var server = try netio.listenTcp(tcp_server_cfg.host, tcp_server_cfg.port, tcp_server_cfg.reuse_port);
    defer server.close();

    while (true) {
        var conn = try server.accept();
        try conn.applyIncomingBuffers(tcp_server_cfg.tcp_buffers);
        if (tcp_server_cfg.no_delay) conn.setNoDelay();
        const thread = try std.Thread.spawn(.{}, handleServerConnection, .{ allocator, io, conn, tcp_server_cfg, &replay_protector, acl_ptr, &traffic_counter });
        thread.detach();
    }
}

pub fn runLocal(allocator: std.mem.Allocator, io: std.Io, env_map: *const std.process.Environ.Map, cfg: *const config.Config) !void {
    if (cfg.servers.len == 0) return error.MissingServer;
    if (cfg.locals.len == 0) return error.MissingLocal;
    var server_set = try buildLocalServerSet(allocator, io, env_map, cfg.servers);
    defer server_set.deinit(allocator, io);
    var selector = ServerSelector{
        .tcp_servers = server_set.tcp_servers,
        .udp_servers = server_set.udp_servers,
    };
    const fake_dns_ptr = try initFakeDnsManager(allocator, io, cfg.locals);
    defer if (fake_dns_ptr) |manager| {
        manager.deinit();
        allocator.destroy(manager);
    };

    if (cfg.locals.len == 1) {
        return try runLocalInstance(allocator, io, &selector, cfg.locals[0], cfg.udp_timeout_seconds, cfg.udp_max_associations, fake_dns_ptr);
    }

    for (cfg.locals[0 .. cfg.locals.len - 1]) |local_cfg| {
        const thread = try std.Thread.spawn(.{}, runLocalInstance, .{ allocator, io, &selector, local_cfg, cfg.udp_timeout_seconds, cfg.udp_max_associations, fake_dns_ptr });
        thread.detach();
    }
    const last = cfg.locals[cfg.locals.len - 1];
    return try runLocalInstance(allocator, io, &selector, last, cfg.udp_timeout_seconds, cfg.udp_max_associations, fake_dns_ptr);
}

fn initFakeDnsManager(allocator: std.mem.Allocator, io: std.Io, locals: []const config.Local) !?*fake_dns.Manager {
    for (locals) |local_cfg| {
        if (local_cfg.protocol == .fake_dns) {
            const manager = try allocator.create(fake_dns.Manager);
            errdefer allocator.destroy(manager);
            manager.* = try fake_dns.Manager.init(
                allocator,
                io,
                local_cfg.fake_dns_ipv4_network,
                local_cfg.fake_dns_ipv6_network,
                local_cfg.fake_dns_database_path,
                local_cfg.fake_dns_record_expire_duration,
            );
            return manager;
        }
    }
    return null;
}

fn runLocalInstance(
    allocator: std.mem.Allocator,
    io: std.Io,
    selector: *ServerSelector,
    local_cfg: config.Local,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
    fake_dns_manager: ?*fake_dns.Manager,
) !void {
    var local_acl: ?acl.AccessControl = null;
    if (local_cfg.acl_path) |path| {
        local_acl = try acl.AccessControl.loadFile(allocator, io, path);
    }
    defer if (local_acl) |*access_control| access_control.deinit();
    const acl_ptr: ?*const acl.AccessControl = if (local_acl) |*access_control| access_control else null;

    switch (local_cfg.protocol) {
        .tunnel => return try runTunnelLocal(allocator, io, selector, local_cfg, udp_timeout_seconds, udp_max_associations, acl_ptr),
        .redir => return try runRedirLocal(allocator, io, selector, local_cfg, udp_timeout_seconds, udp_max_associations, acl_ptr),
        .dns => return try runDnsLocal(allocator, io, selector, local_cfg, udp_timeout_seconds, udp_max_associations, acl_ptr),
        .fake_dns => return try runFakeDnsLocal(allocator, io, local_cfg, fake_dns_manager orelse return error.MissingFakeDnsManager),
        .socks, .http => {},
    }

    if (local_cfg.protocol == .socks and local_cfg.mode.enableUdp()) {
        if (local_cfg.mode.enableTcp()) {
            const udp_thread = try std.Thread.spawn(.{}, udp.runLocal, .{ allocator, io, selector.udp_servers, &selector.udp_next, local_cfg, udp_timeout_seconds, udp_max_associations, fake_dns_manager });
            udp_thread.detach();
        } else {
            return try udp.runLocal(allocator, io, selector.udp_servers, &selector.udp_next, local_cfg, udp_timeout_seconds, udp_max_associations, fake_dns_manager);
        }
    }
    if (!local_cfg.mode.enableTcp()) return;

    var listener = try netio.listenTcp(local_cfg.host, local_cfg.port, local_cfg.reuse_port);
    defer listener.close();

    while (true) {
        var conn = try listener.accept();
        try conn.applyIncomingBuffers(local_cfg.tcp_buffers);
        if (local_cfg.no_delay) conn.setNoDelay();
        const thread = try std.Thread.spawn(.{}, handleLocalConnection, .{ allocator, io, conn, selector, local_cfg, acl_ptr, fake_dns_manager });
        thread.detach();
    }
}

fn runRedirLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    selector: *ServerSelector,
    local_cfg: config.Local,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
    access_control: ?*const acl.AccessControl,
) !void {
    if (local_cfg.mode.enableUdp()) {
        if (local_cfg.mode.enableTcp()) {
            const udp_thread = try std.Thread.spawn(.{}, udp.runLocalRedir, .{
                allocator,
                io,
                selector.udp_servers,
                &selector.udp_next,
                local_cfg,
                udp_timeout_seconds,
                udp_max_associations,
            });
            udp_thread.detach();
        } else {
            return try udp.runLocalRedir(allocator, io, selector.udp_servers, &selector.udp_next, local_cfg, udp_timeout_seconds, udp_max_associations);
        }
    }
    if (!local_cfg.mode.enableTcp()) return;

    var listener = try netio.listenTcpRedir(local_cfg.host, local_cfg.port, local_cfg.tcp_redir, local_cfg.reuse_port);
    defer listener.close();

    while (true) {
        var conn = try listener.accept();
        try conn.applyIncomingBuffers(local_cfg.tcp_buffers);
        if (local_cfg.no_delay) conn.setNoDelay();
        const target = netio.tcpRedirDestination(conn, local_cfg.tcp_redir) catch {
            conn.close();
            continue;
        };
        const target_address = try netio.ipToShadow(target);
        const thread = try std.Thread.spawn(.{}, handleRedirConnection, .{ allocator, io, conn, selector, target_address, local_cfg.no_delay, local_cfg.ipv6_first, local_cfg.tcp_buffers, access_control });
        thread.detach();
    }
}

fn runFakeDnsLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    local_cfg: config.Local,
    manager: *fake_dns.Manager,
) !void {
    if (local_cfg.mode.enableUdp()) {
        if (local_cfg.mode.enableTcp()) {
            const udp_thread = try std.Thread.spawn(.{}, udp.runFakeDnsLocal, .{ allocator, io, local_cfg, manager });
            udp_thread.detach();
        } else {
            return try udp.runFakeDnsLocal(allocator, io, local_cfg, manager);
        }
    }
    if (!local_cfg.mode.enableTcp()) return;

    var listener = try netio.listenTcp(local_cfg.host, local_cfg.port, local_cfg.reuse_port);
    defer listener.close();

    while (true) {
        var conn = try listener.accept();
        try conn.applyIncomingBuffers(local_cfg.tcp_buffers);
        if (local_cfg.no_delay) conn.setNoDelay();
        const thread = try std.Thread.spawn(.{}, handleFakeDnsConnection, .{ allocator, io, conn, manager });
        thread.detach();
    }
}

fn runTunnelLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    selector: *ServerSelector,
    local_cfg: config.Local,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
    access_control: ?*const acl.AccessControl,
) !void {
    const forward_address = try forwardAddress(local_cfg);

    if (local_cfg.mode.enableUdp()) {
        if (local_cfg.mode.enableTcp()) {
            const udp_thread = try std.Thread.spawn(.{}, udp.runLocalTunnel, .{
                allocator,
                io,
                selector.udp_servers,
                &selector.udp_next,
                local_cfg,
                forward_address,
                udp_timeout_seconds,
                udp_max_associations,
            });
            udp_thread.detach();
        } else {
            return try udp.runLocalTunnel(allocator, io, selector.udp_servers, &selector.udp_next, local_cfg, forward_address, udp_timeout_seconds, udp_max_associations);
        }
    }
    if (!local_cfg.mode.enableTcp()) return;

    var listener = try netio.listenTcp(local_cfg.host, local_cfg.port, local_cfg.reuse_port);
    defer listener.close();

    while (true) {
        var conn = try listener.accept();
        try conn.applyIncomingBuffers(local_cfg.tcp_buffers);
        if (local_cfg.no_delay) conn.setNoDelay();
        const thread = try std.Thread.spawn(.{}, handleTunnelConnection, .{ allocator, io, conn, selector, forward_address, local_cfg.no_delay, local_cfg.ipv6_first, local_cfg.tcp_buffers, access_control });
        thread.detach();
    }
}

fn runDnsLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    selector: *ServerSelector,
    local_cfg: config.Local,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
    access_control: ?*const acl.AccessControl,
) !void {
    const remote_dns_address = try forwardAddress(local_cfg);
    const local_dns_address = try localDnsAddress(local_cfg);

    if (local_cfg.mode.enableUdp()) {
        if (local_cfg.mode.enableTcp()) {
            const udp_thread = try std.Thread.spawn(.{}, udp.runDnsLocal, .{
                allocator,
                io,
                selector.udp_servers,
                &selector.udp_next,
                local_cfg,
                remote_dns_address,
                local_dns_address,
                access_control,
                udp_timeout_seconds,
                udp_max_associations,
            });
            udp_thread.detach();
        } else {
            return try udp.runDnsLocal(allocator, io, selector.udp_servers, &selector.udp_next, local_cfg, remote_dns_address, local_dns_address, access_control, udp_timeout_seconds, udp_max_associations);
        }
    }
    if (!local_cfg.mode.enableTcp()) return;

    var listener = try netio.listenTcp(local_cfg.host, local_cfg.port, local_cfg.reuse_port);
    defer listener.close();

    while (true) {
        var conn = try listener.accept();
        try conn.applyIncomingBuffers(local_cfg.tcp_buffers);
        if (local_cfg.no_delay) conn.setNoDelay();
        const thread = try std.Thread.spawn(.{}, handleDnsConnection, .{ allocator, io, conn, selector, remote_dns_address, local_dns_address, local_cfg.no_delay, local_cfg.ipv6_first, local_cfg.tcp_buffers, access_control });
        thread.detach();
    }
}

fn handleTunnelConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: netio.TcpStream,
    selector: *ServerSelector,
    forward_address: ss_address.Address,
    no_delay: bool,
    ipv6_first: bool,
    tcp_buffers: config.TcpBufferConfig,
    access_control: ?*const acl.AccessControl,
) void {
    var wrapped = client;
    targetTcpConnection(allocator, io, &wrapped, selector, forward_address, no_delay, ipv6_first, tcp_buffers, access_control) catch {};
}

fn handleRedirConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: netio.TcpStream,
    selector: *ServerSelector,
    target_address: ss_address.Address,
    no_delay: bool,
    ipv6_first: bool,
    tcp_buffers: config.TcpBufferConfig,
    access_control: ?*const acl.AccessControl,
) void {
    var wrapped = client;
    targetTcpConnection(allocator, io, &wrapped, selector, target_address, no_delay, ipv6_first, tcp_buffers, access_control) catch {};
}

fn handleDnsConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: netio.TcpStream,
    selector: *ServerSelector,
    remote_dns_address: ss_address.Address,
    local_dns_address: ?ss_address.Address,
    no_delay: bool,
    ipv6_first: bool,
    tcp_buffers: config.TcpBufferConfig,
    access_control: ?*const acl.AccessControl,
) void {
    var wrapped = client;
    dnsConnection(allocator, io, &wrapped, selector, remote_dns_address, local_dns_address, no_delay, ipv6_first, tcp_buffers, access_control) catch {};
}

fn handleFakeDnsConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: netio.TcpStream,
    manager: *fake_dns.Manager,
) void {
    var wrapped = client;
    fakeDnsConnection(allocator, io, &wrapped, manager) catch {};
}

fn fakeDnsConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netio.TcpStream,
    manager: *fake_dns.Manager,
) !void {
    defer client.close();

    var len_buf: [2]u8 = undefined;
    try readExact(client, &len_buf);
    const packet_len = std.mem.readInt(u16, &len_buf, .big);
    if (packet_len == 0) return;
    const packet = try allocator.alloc(u8, packet_len);
    defer allocator.free(packet);
    try readExact(client, packet);

    var response_buf: [512]u8 = undefined;
    const response_len = try fake_dns.writeResponse(io, manager, packet, &response_buf);
    std.mem.writeInt(u16, &len_buf, @intCast(response_len), .big);
    try client.writeAll(&len_buf);
    try client.writeAll(response_buf[0..response_len]);
}

fn dnsConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netio.TcpStream,
    selector: *ServerSelector,
    remote_dns_address: ss_address.Address,
    local_dns_address: ?ss_address.Address,
    no_delay: bool,
    ipv6_first: bool,
    tcp_buffers: config.TcpBufferConfig,
    access_control: ?*const acl.AccessControl,
) !void {
    defer client.close();

    var len_buf: [2]u8 = undefined;
    try readExact(client, &len_buf);
    const packet_len = std.mem.readInt(u16, &len_buf, .big);
    if (packet_len == 0) return;
    const packet = try allocator.alloc(u8, packet_len);
    defer allocator.free(packet);
    try readExact(client, packet);

    const target_address = dnsTargetAddress(io, packet, remote_dns_address, local_dns_address, access_control);
    if (local_dns_address != null and isSameAddress(target_address, local_dns_address.?)) {
        var remote = try connectTargetWithOptions(io, target_address, .{ .no_delay = no_delay, .ipv6_first = ipv6_first, .tcp_buffers = tcp_buffers });
        defer remote.close();
        try remote.writeAll(&len_buf);
        try remote.writeAll(packet);
        const inbound_thread = try std.Thread.spawn(.{}, pipePlainToPlain, .{ remote, client.* });
        defer inbound_thread.join();
        try pipePlainToPlain(client.*, remote);
        return;
    }

    const server_cfg = try selector.nextTcp();
    var tunnel = try openRemoteTunnel(allocator, io, server_cfg, target_address);
    defer tunnel.remote.close();
    try writeInitialPayload(allocator, &tunnel, target_address, &len_buf, packet);
    const inbound_thread = try std.Thread.spawn(.{}, pipeServerEncryptedToPlain, .{ allocator, tunnel.remote, client.*, server_cfg.method, tunnel.master });
    defer inbound_thread.join();
    try pipePlainToEncrypted(allocator, client.*, tunnel.remote, &tunnel.outbound);
}

fn targetTcpConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netio.TcpStream,
    selector: *ServerSelector,
    target_address: ss_address.Address,
    no_delay: bool,
    ipv6_first: bool,
    tcp_buffers: config.TcpBufferConfig,
    access_control: ?*const acl.AccessControl,
) !void {
    defer client.close();

    if (targetBypassed(access_control, io, target_address)) {
        var remote = try connectTargetWithOptions(io, target_address, .{ .no_delay = no_delay, .ipv6_first = ipv6_first, .tcp_buffers = tcp_buffers });
        defer remote.close();

        const inbound_thread = try std.Thread.spawn(.{}, pipePlainToPlain, .{ remote, client.* });
        defer inbound_thread.join();
        try pipePlainToPlain(client.*, remote);
        return;
    }

    const server_cfg = try selector.nextTcp();
    var tunnel = try openRemoteTunnel(allocator, io, server_cfg, target_address);
    defer tunnel.remote.close();

    try relayClientPayload(allocator, client, &tunnel, target_address, server_cfg.method);
}

fn localDnsAddress(local_cfg: config.Local) !?ss_address.Address {
    const host = local_cfg.local_dns_host orelse return null;
    const port = local_cfg.local_dns_port orelse 53;
    if (netio.net.IpAddress.parse(host, port)) |address| {
        return try netio.ipToShadow(address);
    } else |_| {
        return .{ .domain = .{ .name = host, .port = port } };
    }
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

const RewriteResult = struct {
    address: ss_address.Address,
    owned_name: ?[]u8 = null,

    fn deinit(self: RewriteResult, allocator: std.mem.Allocator) void {
        if (self.owned_name) |name| allocator.free(name);
    }
};

fn rewriteFakeDnsAddress(allocator: std.mem.Allocator, manager: ?*fake_dns.Manager, io: std.Io, address: ss_address.Address) !RewriteResult {
    const active_manager = manager orelse return .{ .address = address };
    const rewritten = active_manager.rewriteAddress(io, address) orelse return .{ .address = address };
    return switch (rewritten) {
        .domain => |domain| blk: {
            if (netio.net.IpAddress.parse(domain.name, domain.port)) |ip| {
                break :blk .{ .address = try netio.ipToShadow(ip) };
            } else |_| {}
            const name = try allocator.dupe(u8, domain.name);
            break :blk .{ .address = .{ .domain = .{ .name = name, .port = domain.port } }, .owned_name = name };
        },
        else => .{ .address = rewritten },
    };
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

fn forwardAddress(local_cfg: config.Local) !ss_address.Address {
    const host = local_cfg.forward_host orelse return error.MissingForwardAddress;
    const port = local_cfg.forward_port orelse return error.MissingForwardPort;
    if (netio.net.IpAddress.parse(host, port)) |address| {
        return try netio.ipToShadow(address);
    } else |_| {
        return .{ .domain = .{ .name = host, .port = port } };
    }
}

fn pluginLoopbackHost(host: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, host, ':') != null) return "::1";
    return "127.0.0.1";
}

fn handleServerConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: netio.TcpStream,
    server_cfg: config.Server,
    replay_protector: *replay.ReplayProtector,
    access_control: ?*const acl.AccessControl,
    traffic_counter: *traffic.Counter,
) void {
    var wrapped = client;
    serverConnection(allocator, io, &wrapped, server_cfg, replay_protector, access_control, traffic_counter) catch {};
}

fn handleLocalConnection(allocator: std.mem.Allocator, io: std.Io, client: netio.TcpStream, selector: *ServerSelector, local_cfg: config.Local, access_control: ?*const acl.AccessControl, fake_dns_manager: ?*fake_dns.Manager) void {
    var wrapped = client;
    localConnection(allocator, io, &wrapped, selector, local_cfg, access_control, fake_dns_manager) catch {};
}

fn localConnection(allocator: std.mem.Allocator, io: std.Io, client: *netio.TcpStream, selector: *ServerSelector, local_cfg: config.Local, access_control: ?*const acl.AccessControl, fake_dns_manager: ?*fake_dns.Manager) !void {
    defer client.close();

    var first: [1]u8 = undefined;
    try readExact(client, &first);

    switch (first[0]) {
        socks5.version => if (local_cfg.protocol == .socks)
            try socks5LocalConnectionAfterVersion(allocator, io, client, selector, local_cfg, first[0], access_control, fake_dns_manager)
        else
            return error.UnsupportedProtocol,
        socks4.version => if (local_cfg.protocol == .socks)
            try socks4LocalConnectionAfterVersion(allocator, io, client, selector, local_cfg, first[0], access_control, fake_dns_manager)
        else
            return error.UnsupportedProtocol,
        else => if (local_cfg.protocol == .http and http.isMethodInitial(first[0]))
            try httpLocalConnectionAfterFirstByte(allocator, io, client, selector, local_cfg, first[0], access_control, fake_dns_manager)
        else
            return error.UnsupportedVersion,
    }
}

fn socks5LocalConnectionAfterVersion(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netio.TcpStream,
    selector: *ServerSelector,
    local_cfg: config.Local,
    first_byte: u8,
    access_control: ?*const acl.AccessControl,
    fake_dns_manager: ?*fake_dns.Manager,
) !void {
    var method_buf: [255]u8 = undefined;
    const methods = try socks5.readClientGreetingAfterVersion(client, first_byte, &method_buf);
    var small: [64]u8 = undefined;
    const auth_method = socks5.chooseAuthMethod(methods, local_cfg.socks5_users.len > 0) catch {
        small[0] = socks5.version;
        small[1] = @intFromEnum(socks5.AuthMethod.not_acceptable);
        try client.writeAll(small[0..2]);
        return;
    };
    _ = try socks5.writeAuthSelection(auth_method, &small);
    try client.writeAll(small[0..2]);
    if (auth_method == .password) {
        try checkPasswordAuth(client, local_cfg.socks5_users);
    }

    var addr_buf: [257]u8 = undefined;
    const request = try socks5.readRequest(client, &addr_buf);
    switch (request.command) {
        .tcp_connect => {},
        .udp_associate => {
            if (!local_cfg.mode.enableUdp()) {
                const used = try socks5.writeReply(.command_not_supported, unspecifiedAddress(), &small);
                try client.writeAll(small[0..used]);
                return;
            }

            const used = try socks5.writeReply(.succeeded, try localBindAddress(local_cfg), &small);
            try client.writeAll(small[0..used]);
            try drainUntilEof(client);
            return;
        },
        .tcp_bind => {
            const used = try socks5.writeReply(.command_not_supported, unspecifiedAddress(), &small);
            try client.writeAll(small[0..used]);
            return;
        },
    }

    const rewrite = try rewriteFakeDnsAddress(allocator, fake_dns_manager, io, request.address);
    defer rewrite.deinit(allocator);
    const target_address = rewrite.address;
    if (targetBypassed(access_control, io, target_address)) {
        var remote = try connectTargetWithOptions(io, target_address, .{ .no_delay = local_cfg.no_delay, .ipv6_first = local_cfg.ipv6_first, .tcp_buffers = local_cfg.tcp_buffers });
        defer remote.close();

        const success_len = try socks5.writeReply(.succeeded, unspecifiedAddress(), &small);
        try client.writeAll(small[0..success_len]);

        const inbound_thread = try std.Thread.spawn(.{}, pipePlainToPlain, .{ remote, client.* });
        defer inbound_thread.join();
        try pipePlainToPlain(client.*, remote);
        return;
    }

    const server_cfg = try selector.nextTcp();
    var tunnel = try openRemoteTunnel(allocator, io, server_cfg, target_address);
    defer tunnel.remote.close();

    const success_len = try socks5.writeReply(.succeeded, unspecifiedAddress(), &small);
    try client.writeAll(small[0..success_len]);

    try relayClientPayload(allocator, client, &tunnel, target_address, server_cfg.method);
}

fn socks4LocalConnectionAfterVersion(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netio.TcpStream,
    selector: *ServerSelector,
    local_cfg: config.Local,
    first_byte: u8,
    access_control: ?*const acl.AccessControl,
    fake_dns_manager: ?*fake_dns.Manager,
) !void {
    var small: [8]u8 = undefined;
    if (local_cfg.socks5_users.len > 0) {
        const used = try socks4.writeResponse(.request_rejected_or_failed, &small);
        try client.writeAll(small[0..used]);
        return;
    }

    var addr_buf: [257]u8 = undefined;
    const request = try socks4.readRequestAfterVersion(client, first_byte, &addr_buf);
    switch (request.command) {
        .tcp_connect => {},
        .tcp_bind => {
            const used = try socks4.writeResponse(.request_rejected_or_failed, &small);
            try client.writeAll(small[0..used]);
            return;
        },
    }

    const rewrite = try rewriteFakeDnsAddress(allocator, fake_dns_manager, io, request.address);
    defer rewrite.deinit(allocator);
    const target_address = rewrite.address;
    if (targetBypassed(access_control, io, target_address)) {
        var remote = try connectTargetWithOptions(io, target_address, .{ .no_delay = local_cfg.no_delay, .ipv6_first = local_cfg.ipv6_first, .tcp_buffers = local_cfg.tcp_buffers });
        defer remote.close();

        const success_len = try socks4.writeResponse(.request_granted, &small);
        try client.writeAll(small[0..success_len]);

        const inbound_thread = try std.Thread.spawn(.{}, pipePlainToPlain, .{ remote, client.* });
        defer inbound_thread.join();
        try pipePlainToPlain(client.*, remote);
        return;
    }

    const server_cfg = try selector.nextTcp();
    var tunnel = try openRemoteTunnel(allocator, io, server_cfg, target_address);
    defer tunnel.remote.close();

    const success_len = try socks4.writeResponse(.request_granted, &small);
    try client.writeAll(small[0..success_len]);

    try relayClientPayload(allocator, client, &tunnel, target_address, server_cfg.method);
}

fn httpLocalConnectionAfterFirstByte(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netio.TcpStream,
    selector: *ServerSelector,
    local_cfg: config.Local,
    first_byte: u8,
    access_control: ?*const acl.AccessControl,
    fake_dns_manager: ?*fake_dns.Manager,
) !void {
    if (local_cfg.socks5_users.len > 0) return error.HttpUnsupportedWhenAuthConfigured;

    var head_buf: [http.max_request_head_size]u8 = undefined;
    const request = try http.readRequestHeadAfterFirstByte(client, first_byte, &head_buf);

    const rewrite = try rewriteFakeDnsAddress(allocator, fake_dns_manager, io, request.address);
    defer rewrite.deinit(allocator);
    const target_address = rewrite.address;
    if (targetBypassed(access_control, io, target_address)) {
        var remote = try connectTargetWithOptions(io, target_address, .{ .no_delay = local_cfg.no_delay, .ipv6_first = local_cfg.ipv6_first, .tcp_buffers = local_cfg.tcp_buffers });
        defer remote.close();

        switch (request.kind) {
            .connect => try client.writeAll("HTTP/1.1 200 Connection Established\r\n\r\n"),
            .forward => {
                var out_head: [http.max_request_head_size]u8 = undefined;
                const used = try http.writeForwardRequestHead(request, &out_head);
                try remote.writeAll(out_head[0..used]);
            },
        }

        const inbound_thread = try std.Thread.spawn(.{}, pipePlainToPlain, .{ remote, client.* });
        defer inbound_thread.join();
        try pipePlainToPlain(client.*, remote);
        return;
    }

    const server_cfg = try selector.nextTcp();
    var tunnel = try openRemoteTunnel(allocator, io, server_cfg, target_address);
    defer tunnel.remote.close();

    switch (request.kind) {
        .connect => {
            try client.writeAll("HTTP/1.1 200 Connection Established\r\n\r\n");
        },
        .forward => {
            var out_head: [http.max_request_head_size]u8 = undefined;
            const used = try http.writeForwardRequestHead(request, &out_head);
            if (server_cfg.method.category() == .aead2022) {
                try writeFirstClientPayload(allocator, &tunnel, target_address, out_head[0..used]);
            } else {
                try writeEncryptedChunk(allocator, &tunnel.remote, &tunnel.outbound, out_head[0..used]);
            }
        },
    }

    if (server_cfg.method.category() == .aead2022 and request.kind == .connect) {
        return try relayClientPayload(allocator, client, &tunnel, target_address, server_cfg.method);
    }

    const inbound_thread = try std.Thread.spawn(.{}, pipeServerEncryptedToPlain, .{ allocator, tunnel.remote, client.*, server_cfg.method, tunnel.master });
    defer inbound_thread.join();
    try pipePlainToEncrypted(allocator, client.*, tunnel.remote, &tunnel.outbound);
}

fn serverConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netio.TcpStream,
    server_cfg: config.Server,
    replay_protector: *replay.ReplayProtector,
    access_control: ?*const acl.AccessControl,
    traffic_counter: *traffic.Counter,
) !void {
    defer client.close();

    if (clientBlocked(access_control, client.*)) return error.ClientBlockedByAcl;

    var master: [32]u8 = undefined;
    try crypto.deriveMasterKeyWithRawKey(server_cfg.method, server_cfg.password, server_cfg.key, master[0..server_cfg.method.keyLen()]);

    if (server_cfg.method.category() == .aead2022) {
        return try serverConnectionAead2022(allocator, io, client, server_cfg, master, replay_protector, access_control, traffic_counter);
    }

    var req_salt: [32]u8 = undefined;
    try readExact(client, req_salt[0..server_cfg.method.saltLen()]);
    var inbound = try crypto.TcpCipher.init(server_cfg.method, master[0..server_cfg.method.keyLen()], req_salt[0..server_cfg.method.saltLen()]);
    const first_packet = try readEncryptedChunk(allocator, client, &inbound);
    if (try replay_protector.checkAndSet(req_salt[0..server_cfg.method.saltLen()])) return error.RepeatedNonce;
    defer allocator.free(first_packet);
    const parsed = try ss_address.Address.read(first_packet);
    if (outboundBlocked(access_control, io, parsed.address)) return error.OutboundBlockedByAcl;

    var remote = try connectTargetWithOptions(io, parsed.address, .{ .no_delay = server_cfg.no_delay, .ipv6_first = server_cfg.ipv6_first, .tcp_buffers = server_cfg.tcp_buffers, .outbound_bind = server_cfg.outbound_bind });
    defer remote.close();
    if (parsed.used < first_packet.len) {
        const payload = first_packet[parsed.used..];
        try remote.writeAll(payload);
        traffic_counter.add(payload.len);
    }

    var resp_salt: [32]u8 = undefined;
    try io.randomSecure(resp_salt[0..server_cfg.method.saltLen()]);
    try client.writeAll(resp_salt[0..server_cfg.method.saltLen()]);
    var outbound = try crypto.TcpCipher.init(server_cfg.method, master[0..server_cfg.method.keyLen()], resp_salt[0..server_cfg.method.saltLen()]);

    const upstream = try std.Thread.spawn(.{}, pipeEncryptedToPlain, .{ allocator, client.*, remote, &inbound, traffic_counter });
    defer upstream.join();
    try pipePlainToEncryptedCounted(allocator, remote, client.*, &outbound, traffic_counter);
}

fn serverConnectionAead2022(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netio.TcpStream,
    server_cfg: config.Server,
    master: [32]u8,
    replay_protector: *replay.ReplayProtector,
    access_control: ?*const acl.AccessControl,
    traffic_counter: *traffic.Counter,
) !void {
    var req_salt: [32]u8 = undefined;
    try readExact(client, req_salt[0..server_cfg.method.saltLen()]);
    var inbound = try crypto.TcpCipher.init(server_cfg.method, master[0..server_cfg.method.keyLen()], req_salt[0..server_cfg.method.saltLen()]);

    const header_len = 1 + 8 + 2 + server_cfg.method.tagLen();
    var sealed_header: [1 + 8 + 2 + 16]u8 = undefined;
    try readExact(client, sealed_header[0..header_len]);
    const header = switch (inbound) {
        .aead2022 => |*cipher| try cipher.decryptHeader(allocator, sealed_header[0..header_len], .client, 0),
        else => unreachable,
    };
    defer if (header.request_salt) |value| allocator.free(value);
    if (!validAead2022Timestamp(header.timestamp)) return error.AuthenticationFailed;

    const first_packet = try readEncryptedPayload(allocator, client, &inbound, header.data_len);
    defer allocator.free(first_packet);
    if (try replay_protector.checkAndSet(req_salt[0..server_cfg.method.saltLen()])) return error.RepeatedNonce;

    const parsed = try ss_address.Address.read(first_packet);
    if (parsed.used + 2 > first_packet.len) return error.AuthenticationFailed;
    const padding_len = std.mem.readInt(u16, first_packet[parsed.used..][0..2], .big);
    const payload_off = parsed.used + 2 + padding_len;
    if (payload_off > first_packet.len) return error.AuthenticationFailed;
    if (padding_len == 0 and payload_off == first_packet.len) return error.AuthenticationFailed;
    if (outboundBlocked(access_control, io, parsed.address)) return error.OutboundBlockedByAcl;

    var remote = try connectTargetWithOptions(io, parsed.address, .{ .no_delay = server_cfg.no_delay, .ipv6_first = server_cfg.ipv6_first, .tcp_buffers = server_cfg.tcp_buffers, .outbound_bind = server_cfg.outbound_bind });
    defer remote.close();
    if (payload_off < first_packet.len) {
        const payload = first_packet[payload_off..];
        try remote.writeAll(payload);
        traffic_counter.add(payload.len);
    }

    var resp_salt: [32]u8 = undefined;
    try io.randomSecure(resp_salt[0..server_cfg.method.saltLen()]);
    try client.writeAll(resp_salt[0..server_cfg.method.saltLen()]);
    var outbound = try crypto.TcpCipher.init(server_cfg.method, master[0..server_cfg.method.keyLen()], resp_salt[0..server_cfg.method.saltLen()]);
    const first_response = switch (outbound) {
        .aead2022 => |*cipher| try cipher.encryptFirstPayload(
            allocator,
            .server,
            req_salt[0..server_cfg.method.saltLen()],
            "",
            unixTimestamp(),
        ),
        else => unreachable,
    };
    defer allocator.free(first_response);
    try client.writeAll(first_response);

    const upstream = try std.Thread.spawn(.{}, pipeEncryptedToPlain, .{ allocator, client.*, remote, &inbound, traffic_counter });
    defer upstream.join();
    try pipePlainToEncryptedCounted(allocator, remote, client.*, &outbound, traffic_counter);
}

fn connectConfiguredServer(io: std.Io, server_cfg: config.Server) !netio.TcpStream {
    _ = io;
    var stream = try netio.connectTcpPreferredWithBuffers(server_cfg.host, server_cfg.port, server_cfg.ipv6_first, server_cfg.tcp_buffers);
    if (server_cfg.no_delay) stream.setNoDelay();
    return stream;
}

const TargetConnectOptions = struct {
    no_delay: bool = false,
    ipv6_first: bool = false,
    tcp_buffers: config.TcpBufferConfig = .{},
    outbound_bind: config.OutboundBindConfig = .{},
};

fn connectTarget(io: std.Io, address: ss_address.Address, options: TargetConnectOptions) !netio.TcpStream {
    _ = io;
    return try netio.connectTcpAddressWithOptions(try netio.shadowToIpPreferred(address, options.ipv6_first), .{
        .buffers = options.tcp_buffers,
        .outbound_bind = options.outbound_bind,
    });
}

fn connectTargetWithOptions(io: std.Io, address: ss_address.Address, options: TargetConnectOptions) !netio.TcpStream {
    var stream = try connectTarget(io, address, options);
    if (options.no_delay) stream.setNoDelay();
    return stream;
}

fn targetBypassed(access_control: ?*const acl.AccessControl, io: std.Io, address: ss_address.Address) bool {
    const active_acl = access_control orelse return false;
    return !active_acl.shouldProxy(io, address);
}

fn clientBlocked(access_control: ?*const acl.AccessControl, client: netio.TcpStream) bool {
    const active_acl = access_control orelse return false;
    const peer = client.peerAddress() catch return false;
    return active_acl.clientBlocked(peer);
}

fn outboundBlocked(access_control: ?*const acl.AccessControl, io: std.Io, address: ss_address.Address) bool {
    const active_acl = access_control orelse return false;
    return active_acl.outboundBlocked(io, address);
}

const RemoteTunnel = struct {
    remote: netio.TcpStream,
    outbound: crypto.TcpCipher,
    master: [32]u8,
    salt: [32]u8,
    salt_len: usize,
    first_sent: bool,
};

fn openRemoteTunnel(allocator: std.mem.Allocator, io: std.Io, server_cfg: config.Server, target_address: ss_address.Address) !RemoteTunnel {
    var remote = try connectConfiguredServer(io, server_cfg);
    errdefer remote.close();

    var master: [32]u8 = undefined;
    try crypto.deriveMasterKeyWithRawKey(server_cfg.method, server_cfg.password, server_cfg.key, master[0..server_cfg.method.keyLen()]);

    var salt: [32]u8 = undefined;
    try io.randomSecure(salt[0..server_cfg.method.saltLen()]);

    var outbound = try crypto.TcpCipher.init(server_cfg.method, master[0..server_cfg.method.keyLen()], salt[0..server_cfg.method.saltLen()]);
    var target_raw: [259]u8 = undefined;
    const target_len = try target_address.write(&target_raw);
    const first_sent = server_cfg.method.category() != .aead2022;
    if (first_sent) {
        try remote.writeAll(salt[0..server_cfg.method.saltLen()]);
        try writeEncryptedChunk(allocator, &remote, &outbound, target_raw[0..target_len]);
    }

    return .{
        .remote = remote,
        .outbound = outbound,
        .master = master,
        .salt = salt,
        .salt_len = server_cfg.method.saltLen(),
        .first_sent = first_sent,
    };
}

fn relayClientPayload(
    allocator: std.mem.Allocator,
    client: *netio.TcpStream,
    tunnel: *RemoteTunnel,
    target_address: ss_address.Address,
    method: crypto.CipherKind,
) !void {
    if (method.category() == .aead2022 and !tunnel.first_sent) {
        var src = client.*;
        var first_payload: [max_aead_packet_size]u8 = undefined;
        const n = try src.read(&first_payload);
        if (n == 0) return;
        try writeFirstClientPayload(allocator, tunnel, target_address, first_payload[0..n]);

        const inbound_thread = try std.Thread.spawn(.{}, pipeServerEncryptedToPlain, .{ allocator, tunnel.remote, client.*, method, tunnel.master });
        defer inbound_thread.join();
        try pipePlainToEncrypted(allocator, src, tunnel.remote, &tunnel.outbound);
        return;
    }

    const inbound_thread = try std.Thread.spawn(.{}, pipeServerEncryptedToPlain, .{ allocator, tunnel.remote, client.*, method, tunnel.master });
    defer inbound_thread.join();
    try pipePlainToEncrypted(allocator, client.*, tunnel.remote, &tunnel.outbound);
}

fn writeFirstClientPayload(allocator: std.mem.Allocator, tunnel: *RemoteTunnel, target_address: ss_address.Address, payload: []const u8) !void {
    if (tunnel.first_sent) {
        try writeEncryptedChunk(allocator, &tunnel.remote, &tunnel.outbound, payload);
        return;
    }

    var first_plain = std.ArrayList(u8).empty;
    defer first_plain.deinit(allocator);
    var target_raw: [259]u8 = undefined;
    const target_len = try target_address.write(&target_raw);
    try first_plain.appendSlice(allocator, target_raw[0..target_len]);
    try first_plain.appendSlice(allocator, &[_]u8{ 0, 0 });
    try first_plain.appendSlice(allocator, payload);

    try tunnel.remote.writeAll(tunnel.salt[0..tunnel.salt_len]);
    const first_packet = switch (tunnel.outbound) {
        .aead2022 => |*cipher| try cipher.encryptFirstPayload(
            allocator,
            .client,
            null,
            first_plain.items,
            unixTimestamp(),
        ),
        else => unreachable,
    };
    defer allocator.free(first_packet);
    try tunnel.remote.writeAll(first_packet);
    tunnel.first_sent = true;
}

fn writeInitialPayload(allocator: std.mem.Allocator, tunnel: *RemoteTunnel, target_address: ss_address.Address, first: []const u8, second: []const u8) !void {
    var payload = std.ArrayList(u8).empty;
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, first);
    try payload.appendSlice(allocator, second);
    try writeFirstClientPayload(allocator, tunnel, target_address, payload.items);
}

fn pipeServerEncryptedToPlain(
    allocator: std.mem.Allocator,
    src_stream: netio.TcpStream,
    dst_stream: netio.TcpStream,
    method: crypto.CipherKind,
    master_key: [32]u8,
) void {
    var src = src_stream;
    var dst = dst_stream;
    var salt: [32]u8 = undefined;
    readExact(&src, salt[0..method.saltLen()]) catch {
        dst.close();
        return;
    };
    var cipher = crypto.TcpCipher.init(method, master_key[0..method.keyLen()], salt[0..method.saltLen()]) catch {
        dst.close();
        return;
    };
    if (method.category() == .aead2022) {
        const header_len = 1 + 8 + method.saltLen() + 2 + method.tagLen();
        const sealed_header = allocator.alloc(u8, header_len) catch {
            dst.close();
            return;
        };
        defer allocator.free(sealed_header);
        readExact(&src, sealed_header) catch {
            dst.close();
            return;
        };
        const header = switch (cipher) {
            .aead2022 => |*c| c.decryptHeader(allocator, sealed_header, .server, method.saltLen()) catch {
                dst.close();
                return;
            },
            else => unreachable,
        };
        defer if (header.request_salt) |value| allocator.free(value);
        if (!validAead2022Timestamp(header.timestamp)) {
            dst.close();
            return;
        }
        const sealed_payload = allocator.alloc(u8, header.data_len + method.tagLen()) catch {
            dst.close();
            return;
        };
        defer allocator.free(sealed_payload);
        readExact(&src, sealed_payload) catch {
            dst.close();
            return;
        };
        const plain = cipher.decryptPayload(allocator, sealed_payload, header.data_len) catch {
            dst.close();
            return;
        };
        defer allocator.free(plain);
        if (plain.len != 0) dst.writeAll(plain) catch {
            dst.close();
            return;
        };
    }
    pipeEncryptedToPlain(allocator, src, dst, &cipher, null);
}

fn pipeEncryptedToPlain(allocator: std.mem.Allocator, src_stream: netio.TcpStream, dst_stream: netio.TcpStream, cipher: *crypto.TcpCipher, traffic_counter: ?*traffic.Counter) void {
    var src = src_stream;
    var dst = dst_stream;
    defer dst.close();
    while (true) {
        const plain = readEncryptedChunk(allocator, &src, cipher) catch return;
        defer allocator.free(plain);
        if (plain.len == 0) continue;
        dst.writeAll(plain) catch return;
        if (traffic_counter) |counter| counter.add(plain.len);
    }
}

fn pipePlainToEncrypted(allocator: std.mem.Allocator, src_stream: netio.TcpStream, dst_stream: netio.TcpStream, cipher: *crypto.TcpCipher) !void {
    try pipePlainToEncryptedCounted(allocator, src_stream, dst_stream, cipher, null);
}

fn pipePlainToEncryptedCounted(allocator: std.mem.Allocator, src_stream: netio.TcpStream, dst_stream: netio.TcpStream, cipher: *crypto.TcpCipher, traffic_counter: ?*traffic.Counter) !void {
    var src = src_stream;
    var dst = dst_stream;
    var buf: [max_aead_packet_size]u8 = undefined;
    while (true) {
        const n = try src.read(&buf);
        if (n == 0) return;
        try writeEncryptedChunk(allocator, &dst, cipher, buf[0..n]);
        if (traffic_counter) |counter| counter.add(n);
    }
}

fn pipePlainToPlain(src_stream: netio.TcpStream, dst_stream: netio.TcpStream) !void {
    var src = src_stream;
    var dst = dst_stream;
    defer dst.close();
    var buf: [max_aead_packet_size]u8 = undefined;
    while (true) {
        const n = try src.read(&buf);
        if (n == 0) return;
        try dst.writeAll(buf[0..n]);
    }
}

fn writeEncryptedChunk(allocator: std.mem.Allocator, dst: *netio.TcpStream, cipher: *crypto.TcpCipher, plain: []const u8) !void {
    const packet = try cipher.encryptChunk(allocator, plain);
    defer allocator.free(packet);
    try dst.writeAll(packet);
}

fn readEncryptedChunk(allocator: std.mem.Allocator, stream: *netio.TcpStream, cipher: *crypto.TcpCipher) ![]u8 {
    const tag_len = cipher.kind().tagLen();
    var sealed_len: [2 + 16]u8 = undefined;
    try readExact(stream, sealed_len[0 .. 2 + tag_len]);
    const len = try cipher.decryptLength(sealed_len[0 .. 2 + tag_len]);
    return try readEncryptedPayload(allocator, stream, cipher, len);
}

fn readEncryptedPayload(allocator: std.mem.Allocator, stream: *netio.TcpStream, cipher: *crypto.TcpCipher, len: usize) ![]u8 {
    const tag_len = cipher.kind().tagLen();
    const sealed_payload = try allocator.alloc(u8, len + tag_len);
    defer allocator.free(sealed_payload);
    try readExact(stream, sealed_payload);
    return try cipher.decryptPayload(allocator, sealed_payload, len);
}

fn validAead2022Timestamp(timestamp: u64) bool {
    const now = unixTimestamp();
    return if (now >= timestamp)
        now - timestamp <= max_aead2022_timestamp_diff
    else
        timestamp - now <= max_aead2022_timestamp_diff;
}

fn unixTimestamp() u64 {
    var ts: std.posix.timespec = undefined;
    return switch (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => if (ts.sec < 0) 0 else @intCast(ts.sec),
        else => 0,
    };
}

fn unspecifiedAddress() ss_address.Address {
    return .{ .ipv4 = .{ .ip = [_]u8{ 0, 0, 0, 0 }, .port = 0 } };
}

fn localBindAddress(local_cfg: config.Local) !ss_address.Address {
    const addr = try netio.net.IpAddress.parse(local_cfg.host, local_cfg.port);
    return switch (addr) {
        .ip4 => |ip4| .{ .ipv4 = .{ .ip = ip4.bytes, .port = ip4.port } },
        .ip6 => |ip6| .{ .ipv6 = .{ .ip = ip6.bytes, .port = ip6.port } },
    };
}

fn drainUntilEof(stream: *netio.TcpStream) !void {
    var buf: [1024]u8 = undefined;
    while (true) {
        const n = try stream.read(&buf);
        if (n == 0) return;
    }
}

fn checkPasswordAuth(stream: *netio.TcpStream, users: []const config.Socks5User) !void {
    var buf: [512]u8 = undefined;
    const req = try socks5.readPasswordAuthRequest(stream, &buf);
    const success = checkUser(users, req.user_name, req.password);
    var response: [2]u8 = undefined;
    _ = try socks5.writePasswordAuthResponse(success, &response);
    try stream.writeAll(&response);
    if (!success) return error.AuthenticationFailed;
}

fn checkUser(users: []const config.Socks5User, user_name: []const u8, password: []const u8) bool {
    for (users) |user| {
        if (std.mem.eql(u8, user.user_name, user_name) and std.mem.eql(u8, user.password, password)) return true;
    }
    return false;
}

fn readExact(stream: *netio.TcpStream, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = try stream.read(buf[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

test "AEAD packet size mirrors shadowsocks-rust limit" {
    try std.testing.expectEqual(@as(usize, 0x3fff), max_aead_packet_size);
}
