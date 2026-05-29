const std = @import("std");
const shadowsocks = @import("shadowsocks");

const usage =
    \\ss-zig --check -c <config.json>
    \\ss-zig --local -c <config.json>
    \\ss-zig --server -c <config.json>
    \\ss-zig --manager -c <config.json>
    \\ss-local -c <config.json>
    \\ss-server -c <config.json>
    \\ss-manager -c <config.json>
    \\ss-redir -s <server> -p <port> -k <password> -m <method> -l <local_port>
    \\ss-tunnel -s <server> -p <port> -k <password> -m <method> -l <local_port> -L <target:port>
    \\
    \\Mode-specific executable names infer --local, --server, or --manager. Explicit mode flags override the executable-name default.
    \\Common libev flags are accepted: -s, -p, -b, -l, -k, -m, -t, -u, -U, -L, -6, --key, --plugin, --plugin-opts, --acl, --manager-address, --no-delay, --reuse-port, and TCP buffer size flags.
    \\--local runs TCP SOCKS5/SOCKS4/HTTP/DNS/Tunnel/Redir/Fake-DNS ss-local; --server runs TCP/UDP ss-server; --manager runs the manager control API.
    \\
;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    const executable_path = args.next() orelse "ss-zig";

    var config_path: ?[]const u8 = null;
    var explicit_mode: ?shadowsocks.cli.Mode = null;
    var overrides = shadowsocks.config.Overrides{
        .protocol = shadowsocks.cli.defaultProtocolFromExecutablePath(executable_path),
    };
    var bind_host: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            config_path = args.next() orelse {
                try std.Io.File.stderr().writeStreamingAll(io, usage);
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--check")) {
            if (explicit_mode != null) {
                try std.Io.File.stderr().writeStreamingAll(io, usage);
                return error.InvalidArgs;
            }
            explicit_mode = .check;
        } else if (std.mem.eql(u8, arg, "--local")) {
            if (explicit_mode != null) {
                try std.Io.File.stderr().writeStreamingAll(io, usage);
                return error.InvalidArgs;
            }
            explicit_mode = .local;
        } else if (std.mem.eql(u8, arg, "--server")) {
            if (explicit_mode != null) {
                try std.Io.File.stderr().writeStreamingAll(io, usage);
                return error.InvalidArgs;
            }
            explicit_mode = .server;
        } else if (std.mem.eql(u8, arg, "--manager")) {
            if (explicit_mode != null) {
                try std.Io.File.stderr().writeStreamingAll(io, usage);
                return error.InvalidArgs;
            }
            explicit_mode = .manager;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try std.Io.File.stdout().writeStreamingAll(io, usage);
            return;
        } else if (std.mem.eql(u8, arg, "-s")) {
            try applyHostPortArg(args.next() orelse return invalidArgs(io), &overrides.server_host, &overrides.server_port);
        } else if (std.mem.eql(u8, arg, "-p")) {
            overrides.server_port = try parsePortArg(args.next() orelse return invalidArgs(io));
        } else if (std.mem.eql(u8, arg, "-b")) {
            bind_host = args.next() orelse return invalidArgs(io);
        } else if (std.mem.eql(u8, arg, "-l")) {
            overrides.local_port = try parsePortArg(args.next() orelse return invalidArgs(io));
        } else if (std.mem.eql(u8, arg, "-k") or std.mem.eql(u8, arg, "--password")) {
            overrides.password = args.next() orelse return invalidArgs(io);
        } else if (std.mem.eql(u8, arg, "--key")) {
            overrides.key = args.next() orelse return invalidArgs(io);
        } else if (std.mem.eql(u8, arg, "-m")) {
            overrides.method = shadowsocks.crypto.CipherKind.parse(args.next() orelse return invalidArgs(io)) catch return error.InvalidCipher;
        } else if (std.mem.eql(u8, arg, "-t")) {
            overrides.timeout_seconds = try parseU64Arg(args.next() orelse return invalidArgs(io));
        } else if (std.mem.eql(u8, arg, "-u")) {
            overrides.mode = .tcp_and_udp;
        } else if (std.mem.eql(u8, arg, "-U")) {
            overrides.mode = .udp_only;
        } else if (std.mem.eql(u8, arg, "-L")) {
            overrides.protocol = .tunnel;
            try applyHostPortArg(args.next() orelse return invalidArgs(io), &overrides.forward_host, &overrides.forward_port);
        } else if (std.mem.eql(u8, arg, "-T")) {
            overrides.protocol = .redir;
            overrides.tcp_redir = .tproxy;
        } else if (std.mem.eql(u8, arg, "--plugin")) {
            overrides.plugin = args.next() orelse return invalidArgs(io);
        } else if (std.mem.eql(u8, arg, "--plugin-opts")) {
            overrides.plugin_opts = args.next() orelse return invalidArgs(io);
        } else if (std.mem.eql(u8, arg, "--acl")) {
            overrides.acl_path = args.next() orelse return invalidArgs(io);
        } else if (std.mem.eql(u8, arg, "--manager-address")) {
            overrides.manager_address = args.next() orelse return invalidArgs(io);
        } else if (std.mem.eql(u8, arg, "--protocol")) {
            overrides.protocol = try shadowsocks.config.LocalProtocol.parse(args.next() orelse return invalidArgs(io));
        } else if (std.mem.eql(u8, arg, "--tcp-redir")) {
            overrides.tcp_redir = try shadowsocks.config.RedirType.parse(args.next() orelse return invalidArgs(io), .not_supported);
        } else if (std.mem.eql(u8, arg, "--udp-redir")) {
            overrides.udp_redir = try shadowsocks.config.RedirType.parse(args.next() orelse return invalidArgs(io), .not_supported);
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--mtu")) {
            _ = args.next() orelse return invalidArgs(io);
        } else if (std.mem.eql(u8, arg, "--no-delay")) {
            overrides.no_delay = true;
        } else if (std.mem.eql(u8, arg, "--reuse-port")) {
            overrides.reuse_port = true;
        } else if (std.mem.eql(u8, arg, "-6")) {
            overrides.ipv6_first = true;
        } else if (std.mem.eql(u8, arg, "--tcp-incoming-sndbuf")) {
            overrides.tcp_buffers.incoming_sndbuf = try parseTcpBufferArg(args.next() orelse return invalidArgs(io));
        } else if (std.mem.eql(u8, arg, "--tcp-incoming-rcvbuf")) {
            overrides.tcp_buffers.incoming_rcvbuf = try parseTcpBufferArg(args.next() orelse return invalidArgs(io));
        } else if (std.mem.eql(u8, arg, "--tcp-outgoing-sndbuf")) {
            overrides.tcp_buffers.outgoing_sndbuf = try parseTcpBufferArg(args.next() orelse return invalidArgs(io));
        } else if (std.mem.eql(u8, arg, "--tcp-outgoing-rcvbuf")) {
            overrides.tcp_buffers.outgoing_rcvbuf = try parseTcpBufferArg(args.next() orelse return invalidArgs(io));
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--fast-open")) {
            continue;
        } else {
            try std.Io.File.stderr().writeStreamingAll(io, usage);
            return error.InvalidArgs;
        }
    }

    const mode = explicit_mode orelse shadowsocks.cli.defaultModeFromExecutablePath(executable_path) orelse {
        try std.Io.File.stderr().writeStreamingAll(io, usage);
        return error.InvalidArgs;
    };
    if (bind_host) |host| {
        const bind_mode = if (mode == .check) shadowsocks.cli.defaultModeFromExecutablePath(executable_path) orelse .local else mode;
        if (bind_mode == .server) {
            if (std.Io.net.IpAddress.parse(host, 0)) |address| {
                switch (address) {
                    .ip4 => overrides.outbound_bind.ipv4 = host,
                    .ip6 => overrides.outbound_bind.ipv6 = host,
                }
            } else |_| {
                return error.InvalidArgs;
            }
        } else {
            overrides.local_host = host;
        }
    }
    if (mode == .local and overrides.protocol == null) overrides.protocol = .socks;

    if (config_path == null and !overrides.hasAny()) {
        try std.Io.File.stderr().writeStreamingAll(io, usage);
        return error.InvalidArgs;
    }

    var cfg = if (config_path) |path|
        try shadowsocks.config.Config.parseFile(allocator, io, path)
    else
        try shadowsocks.config.Config.fromOverrides(allocator, overrides);
    defer cfg.deinit();
    if (config_path != null) try cfg.applyOverrides(overrides);

    if (mode == .check) {
        var stdout_buf: [4096]u8 = undefined;
        var stdout_file = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
        const stdout = &stdout_file.interface;
        try stdout.print("config ok: {d} server(s), {d} local listener(s)\n", .{ cfg.servers.len, cfg.locals.len });
        for (cfg.servers) |server_cfg| {
            try stdout.print("server {s}:{d} method={s} mode={s} tcp_weight={d}/{d} udp_weight={d}/{d} implemented={}\n", .{
                server_cfg.host,
                server_cfg.port,
                server_cfg.method.name(),
                @tagName(server_cfg.mode),
                server_cfg.tcp_weight,
                shadowsocks.config.server_weight_scale,
                server_cfg.udp_weight,
                shadowsocks.config.server_weight_scale,
                server_cfg.method.isImplemented(),
            });
            if (server_cfg.plugin) |plugin_name| {
                try stdout.print("  plugin={s} plugin_mode={s}\n", .{ plugin_name, @tagName(server_cfg.plugin_mode) });
                if (server_cfg.plugin_args.len != 0) {
                    try stdout.print("  plugin_args=", .{});
                    for (server_cfg.plugin_args, 0..) |arg, i| {
                        if (i != 0) try stdout.print(" ", .{});
                        try stdout.print("{s}", .{arg});
                    }
                    try stdout.print("\n", .{});
                }
            }
            if (server_cfg.acl_path) |acl_path| {
                try stdout.print("  acl={s}\n", .{acl_path});
            }
            if (server_cfg.ipv6_first) {
                try stdout.print("  ipv6_first=true\n", .{});
            }
            try printTcpBuffers(stdout, "server", server_cfg.tcp_buffers);
            if (server_cfg.outbound_bind.hasAny()) {
                try stdout.print("  outbound_bind", .{});
                if (server_cfg.outbound_bind.ipv4) |host| try stdout.print(" ipv4={s}", .{host});
                if (server_cfg.outbound_bind.ipv6) |host| try stdout.print(" ipv6={s}", .{host});
                try stdout.print("\n", .{});
            }
        }
        for (cfg.locals) |local_cfg| {
            try stdout.print("local {s}:{d} protocol={s} mode={s}", .{ local_cfg.host, local_cfg.port, local_cfg.protocol.name(), @tagName(local_cfg.mode) });
            if (local_cfg.protocol == .redir) {
                try stdout.print(" tcp_redir={s} udp_redir={s}", .{ local_cfg.tcp_redir.name(), local_cfg.udp_redir.name() });
            }
            if (local_cfg.forward_host) |forward_host| {
                try stdout.print(" forward={s}:{d}", .{ forward_host, local_cfg.forward_port orelse 0 });
            }
            if (local_cfg.local_dns_host) |local_dns_host| {
                try stdout.print(" local_dns={s}:{d}", .{ local_dns_host, local_cfg.local_dns_port orelse 53 });
            }
            if (local_cfg.fake_dns_ipv4_network) |network| {
                try stdout.print(" fake_dns_ipv4_network={s}", .{network});
            }
            if (local_cfg.fake_dns_ipv6_network) |network| {
                try stdout.print(" fake_dns_ipv6_network={s}", .{network});
            }
            if (local_cfg.fake_dns_database_path) |path| {
                try stdout.print(" fake_dns_database_path={s}", .{path});
            }
            if (local_cfg.acl_path) |acl_path| {
                try stdout.print(" acl={s}", .{acl_path});
            }
            if (local_cfg.ipv6_first) {
                try stdout.print(" ipv6_first=true", .{});
            }
            try printTcpBuffersInline(stdout, local_cfg.tcp_buffers);
            try stdout.print("\n", .{});
        }
        if (cfg.manager) |manager_cfg| {
            try stdout.print("manager {s} transport={s}\n", .{ manager_cfg.address, @tagName(manager_cfg.transport) });
        }
        try stdout.flush();
    } else if (mode == .local) {
        try shadowsocks.relay.tcp.runLocal(allocator, io, init.environ_map, &cfg);
    } else if (mode == .server) {
        try shadowsocks.relay.tcp.runServer(allocator, io, init.environ_map, &cfg);
    } else if (mode == .manager) {
        try shadowsocks.manager.run(allocator, io, init.environ_map, executable_path, &cfg);
    }
}

fn invalidArgs(io: std.Io) error{InvalidArgs} {
    std.Io.File.stderr().writeStreamingAll(io, usage) catch {};
    return error.InvalidArgs;
}

fn parsePortArg(text: []const u8) !u16 {
    const port = std.fmt.parseInt(u16, text, 10) catch return error.InvalidArgs;
    if (port == 0) return error.InvalidArgs;
    return port;
}

fn parseU64Arg(text: []const u8) !u64 {
    return std.fmt.parseInt(u64, text, 10) catch return error.InvalidArgs;
}

fn parseTcpBufferArg(text: []const u8) !u32 {
    const raw = try parseU64Arg(text);
    if (raw == 0 or raw > std.math.maxInt(c_int)) return error.InvalidArgs;
    return @intCast(raw);
}

fn applyHostPortArg(text: []const u8, host: *?[]const u8, port: *?u16) !void {
    if (text.len == 0) return error.InvalidArgs;
    if (text[0] == '[') {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return error.InvalidArgs;
        if (close <= 1) return error.InvalidArgs;
        host.* = text[1..close];
        if (close + 1 < text.len) {
            if (text[close + 1] != ':') return error.InvalidArgs;
            port.* = try parsePortArg(text[close + 2 ..]);
        }
        return;
    }

    var colon_count: usize = 0;
    for (text) |byte| {
        if (byte == ':') colon_count += 1;
    }
    if (colon_count == 1) {
        const colon = std.mem.indexOfScalar(u8, text, ':').?;
        if (colon == 0 or colon + 1 >= text.len) return error.InvalidArgs;
        host.* = text[0..colon];
        port.* = try parsePortArg(text[colon + 1 ..]);
        return;
    }

    host.* = text;
}

fn printTcpBuffers(stdout: anytype, prefix: []const u8, buffers: shadowsocks.config.TcpBufferConfig) !void {
    if (!buffers.hasAny()) return;
    try stdout.print("  {s}_tcp_buffers", .{prefix});
    if (buffers.incoming_sndbuf) |value| try stdout.print(" incoming_sndbuf={d}", .{value});
    if (buffers.incoming_rcvbuf) |value| try stdout.print(" incoming_rcvbuf={d}", .{value});
    if (buffers.outgoing_sndbuf) |value| try stdout.print(" outgoing_sndbuf={d}", .{value});
    if (buffers.outgoing_rcvbuf) |value| try stdout.print(" outgoing_rcvbuf={d}", .{value});
    try stdout.print("\n", .{});
}

fn printTcpBuffersInline(stdout: anytype, buffers: shadowsocks.config.TcpBufferConfig) !void {
    if (buffers.incoming_sndbuf) |value| try stdout.print(" tcp_incoming_sndbuf={d}", .{value});
    if (buffers.incoming_rcvbuf) |value| try stdout.print(" tcp_incoming_rcvbuf={d}", .{value});
    if (buffers.outgoing_sndbuf) |value| try stdout.print(" tcp_outgoing_sndbuf={d}", .{value});
    if (buffers.outgoing_rcvbuf) |value| try stdout.print(" tcp_outgoing_rcvbuf={d}", .{value});
}
