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
    \\
    \\Mode-specific executable names infer --local, --server, or --manager. Explicit mode flags override the executable-name default.
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
        } else {
            try std.Io.File.stderr().writeStreamingAll(io, usage);
            return error.InvalidArgs;
        }
    }

    const mode = explicit_mode orelse shadowsocks.cli.defaultModeFromExecutablePath(executable_path) orelse {
        try std.Io.File.stderr().writeStreamingAll(io, usage);
        return error.InvalidArgs;
    };
    if (config_path == null) {
        try std.Io.File.stderr().writeStreamingAll(io, usage);
        return error.InvalidArgs;
    }

    var cfg = try shadowsocks.config.Config.parseFile(allocator, io, config_path.?);
    defer cfg.deinit();

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
