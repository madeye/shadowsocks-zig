const std = @import("std");

pub const Mode = enum {
    client,
    server,
};

pub const Endpoint = struct {
    host: []const u8,
    port: u16,
};

pub const StartOptions = struct {
    plugin: []const u8,
    plugin_opts: ?[]const u8 = null,
    plugin_args: []const []const u8 = &.{},
    remote: Endpoint,
    local: Endpoint,
    mode: Mode,
};

pub const Process = struct {
    child: std.process.Child,

    pub fn stop(self: *Process, io: std.Io) void {
        self.child.kill(io);
    }
};

pub fn start(
    allocator: std.mem.Allocator,
    io: std.Io,
    base_env: *const std.process.Environ.Map,
    options: StartOptions,
) !Process {
    if (options.plugin.len == 0) return error.InvalidPlugin;

    var env = try buildEnvironment(allocator, io, base_env, options);
    defer env.deinit();

    const argv = try buildArgv(allocator, options);
    defer allocator.free(argv);
    const child = try std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    return .{ .child = child };
}

pub fn buildArgv(allocator: std.mem.Allocator, options: StartOptions) ![][]const u8 {
    if (options.plugin.len == 0) return error.InvalidPlugin;
    const argv = try allocator.alloc([]const u8, options.plugin_args.len + 1);
    argv[0] = options.plugin;
    for (options.plugin_args, 0..) |arg, i| argv[i + 1] = arg;
    return argv;
}

pub fn buildEnvironment(
    allocator: std.mem.Allocator,
    io: std.Io,
    base_env: *const std.process.Environ.Map,
    options: StartOptions,
) !std.process.Environ.Map {
    var env = try base_env.clone(allocator);
    errdefer env.deinit();

    if (env.getPtr("PATH")) |path| {
        const cwd = try std.process.currentPathAlloc(io, allocator);
        defer allocator.free(cwd);
        const path_with_cwd = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ cwd, path.* });
        defer allocator.free(path_with_cwd);
        try env.put("PATH", path_with_cwd);
    }

    var remote_port_buf: [16]u8 = undefined;
    var local_port_buf: [16]u8 = undefined;
    const remote_port = try std.fmt.bufPrint(&remote_port_buf, "{d}", .{options.remote.port});
    const local_port = try std.fmt.bufPrint(&local_port_buf, "{d}", .{options.local.port});

    try env.put("SS_REMOTE_HOST", options.remote.host);
    try env.put("SS_REMOTE_PORT", remote_port);
    try env.put("SS_LOCAL_HOST", options.local.host);
    try env.put("SS_LOCAL_PORT", local_port);
    if (options.plugin_opts) |plugin_opts| try env.put("SS_PLUGIN_OPTIONS", plugin_opts);

    return env;
}

test "SIP003 argv includes plugin args" {
    const argv = try buildArgv(std.testing.allocator, .{
        .plugin = "fake-plugin",
        .plugin_args = &.{ "--verbose", "--fast-open" },
        .remote = .{ .host = "server.example", .port = 8388 },
        .local = .{ .host = "127.0.0.1", .port = 19000 },
        .mode = .client,
    });
    defer std.testing.allocator.free(argv);

    try std.testing.expectEqual(@as(usize, 3), argv.len);
    try std.testing.expectEqualStrings("fake-plugin", argv[0]);
    try std.testing.expectEqualStrings("--verbose", argv[1]);
    try std.testing.expectEqualStrings("--fast-open", argv[2]);
}

test "SIP003 environment contains required endpoints and options" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var base = std.process.Environ.Map.init(std.testing.allocator);
    defer base.deinit();
    try base.put("PATH", "/usr/bin");

    var env = try buildEnvironment(std.testing.allocator, threaded.io(), &base, .{
        .plugin = "fake-plugin",
        .plugin_opts = "obfs=http;host=example.com",
        .remote = .{ .host = "server.example", .port = 8388 },
        .local = .{ .host = "127.0.0.1", .port = 19000 },
        .mode = .client,
    });
    defer env.deinit();

    try std.testing.expectEqualStrings("server.example", env.getPtr("SS_REMOTE_HOST").?.*);
    try std.testing.expectEqualStrings("8388", env.getPtr("SS_REMOTE_PORT").?.*);
    try std.testing.expectEqualStrings("127.0.0.1", env.getPtr("SS_LOCAL_HOST").?.*);
    try std.testing.expectEqualStrings("19000", env.getPtr("SS_LOCAL_PORT").?.*);
    try std.testing.expectEqualStrings("obfs=http;host=example.com", env.getPtr("SS_PLUGIN_OPTIONS").?.*);
    try std.testing.expect(std.mem.endsWith(u8, env.getPtr("PATH").?.*, ":/usr/bin"));
}
