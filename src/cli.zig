const std = @import("std");
const config = @import("config.zig");

pub const Mode = enum {
    check,
    local,
    server,
    manager,
};

pub fn defaultModeFromExecutablePath(path: []const u8) ?Mode {
    const name = std.fs.path.basename(path);
    if (std.mem.eql(u8, name, "ss-local") or std.mem.eql(u8, name, "sslocal")) return .local;
    if (std.mem.eql(u8, name, "ss-redir")) return .local;
    if (std.mem.eql(u8, name, "ss-tunnel")) return .local;
    if (std.mem.eql(u8, name, "ss-server") or std.mem.eql(u8, name, "ssserver")) return .server;
    if (std.mem.eql(u8, name, "ss-manager") or std.mem.eql(u8, name, "ssmanager")) return .manager;
    return null;
}

pub fn defaultProtocolFromExecutablePath(path: []const u8) ?config.LocalProtocol {
    const name = std.fs.path.basename(path);
    if (std.mem.eql(u8, name, "ss-redir")) return .redir;
    if (std.mem.eql(u8, name, "ss-tunnel")) return .tunnel;
    return null;
}

test "libev and shadowsocks-rust executable names select default modes" {
    try std.testing.expectEqual(Mode.local, defaultModeFromExecutablePath("/usr/local/bin/ss-local").?);
    try std.testing.expectEqual(Mode.local, defaultModeFromExecutablePath("sslocal").?);
    try std.testing.expectEqual(Mode.local, defaultModeFromExecutablePath("/usr/local/bin/ss-redir").?);
    try std.testing.expectEqual(Mode.local, defaultModeFromExecutablePath("/usr/local/bin/ss-tunnel").?);
    try std.testing.expectEqual(Mode.server, defaultModeFromExecutablePath("/opt/bin/ss-server").?);
    try std.testing.expectEqual(Mode.server, defaultModeFromExecutablePath("ssserver").?);
    try std.testing.expectEqual(Mode.manager, defaultModeFromExecutablePath("/opt/bin/ss-manager").?);
    try std.testing.expectEqual(Mode.manager, defaultModeFromExecutablePath("ssmanager").?);
    try std.testing.expectEqual(@as(?Mode, null), defaultModeFromExecutablePath("ss-zig"));
}

test "libev local executable names select default protocols" {
    try std.testing.expectEqual(config.LocalProtocol.redir, defaultProtocolFromExecutablePath("/usr/local/bin/ss-redir").?);
    try std.testing.expectEqual(config.LocalProtocol.tunnel, defaultProtocolFromExecutablePath("/usr/local/bin/ss-tunnel").?);
    try std.testing.expectEqual(@as(?config.LocalProtocol, null), defaultProtocolFromExecutablePath("ss-local"));
}
