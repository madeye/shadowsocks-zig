const std = @import("std");

pub const Mode = enum {
    check,
    local,
    server,
    manager,
};

pub fn defaultModeFromExecutablePath(path: []const u8) ?Mode {
    const name = std.fs.path.basename(path);
    if (std.mem.eql(u8, name, "ss-local") or std.mem.eql(u8, name, "sslocal")) return .local;
    if (std.mem.eql(u8, name, "ss-server") or std.mem.eql(u8, name, "ssserver")) return .server;
    if (std.mem.eql(u8, name, "ss-manager") or std.mem.eql(u8, name, "ssmanager")) return .manager;
    return null;
}

test "libev and shadowsocks-rust executable names select default modes" {
    try std.testing.expectEqual(Mode.local, defaultModeFromExecutablePath("/usr/local/bin/ss-local").?);
    try std.testing.expectEqual(Mode.local, defaultModeFromExecutablePath("sslocal").?);
    try std.testing.expectEqual(Mode.server, defaultModeFromExecutablePath("/opt/bin/ss-server").?);
    try std.testing.expectEqual(Mode.server, defaultModeFromExecutablePath("ssserver").?);
    try std.testing.expectEqual(Mode.manager, defaultModeFromExecutablePath("/opt/bin/ss-manager").?);
    try std.testing.expectEqual(Mode.manager, defaultModeFromExecutablePath("ssmanager").?);
    try std.testing.expectEqual(@as(?Mode, null), defaultModeFromExecutablePath("ss-zig"));
}
