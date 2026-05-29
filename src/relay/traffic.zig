const std = @import("std");

const config = @import("../config.zig");
const netio = @import("netio.zig");

const UnixAddress = extern union {
    any: std.posix.sockaddr,
    un: std.posix.sockaddr.un,
};

pub const Counter = struct {
    total: std.atomic.Value(u64) = .init(0),

    pub fn add(self: *Counter, n: usize) void {
        _ = self.total.fetchAdd(@intCast(n), .monotonic);
    }

    pub fn load(self: *Counter) u64 {
        return self.total.load(.monotonic);
    }
};

pub fn startReporter(io: std.Io, manager: config.Manager, server_port: u16, counter: *Counter) !std.Thread {
    return try std.Thread.spawn(.{}, reporterLoop, .{ io, manager, server_port, counter });
}

fn reporterLoop(io: std.Io, manager: config.Manager, server_port: u16, counter: *Counter) void {
    switch (manager.transport) {
        .ip => reporterLoopIp(io, manager, server_port, counter),
        .unix => reporterLoopUnix(io, manager, server_port, counter),
    }
}

fn reporterLoopIp(io: std.Io, manager: config.Manager, server_port: u16, counter: *Counter) void {
    const address = netio.resolveIp(manager.host, manager.port) catch return;
    var socket = netio.openUdp(address) catch return;
    defer socket.close();

    while (true) {
        std.Io.sleep(io, .fromSeconds(5), .awake) catch return;
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "stat: {{\"{d}\":{d}}}", .{ server_port, counter.load() }) catch continue;
        _ = socket.sendTo(msg, address) catch continue;
    }
}

fn reporterLoopUnix(io: std.Io, manager: config.Manager, server_port: u16, counter: *Counter) void {
    const fd = openUnixDatagramSocket() catch return;
    defer closeFd(fd);

    var local_path_buf: [128]u8 = undefined;
    const local_path = std.fmt.bufPrint(&local_path_buf, "/tmp/ss-zig-stat-{d}.sock", .{server_port}) catch return;
    std.Io.Dir.deleteFileAbsolute(io, local_path) catch {};
    defer std.Io.Dir.deleteFileAbsolute(io, local_path) catch {};

    var local = unixAddress(local_path) catch return;
    bindUnixDatagram(fd, &local.storage.any, local.len) catch return;
    var remote = unixAddress(manager.path) catch return;

    while (true) {
        std.Io.sleep(io, .fromSeconds(5), .awake) catch return;
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "stat: {{\"{d}\":{d}}}", .{ server_port, counter.load() }) catch continue;
        sendToUnix(fd, msg, &remote.storage.any, remote.len) catch continue;
    }
}

const UnixSockaddr = struct {
    storage: UnixAddress,
    len: std.posix.socklen_t,
};

fn unixAddress(path: []const u8) !UnixSockaddr {
    var storage: UnixAddress = undefined;
    storage.un = .{
        .family = std.posix.AF.UNIX,
        .path = [_]u8{0} ** @sizeOf(@TypeOf(storage.un.path)),
    };
    if (path.len == 0 or path.len >= storage.un.path.len) return error.InvalidManagerAddress;
    @memcpy(storage.un.path[0..path.len], path);
    return .{
        .storage = storage,
        .len = @intCast(@offsetOf(std.posix.sockaddr.un, "path") + path.len + 1),
    };
}

fn openUnixDatagramSocket() !std.posix.socket_t {
    while (true) {
        const rc = std.posix.system.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn bindUnixDatagram(fd: std.posix.socket_t, address: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
    while (true) {
        switch (std.posix.errno(std.posix.system.bind(fd, address, len))) {
            .SUCCESS => return,
            .INTR => continue,
            .ACCES => return error.AccessDenied,
            .ADDRINUSE => return error.AddressInUse,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .NAMETOOLONG => return error.NameTooLong,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .ROFS => return error.ReadOnlyFileSystem,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn sendToUnix(fd: std.posix.socket_t, bytes: []const u8, address: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = std.posix.system.sendto(fd, bytes[offset..].ptr, bytes.len - offset, 0, address, len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => offset += @intCast(rc),
            .INTR => continue,
            .AGAIN => continue,
            .ACCES => return error.AccessDenied,
            .BADF => return error.SocketNotConnected,
            .CONNREFUSED => return error.ConnectionRefused,
            .MSGSIZE => return error.MessageTooLarge,
            .NOMEM, .NOBUFS => return error.SystemResources,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn closeFd(fd: std.posix.fd_t) void {
    switch (std.posix.errno(std.posix.system.close(fd))) {
        .SUCCESS, .INTR => {},
        else => {},
    }
}

test "traffic counter accumulates bytes" {
    var counter = Counter{};
    counter.add(7);
    counter.add(35);
    try std.testing.expectEqual(@as(u64, 42), counter.load());
}
