const std = @import("std");
const ss_address = @import("address.zig");

pub const version: u8 = 0x04;

pub const Command = enum(u8) {
    tcp_connect = 0x01,
    tcp_bind = 0x02,
};

pub const Reply = enum(u8) {
    request_granted = 0x5a,
    request_rejected_or_failed = 0x5b,
    request_rejected_cannot_connect_identd = 0x5c,
    request_rejected_different_user_id = 0x5d,
};

pub const Error = error{
    BufferTooSmall,
    UnsupportedCommand,
    UnsupportedVersion,
} || ss_address.AddressError;

pub const Request = struct {
    command: Command,
    address: ss_address.Address,
};

pub fn readRequestAfterVersion(stream: anytype, first_byte: u8, buf: []u8) !Request {
    if (first_byte != version) return error.UnsupportedVersion;

    var fixed: [7]u8 = undefined;
    try readExact(stream, &fixed);

    const command = parseCommand(fixed[0]) orelse return error.UnsupportedCommand;
    const port = std.mem.readInt(u16, fixed[1..3], .big);
    var ip: [4]u8 = undefined;
    @memcpy(&ip, fixed[3..7]);

    _ = try readNullTerminated(stream, buf);

    if (isSocks4aIp(ip)) {
        const domain = try readNullTerminated(stream, buf);
        return .{
            .command = command,
            .address = .{ .domain = .{ .name = domain, .port = port } },
        };
    }

    return .{
        .command = command,
        .address = .{ .ipv4 = .{ .ip = ip, .port = port } },
    };
}

pub fn writeResponse(reply: Reply, out: []u8) Error!usize {
    if (out.len < 8) return error.BufferTooSmall;
    out[0] = 0x00;
    out[1] = @intFromEnum(reply);
    @memset(out[2..8], 0);
    return 8;
}

fn isSocks4aIp(ip: [4]u8) bool {
    return ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] != 0;
}

fn parseCommand(value: u8) ?Command {
    return switch (value) {
        @intFromEnum(Command.tcp_connect) => .tcp_connect,
        @intFromEnum(Command.tcp_bind) => .tcp_bind,
        else => null,
    };
}

fn readNullTerminated(stream: anytype, buf: []u8) ![]const u8 {
    var len: usize = 0;
    while (true) {
        var byte: [1]u8 = undefined;
        try readExact(stream, &byte);
        if (byte[0] == 0) return buf[0..len];
        if (len == buf.len) return error.BufferTooSmall;
        buf[len] = byte[0];
        len += 1;
    }
}

fn readExact(stream: anytype, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = try stream.read(buf[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

const SliceReader = struct {
    data: []const u8,
    offset: usize = 0,

    fn read(self: *SliceReader, out: []u8) !usize {
        if (self.offset >= self.data.len) return 0;
        const n = @min(out.len, self.data.len - self.offset);
        @memcpy(out[0..n], self.data[self.offset..][0..n]);
        self.offset += n;
        return n;
    }
};

test "parse SOCKS4 IPv4 connect request" {
    const raw = [_]u8{ 0x04, 0x01, 0x01, 0xbb, 127, 0, 0, 1 } ++ "user".* ++ [_]u8{0};
    var reader = SliceReader{ .data = &raw };
    var first: [1]u8 = undefined;
    try readExact(&reader, &first);
    var buf: [256]u8 = undefined;
    const req = try readRequestAfterVersion(&reader, first[0], &buf);
    try std.testing.expectEqual(Command.tcp_connect, req.command);
    try std.testing.expectEqual(@as(u16, 443), req.address.ipv4.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &req.address.ipv4.ip);
}

test "parse SOCKS4a domain connect request" {
    const raw = [_]u8{ 0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1 } ++ "user".* ++ [_]u8{0} ++ "example.com".* ++ [_]u8{0};
    var reader = SliceReader{ .data = &raw };
    var first: [1]u8 = undefined;
    try readExact(&reader, &first);
    var buf: [256]u8 = undefined;
    const req = try readRequestAfterVersion(&reader, first[0], &buf);
    try std.testing.expectEqual(Command.tcp_connect, req.command);
    try std.testing.expectEqualStrings("example.com", req.address.domain.name);
    try std.testing.expectEqual(@as(u16, 80), req.address.domain.port);
}

test "write SOCKS4 granted response" {
    var out: [8]u8 = undefined;
    const used = try writeResponse(.request_granted, &out);
    try std.testing.expectEqual(@as(usize, 8), used);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0x5a, 0, 0, 0, 0, 0, 0 }, &out);
}
