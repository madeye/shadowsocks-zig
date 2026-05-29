const std = @import("std");
const ss_address = @import("address.zig");

pub const version: u8 = 0x05;

pub const AuthMethod = enum(u8) {
    none = 0x00,
    gssapi = 0x01,
    password = 0x02,
    not_acceptable = 0xff,
};

pub const Command = enum(u8) {
    tcp_connect = 0x01,
    tcp_bind = 0x02,
    udp_associate = 0x03,
};

pub const Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

pub const Error = error{
    AuthenticationFailed,
    BufferTooSmall,
    InvalidReservedByte,
    InvalidPasswordAuthRequest,
    NoAcceptableAuthMethod,
    UnsupportedAuthVersion,
    UnsupportedCommand,
    UnsupportedVersion,
} || ss_address.AddressError;

pub const Request = struct {
    command: Command,
    address: ss_address.Address,

    pub fn read(buf: []const u8) Error!struct { request: Request, used: usize } {
        if (buf.len < 4) return error.BufferTooSmall;
        if (buf[0] != version) return error.UnsupportedVersion;
        if (buf[2] != 0) return error.InvalidReservedByte;
        const command = parseCommand(buf[1]) orelse return error.UnsupportedCommand;
        const parsed = try ss_address.Address.read(buf[3..]);
        return .{
            .request = .{ .command = command, .address = parsed.address },
            .used = 3 + parsed.used,
        };
    }
};

pub const UdpAssociateHeader = struct {
    frag: u8,
    address: ss_address.Address,

    pub fn encodedLen(self: UdpAssociateHeader) usize {
        return 3 + self.address.encodedLen();
    }

    pub fn read(buf: []const u8) Error!struct { header: UdpAssociateHeader, used: usize } {
        if (buf.len < 4) return error.BufferTooSmall;
        if (buf[0] != 0 or buf[1] != 0) return error.InvalidReservedByte;
        const parsed = try ss_address.Address.read(buf[3..]);
        return .{
            .header = .{ .frag = buf[2], .address = parsed.address },
            .used = 3 + parsed.used,
        };
    }

    pub fn write(self: UdpAssociateHeader, out: []u8) Error!usize {
        if (out.len < self.encodedLen()) return error.BufferTooSmall;
        out[0] = 0;
        out[1] = 0;
        out[2] = self.frag;
        return 3 + try self.address.write(out[3..]);
    }
};

pub fn readClientGreeting(stream: anytype, buf: []u8) ![]const u8 {
    var first: [1]u8 = undefined;
    try readExact(stream, &first);
    return readClientGreetingAfterVersion(stream, first[0], buf);
}

pub fn readClientGreetingAfterVersion(stream: anytype, first_byte: u8, buf: []u8) ![]const u8 {
    if (first_byte != version) return error.UnsupportedVersion;
    var count: [1]u8 = undefined;
    try readExact(stream, &count);
    const nmethods = count[0];
    if (buf.len < nmethods) return error.BufferTooSmall;
    try readExact(stream, buf[0..nmethods]);
    return buf[0..nmethods];
}

pub fn chooseNoAuth(methods: []const u8) Error!void {
    for (methods) |method| {
        if (method == @intFromEnum(AuthMethod.none)) return;
    }
    return error.NoAcceptableAuthMethod;
}

pub fn chooseAuthMethod(methods: []const u8, password_required: bool) Error!AuthMethod {
    var has_no_auth = false;
    var has_password = false;
    for (methods) |method| {
        switch (method) {
            @intFromEnum(AuthMethod.none) => has_no_auth = true,
            @intFromEnum(AuthMethod.password) => has_password = true,
            else => {},
        }
    }

    if (password_required) {
        if (has_password) return .password;
    } else if (has_no_auth) {
        return .none;
    } else if (has_password) {
        return .password;
    }

    return error.NoAcceptableAuthMethod;
}

pub fn readRequest(stream: anytype, buf: []u8) !Request {
    var header: [4]u8 = undefined;
    try readExact(stream, &header);
    if (header[0] != version) return error.UnsupportedVersion;
    if (header[2] != 0) return error.InvalidReservedByte;

    const command = parseCommand(header[1]) orelse return error.UnsupportedCommand;
    const address = try readStreamAddress(stream, header[3], buf);
    return .{ .command = command, .address = address };
}

pub fn writeNoAuthSelection(out: []u8) Error!usize {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = version;
    out[1] = @intFromEnum(AuthMethod.none);
    return 2;
}

pub fn writeAuthSelection(method: AuthMethod, out: []u8) Error!usize {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = version;
    out[1] = @intFromEnum(method);
    return 2;
}

pub fn writeReply(reply: Reply, bind: ss_address.Address, out: []u8) Error!usize {
    if (out.len < 3 + bind.encodedLen()) return error.BufferTooSmall;
    out[0] = version;
    out[1] = @intFromEnum(reply);
    out[2] = 0;
    return 3 + try bind.write(out[3..]);
}

pub const PasswordAuthRequest = struct {
    user_name: []const u8,
    password: []const u8,
};

pub fn readPasswordAuthRequest(stream: anytype, buf: []u8) !PasswordAuthRequest {
    var header: [2]u8 = undefined;
    try readExact(stream, &header);
    if (header[0] != 0x01) return error.UnsupportedAuthVersion;
    const user_len = header[1];
    if (buf.len < user_len + 1) return error.BufferTooSmall;
    try readExact(stream, buf[0 .. user_len + 1]);
    const pass_len = buf[user_len];
    if (buf.len < user_len + 1 + pass_len) return error.BufferTooSmall;
    try readExact(stream, buf[user_len + 1 .. user_len + 1 + pass_len]);
    return .{
        .user_name = buf[0..user_len],
        .password = buf[user_len + 1 .. user_len + 1 + pass_len],
    };
}

pub fn writePasswordAuthResponse(success: bool, out: []u8) Error!usize {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = 0x01;
    out[1] = if (success) 0x00 else 0xff;
    return 2;
}

fn readStreamAddress(stream: anytype, atyp: u8, buf: []u8) !ss_address.Address {
    return switch (atyp) {
        @intFromEnum(ss_address.Type.ipv4) => blk: {
            var raw: [6]u8 = undefined;
            try readExact(stream, &raw);
            var ip: [4]u8 = undefined;
            @memcpy(&ip, raw[0..4]);
            break :blk .{ .ipv4 = .{ .ip = ip, .port = std.mem.readInt(u16, raw[4..6], .big) } };
        },
        @intFromEnum(ss_address.Type.domain) => blk: {
            var len_raw: [1]u8 = undefined;
            try readExact(stream, &len_raw);
            const len = len_raw[0];
            if (buf.len < len + 2) return error.BufferTooSmall;
            try readExact(stream, buf[0 .. len + 2]);
            break :blk .{
                .domain = .{
                    .name = buf[0..len],
                    .port = std.mem.readInt(u16, buf[len..][0..2], .big),
                },
            };
        },
        @intFromEnum(ss_address.Type.ipv6) => blk: {
            var raw: [18]u8 = undefined;
            try readExact(stream, &raw);
            var ip: [16]u8 = undefined;
            @memcpy(&ip, raw[0..16]);
            break :blk .{ .ipv6 = .{ .ip = ip, .port = std.mem.readInt(u16, raw[16..18], .big) } };
        },
        else => error.UnsupportedAddressType,
    };
}

fn parseCommand(value: u8) ?Command {
    return switch (value) {
        @intFromEnum(Command.tcp_connect) => .tcp_connect,
        @intFromEnum(Command.tcp_bind) => .tcp_bind,
        @intFromEnum(Command.udp_associate) => .udp_associate,
        else => null,
    };
}

fn readExact(stream: anytype, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = try stream.read(buf[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

test "parse SOCKS5 connect request" {
    const raw = [_]u8{ 0x05, 0x01, 0x00, 0x03, 0x0b } ++ "example.com".* ++ [_]u8{ 0x01, 0xbb };
    const parsed = try Request.read(&raw);
    try std.testing.expectEqual(Command.tcp_connect, parsed.request.command);
    try std.testing.expectEqualStrings("example.com", parsed.request.address.domain.name);
    try std.testing.expectEqual(@as(u16, 443), parsed.request.address.domain.port);
}

test "SOCKS5 UDP associate header codec" {
    const header = UdpAssociateHeader{
        .frag = 0,
        .address = .{ .domain = .{ .name = "example.com", .port = 53 } },
    };
    var buf: [512]u8 = undefined;
    const used = try header.write(&buf);
    try std.testing.expectEqual(@as(usize, 3 + 1 + 1 + 11 + 2), used);

    const parsed = try UdpAssociateHeader.read(buf[0..used]);
    try std.testing.expectEqual(@as(u8, 0), parsed.header.frag);
    try std.testing.expectEqualStrings("example.com", parsed.header.address.domain.name);
    try std.testing.expectEqual(@as(u16, 53), parsed.header.address.domain.port);
    try std.testing.expectEqual(used, parsed.used);
}

test "SOCKS5 auth method selection" {
    try std.testing.expectEqual(AuthMethod.none, try chooseAuthMethod(&.{@intFromEnum(AuthMethod.none)}, false));
    try std.testing.expectEqual(AuthMethod.password, try chooseAuthMethod(&.{ @intFromEnum(AuthMethod.none), @intFromEnum(AuthMethod.password) }, true));
    try std.testing.expectError(error.NoAcceptableAuthMethod, chooseAuthMethod(&.{@intFromEnum(AuthMethod.none)}, true));
}
