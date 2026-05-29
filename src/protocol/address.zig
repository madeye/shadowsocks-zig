const std = @import("std");

pub const AddressError = error{
    BufferTooSmall,
    DomainTooLong,
    InvalidAddress,
    UnsupportedAddressType,
};

pub const Type = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const Address = union(Type) {
    ipv4: struct { ip: [4]u8, port: u16 },
    domain: struct { name: []const u8, port: u16 },
    ipv6: struct { ip: [16]u8, port: u16 },

    pub fn encodedLen(self: Address) usize {
        return switch (self) {
            .ipv4 => 1 + 4 + 2,
            .domain => |d| 1 + 1 + d.name.len + 2,
            .ipv6 => 1 + 16 + 2,
        };
    }

    pub fn write(self: Address, out: []u8) AddressError!usize {
        if (out.len < self.encodedLen()) return error.BufferTooSmall;
        switch (self) {
            .ipv4 => |v| {
                out[0] = @intFromEnum(Type.ipv4);
                @memcpy(out[1..5], &v.ip);
                std.mem.writeInt(u16, out[5..7], v.port, .big);
                return 7;
            },
            .domain => |d| {
                if (d.name.len > 255) return error.DomainTooLong;
                out[0] = @intFromEnum(Type.domain);
                out[1] = @intCast(d.name.len);
                @memcpy(out[2..][0..d.name.len], d.name);
                std.mem.writeInt(u16, out[2 + d.name.len ..][0..2], d.port, .big);
                return 1 + 1 + d.name.len + 2;
            },
            .ipv6 => |v| {
                out[0] = @intFromEnum(Type.ipv6);
                @memcpy(out[1..17], &v.ip);
                std.mem.writeInt(u16, out[17..19], v.port, .big);
                return 19;
            },
        }
    }

    pub fn read(buf: []const u8) AddressError!struct { address: Address, used: usize } {
        if (buf.len < 1) return error.BufferTooSmall;
        return switch (buf[0]) {
            @intFromEnum(Type.ipv4) => blk: {
                if (buf.len < 7) return error.BufferTooSmall;
                var ip: [4]u8 = undefined;
                @memcpy(&ip, buf[1..5]);
                break :blk .{ .address = .{ .ipv4 = .{ .ip = ip, .port = std.mem.readInt(u16, buf[5..7], .big) } }, .used = 7 };
            },
            @intFromEnum(Type.domain) => blk: {
                if (buf.len < 2) return error.BufferTooSmall;
                const len = buf[1];
                if (buf.len < 2 + len + 2) return error.BufferTooSmall;
                break :blk .{
                    .address = .{ .domain = .{ .name = buf[2..][0..len], .port = std.mem.readInt(u16, buf[2 + len ..][0..2], .big) } },
                    .used = 2 + len + 2,
                };
            },
            @intFromEnum(Type.ipv6) => blk: {
                if (buf.len < 19) return error.BufferTooSmall;
                var ip: [16]u8 = undefined;
                @memcpy(&ip, buf[1..17]);
                break :blk .{ .address = .{ .ipv6 = .{ .ip = ip, .port = std.mem.readInt(u16, buf[17..19], .big) } }, .used = 19 };
            },
            else => error.UnsupportedAddressType,
        };
    }
};

test "domain address codec matches shadowsocks wire format" {
    const addr = Address{ .domain = .{ .name = "example.com", .port = 443 } };
    var buf: [256]u8 = undefined;
    const used = try addr.write(&buf);
    try std.testing.expectEqual(@as(usize, 15), used);
    try std.testing.expectEqual(@as(u8, 0x03), buf[0]);
    try std.testing.expectEqual(@as(u8, 11), buf[1]);
    try std.testing.expectEqualSlices(u8, "example.com", buf[2..13]);
    try std.testing.expectEqual(@as(u16, 443), std.mem.readInt(u16, buf[13..15], .big));

    const parsed = try Address.read(buf[0..used]);
    try std.testing.expectEqual(@as(usize, used), parsed.used);
    try std.testing.expectEqualStrings("example.com", parsed.address.domain.name);
    try std.testing.expectEqual(@as(u16, 443), parsed.address.domain.port);
}
