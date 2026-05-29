const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config.zig");
const acl = @import("../security/acl.zig");
const fake_dns = @import("fake_dns.zig");

const net = std.Io.net;
const ipv4_header_len = 20;
const ipv6_header_len = 40;
const udp_header_len = 8;

pub const IpVersion = enum {
    ipv4,
    ipv6,
};

pub const IpProtocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    icmpv6 = 58,
    other = 255,

    fn fromByte(value: u8) IpProtocol {
        return switch (value) {
            1 => .icmp,
            6 => .tcp,
            17 => .udp,
            58 => .icmpv6,
            else => .other,
        };
    }
};

pub const IpPacket = struct {
    version: IpVersion,
    protocol: IpProtocol,
    protocol_number: u8,
    source: net.IpAddress,
    destination: net.IpAddress,
    payload: []const u8,
};

pub const UdpPacket = struct {
    version: IpVersion,
    source: net.IpAddress,
    destination: net.IpAddress,
    payload: []const u8,
};

pub fn runLocal(
    allocator: std.mem.Allocator,
    io: std.Io,
    tcp_servers: []const config.Server,
    udp_servers: []const config.Server,
    tcp_next: *std.atomic.Value(usize),
    udp_next: *std.atomic.Value(usize),
    local_cfg: config.Local,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,
    access_control: ?*const acl.AccessControl,
    fake_dns_manager: ?*fake_dns.Manager,
) !void {
    _ = allocator;
    _ = io;
    _ = tcp_servers;
    _ = udp_servers;
    _ = tcp_next;
    _ = udp_next;
    _ = local_cfg;
    _ = udp_timeout_seconds;
    _ = udp_max_associations;
    _ = access_control;
    _ = fake_dns_manager;

    return switch (builtin.os.tag) {
        .linux, .macos, .ios, .windows => error.TunLocalPacketStackNotImplemented,
        else => error.TunLocalUnsupportedPlatform,
    };
}

pub fn parseIpPacket(packet: []const u8) !?IpPacket {
    if (packet.len == 0) return null;
    return switch (packet[0] >> 4) {
        4 => try parseIpv4Packet(packet),
        6 => try parseIpv6Packet(packet),
        else => null,
    };
}

pub fn parseUdpPacket(packet: []const u8) !?UdpPacket {
    const ip = (try parseIpPacket(packet)) orelse return null;
    if (ip.protocol != .udp) return null;
    if (ip.payload.len < udp_header_len) return error.InvalidTunPacket;

    const udp_len = std.mem.readInt(u16, ip.payload[4..6], .big);
    if (udp_len < udp_header_len or udp_len > ip.payload.len) return error.InvalidTunPacket;
    const udp_payload = ip.payload[udp_header_len..udp_len];

    var source = ip.source;
    var destination = ip.destination;
    switch (source) {
        .ip4 => |*ip4| ip4.port = std.mem.readInt(u16, ip.payload[0..2], .big),
        .ip6 => |*ip6| ip6.port = std.mem.readInt(u16, ip.payload[0..2], .big),
    }
    switch (destination) {
        .ip4 => |*ip4| ip4.port = std.mem.readInt(u16, ip.payload[2..4], .big),
        .ip6 => |*ip6| ip6.port = std.mem.readInt(u16, ip.payload[2..4], .big),
    }

    const checksum = std.mem.readInt(u16, ip.payload[6..8], .big);
    switch (ip.version) {
        .ipv4 => if (checksum != 0 and udpChecksum(source, destination, ip.payload[0..udp_len]) != 0) return error.InvalidTunPacket,
        .ipv6 => if (checksum == 0 or udpChecksum(source, destination, ip.payload[0..udp_len]) != 0) return error.InvalidTunPacket,
    }

    return .{
        .version = ip.version,
        .source = source,
        .destination = destination,
        .payload = udp_payload,
    };
}

pub fn buildUdpPacket(out: []u8, source: net.IpAddress, destination: net.IpAddress, payload: []const u8) ![]u8 {
    return switch (source) {
        .ip4 => switch (destination) {
            .ip4 => try buildIpv4UdpPacket(out, source, destination, payload),
            .ip6 => error.AddressFamilyMismatch,
        },
        .ip6 => switch (destination) {
            .ip4 => error.AddressFamilyMismatch,
            .ip6 => try buildIpv6UdpPacket(out, source, destination, payload),
        },
    };
}

fn parseIpv4Packet(packet: []const u8) !IpPacket {
    if (packet.len < ipv4_header_len) return error.InvalidTunPacket;
    const header_len = @as(usize, packet[0] & 0x0f) * 4;
    if (header_len < ipv4_header_len or header_len > packet.len) return error.InvalidTunPacket;
    const total_len = std.mem.readInt(u16, packet[2..4], .big);
    if (total_len < header_len or total_len > packet.len) return error.InvalidTunPacket;

    const fragment = std.mem.readInt(u16, packet[6..8], .big);
    if ((fragment & 0x3fff) != 0 or (fragment & 0x2000) != 0) return error.UnsupportedTunFragment;
    if (internetChecksum(packet[0..header_len]) != 0) return error.InvalidTunPacket;

    return .{
        .version = .ipv4,
        .protocol = IpProtocol.fromByte(packet[9]),
        .protocol_number = packet[9],
        .source = .{ .ip4 = .{ .bytes = packet[12..16].*, .port = 0 } },
        .destination = .{ .ip4 = .{ .bytes = packet[16..20].*, .port = 0 } },
        .payload = packet[header_len..total_len],
    };
}

fn parseIpv6Packet(packet: []const u8) !IpPacket {
    if (packet.len < ipv6_header_len) return error.InvalidTunPacket;
    const payload_len = std.mem.readInt(u16, packet[4..6], .big);
    const total_len = ipv6_header_len + @as(usize, payload_len);
    if (total_len > packet.len) return error.InvalidTunPacket;

    return .{
        .version = .ipv6,
        .protocol = IpProtocol.fromByte(packet[6]),
        .protocol_number = packet[6],
        .source = .{ .ip6 = .{ .bytes = packet[8..24].*, .port = 0, .interface = .none } },
        .destination = .{ .ip6 = .{ .bytes = packet[24..40].*, .port = 0, .interface = .none } },
        .payload = packet[ipv6_header_len..total_len],
    };
}

fn buildIpv4UdpPacket(out: []u8, source: net.IpAddress, destination: net.IpAddress, payload: []const u8) ![]u8 {
    const total_len = ipv4_header_len + udp_header_len + payload.len;
    if (total_len > out.len or total_len > std.math.maxInt(u16)) return error.PacketTooLarge;
    const udp_len: u16 = @intCast(udp_header_len + payload.len);
    const ip4_source = source.ip4;
    const ip4_destination = destination.ip4;

    @memset(out[0..total_len], 0);
    out[0] = 0x45;
    std.mem.writeInt(u16, out[2..4], @intCast(total_len), .big);
    out[8] = 64;
    out[9] = @intFromEnum(IpProtocol.udp);
    @memcpy(out[12..16], &ip4_source.bytes);
    @memcpy(out[16..20], &ip4_destination.bytes);
    std.mem.writeInt(u16, out[10..12], internetChecksum(out[0..ipv4_header_len]), .big);

    const udp = out[ipv4_header_len..total_len];
    std.mem.writeInt(u16, udp[0..2], ip4_source.port, .big);
    std.mem.writeInt(u16, udp[2..4], ip4_destination.port, .big);
    std.mem.writeInt(u16, udp[4..6], udp_len, .big);
    @memcpy(udp[udp_header_len..], payload);
    var checksum = udpChecksum(source, destination, udp);
    if (checksum == 0) checksum = 0xffff;
    std.mem.writeInt(u16, udp[6..8], checksum, .big);

    return out[0..total_len];
}

fn buildIpv6UdpPacket(out: []u8, source: net.IpAddress, destination: net.IpAddress, payload: []const u8) ![]u8 {
    const total_len = ipv6_header_len + udp_header_len + payload.len;
    if (total_len > out.len or udp_header_len + payload.len > std.math.maxInt(u16)) return error.PacketTooLarge;
    const udp_len: u16 = @intCast(udp_header_len + payload.len);
    const ip6_source = source.ip6;
    const ip6_destination = destination.ip6;

    @memset(out[0..total_len], 0);
    out[0] = 0x60;
    std.mem.writeInt(u16, out[4..6], udp_len, .big);
    out[6] = @intFromEnum(IpProtocol.udp);
    out[7] = 64;
    @memcpy(out[8..24], &ip6_source.bytes);
    @memcpy(out[24..40], &ip6_destination.bytes);

    const udp = out[ipv6_header_len..total_len];
    std.mem.writeInt(u16, udp[0..2], ip6_source.port, .big);
    std.mem.writeInt(u16, udp[2..4], ip6_destination.port, .big);
    std.mem.writeInt(u16, udp[4..6], udp_len, .big);
    @memcpy(udp[udp_header_len..], payload);
    var checksum = udpChecksum(source, destination, udp);
    if (checksum == 0) checksum = 0xffff;
    std.mem.writeInt(u16, udp[6..8], checksum, .big);

    return out[0..total_len];
}

fn udpChecksum(source: net.IpAddress, destination: net.IpAddress, udp: []const u8) u16 {
    var sum: u32 = 0;
    switch (source) {
        .ip4 => |src| {
            const dst = destination.ip4;
            sum = checksumAdd(sum, &src.bytes);
            sum = checksumAdd(sum, &dst.bytes);
            sum += @intFromEnum(IpProtocol.udp);
            sum += @intCast(udp.len);
        },
        .ip6 => |src| {
            const dst = destination.ip6;
            sum = checksumAdd(sum, &src.bytes);
            sum = checksumAdd(sum, &dst.bytes);
            sum += @intCast((udp.len >> 16) & 0xffff);
            sum += @intCast(udp.len & 0xffff);
            sum += @intFromEnum(IpProtocol.udp);
        },
    }
    sum = checksumAdd(sum, udp);
    return finalizeChecksum(sum);
}

fn internetChecksum(bytes: []const u8) u16 {
    return finalizeChecksum(checksumAdd(0, bytes));
}

fn checksumAdd(initial: u32, bytes: []const u8) u32 {
    var sum = initial;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u16, bytes[i]) << 8) | bytes[i + 1];
    }
    if (i < bytes.len) {
        sum += @as(u16, bytes[i]) << 8;
    }
    return sum;
}

fn finalizeChecksum(initial: u32) u16 {
    var sum = initial;
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @intCast(sum & 0xffff));
}

test "tun parses synthesized IPv4 UDP packet" {
    var buf: [1500]u8 = undefined;
    const source = try net.IpAddress.parse("192.0.2.10", 53000);
    const destination = try net.IpAddress.parse("198.51.100.20", 53);
    const packet = try buildUdpPacket(&buf, source, destination, "hello");

    const ip = (try parseIpPacket(packet)).?;
    try std.testing.expectEqual(IpVersion.ipv4, ip.version);
    try std.testing.expectEqual(IpProtocol.udp, ip.protocol);
    try std.testing.expectEqual(@as(u8, 17), ip.protocol_number);

    const udp = (try parseUdpPacket(packet)).?;
    try std.testing.expectEqual(source, udp.source);
    try std.testing.expectEqual(destination, udp.destination);
    try std.testing.expectEqualStrings("hello", udp.payload);
}

test "tun parses synthesized IPv6 UDP packet" {
    var buf: [1500]u8 = undefined;
    const source = try net.IpAddress.parse("2001:db8::1", 53000);
    const destination = try net.IpAddress.parse("2001:db8::2", 53);
    const packet = try buildUdpPacket(&buf, source, destination, "hello-v6");

    const ip = (try parseIpPacket(packet)).?;
    try std.testing.expectEqual(IpVersion.ipv6, ip.version);
    try std.testing.expectEqual(IpProtocol.udp, ip.protocol);
    try std.testing.expectEqual(@as(u8, 17), ip.protocol_number);

    const udp = (try parseUdpPacket(packet)).?;
    try std.testing.expectEqual(source, udp.source);
    try std.testing.expectEqual(destination, udp.destination);
    try std.testing.expectEqualStrings("hello-v6", udp.payload);
}

test "tun rejects fragmented IPv4 UDP packet" {
    var buf: [1500]u8 = undefined;
    const source = try net.IpAddress.parse("192.0.2.10", 53000);
    const destination = try net.IpAddress.parse("198.51.100.20", 53);
    const packet = try buildUdpPacket(&buf, source, destination, "hello");
    buf[6] = 0x20;
    std.mem.writeInt(u16, buf[10..12], 0, .big);
    std.mem.writeInt(u16, buf[10..12], internetChecksum(packet[0..ipv4_header_len]), .big);

    try std.testing.expectError(error.UnsupportedTunFragment, parseIpPacket(packet));
}
