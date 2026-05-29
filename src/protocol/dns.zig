const std = @import("std");

pub const DnsError = error{
    InvalidDnsPacket,
    UnsupportedDnsNameCompression,
    DnsNameTooLong,
    BufferTooSmall,
};

pub const QueryType = enum(u16) {
    a = 1,
    aaaa = 28,
    other = 0,
};

pub const Question = struct {
    host: []const u8,
    qtype: QueryType,
    qtype_raw: u16,
    qclass: u16,
    question_end: usize,
};

pub fn queryHost(packet: []const u8, out: *[255]u8) DnsError![]const u8 {
    return (try queryQuestion(packet, out)).host;
}

pub fn queryQuestion(packet: []const u8, out: *[255]u8) DnsError!Question {
    if (packet.len < 12) return error.InvalidDnsPacket;
    const question_count = std.mem.readInt(u16, packet[4..6], .big);
    if (question_count == 0) return error.InvalidDnsPacket;

    var offset: usize = 12;
    var written: usize = 0;
    while (true) {
        if (offset >= packet.len) return error.InvalidDnsPacket;
        const label_len = packet[offset];
        offset += 1;
        if ((label_len & 0xc0) != 0) return error.UnsupportedDnsNameCompression;
        if (label_len == 0) break;
        if (label_len > 63 or offset + label_len > packet.len) return error.InvalidDnsPacket;
        if (written != 0) {
            if (written >= out.len) return error.DnsNameTooLong;
            out[written] = '.';
            written += 1;
        }
        if (written + label_len > out.len) return error.DnsNameTooLong;
        @memcpy(out[written .. written + label_len], packet[offset .. offset + label_len]);
        written += label_len;
        offset += label_len;
    }
    if (offset + 4 > packet.len or written == 0) return error.InvalidDnsPacket;
    const qtype_raw = std.mem.readInt(u16, packet[offset..][0..2], .big);
    const qclass = std.mem.readInt(u16, packet[offset + 2 ..][0..2], .big);
    return .{
        .host = out[0..written],
        .qtype = switch (qtype_raw) {
            1 => .a,
            28 => .aaaa,
            else => .other,
        },
        .qtype_raw = qtype_raw,
        .qclass = qclass,
        .question_end = offset + 4,
    };
}

pub fn writeFakeResponse(
    query: []const u8,
    out: []u8,
    question: Question,
    ipv4: ?[4]u8,
    ipv6: ?[16]u8,
    ttl_seconds: u32,
) DnsError!usize {
    if (query.len < 12 or question.question_end > query.len) return error.InvalidDnsPacket;
    const answer_len: usize = switch (question.qtype) {
        .a => if (ipv4 != null and question.qclass == 1) 16 else 0,
        .aaaa => if (ipv6 != null and question.qclass == 1) 28 else 0,
        .other => 0,
    };
    const response_len = 12 + (question.question_end - 12) + answer_len;
    if (out.len < response_len) return error.BufferTooSmall;

    @memset(out[0..response_len], 0);
    @memcpy(out[0..2], query[0..2]);
    out[2] = 0x80 | (query[2] & 0x01);
    out[3] = 0x80;
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], if (answer_len != 0) 1 else 0, .big);
    @memcpy(out[12..][0 .. question.question_end - 12], query[12..question.question_end]);

    var offset = question.question_end;
    if (answer_len == 0) return offset;

    out[offset] = 0xc0;
    out[offset + 1] = 0x0c;
    offset += 2;
    std.mem.writeInt(u16, out[offset..][0..2], question.qtype_raw, .big);
    offset += 2;
    std.mem.writeInt(u16, out[offset..][0..2], question.qclass, .big);
    offset += 2;
    std.mem.writeInt(u32, out[offset..][0..4], ttl_seconds, .big);
    offset += 4;
    switch (question.qtype) {
        .a => {
            std.mem.writeInt(u16, out[offset..][0..2], 4, .big);
            offset += 2;
            @memcpy(out[offset..][0..4], &(ipv4.?));
            offset += 4;
        },
        .aaaa => {
            std.mem.writeInt(u16, out[offset..][0..2], 16, .big);
            offset += 2;
            @memcpy(out[offset..][0..16], &(ipv6.?));
            offset += 16;
        },
        .other => unreachable,
    }
    return offset;
}

test "parse DNS query host" {
    const packet =
        "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x07example\x03com\x00\x00\x01\x00\x01";
    var out: [255]u8 = undefined;
    try std.testing.expectEqualStrings("example.com", try queryHost(packet, &out));
}

test "build fake A response" {
    const packet =
        "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x07example\x03com\x00\x00\x01\x00\x01";
    var host_buf: [255]u8 = undefined;
    const question = try queryQuestion(packet, &host_buf);
    var response: [512]u8 = undefined;
    const used = try writeFakeResponse(packet, &response, question, .{ 172, 16, 0, 1 }, null, 10);
    try std.testing.expectEqual(@as(usize, packet.len + 16), used);
    try std.testing.expectEqualSlices(u8, "\x12\x34", response[0..2]);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, response[6..8], .big));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 172, 16, 0, 1 }, response[used - 4 .. used]);
}
