const std = @import("std");
const ss_address = @import("address.zig");

pub const max_request_head_size: usize = 64 * 1024;

pub const Error = error{
    BufferTooSmall,
    HeaderTooLarge,
    InvalidHttpRequest,
    InvalidPort,
    MissingHost,
    UnsupportedScheme,
} || ss_address.AddressError;

pub const RequestKind = enum {
    connect,
    forward,
};

pub const RequestHead = struct {
    kind: RequestKind,
    method: []const u8,
    target: []const u8,
    version: []const u8,
    headers: []const u8,
    address: ss_address.Address,
    authority: []const u8,
    forward_target: []const u8,
    forward_target_needs_slash: bool = false,
};

pub fn isMethodInitial(byte: u8) bool {
    return switch (byte) {
        'G', 'g', 'H', 'h', 'P', 'p', 'D', 'd', 'C', 'c', 'O', 'o', 'T', 't' => true,
        else => false,
    };
}

pub fn readRequestHeadAfterFirstByte(stream: anytype, first_byte: u8, buf: []u8) !RequestHead {
    if (buf.len == 0) return error.BufferTooSmall;
    buf[0] = first_byte;
    var len: usize = 1;
    while (true) {
        if (endsWithHeaderTerminator(buf[0..len])) return parseRequestHead(buf[0..len]);
        if (len == buf.len) return error.HeaderTooLarge;
        var byte: [1]u8 = undefined;
        try readExact(stream, &byte);
        buf[len] = byte[0];
        len += 1;
    }
}

pub fn parseRequestHead(raw: []const u8) Error!RequestHead {
    if (!endsWithHeaderTerminator(raw)) return error.InvalidHttpRequest;
    const line_end = std.mem.indexOf(u8, raw, "\r\n") orelse return error.InvalidHttpRequest;
    const request_line = raw[0..line_end];

    var parts = std.mem.tokenizeScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.InvalidHttpRequest;
    const target = parts.next() orelse return error.InvalidHttpRequest;
    const version = parts.next() orelse return error.InvalidHttpRequest;
    if (parts.next() != null) return error.InvalidHttpRequest;
    if (!std.mem.startsWith(u8, version, "HTTP/")) return error.InvalidHttpRequest;

    const headers = raw[line_end + 2 .. raw.len - 2];
    if (std.ascii.eqlIgnoreCase(method, "CONNECT")) {
        const authority = stripUserInfo(target);
        return .{
            .kind = .connect,
            .method = method,
            .target = target,
            .version = version,
            .headers = headers,
            .address = try parseAuthority(null, authority),
            .authority = authority,
            .forward_target = target,
        };
    }

    if (parseAbsoluteTarget(target)) |absolute| {
        return .{
            .kind = .forward,
            .method = method,
            .target = target,
            .version = version,
            .headers = headers,
            .address = try parseAuthority(absolute.scheme, absolute.authority),
            .authority = absolute.authority,
            .forward_target = absolute.path_query,
            .forward_target_needs_slash = absolute.needs_slash,
        };
    }

    const authority = try hostHeader(headers);
    return .{
        .kind = .forward,
        .method = method,
        .target = target,
        .version = version,
        .headers = headers,
        .address = try parseAuthority("http", authority),
        .authority = authority,
        .forward_target = target,
    };
}

pub fn writeForwardRequestHead(req: RequestHead, out: []u8) Error!usize {
    if (req.kind != .forward) return error.InvalidHttpRequest;
    var writer = FixedWriter{ .buf = out };

    try writer.write(req.method);
    try writer.write(" ");
    if (req.forward_target_needs_slash) try writer.write("/");
    if (req.forward_target.len == 0) {
        try writer.write("/");
    } else {
        try writer.write(req.forward_target);
    }
    try writer.write(" ");
    try writer.write(req.version);
    try writer.write("\r\n");

    var saw_host = false;
    var lines = std.mem.splitSequence(u8, req.headers, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHttpRequest;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (shouldDropHeader(req.headers, name)) continue;
        if (std.ascii.eqlIgnoreCase(name, "Host")) saw_host = true;
        try writer.write(line);
        try writer.write("\r\n");
    }

    if (!saw_host) {
        try writer.write("Host: ");
        try writer.write(req.authority);
        try writer.write("\r\n");
    }
    try writer.write("Connection: close\r\n\r\n");
    return writer.pos;
}

fn parseAbsoluteTarget(target: []const u8) ?struct {
    scheme: []const u8,
    authority: []const u8,
    path_query: []const u8,
    needs_slash: bool,
} {
    const scheme_end = std.mem.indexOf(u8, target, "://") orelse return null;
    const scheme = target[0..scheme_end];
    const rest = target[scheme_end + 3 ..];
    const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    if (authority_end == 0) return null;
    const authority = stripUserInfo(rest[0..authority_end]);
    const suffix = rest[authority_end..];
    const needs_slash = suffix.len == 0 or suffix[0] != '/';
    return .{ .scheme = scheme, .authority = authority, .path_query = suffix, .needs_slash = needs_slash };
}

fn parseAuthority(scheme: ?[]const u8, authority: []const u8) Error!ss_address.Address {
    const default_port: u16 = if (scheme) |s| blk: {
        if (std.ascii.eqlIgnoreCase(s, "http")) break :blk 80;
        if (std.ascii.eqlIgnoreCase(s, "https")) break :blk 443;
        return error.UnsupportedScheme;
    } else 80;

    if (authority.len == 0) return error.MissingHost;
    var host: []const u8 = undefined;
    var port = default_port;

    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.MissingHost;
        host = authority[1..close];
        if (authority.len > close + 1) {
            if (authority[close + 1] != ':') return error.InvalidPort;
            port = try parsePort(authority[close + 2 ..]);
        }
        const parsed = std.Io.net.IpAddress.parseIp6(host, port) catch return error.InvalidHttpRequest;
        return switch (parsed) {
            .ip6 => |ip6| .{ .ipv6 = .{ .ip = ip6.bytes, .port = port } },
            .ip4 => error.InvalidHttpRequest,
        };
    }

    const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
    if (colon) |idx| {
        host = authority[0..idx];
        port = try parsePort(authority[idx + 1 ..]);
    } else {
        host = authority;
    }
    if (host.len == 0) return error.MissingHost;

    if (std.Io.net.IpAddress.parseIp4(host, port)) |parsed| {
        return switch (parsed) {
            .ip4 => |ip4| .{ .ipv4 = .{ .ip = ip4.bytes, .port = port } },
            .ip6 => unreachable,
        };
    } else |_| {}

    if (host.len > 255) return error.DomainTooLong;
    return .{ .domain = .{ .name = host, .port = port } };
}

fn parsePort(value: []const u8) Error!u16 {
    if (value.len == 0) return error.InvalidPort;
    return std.fmt.parseInt(u16, value, 10) catch error.InvalidPort;
}

fn hostHeader(headers: []const u8) Error![]const u8 {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Host")) {
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (value.len == 0) return error.MissingHost;
            return stripUserInfo(value);
        }
    }
    return error.MissingHost;
}

fn shouldDropHeader(all_headers: []const u8, name: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Trailer") or
        std.ascii.eqlIgnoreCase(name, "Upgrade") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Connection"))
    {
        return true;
    }
    return listedByConnectionHeader(all_headers, name);
}

fn listedByConnectionHeader(all_headers: []const u8, name: []const u8) bool {
    var lines = std.mem.splitSequence(u8, all_headers, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const header_name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(header_name, "Connection") and
            !std.ascii.eqlIgnoreCase(header_name, "Proxy-Connection"))
        {
            continue;
        }
        var tokens = std.mem.splitScalar(u8, line[colon + 1 ..], ',');
        while (tokens.next()) |token| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), name)) return true;
        }
    }
    return false;
}

fn stripUserInfo(authority: []const u8) []const u8 {
    const at = std.mem.lastIndexOfScalar(u8, authority, '@') orelse return authority;
    return authority[at + 1 ..];
}

fn endsWithHeaderTerminator(buf: []const u8) bool {
    return std.mem.endsWith(u8, buf, "\r\n\r\n");
}

fn readExact(stream: anytype, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = try stream.read(buf[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

const FixedWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn write(self: *FixedWriter, data: []const u8) Error!void {
        if (self.buf.len - self.pos < data.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }
};

test "parse HTTP CONNECT request" {
    const raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    const req = try parseRequestHead(raw);
    try std.testing.expectEqual(RequestKind.connect, req.kind);
    try std.testing.expectEqualStrings("CONNECT", req.method);
    try std.testing.expectEqualStrings("example.com", req.address.domain.name);
    try std.testing.expectEqual(@as(u16, 443), req.address.domain.port);
}

test "parse absolute-form HTTP request and rewrite to origin-form" {
    const raw = "GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\nConnection: X-Test\r\nX-Test: drop\r\nUser-Agent: test\r\n\r\n";
    const req = try parseRequestHead(raw);
    try std.testing.expectEqual(RequestKind.forward, req.kind);
    try std.testing.expectEqualStrings("example.com", req.address.domain.name);
    try std.testing.expectEqual(@as(u16, 8080), req.address.domain.port);

    var out: [512]u8 = undefined;
    const used = try writeForwardRequestHead(req, &out);
    const rewritten = out[0..used];
    try std.testing.expect(std.mem.startsWith(u8, rewritten, "GET /path?q=1 HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, rewritten, "Proxy-Connection") == null);
    try std.testing.expect(std.mem.indexOf(u8, rewritten, "X-Test") == null);
    try std.testing.expect(std.mem.indexOf(u8, rewritten, "User-Agent: test\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, rewritten, "Connection: close\r\n\r\n"));
}

test "parse origin-form HTTP request with Host header" {
    const raw = "GET /status HTTP/1.1\r\nHost: 127.0.0.1:18080\r\n\r\n";
    const req = try parseRequestHead(raw);
    try std.testing.expectEqual(RequestKind.forward, req.kind);
    try std.testing.expectEqual(@as(u16, 18080), req.address.ipv4.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &req.address.ipv4.ip);
    try std.testing.expectEqualStrings("/status", req.forward_target);
}
