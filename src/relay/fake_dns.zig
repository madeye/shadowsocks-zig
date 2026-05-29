const std = @import("std");
const ss_address = @import("../protocol/address.zig");
const dns = @import("../protocol/dns.zig");

pub const FakeDnsError = anyerror;

const Mapping = struct {
    ipv4: ?u32 = null,
    ipv6: ?u128 = null,
    expire_ns: i64,
};

const ParsedAddress = struct {
    family: ss_address.Type,
    ip4: u32 = 0,
    ip6: u128 = 0,
    port: u16,
};

const SpinLock = struct {
    locked: std.atomic.Value(bool) = .init(false),

    fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};

const Ipv4Pool = struct {
    first: u32,
    last: u32,
    next: u32,

    fn parse(cidr: []const u8) FakeDnsError!Ipv4Pool {
        const slash = std.mem.indexOfScalar(u8, cidr, '/') orelse return error.InvalidNetwork;
        const ip_text = cidr[0..slash];
        const prefix_text = cidr[slash + 1 ..];
        const prefix = std.fmt.parseInt(u8, prefix_text, 10) catch return error.InvalidNetwork;
        if (prefix > 32) return error.InvalidNetwork;
        const parsed = std.Io.net.IpAddress.parse(ip_text, 0) catch return error.InvalidNetwork;
        const base_ip = switch (parsed) {
            .ip4 => |ip4| bytesToU32(ip4.bytes),
            else => return error.InvalidNetwork,
        };
        const shift: u5 = if (prefix == 0) 0 else @intCast(32 - prefix);
        const mask: u32 = if (prefix == 0) 0 else @as(u32, std.math.maxInt(u32)) << shift;
        const network = base_ip & mask;
        const broadcast = network | ~mask;
        const first = if (prefix <= 30) network + 1 else network;
        const last = if (prefix <= 30) broadcast - 1 else broadcast;
        if (first > last) return error.InvalidNetwork;
        return .{ .first = first, .last = last, .next = first };
    }

    fn nextIp(self: *Ipv4Pool) u32 {
        const ip = self.next;
        self.next = if (self.next >= self.last) self.first else self.next + 1;
        return ip;
    }

    fn capacity(self: Ipv4Pool) u64 {
        return @as(u64, self.last) - self.first + 1;
    }
};

const Ipv6Pool = struct {
    first: u128,
    last: u128,
    next: u128,

    fn parse(cidr: []const u8) FakeDnsError!Ipv6Pool {
        const slash = std.mem.indexOfScalar(u8, cidr, '/') orelse return error.InvalidNetwork;
        const ip_text = cidr[0..slash];
        const prefix_text = cidr[slash + 1 ..];
        const prefix = std.fmt.parseInt(u8, prefix_text, 10) catch return error.InvalidNetwork;
        if (prefix > 128) return error.InvalidNetwork;
        const parsed = std.Io.net.IpAddress.parse(ip_text, 0) catch return error.InvalidNetwork;
        const base_ip = switch (parsed) {
            .ip6 => |ip6| bytesToU128(ip6.bytes),
            else => return error.InvalidNetwork,
        };
        const shift: u7 = if (prefix == 0) 0 else @intCast(128 - prefix);
        const mask: u128 = if (prefix == 0) 0 else @as(u128, std.math.maxInt(u128)) << shift;
        const network = base_ip & mask;
        const broadcast = network | ~mask;
        const first = if (prefix < 128) network + 1 else network;
        const last = broadcast;
        if (first > last) return error.InvalidNetwork;
        return .{ .first = first, .last = last, .next = first };
    }

    fn nextIp(self: *Ipv6Pool) u128 {
        const ip = self.next;
        self.next = if (self.next >= self.last) self.first else self.next + 1;
        return ip;
    }

    fn capacity(self: Ipv6Pool) u128 {
        return self.last - self.first + 1;
    }
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    mutex: SpinLock = .{},
    ipv4_pool: Ipv4Pool,
    ipv6_pool: Ipv6Pool,
    expire_ns: i64,
    database_path: ?[]const u8,
    domain_to_mapping: std.StringHashMap(Mapping),
    ip_to_domain: std.AutoHashMap(u32, []const u8),
    ip6_to_domain: std.AutoHashMap(u128, []const u8),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        ipv4_network: ?[]const u8,
        ipv6_network: ?[]const u8,
        database_path: ?[]const u8,
        expire_seconds: u64,
    ) FakeDnsError!Manager {
        var self = Manager{
            .allocator = allocator,
            .ipv4_pool = try Ipv4Pool.parse(ipv4_network orelse "172.16.0.0/12"),
            .ipv6_pool = try Ipv6Pool.parse(ipv6_network orelse "fc00::/7"),
            .expire_ns = timeoutNs(expire_seconds),
            .database_path = if (database_path) |path| try allocator.dupe(u8, path) else null,
            .domain_to_mapping = std.StringHashMap(Mapping).init(allocator),
            .ip_to_domain = std.AutoHashMap(u32, []const u8).init(allocator),
            .ip6_to_domain = std.AutoHashMap(u128, []const u8).init(allocator),
        };
        errdefer self.deinit();
        try self.load(io);
        return self;
    }

    pub fn deinit(self: *Manager) void {
        var it = self.domain_to_mapping.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        if (self.database_path) |path| self.allocator.free(path);
        self.domain_to_mapping.deinit();
        self.ip_to_domain.deinit();
        self.ip6_to_domain.deinit();
        self.* = undefined;
    }

    pub fn mapDomainIpv4(self: *Manager, io: std.Io, domain: []const u8) FakeDnsError![4]u8 {
        const now = nowNs(io);
        self.mutex.lock();
        defer self.mutex.unlock();

        const lookup_key = try lowerAlloc(self.allocator, domain);
        errdefer self.allocator.free(lookup_key);
        const entry = try self.domain_to_mapping.getOrPut(lookup_key);
        const stored_key = if (entry.found_existing) entry.key_ptr.* else lookup_key;
        if (entry.found_existing and entry.value_ptr.expire_ns >= now and entry.value_ptr.ipv4 != null) {
            self.allocator.free(lookup_key);
            entry.value_ptr.expire_ns = now + self.expire_ns;
            try self.save(io);
            return u32ToBytes(entry.value_ptr.ipv4.?);
        }

        const ip = try self.allocateIpv4(now);
        if (entry.found_existing) {
            self.allocator.free(lookup_key);
            entry.value_ptr.ipv4 = ip;
            entry.value_ptr.expire_ns = now + self.expire_ns;
        } else {
            entry.value_ptr.* = .{ .ipv4 = ip, .expire_ns = now + self.expire_ns };
        }
        try self.ip_to_domain.put(ip, stored_key);
        try self.save(io);
        return u32ToBytes(ip);
    }

    pub fn mapDomainIpv6(self: *Manager, io: std.Io, domain: []const u8) FakeDnsError![16]u8 {
        const now = nowNs(io);
        self.mutex.lock();
        defer self.mutex.unlock();

        const lookup_key = try lowerAlloc(self.allocator, domain);
        errdefer self.allocator.free(lookup_key);
        const entry = try self.domain_to_mapping.getOrPut(lookup_key);
        const stored_key = if (entry.found_existing) entry.key_ptr.* else lookup_key;
        if (entry.found_existing and entry.value_ptr.expire_ns >= now and entry.value_ptr.ipv6 != null) {
            self.allocator.free(lookup_key);
            entry.value_ptr.expire_ns = now + self.expire_ns;
            try self.save(io);
            return u128ToBytes(entry.value_ptr.ipv6.?);
        }

        const ip = try self.allocateIpv6(now);
        if (entry.found_existing) {
            self.allocator.free(lookup_key);
            entry.value_ptr.ipv6 = ip;
            entry.value_ptr.expire_ns = now + self.expire_ns;
        } else {
            entry.value_ptr.* = .{ .ipv6 = ip, .expire_ns = now + self.expire_ns };
        }
        try self.ip6_to_domain.put(ip, stored_key);
        try self.save(io);
        return u128ToBytes(ip);
    }

    pub fn rewriteAddress(self: *Manager, io: std.Io, address: ss_address.Address) ?ss_address.Address {
        const parsed: ParsedAddress = switch (address) {
            .ipv4 => |v| .{ .family = ss_address.Type.ipv4, .ip4 = bytesToU32(v.ip), .ip6 = @as(u128, 0), .port = v.port },
            .ipv6 => |v| .{ .family = ss_address.Type.ipv6, .ip4 = @as(u32, 0), .ip6 = bytesToU128(v.ip), .port = v.port },
            else => return null,
        };
        const now = nowNs(io);
        self.mutex.lock();
        defer self.mutex.unlock();
        const domain = switch (parsed.family) {
            .ipv4 => self.ip_to_domain.get(parsed.ip4) orelse self.findDomainByIpv4(parsed.ip4, now) orelse return null,
            .ipv6 => self.ip6_to_domain.get(parsed.ip6) orelse self.findDomainByIpv6(parsed.ip6, now) orelse return null,
            .domain => unreachable,
        };
        const mapping = self.domain_to_mapping.getPtr(domain) orelse return null;
        if (mapping.expire_ns < now) return null;
        mapping.expire_ns = now + self.expire_ns;
        return .{ .domain = .{ .name = domain, .port = parsed.port } };
    }

    fn findDomainByIpv4(self: *Manager, ip: u32, now: i64) ?[]const u8 {
        var it = self.domain_to_mapping.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.ipv4 != null and entry.value_ptr.ipv4.? == ip and entry.value_ptr.expire_ns >= now) return entry.key_ptr.*;
        }
        return null;
    }

    fn findDomainByIpv6(self: *Manager, ip: u128, now: i64) ?[]const u8 {
        var it = self.domain_to_mapping.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.ipv6 != null and entry.value_ptr.ipv6.? == ip and entry.value_ptr.expire_ns >= now) return entry.key_ptr.*;
        }
        return null;
    }

    fn allocateIpv4(self: *Manager, now: i64) FakeDnsError!u32 {
        var attempts: u64 = 0;
        const limit = self.ipv4_pool.capacity();
        while (attempts < limit) : (attempts += 1) {
            const ip = self.ipv4_pool.nextIp();
            const domain = self.ip_to_domain.get(ip) orelse return ip;
            const mapping = self.domain_to_mapping.get(domain) orelse return ip;
            if (mapping.expire_ns < now or mapping.ipv4 == null) return ip;
        }
        return error.AddressPoolExhausted;
    }

    fn allocateIpv6(self: *Manager, now: i64) FakeDnsError!u128 {
        var attempts: u64 = 0;
        const capacity = self.ipv6_pool.capacity();
        const limit: u64 = if (capacity > std.math.maxInt(u64)) std.math.maxInt(u64) else @intCast(capacity);
        while (attempts < limit) : (attempts += 1) {
            const ip = self.ipv6_pool.nextIp();
            const domain = self.ip6_to_domain.get(ip) orelse return ip;
            const mapping = self.domain_to_mapping.get(domain) orelse return ip;
            if (mapping.expire_ns < now or mapping.ipv6 == null) return ip;
        }
        return error.AddressPoolExhausted;
    }

    fn load(self: *Manager, io: std.Io) FakeDnsError!void {
        const path = self.database_path orelse return;
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, self.allocator, .limited(1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => return,
            else => |e| return e,
        };
        defer self.allocator.free(bytes);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, bytes, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return;
        const records_value = parsed.value.object.get("records") orelse return;
        if (records_value != .array) return;
        const now_unix = nowUnixSeconds(io);
        const now_ns = nowNs(io);
        for (records_value.array.items) |record| {
            if (record != .object) continue;
            const domain_raw = jsonString(record.object.get("domain")) orelse continue;
            const expire_unix = jsonU64(record.object.get("expire_unix")) orelse continue;
            if (expire_unix <= now_unix) continue;
            const domain = try lowerAlloc(self.allocator, domain_raw);
            errdefer self.allocator.free(domain);
            var mapping = Mapping{ .expire_ns = now_ns + timeoutNs(expire_unix - now_unix) };
            if (jsonString(record.object.get("ipv4"))) |ipv4_text| {
                if (std.Io.net.IpAddress.parse(ipv4_text, 0)) |address| {
                    if (address == .ip4) mapping.ipv4 = bytesToU32(address.ip4.bytes);
                } else |_| {}
            }
            if (jsonString(record.object.get("ipv6"))) |ipv6_text| {
                if (std.Io.net.IpAddress.parse(ipv6_text, 0)) |address| {
                    if (address == .ip6) mapping.ipv6 = bytesToU128(address.ip6.bytes);
                } else |_| {}
            }
            if (mapping.ipv4 == null and mapping.ipv6 == null) continue;
            const entry = try self.domain_to_mapping.getOrPut(domain);
            if (entry.found_existing) {
                self.allocator.free(domain);
                entry.value_ptr.* = mapping;
            } else {
                entry.value_ptr.* = mapping;
            }
            const stored_key = entry.key_ptr.*;
            if (mapping.ipv4) |ip| try self.ip_to_domain.put(ip, stored_key);
            if (mapping.ipv6) |ip| try self.ip6_to_domain.put(ip, stored_key);
        }
    }

    fn save(self: *Manager, io: std.Io) FakeDnsError!void {
        const path = self.database_path orelse return;
        if (std.fs.path.dirname(path)) |dir| {
            if (dir.len != 0) try std.Io.Dir.cwd().createDirPath(io, dir);
        }
        const bytes = try self.render(io);
        defer self.allocator.free(bytes);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
    }

    fn render(self: *Manager, io: std.Io) FakeDnsError![]u8 {
        const now_unix = nowUnixSeconds(io);
        const now_ns = nowNs(io);
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\n  \"version\":1,\n  \"records\":[");
        var first = true;
        var it = self.domain_to_mapping.iterator();
        while (it.next()) |entry| {
            const mapping = entry.value_ptr.*;
            if (mapping.expire_ns < now_ns) continue;
            const ttl_ns: u64 = @intCast(mapping.expire_ns - now_ns);
            const expire_unix = now_unix + ttl_ns / std.time.ns_per_s;
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try out.appendSlice(self.allocator, "\n    {\"domain\":");
            try appendJsonString(&out, self.allocator, entry.key_ptr.*);
            if (mapping.ipv4) |ip| {
                try out.appendSlice(self.allocator, ",\"ipv4\":");
                const text = try ipv4String(self.allocator, ip);
                defer self.allocator.free(text);
                try appendJsonString(&out, self.allocator, text);
            }
            if (mapping.ipv6) |ip| {
                try out.appendSlice(self.allocator, ",\"ipv6\":");
                const text = try ipv6String(self.allocator, ip);
                defer self.allocator.free(text);
                try appendJsonString(&out, self.allocator, text);
            }
            try out.appendSlice(self.allocator, ",\"expire_unix\":");
            try appendInt(&out, self.allocator, expire_unix);
            try out.append(self.allocator, '}');
        }
        try out.appendSlice(self.allocator, "\n  ]\n}\n");
        return try out.toOwnedSlice(self.allocator);
    }
};

pub fn writeResponse(io: std.Io, manager: *Manager, packet: []const u8, out: []u8) !usize {
    var host_buf: [255]u8 = undefined;
    const question = try dns.queryQuestion(packet, &host_buf);
    const ipv4 = if (question.qtype == .a and question.qclass == 1)
        try manager.mapDomainIpv4(io, question.host)
    else
        null;
    const ipv6 = if (question.qtype == .aaaa and question.qclass == 1)
        try manager.mapDomainIpv6(io, question.host)
    else
        null;
    return try dns.writeFakeResponse(packet, out, question, ipv4, ipv6, @intCast(@divTrunc(manager.expire_ns, std.time.ns_per_s)));
}

fn lowerAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, value.len);
    for (value, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

fn jsonString(value: ?std.json.Value) ?[]const u8 {
    const v = value orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn jsonU64(value: ?std.json.Value) ?u64 {
    const v = value orelse return null;
    return switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else null,
        .float => |f| if (f >= 0) @intFromFloat(f) else null,
        else => null,
    };
}

fn appendInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, "{d}", .{value});
    defer allocator.free(text);
    try out.appendSlice(allocator, text);
}

fn appendJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.append(allocator, '"');
    for (value) |byte| {
        switch (byte) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (byte < 0x20) {
                    const escaped = try std.fmt.allocPrint(allocator, "\\u{x:0>4}", .{byte});
                    defer allocator.free(escaped);
                    try out.appendSlice(allocator, escaped);
                } else {
                    try out.append(allocator, byte);
                }
            },
        }
    }
    try out.append(allocator, '"');
}

fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

fn nowUnixSeconds(io: std.Io) u64 {
    return @intCast(std.Io.Clock.real.now(io).toSeconds());
}

fn timeoutNs(seconds: u64) i64 {
    const ns = seconds *| std.time.ns_per_s;
    return std.math.cast(i64, ns) orelse std.math.maxInt(i64);
}

fn bytesToU32(bytes: [4]u8) u32 {
    return std.mem.readInt(u32, &bytes, .big);
}

fn u32ToBytes(value: u32) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, value, .big);
    return out;
}

fn ipv4String(allocator: std.mem.Allocator, ip: u32) ![]u8 {
    const bytes = u32ToBytes(ip);
    return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
}

fn bytesToU128(bytes: [16]u8) u128 {
    return std.mem.readInt(u128, &bytes, .big);
}

fn u128ToBytes(value: u128) [16]u8 {
    var out: [16]u8 = undefined;
    std.mem.writeInt(u128, &out, value, .big);
    return out;
}

fn ipv6String(allocator: std.mem.Allocator, ip: u128) ![]u8 {
    const bytes = u128ToBytes(ip);
    return try std.fmt.allocPrint(
        allocator,
        "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}",
        .{
            std.mem.readInt(u16, bytes[0..2], .big),
            std.mem.readInt(u16, bytes[2..4], .big),
            std.mem.readInt(u16, bytes[4..6], .big),
            std.mem.readInt(u16, bytes[6..8], .big),
            std.mem.readInt(u16, bytes[8..10], .big),
            std.mem.readInt(u16, bytes[10..12], .big),
            std.mem.readInt(u16, bytes[12..14], .big),
            std.mem.readInt(u16, bytes[14..16], .big),
        },
    );
}

fn deleteFileIgnoreMissing(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => {},
    };
}

test "fake DNS manager allocates stable IPv4 mappings and rewrites addresses" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var manager = try Manager.init(std.testing.allocator, io, "10.255.0.0/30", "fc00::/126", null, 10);
    defer manager.deinit();

    const first = try manager.mapDomainIpv4(io, "Example.COM");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 255, 0, 1 }, &first);
    const again = try manager.mapDomainIpv4(io, "example.com");
    try std.testing.expectEqualSlices(u8, &first, &again);

    const rewritten = manager.rewriteAddress(io, .{ .ipv4 = .{ .ip = first, .port = 443 } }).?;
    try std.testing.expectEqualStrings("example.com", rewritten.domain.name);
    try std.testing.expectEqual(@as(u16, 443), rewritten.domain.port);

    const first6 = try manager.mapDomainIpv6(io, "Example.COM");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &first6);
    const again6 = try manager.mapDomainIpv6(io, "example.com");
    try std.testing.expectEqualSlices(u8, &first6, &again6);

    const rewritten6 = manager.rewriteAddress(io, .{ .ipv6 = .{ .ip = first6, .port = 8443 } }).?;
    try std.testing.expectEqualStrings("example.com", rewritten6.domain.name);
    try std.testing.expectEqual(@as(u16, 8443), rewritten6.domain.port);
}

test "fake DNS response builds AAAA answers" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var manager = try Manager.init(std.testing.allocator, io, "10.255.0.0/30", "fc00::/126", null, 10);
    defer manager.deinit();

    const packet =
        "\x12\x35\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x07example\x03com\x00\x00\x1c\x00\x01";
    var response: [512]u8 = undefined;
    const used = try writeResponse(io, &manager, packet, &response);
    try std.testing.expectEqual(@as(usize, packet.len + 28), used);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, response[6..8], .big));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, response[used - 16 .. used]);
}

test "fake DNS database persists IPv4 and IPv6 mappings" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const path = ".zig-cache/fakedns-persistence-test.json";
    deleteFileIgnoreMissing(io, path);
    defer deleteFileIgnoreMissing(io, path);

    {
        var manager = try Manager.init(std.testing.allocator, io, "10.250.0.0/30", "fc00:1::/126", path, 60);
        defer manager.deinit();
        const ip4 = try manager.mapDomainIpv4(io, "Persist.EXAMPLE");
        try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 250, 0, 1 }, &ip4);
        const ip6 = try manager.mapDomainIpv6(io, "Persist.EXAMPLE");
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &ip6);
    }

    {
        var manager = try Manager.init(std.testing.allocator, io, "10.250.0.0/30", "fc00:1::/126", path, 60);
        defer manager.deinit();
        const ip4 = try manager.mapDomainIpv4(io, "persist.example");
        try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 250, 0, 1 }, &ip4);
        const ip6 = try manager.mapDomainIpv6(io, "persist.example");
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &ip6);
    }
}
