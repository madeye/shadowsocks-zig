const std = @import("std");
const ss_address = @import("../protocol/address.zig");
const netio = @import("../relay/netio.zig");
const re2 = @import("../deps/re2.zig");

pub const Mode = enum {
    black_list,
    white_list,
};

pub const AccessControl = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    black_list: Rules,
    white_list: Rules,
    outbound_block: Rules,
    outbound_allow: Rules,
    mode: Mode,
    outbound_mode: Mode,

    pub fn loadFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !AccessControl {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
        defer allocator.free(bytes);
        return parseSlice(allocator, bytes);
    }

    pub fn parseSlice(allocator: std.mem.Allocator, bytes: []const u8) !AccessControl {
        var arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        const a = arena.allocator();

        var acl = AccessControl{
            .allocator = allocator,
            .arena = arena,
            .black_list = .empty,
            .white_list = .empty,
            .outbound_block = .empty,
            .outbound_allow = .empty,
            .mode = .black_list,
            .outbound_mode = .black_list,
        };
        errdefer acl.deinit();

        var current: *Rules = &acl.black_list;
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |raw_line| {
            const without_comment = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
            const line = std.mem.trim(u8, without_comment, " \t\r\n");
            if (line.len == 0) continue;
            if (!isAscii(line)) continue;

            if (std.mem.eql(u8, line, "[reject_all]") or std.mem.eql(u8, line, "[bypass_all]")) {
                acl.mode = .white_list;
            } else if (std.mem.eql(u8, line, "[accept_all]") or std.mem.eql(u8, line, "[proxy_all]")) {
                acl.mode = .black_list;
            } else if (std.mem.eql(u8, line, "[outbound_block_all]")) {
                acl.outbound_mode = .white_list;
            } else if (std.mem.eql(u8, line, "[outbound_allow_all]")) {
                acl.outbound_mode = .black_list;
            } else if (std.mem.eql(u8, line, "[black_list]") or std.mem.eql(u8, line, "[bypass_list]")) {
                current = &acl.black_list;
            } else if (std.mem.eql(u8, line, "[white_list]") or std.mem.eql(u8, line, "[proxy_list]")) {
                current = &acl.white_list;
            } else if (std.mem.eql(u8, line, "[outbound_block_list]")) {
                current = &acl.outbound_block;
            } else if (std.mem.eql(u8, line, "[outbound_allow_list]")) {
                current = &acl.outbound_allow;
            } else {
                try current.add(a, line);
            }
        }

        return acl;
    }

    pub fn deinit(self: *AccessControl) void {
        self.black_list.deinit();
        self.white_list.deinit();
        self.outbound_block.deinit();
        self.outbound_allow.deinit();
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn shouldProxy(self: *const AccessControl, io: std.Io, address: ss_address.Address) bool {
        switch (address) {
            .ipv4 => |ip4| return self.checkIpInProxyList(.{ .ip4 = .{ .bytes = ip4.ip, .port = ip4.port } }),
            .ipv6 => |ip6| return self.checkIpInProxyList(.{ .ip6 = .{ .bytes = ip6.ip, .port = ip6.port, .interface = .none } }),
            .domain => |domain| {
                if (self.checkHostInProxyList(domain.name)) |proxy| return proxy;
                if (self.mode == .black_list and self.black_list.isIpEmpty()) return true;
                if (self.mode == .white_list and self.white_list.isIpEmpty()) return false;
                const resolved = netio.resolveIp(domain.name, domain.port) catch return self.defaultProxy();
                _ = io;
                return self.checkIpInProxyList(resolved);
            },
        }
    }

    pub fn checkHostInProxyList(self: *const AccessControl, host: []const u8) ?bool {
        if (self.white_list.matchesHost(host)) return true;
        if (self.black_list.matchesHost(host)) return false;
        return null;
    }

    pub fn checkIpInProxyList(self: *const AccessControl, address: netio.net.IpAddress) bool {
        if (self.black_list.matchesIp(address)) return false;
        if (self.white_list.matchesIp(address)) return true;
        return self.defaultProxy();
    }

    pub fn clientBlocked(self: *const AccessControl, address: netio.net.IpAddress) bool {
        return switch (self.mode) {
            .black_list => self.black_list.matchesIp(address),
            .white_list => !self.white_list.matchesIp(address),
        };
    }

    pub fn outboundBlocked(self: *const AccessControl, io: std.Io, address: ss_address.Address) bool {
        switch (address) {
            .ipv4 => |ip4| return self.checkOutboundIpBlocked(.{ .ip4 = .{ .bytes = ip4.ip, .port = ip4.port } }),
            .ipv6 => |ip6| return self.checkOutboundIpBlocked(.{ .ip6 = .{ .bytes = ip6.ip, .port = ip6.port, .interface = .none } }),
            .domain => |domain| {
                if (self.outbound_block.matchesHost(domain.name)) return true;
                if (self.outbound_allow.matchesHost(domain.name)) return false;
                if (self.outbound_mode == .black_list and self.outbound_block.isIpEmpty()) return false;
                if (self.outbound_mode == .white_list and self.outbound_allow.isIpEmpty()) return true;
                const resolved = netio.resolveIp(domain.name, domain.port) catch return self.defaultOutboundBlocked();
                _ = io;
                return self.checkOutboundIpBlocked(resolved);
            },
        }
    }

    fn checkOutboundIpBlocked(self: *const AccessControl, address: netio.net.IpAddress) bool {
        if (self.outbound_block.matchesIp(address)) return true;
        if (self.outbound_allow.matchesIp(address)) return false;
        return self.defaultOutboundBlocked();
    }

    fn defaultProxy(self: *const AccessControl) bool {
        return self.mode == .black_list;
    }

    fn defaultOutboundBlocked(self: *const AccessControl) bool {
        return self.outbound_mode == .white_list;
    }
};

const Rules = struct {
    ip_rules: []IpRule,
    exact_hosts: []const []const u8,
    tree_hosts: []const []const u8,
    regex_rules: []RegexRule,

    const empty = Rules{
        .ip_rules = &.{},
        .exact_hosts = &.{},
        .tree_hosts = &.{},
        .regex_rules = &.{},
    };

    fn deinit(self: Rules) void {
        for (self.regex_rules) |*rule| {
            rule.deinit();
        }
    }

    fn add(self: *Rules, allocator: std.mem.Allocator, raw: []const u8) !void {
        if (std.mem.startsWith(u8, raw, "||")) {
            try appendString(allocator, &self.tree_hosts, canonicalHost(raw[2..]));
        } else if (std.mem.startsWith(u8, raw, "|")) {
            try appendString(allocator, &self.exact_hosts, canonicalHost(raw[1..]));
        } else if (try parseIpRule(raw)) |ip_rule| {
            try appendIpRule(allocator, &self.ip_rules, ip_rule);
        } else if (optimizedDomainRule(raw)) |optimized| {
            switch (optimized.kind) {
                .exact => try appendString(allocator, &self.exact_hosts, canonicalHost(optimized.host)),
                .subdomain => try appendString(allocator, &self.tree_hosts, canonicalHost(optimized.host)),
            }
        } else {
            try appendRegexRule(allocator, &self.regex_rules, try RegexRule.compile(allocator, raw));
        }
    }

    fn isIpEmpty(self: Rules) bool {
        return self.ip_rules.len == 0;
    }

    fn matchesIp(self: Rules, address: netio.net.IpAddress) bool {
        for (self.ip_rules) |rule| {
            if (rule.matches(address)) return true;
        }
        return false;
    }

    fn matchesHost(self: Rules, host: []const u8) bool {
        const normalized = trimTrailingDot(host);
        for (self.exact_hosts) |exact| {
            if (std.ascii.eqlIgnoreCase(normalized, exact)) return true;
        }
        for (self.tree_hosts) |suffix| {
            if (std.ascii.eqlIgnoreCase(normalized, suffix)) return true;
            if (normalized.len > suffix.len and normalized[normalized.len - suffix.len - 1] == '.' and std.ascii.eqlIgnoreCase(normalized[normalized.len - suffix.len ..], suffix)) return true;
        }
        for (self.regex_rules) |*rule| {
            if (rule.matches(normalized)) return true;
        }
        return false;
    }
};

const RegexRule = struct {
    compiled: re2.Regex,
    mutex: std.atomic.Mutex = .unlocked,

    fn compile(allocator: std.mem.Allocator, pattern: []const u8) !RegexRule {
        if (pattern.len == 0) return error.InvalidAclRegex;
        return .{ .compiled = re2.Regex.compile(allocator, pattern) catch return error.InvalidAclRegex };
    }

    fn deinit(self: *RegexRule) void {
        self.compiled.deinit();
    }

    fn matches(self: *RegexRule, host: []const u8) bool {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        defer self.mutex.unlock();
        return self.compiled.partialMatch(host) catch false;
    }
};

const IpRule = union(enum) {
    ipv4: struct { network: u32, prefix: u8 },
    ipv6: struct { network: u128, prefix: u8 },

    fn matches(self: IpRule, address: netio.net.IpAddress) bool {
        return switch (self) {
            .ipv4 => |rule| switch (address) {
                .ip4 => |ip4| masked(ip4ToInt(ip4.bytes), rule.prefix) == rule.network,
                .ip6 => false,
            },
            .ipv6 => |rule| switch (address) {
                .ip4 => false,
                .ip6 => |ip6| masked128(ip6ToInt(ip6.bytes), rule.prefix) == rule.network,
            },
        };
    }
};

fn parseIpRule(raw: []const u8) !?IpRule {
    const slash = std.mem.indexOfScalar(u8, raw, '/');
    const host = if (slash) |idx| raw[0..idx] else raw;
    if (std.Io.net.IpAddress.parseIp4(host, 0)) |parsed| {
        const prefix = if (slash) |idx| try parsePrefix(raw[idx + 1 ..], 32) else 32;
        return .{ .ipv4 = .{ .network = masked(ip4ToInt(parsed.ip4.bytes), prefix), .prefix = prefix } };
    } else |_| {}
    if (std.Io.net.IpAddress.parseIp6(host, 0)) |parsed| {
        const prefix = if (slash) |idx| try parsePrefix(raw[idx + 1 ..], 128) else 128;
        return .{ .ipv6 = .{ .network = masked128(ip6ToInt(parsed.ip6.bytes), prefix), .prefix = prefix } };
    } else |_| {}
    return null;
}

fn parsePrefix(raw: []const u8, max: u8) !u8 {
    const prefix = try std.fmt.parseInt(u8, raw, 10);
    if (prefix > max) return error.InvalidAclPrefix;
    return prefix;
}

fn masked(value: u32, prefix: u8) u32 {
    if (prefix == 0) return 0;
    return value & (@as(u32, std.math.maxInt(u32)) << @intCast(32 - prefix));
}

fn masked128(value: u128, prefix: u8) u128 {
    if (prefix == 0) return 0;
    return value & (@as(u128, std.math.maxInt(u128)) << @intCast(128 - prefix));
}

fn ip4ToInt(bytes: [4]u8) u32 {
    return std.mem.readInt(u32, &bytes, .big);
}

fn ip6ToInt(bytes: [16]u8) u128 {
    return std.mem.readInt(u128, &bytes, .big);
}

fn appendIpRule(allocator: std.mem.Allocator, target: *[]IpRule, value: IpRule) !void {
    const next = try allocator.alloc(IpRule, target.len + 1);
    @memcpy(next[0..target.len], target.*);
    next[target.len] = value;
    target.* = next;
}

fn appendString(allocator: std.mem.Allocator, target: *[]const []const u8, value: []const u8) !void {
    const next = try allocator.alloc([]const u8, target.len + 1);
    @memcpy(next[0..target.len], target.*);
    next[target.len] = try allocator.dupe(u8, value);
    target.* = next;
}

fn appendRegexRule(allocator: std.mem.Allocator, target: *[]RegexRule, value: RegexRule) !void {
    var owned = value;
    errdefer owned.deinit();
    const next = try allocator.alloc(RegexRule, target.len + 1);
    @memcpy(next[0..target.len], target.*);
    next[target.len] = owned;
    target.* = next;
}

fn canonicalHost(host: []const u8) []const u8 {
    return trimTrailingDot(std.mem.trim(u8, host, " \t\r\n"));
}

fn trimTrailingDot(host: []const u8) []const u8 {
    if (host.len > 0 and host[host.len - 1] == '.') return host[0 .. host.len - 1];
    return host;
}

fn isAscii(value: []const u8) bool {
    for (value) |byte| {
        if (byte >= 0x80) return false;
    }
    return true;
}

const OptimizedRule = struct {
    kind: enum { exact, subdomain },
    host: []const u8,
};

fn optimizedDomainRule(raw: []const u8) ?OptimizedRule {
    if (std.mem.startsWith(u8, raw, "^") and std.mem.endsWith(u8, raw, "$")) {
        const inner = raw[1 .. raw.len - 1];
        if (isPlainEscapedDomain(inner)) return .{ .kind = .exact, .host = inner };
    }
    if (std.mem.startsWith(u8, raw, "(^|\\.)") and std.mem.endsWith(u8, raw, "$")) {
        const inner = raw["(^|\\.)".len .. raw.len - 1];
        if (isPlainEscapedDomain(inner)) return .{ .kind = .subdomain, .host = inner };
    }
    if (std.mem.startsWith(u8, raw, "(?:^|\\.)") and std.mem.endsWith(u8, raw, "$")) {
        const inner = raw["(?:^|\\.)".len .. raw.len - 1];
        if (isPlainEscapedDomain(inner)) return .{ .kind = .subdomain, .host = inner };
    }
    return null;
}

fn isPlainEscapedDomain(value: []const u8) bool {
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '\\') continue;
        return false;
    }
    return value.len != 0;
}

test "ACL parses local proxy and bypass rules" {
    var acl = try AccessControl.parseSlice(std.testing.allocator,
        \\[bypass_all]
        \\[proxy_list]
        \\||example.com
        \\|exact.test
        \\8.8.8.0/24
        \\[bypass_list]
        \\||direct.example
        \\
    );
    defer acl.deinit();

    try std.testing.expect(acl.shouldProxy(std.testing.io, .{ .domain = .{ .name = "www.example.com", .port = 80 } }));
    try std.testing.expect(acl.shouldProxy(std.testing.io, .{ .domain = .{ .name = "exact.test.", .port = 80 } }));
    try std.testing.expect(!acl.shouldProxy(std.testing.io, .{ .domain = .{ .name = "x.direct.example", .port = 80 } }));
    try std.testing.expect(acl.shouldProxy(std.testing.io, .{ .ipv4 = .{ .ip = .{ 8, 8, 8, 8 }, .port = 53 } }));
    try std.testing.expect(!acl.shouldProxy(std.testing.io, .{ .ipv4 = .{ .ip = .{ 1, 1, 1, 1 }, .port = 53 } }));
}

test "ACL uses RE2 rules for host patterns" {
    var acl = try AccessControl.parseSlice(std.testing.allocator,
        \\[bypass_all]
        \\[proxy_list]
        \\^api-[0-9]+\.service\.(com|net)$
        \\[bypass_list]
        \\.*\.direct-[a-z]{2}\.example$
        \\
    );
    defer acl.deinit();

    try std.testing.expect(acl.shouldProxy(std.testing.io, .{ .domain = .{ .name = "api-42.service.com", .port = 443 } }));
    try std.testing.expect(acl.shouldProxy(std.testing.io, .{ .domain = .{ .name = "api-7.service.net.", .port = 443 } }));
    try std.testing.expect(!acl.shouldProxy(std.testing.io, .{ .domain = .{ .name = "cdn.direct-us.example", .port = 443 } }));
    try std.testing.expect(!acl.shouldProxy(std.testing.io, .{ .domain = .{ .name = "api-x.service.com", .port = 443 } }));
}

test "ACL rejects invalid regex rules" {
    try std.testing.expectError(error.InvalidAclRegex, AccessControl.parseSlice(std.testing.allocator,
        \\[proxy_list]
        \\[invalid
        \\
    ));
}

test "ACL parses server outbound and client rules" {
    var acl = try AccessControl.parseSlice(std.testing.allocator,
        \\[reject_all]
        \\[white_list]
        \\127.0.0.1
        \\[outbound_block_all]
        \\[outbound_allow_list]
        \\||allowed.example
        \\10.0.0.0/8
        \\
    );
    defer acl.deinit();

    try std.testing.expect(!acl.clientBlocked(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1000 } }));
    try std.testing.expect(acl.clientBlocked(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 1000 } }));
    try std.testing.expect(!acl.outboundBlocked(std.testing.io, .{ .domain = .{ .name = "www.allowed.example", .port = 80 } }));
    try std.testing.expect(!acl.outboundBlocked(std.testing.io, .{ .ipv4 = .{ .ip = .{ 10, 1, 2, 3 }, .port = 80 } }));
    try std.testing.expect(acl.outboundBlocked(std.testing.io, .{ .ipv4 = .{ .ip = .{ 11, 1, 2, 3 }, .port = 80 } }));
}
