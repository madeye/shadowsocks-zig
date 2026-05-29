const std = @import("std");
const crypto = @import("crypto.zig");

pub const ConfigError = anyerror;
pub const server_weight_scale: u16 = 100;

pub const Mode = enum {
    tcp_only,
    tcp_and_udp,
    udp_only,

    pub fn parse(value: ?[]const u8) Mode {
        const v = value orelse return .tcp_only;
        if (std.mem.eql(u8, v, "tcp_and_udp")) return .tcp_and_udp;
        if (std.mem.eql(u8, v, "udp_only")) return .udp_only;
        return .tcp_only;
    }

    pub fn enableTcp(self: Mode) bool {
        return self == .tcp_only or self == .tcp_and_udp;
    }

    pub fn enableUdp(self: Mode) bool {
        return self == .udp_only or self == .tcp_and_udp;
    }
};

pub const LocalProtocol = enum {
    socks,
    http,
    tunnel,
    redir,
    dns,
    fake_dns,

    pub fn parse(value: ?[]const u8) ConfigError!LocalProtocol {
        const v = value orelse return .socks;
        if (std.ascii.eqlIgnoreCase(v, "socks")) return .socks;
        if (std.ascii.eqlIgnoreCase(v, "http")) return .http;
        if (std.ascii.eqlIgnoreCase(v, "tunnel")) return .tunnel;
        if (std.ascii.eqlIgnoreCase(v, "redir")) return .redir;
        if (std.ascii.eqlIgnoreCase(v, "dns")) return .dns;
        if (std.ascii.eqlIgnoreCase(v, "fake-dns") or std.ascii.eqlIgnoreCase(v, "fake_dns")) return .fake_dns;
        return error.InvalidProtocol;
    }

    pub fn name(self: LocalProtocol) []const u8 {
        return switch (self) {
            .fake_dns => "fake-dns",
            else => @tagName(self),
        };
    }
};

pub const RedirType = enum {
    not_supported,
    redirect,
    tproxy,
    pf,
    ipfw,

    pub fn parse(value: ?[]const u8, default: RedirType) ConfigError!RedirType {
        const v = value orelse return default;
        if (std.ascii.eqlIgnoreCase(v, "redirect")) return .redirect;
        if (std.ascii.eqlIgnoreCase(v, "tproxy")) return .tproxy;
        if (std.ascii.eqlIgnoreCase(v, "pf")) return .pf;
        if (std.ascii.eqlIgnoreCase(v, "ipfw")) return .ipfw;
        if (std.ascii.eqlIgnoreCase(v, "not_supported")) return .not_supported;
        return error.InvalidRedirType;
    }

    pub fn tcpDefault() RedirType {
        return switch (@import("builtin").os.tag) {
            .linux => .redirect,
            .freebsd, .openbsd, .macos, .ios => .pf,
            else => .not_supported,
        };
    }

    pub fn udpDefault() RedirType {
        return switch (@import("builtin").os.tag) {
            .linux => .tproxy,
            .freebsd, .openbsd, .macos, .ios => .pf,
            else => .not_supported,
        };
    }

    pub fn name(self: RedirType) []const u8 {
        return switch (self) {
            .not_supported => "not_supported",
            .redirect => "redirect",
            .tproxy => "tproxy",
            .pf => "pf",
            .ipfw => "ipfw",
        };
    }
};

pub const Server = struct {
    host: []const u8,
    port: u16,
    password: []const u8,
    method: crypto.CipherKind,
    mode: Mode,
    tcp_weight: u16,
    udp_weight: u16,
    acl_path: ?[]const u8,
    plugin: ?[]const u8,
    plugin_opts: ?[]const u8,
    plugin_args: []const []const u8,
    plugin_mode: Mode,
};

pub const Local = struct {
    host: []const u8,
    port: u16,
    mode: Mode,
    protocol: LocalProtocol,
    tcp_redir: RedirType,
    udp_redir: RedirType,
    forward_host: ?[]const u8,
    forward_port: ?u16,
    local_dns_host: ?[]const u8,
    local_dns_port: ?u16,
    fake_dns_ipv4_network: ?[]const u8,
    fake_dns_ipv6_network: ?[]const u8,
    fake_dns_database_path: ?[]const u8,
    fake_dns_record_expire_duration: u64,
    acl_path: ?[]const u8,
    socks5_users: []const Socks5User,
};

pub const Socks5User = struct {
    user_name: []const u8,
    password: []const u8,
};

pub const ManagerTransport = enum {
    ip,
    unix,
};

pub const Manager = struct {
    transport: ManagerTransport,
    address: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,
};

pub const Overrides = struct {
    server_host: ?[]const u8 = null,
    server_port: ?u16 = null,
    local_host: ?[]const u8 = null,
    local_port: ?u16 = null,
    password: ?[]const u8 = null,
    method: ?crypto.CipherKind = null,
    timeout_seconds: ?u64 = null,
    mode: ?Mode = null,
    protocol: ?LocalProtocol = null,
    tcp_redir: ?RedirType = null,
    udp_redir: ?RedirType = null,
    forward_host: ?[]const u8 = null,
    forward_port: ?u16 = null,
    manager_address: ?[]const u8 = null,
    acl_path: ?[]const u8 = null,
    plugin: ?[]const u8 = null,
    plugin_opts: ?[]const u8 = null,

    pub fn hasAny(self: Overrides) bool {
        return self.server_host != null or
            self.server_port != null or
            self.local_host != null or
            self.local_port != null or
            self.password != null or
            self.method != null or
            self.timeout_seconds != null or
            self.mode != null or
            self.protocol != null or
            self.tcp_redir != null or
            self.udp_redir != null or
            self.forward_host != null or
            self.forward_port != null or
            self.manager_address != null or
            self.acl_path != null or
            self.plugin != null or
            self.plugin_opts != null;
    }
};

pub const Config = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    servers: []Server,
    locals: []Local,
    manager: ?Manager,
    timeout_seconds: u64,
    udp_timeout_seconds: u64,
    udp_max_associations: ?usize,

    pub fn deinit(self: *Config) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn parseFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ConfigError!Config {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
        defer allocator.free(bytes);
        return parseSliceWithIo(allocator, io, bytes);
    }

    pub fn parseSlice(allocator: std.mem.Allocator, bytes: []const u8) ConfigError!Config {
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer parsed.deinit();
        return fromJsonValue(allocator, null, parsed.value);
    }

    pub fn parseSliceWithIo(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8) ConfigError!Config {
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer parsed.deinit();
        return fromJsonValue(allocator, io, parsed.value);
    }

    pub fn fromOverrides(allocator: std.mem.Allocator, overrides: Overrides) ConfigError!Config {
        var arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }
        const a = arena.allocator();
        const protocol = overrides.protocol orelse .socks;
        const mode = overrides.mode orelse parseLocalMode(protocol, null);
        const timeout = overrides.timeout_seconds orelse 300;
        const server_host = overrides.server_host orelse return error.MissingServer;
        const server_port = overrides.server_port orelse return error.MissingServerPort;
        const password = overrides.password orelse return error.MissingPassword;
        const forward_host = overrides.forward_host;
        const forward_port = overrides.forward_port;
        if ((protocol == .tunnel or protocol == .dns) and (forward_host == null or forward_port == null)) {
            return error.MissingForwardAddress;
        }

        const servers = try a.alloc(Server, 1);
        servers[0] = .{
            .host = try a.dupe(u8, server_host),
            .port = server_port,
            .password = try a.dupe(u8, password),
            .method = overrides.method orelse .aes_256_gcm,
            .mode = mode,
            .tcp_weight = server_weight_scale,
            .udp_weight = server_weight_scale,
            .acl_path = try dupeOptionalSlice(a, overrides.acl_path),
            .plugin = try dupeOptionalSlice(a, overrides.plugin),
            .plugin_opts = try dupeOptionalSlice(a, overrides.plugin_opts),
            .plugin_args = &.{},
            .plugin_mode = mode,
        };

        const locals = try a.alloc(Local, 1);
        locals[0] = .{
            .host = try a.dupe(u8, overrides.local_host orelse "127.0.0.1"),
            .port = overrides.local_port orelse 1080,
            .mode = mode,
            .protocol = protocol,
            .tcp_redir = overrides.tcp_redir orelse RedirType.tcpDefault(),
            .udp_redir = overrides.udp_redir orelse RedirType.udpDefault(),
            .forward_host = try dupeOptionalSlice(a, forward_host),
            .forward_port = forward_port,
            .local_dns_host = null,
            .local_dns_port = null,
            .fake_dns_ipv4_network = null,
            .fake_dns_ipv6_network = null,
            .fake_dns_database_path = null,
            .fake_dns_record_expire_duration = 10,
            .acl_path = try dupeOptionalSlice(a, overrides.acl_path),
            .socks5_users = &.{},
        };

        return .{
            .allocator = allocator,
            .arena = arena,
            .servers = servers,
            .locals = locals,
            .manager = if (overrides.manager_address) |address| try parseManagerAddress(a, address) else null,
            .timeout_seconds = timeout,
            .udp_timeout_seconds = timeout,
            .udp_max_associations = null,
        };
    }

    pub fn applyOverrides(self: *Config, overrides: Overrides) ConfigError!void {
        if (!overrides.hasAny()) return;
        const a = self.arena.allocator();
        for (self.servers) |*server| {
            if (overrides.server_host) |host| server.host = try a.dupe(u8, host);
            if (overrides.server_port) |port| server.port = port;
            if (overrides.password) |password| server.password = try a.dupe(u8, password);
            if (overrides.method) |method| server.method = method;
            if (overrides.mode) |mode| server.mode = mode;
            if (overrides.acl_path) |acl_path| server.acl_path = try a.dupe(u8, acl_path);
            if (overrides.plugin) |plugin| server.plugin = try a.dupe(u8, plugin);
            if (overrides.plugin_opts) |plugin_opts| server.plugin_opts = try a.dupe(u8, plugin_opts);
            if (overrides.mode) |mode| server.plugin_mode = mode;
        }
        for (self.locals) |*local| {
            if (overrides.local_host) |host| local.host = try a.dupe(u8, host);
            if (overrides.local_port) |port| local.port = port;
            if (overrides.mode) |mode| local.mode = mode;
            if (overrides.protocol) |protocol| local.protocol = protocol;
            if (overrides.tcp_redir) |redir| local.tcp_redir = redir;
            if (overrides.udp_redir) |redir| local.udp_redir = redir;
            if (overrides.forward_host) |host| local.forward_host = try a.dupe(u8, host);
            if (overrides.forward_port) |port| local.forward_port = port;
            if (overrides.acl_path) |acl_path| local.acl_path = try a.dupe(u8, acl_path);
            if ((local.protocol == .tunnel or local.protocol == .dns) and (local.forward_host == null or local.forward_port == null)) {
                return error.MissingForwardAddress;
            }
        }
        if (overrides.timeout_seconds) |timeout| {
            self.timeout_seconds = timeout;
            self.udp_timeout_seconds = timeout;
        }
        if (overrides.manager_address) |address| {
            self.manager = try parseManagerAddress(a, address);
        }
    }

    fn fromJsonValue(allocator: std.mem.Allocator, io: ?std.Io, value: std.json.Value) ConfigError!Config {
        if (value != .object) return error.InvalidConfig;

        const root = value.object;
        var arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }
        const a = arena.allocator();

        var servers = std.ArrayList(Server).empty;
        if (root.get("servers")) |svrs| {
            if (svrs != .array) return error.InvalidConfig;
            for (svrs.array.items) |item| try servers.append(a, try parseServer(a, item, root));
        } else if (root.get("shadowsocks")) |svrs| {
            if (svrs != .array) return error.InvalidConfig;
            for (svrs.array.items) |item| try servers.append(a, try parseServer(a, item, root));
        } else {
            try servers.append(a, try parseServer(a, value, root));
        }

        var locals = std.ArrayList(Local).empty;
        if (root.get("locals")) |items| {
            if (items != .array) return error.InvalidConfig;
            for (items.array.items) |item| try locals.append(a, try parseLocal(a, io, item, root));
        } else {
            try locals.append(a, try parseLocal(a, io, value, root));
        }

        return .{
            .allocator = allocator,
            .arena = arena,
            .servers = try servers.toOwnedSlice(a),
            .locals = try locals.toOwnedSlice(a),
            .manager = try parseManager(a, root),
            .timeout_seconds = asU64(root.get("timeout")) orelse 300,
            .udp_timeout_seconds = asU64(root.get("udp_timeout")) orelse 300,
            .udp_max_associations = asUsize(root.get("udp_max_associations")),
        };
    }

    fn parseServer(allocator: std.mem.Allocator, value: std.json.Value, root: std.json.ObjectMap) ConfigError!Server {
        if (value != .object) return error.InvalidConfig;
        const object = value.object;
        const host = try dupString(allocator, object.get("server") orelse root.get("server") orelse return error.MissingServer);
        const port: u16 = @intCast(asU64(object.get("server_port") orelse root.get("server_port") orelse return error.MissingServerPort) orelse return error.MissingServerPort);
        const password = try dupString(allocator, object.get("password") orelse root.get("password") orelse return error.MissingPassword);
        const method_name = asString(object.get("method") orelse root.get("method")) orelse "aes-256-gcm";
        const method = crypto.CipherKind.parse(method_name) catch return error.InvalidCipher;
        const mode = Mode.parse(asString(object.get("mode") orelse root.get("mode")));
        return .{
            .host = host,
            .port = port,
            .password = password,
            .method = method,
            .mode = mode,
            .tcp_weight = try parseWeight(object.get("tcp_weight") orelse root.get("tcp_weight")),
            .udp_weight = try parseWeight(object.get("udp_weight") orelse root.get("udp_weight")),
            .acl_path = try dupOptionalNonEmptyString(allocator, object.get("acl") orelse root.get("acl")),
            .plugin = try dupOptionalNonEmptyString(allocator, object.get("plugin") orelse root.get("plugin")),
            .plugin_opts = try dupOptionalNonEmptyString(allocator, object.get("plugin_opts") orelse root.get("plugin_opts")),
            .plugin_args = try parseStringArray(allocator, object.get("plugin_args") orelse root.get("plugin_args")),
            .plugin_mode = Mode.parse(asString(object.get("plugin_mode") orelse root.get("plugin_mode"))),
        };
    }

    fn parseLocal(allocator: std.mem.Allocator, io: ?std.Io, value: std.json.Value, root: std.json.ObjectMap) ConfigError!Local {
        if (value != .object) return error.InvalidConfig;
        const object = value.object;
        const protocol = try LocalProtocol.parse(asString(object.get("protocol") orelse root.get("protocol")));
        const forward_host = if (protocol == .dns) try parseRemoteDnsHost(allocator, object, root) else try parseForwardHost(allocator, object, root);
        const forward_port = if (protocol == .dns) parseRemoteDnsPort(object, root) else parseForwardPort(object, root);
        if ((protocol == .tunnel or protocol == .dns) and (forward_host == null or forward_port == null)) {
            return error.MissingForwardAddress;
        }
        const local_dns_host = if (protocol == .dns) try parseLocalDnsHost(allocator, object, root) else null;
        return .{
            .host = try dupString(allocator, object.get("local_address") orelse root.get("local_address") orelse std.json.Value{ .string = "127.0.0.1" }),
            .port = @intCast(asU64(object.get("local_port") orelse root.get("local_port") orelse std.json.Value{ .integer = 1080 }) orelse 1080),
            .mode = parseLocalMode(protocol, asString(object.get("mode") orelse root.get("mode"))),
            .protocol = protocol,
            .tcp_redir = try RedirType.parse(asString(object.get("tcp_redir") orelse root.get("tcp_redir")), RedirType.tcpDefault()),
            .udp_redir = try RedirType.parse(asString(object.get("udp_redir") orelse root.get("udp_redir")), RedirType.udpDefault()),
            .forward_host = forward_host,
            .forward_port = forward_port,
            .local_dns_host = local_dns_host,
            .local_dns_port = if (local_dns_host != null) parseLocalDnsPort(object, root) else null,
            .fake_dns_ipv4_network = try dupOptionalNonEmptyString(allocator, object.get("fake_dns_ipv4_network") orelse root.get("fake_dns_ipv4_network")),
            .fake_dns_ipv6_network = try dupOptionalNonEmptyString(allocator, object.get("fake_dns_ipv6_network") orelse root.get("fake_dns_ipv6_network")),
            .fake_dns_database_path = try dupOptionalNonEmptyString(allocator, object.get("fake_dns_database_path") orelse root.get("fake_dns_database_path")),
            .fake_dns_record_expire_duration = asU64(object.get("fake_dns_record_expire_duration") orelse root.get("fake_dns_record_expire_duration")) orelse 10,
            .acl_path = try dupOptionalNonEmptyString(allocator, object.get("acl") orelse root.get("acl")),
            .socks5_users = try parseSocks5Users(
                allocator,
                io,
                object.get("socks5_auth") orelse root.get("socks5_auth"),
                asString(object.get("socks5_auth_config_path") orelse root.get("socks5_auth_config_path")),
            ),
        };
    }
};

fn parseLocalMode(protocol: LocalProtocol, value: ?[]const u8) Mode {
    if (value) |v| return Mode.parse(v);
    return switch (protocol) {
        .dns, .fake_dns => .tcp_and_udp,
        else => .tcp_only,
    };
}

fn parseForwardHost(allocator: std.mem.Allocator, object: std.json.ObjectMap, root: std.json.ObjectMap) ConfigError!?[]const u8 {
    if (object.get("forward_address") orelse root.get("forward_address")) |value| {
        return try dupOptionalNonEmptyString(allocator, value);
    }
    if (object.get("tunnel_address") orelse root.get("tunnel_address")) |value| {
        const raw = asString(value) orelse return error.InvalidConfig;
        const parsed = try parseHostPort(raw);
        return try allocator.dupe(u8, parsed.host);
    }
    return null;
}

fn parseRemoteDnsHost(allocator: std.mem.Allocator, object: std.json.ObjectMap, root: std.json.ObjectMap) ConfigError!?[]const u8 {
    if (object.get("remote_dns_address") orelse root.get("remote_dns_address")) |value| {
        return try dupOptionalNonEmptyString(allocator, value);
    }
    return try parseForwardHost(allocator, object, root);
}

fn parseLocalDnsHost(allocator: std.mem.Allocator, object: std.json.ObjectMap, root: std.json.ObjectMap) ConfigError!?[]const u8 {
    if (object.get("local_dns_address") orelse root.get("local_dns_address")) |value| {
        return try dupOptionalNonEmptyString(allocator, value);
    }
    return null;
}

fn parseForwardPort(object: std.json.ObjectMap, root: std.json.ObjectMap) ?u16 {
    if (asU64(object.get("forward_port") orelse root.get("forward_port"))) |port| {
        if (port == 0 or port > std.math.maxInt(u16)) return null;
        return @intCast(port);
    }
    if (object.get("tunnel_address") orelse root.get("tunnel_address")) |value| {
        const raw = asString(value) orelse return null;
        const parsed = parseHostPort(raw) catch return null;
        return parsed.port;
    }
    return null;
}

fn parseRemoteDnsPort(object: std.json.ObjectMap, root: std.json.ObjectMap) ?u16 {
    return parsePortWithDefault(object.get("remote_dns_port") orelse root.get("remote_dns_port"), 53);
}

fn parseLocalDnsPort(object: std.json.ObjectMap, root: std.json.ObjectMap) ?u16 {
    return parsePortWithDefault(object.get("local_dns_port") orelse root.get("local_dns_port"), 53);
}

fn parsePortWithDefault(value: ?std.json.Value, default: u16) ?u16 {
    const port = asU64(value) orelse return default;
    if (port == 0 or port > std.math.maxInt(u16)) return null;
    return @intCast(port);
}

fn parseManager(allocator: std.mem.Allocator, root: std.json.ObjectMap) ConfigError!?Manager {
    const address_value = root.get("manager_address") orelse return null;
    const address = asString(address_value) orelse return error.InvalidConfig;
    if (address.len == 0) return null;
    if (parseHostPort(address)) |_| {
        return try parseManagerAddress(allocator, address);
    } else |_| {
        const maybe_port = asU64(root.get("manager_port"));
        if (maybe_port == null) return try parseManagerAddress(allocator, address);
        const port: u16 = @intCast(maybe_port.?);
        return .{
            .transport = .ip,
            .address = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ address, port }),
            .host = try allocator.dupe(u8, address),
            .port = port,
            .path = "",
        };
    }
}

fn parseManagerAddress(allocator: std.mem.Allocator, address: []const u8) ConfigError!Manager {
    if (parseHostPort(address)) |parsed| {
        return .{
            .transport = .ip,
            .address = try allocator.dupe(u8, address),
            .host = try allocator.dupe(u8, parsed.host),
            .port = parsed.port,
            .path = "",
        };
    } else |_| {
        return .{
            .transport = .unix,
            .address = try allocator.dupe(u8, address),
            .host = "",
            .port = 0,
            .path = try allocator.dupe(u8, address),
        };
    }
}

const HostPort = struct {
    host: []const u8,
    port: u16,
};

fn parseHostPort(address: []const u8) ConfigError!HostPort {
    const colon = std.mem.lastIndexOfScalar(u8, address, ':') orelse return error.MissingManagerPort;
    if (colon == 0 or colon + 1 >= address.len) return error.InvalidConfig;
    const host = address[0..colon];
    const port_text = address[colon + 1 ..];
    const port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidConfig;
    return .{ .host = host, .port = port };
}

fn asString(value: ?std.json.Value) ?[]const u8 {
    const v = value orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn dupString(allocator: std.mem.Allocator, value: std.json.Value) ConfigError![]const u8 {
    const s = asString(value) orelse return error.InvalidConfig;
    return try allocator.dupe(u8, s);
}

fn dupOptionalNonEmptyString(allocator: std.mem.Allocator, value: ?std.json.Value) ConfigError!?[]const u8 {
    const s = asString(value) orelse return null;
    if (s.len == 0) return null;
    return try allocator.dupe(u8, s);
}

fn dupeOptionalSlice(allocator: std.mem.Allocator, value: ?[]const u8) ConfigError!?[]const u8 {
    const s = value orelse return null;
    if (s.len == 0) return null;
    return try allocator.dupe(u8, s);
}

fn parseStringArray(allocator: std.mem.Allocator, value: ?std.json.Value) ConfigError![]const []const u8 {
    const v = value orelse return &.{};
    if (v != .array) return error.InvalidConfig;
    var items = std.ArrayList([]const u8).empty;
    for (v.array.items) |item| {
        const string = try dupString(allocator, item);
        try items.append(allocator, string);
    }
    return try items.toOwnedSlice(allocator);
}

fn asU64(value: ?std.json.Value) ?u64 {
    const v = value orelse return null;
    return switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else null,
        .float => |f| if (f >= 0) @intFromFloat(f) else null,
        else => null,
    };
}

fn asF64(value: ?std.json.Value) ?f64 {
    const v = value orelse return null;
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => null,
    };
}

fn parseWeight(value: ?std.json.Value) ConfigError!u16 {
    const raw = asF64(value) orelse return server_weight_scale;
    if (raw < 0 or raw > 1) return error.InvalidWeight;
    if (raw == 0) return 0;
    const scaled = @ceil(raw * @as(f64, @floatFromInt(server_weight_scale)));
    return @intFromFloat(scaled);
}

fn asUsize(value: ?std.json.Value) ?usize {
    const n = asU64(value) orelse return null;
    return std.math.cast(usize, n) orelse null;
}

fn parseSocks5Users(allocator: std.mem.Allocator, io: ?std.Io, inline_value: ?std.json.Value, path: ?[]const u8) ConfigError![]const Socks5User {
    if (inline_value) |value| return try parseSocks5UsersValue(allocator, value);
    if (path) |p| {
        const active_io = io orelse return error.IoRequiredForAuthConfigPath;
        const bytes = try std.Io.Dir.cwd().readFileAlloc(active_io, p, allocator, .limited(1024 * 1024));
        defer allocator.free(bytes);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer parsed.deinit();
        return try parseSocks5UsersValue(allocator, parsed.value);
    }
    return &.{};
}

fn parseSocks5UsersValue(allocator: std.mem.Allocator, value: std.json.Value) ConfigError![]const Socks5User {
    if (value != .object) return error.InvalidConfig;
    const password_config = value.object.get("password") orelse return &.{};
    if (password_config != .object) return error.InvalidConfig;
    const users_value = password_config.object.get("users") orelse return &.{};
    if (users_value != .array) return error.InvalidConfig;

    var users = std.ArrayList(Socks5User).empty;
    for (users_value.array.items) |item| {
        if (item != .object) return error.InvalidConfig;
        try users.append(allocator, .{
            .user_name = try dupString(allocator, item.object.get("user_name") orelse return error.InvalidConfig),
            .password = try dupString(allocator, item.object.get("password") orelse return error.InvalidConfig),
        });
    }
    return try users.toOwnedSlice(allocator);
}

test "parse classic shadowsocks config" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "local_address": "127.0.0.1",
        \\  "local_port": 1080,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "mode": "tcp_and_udp",
        \\  "plugin": "v2ray-plugin",
        \\  "plugin_opts": "server;tls;host=example.com",
        \\  "plugin_args": ["--verbose", "--fast-open"],
        \\  "plugin_mode": "tcp_only",
        \\  "acl": "tests/local.acl",
        \\  "manager_address": "127.0.0.1:6001",
        \\  "udp_timeout": 10,
        \\  "udp_max_associations": 32
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(@as(usize, 1), cfg.servers.len);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.servers[0].host);
    try std.testing.expectEqual(@as(u16, 8388), cfg.servers[0].port);
    try std.testing.expectEqual(crypto.CipherKind.aes_256_gcm, cfg.servers[0].method);
    try std.testing.expect(cfg.servers[0].mode.enableUdp());
    try std.testing.expectEqual(server_weight_scale, cfg.servers[0].tcp_weight);
    try std.testing.expectEqual(server_weight_scale, cfg.servers[0].udp_weight);
    try std.testing.expectEqualStrings("v2ray-plugin", cfg.servers[0].plugin.?);
    try std.testing.expectEqualStrings("server;tls;host=example.com", cfg.servers[0].plugin_opts.?);
    try std.testing.expectEqual(@as(usize, 2), cfg.servers[0].plugin_args.len);
    try std.testing.expectEqualStrings("--verbose", cfg.servers[0].plugin_args[0]);
    try std.testing.expectEqualStrings("--fast-open", cfg.servers[0].plugin_args[1]);
    try std.testing.expectEqual(Mode.tcp_only, cfg.servers[0].plugin_mode);
    try std.testing.expectEqualStrings("tests/local.acl", cfg.servers[0].acl_path.?);
    try std.testing.expectEqualStrings("tests/local.acl", cfg.locals[0].acl_path.?);
    try std.testing.expectEqual(@as(u16, 1080), cfg.locals[0].port);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.locals[0].mode);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.manager.?.host);
    try std.testing.expectEqual(@as(u16, 6001), cfg.manager.?.port);
    try std.testing.expectEqual(ManagerTransport.ip, cfg.manager.?.transport);
    try std.testing.expectEqual(@as(u64, 10), cfg.udp_timeout_seconds);
    try std.testing.expectEqual(@as(?usize, 32), cfg.udp_max_associations);
}

test "build config from libev-style CLI overrides" {
    var cfg = try Config.fromOverrides(std.testing.allocator, .{
        .server_host = "198.51.100.10",
        .server_port = 8388,
        .local_host = "127.0.0.2",
        .local_port = 1081,
        .password = "secret",
        .method = .aes_128_gcm,
        .mode = .tcp_and_udp,
        .plugin = "fake-plugin",
        .plugin_opts = "obfs=tls",
    });
    defer cfg.deinit();

    try std.testing.expectEqualStrings("198.51.100.10", cfg.servers[0].host);
    try std.testing.expectEqual(@as(u16, 8388), cfg.servers[0].port);
    try std.testing.expectEqualStrings("127.0.0.2", cfg.locals[0].host);
    try std.testing.expectEqual(@as(u16, 1081), cfg.locals[0].port);
    try std.testing.expectEqual(crypto.CipherKind.aes_128_gcm, cfg.servers[0].method);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.servers[0].mode);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.locals[0].mode);
    try std.testing.expectEqualStrings("fake-plugin", cfg.servers[0].plugin.?);
    try std.testing.expectEqualStrings("obfs=tls", cfg.servers[0].plugin_opts.?);
}

test "apply CLI overrides to parsed config" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "local_address": "127.0.0.1",
        \\  "local_port": 1080,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm"
        \\}
    );
    defer cfg.deinit();

    try cfg.applyOverrides(.{
        .server_host = "203.0.113.7",
        .server_port = 8443,
        .local_port = 1090,
        .password = "override",
        .method = .xchacha20_ietf_poly1305,
        .mode = .udp_only,
        .protocol = .redir,
        .tcp_redir = .tproxy,
    });

    try std.testing.expectEqualStrings("203.0.113.7", cfg.servers[0].host);
    try std.testing.expectEqual(@as(u16, 8443), cfg.servers[0].port);
    try std.testing.expectEqualStrings("override", cfg.servers[0].password);
    try std.testing.expectEqual(crypto.CipherKind.xchacha20_ietf_poly1305, cfg.servers[0].method);
    try std.testing.expectEqual(Mode.udp_only, cfg.servers[0].mode);
    try std.testing.expectEqual(@as(u16, 1090), cfg.locals[0].port);
    try std.testing.expectEqual(LocalProtocol.redir, cfg.locals[0].protocol);
    try std.testing.expectEqual(RedirType.tproxy, cfg.locals[0].tcp_redir);
}

test "reject non-aead legacy cipher methods" {
    try std.testing.expectError(error.InvalidCipher, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-cfb"
        \\}
    ));

    try std.testing.expectError(error.InvalidCipher, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "rc4-md5"
        \\}
    ));
}

test "parse unix manager address" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "manager_address": "/tmp/ss-zig-manager.sock"
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(ManagerTransport.unix, cfg.manager.?.transport);
    try std.testing.expectEqualStrings("/tmp/ss-zig-manager.sock", cfg.manager.?.path);
    try std.testing.expectEqual(@as(u16, 0), cfg.manager.?.port);
}

test "parse shadowsocks-rust extended servers/locals config" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "servers": [
        \\    {"server": "one.example", "server_port": 8388, "password": "one", "method": "aes-128-gcm", "tcp_weight": 0.25, "udp_weight": 0},
        \\    {"server": "two.example", "server_port": 8389, "password": "two", "method": "chacha20-ietf-poly1305", "tcp_weight": 1.0, "udp_weight": 0.5}
        \\  ],
        \\  "locals": [
        \\    {
        \\      "local_address": "127.0.0.1",
        \\      "local_port": 1081,
        \\      "protocol": "socks",
        \\      "socks5_auth": {
        \\        "password": {
        \\          "users": [
        \\            {"user_name": "alice", "password": "wonderland"}
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(@as(usize, 2), cfg.servers.len);
    try std.testing.expectEqualStrings("two.example", cfg.servers[1].host);
    try std.testing.expectEqual(crypto.CipherKind.chacha20_ietf_poly1305, cfg.servers[1].method);
    try std.testing.expectEqual(@as(u16, 25), cfg.servers[0].tcp_weight);
    try std.testing.expectEqual(@as(u16, 0), cfg.servers[0].udp_weight);
    try std.testing.expectEqual(@as(u16, 100), cfg.servers[1].tcp_weight);
    try std.testing.expectEqual(@as(u16, 50), cfg.servers[1].udp_weight);
    try std.testing.expectEqual(@as(usize, 1), cfg.locals[0].socks5_users.len);
    try std.testing.expectEqual(LocalProtocol.socks, cfg.locals[0].protocol);
    try std.testing.expectEqualStrings("alice", cfg.locals[0].socks5_users[0].user_name);
}

test "parse tunnel local forward address" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "locals": [
        \\    {
        \\      "protocol": "tunnel",
        \\      "local_address": "127.0.0.1",
        \\      "local_port": 5353,
        \\      "forward_address": "8.8.8.8",
        \\      "forward_port": 53,
        \\      "mode": "tcp_and_udp"
        \\    }
        \\  ]
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(LocalProtocol.tunnel, cfg.locals[0].protocol);
    try std.testing.expectEqualStrings("8.8.8.8", cfg.locals[0].forward_host.?);
    try std.testing.expectEqual(@as(?u16, 53), cfg.locals[0].forward_port);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.locals[0].mode);
}

test "parse dns local remote dns defaults" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "locals": [
        \\    {
        \\      "protocol": "dns",
        \\      "local_address": "127.0.0.1",
        \\      "local_port": 1053,
        \\      "local_dns_address": "114.114.114.114",
        \\      "remote_dns_address": "8.8.8.8"
        \\    }
        \\  ]
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(LocalProtocol.dns, cfg.locals[0].protocol);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.locals[0].mode);
    try std.testing.expectEqualStrings("8.8.8.8", cfg.locals[0].forward_host.?);
    try std.testing.expectEqual(@as(?u16, 53), cfg.locals[0].forward_port);
    try std.testing.expectEqualStrings("114.114.114.114", cfg.locals[0].local_dns_host.?);
    try std.testing.expectEqual(@as(?u16, 53), cfg.locals[0].local_dns_port);
}

test "parse fake-dns local defaults" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "locals": [
        \\    {
        \\      "protocol": "fake-dns",
        \\      "local_address": "127.0.0.1",
        \\      "local_port": 10053,
        \\      "fake_dns_ipv4_network": "10.255.0.0/16",
        \\      "fake_dns_ipv6_network": "fc00::/7",
        \\      "fake_dns_database_path": "/tmp/fakedns.db",
        \\      "fake_dns_record_expire_duration": 30
        \\    }
        \\  ]
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(LocalProtocol.fake_dns, cfg.locals[0].protocol);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.locals[0].mode);
    try std.testing.expectEqualStrings("10.255.0.0/16", cfg.locals[0].fake_dns_ipv4_network.?);
    try std.testing.expectEqualStrings("fc00::/7", cfg.locals[0].fake_dns_ipv6_network.?);
    try std.testing.expectEqualStrings("/tmp/fakedns.db", cfg.locals[0].fake_dns_database_path.?);
    try std.testing.expectEqual(@as(u64, 30), cfg.locals[0].fake_dns_record_expire_duration);
}

test "parse redir local defaults and explicit transparent proxy types" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "locals": [
        \\    {
        \\      "protocol": "redir",
        \\      "local_address": "127.0.0.1",
        \\      "local_port": 1082,
        \\      "mode": "tcp_and_udp",
        \\      "tcp_redir": "redirect",
        \\      "udp_redir": "tproxy"
        \\    }
        \\  ]
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(LocalProtocol.redir, cfg.locals[0].protocol);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.locals[0].mode);
    try std.testing.expectEqual(RedirType.redirect, cfg.locals[0].tcp_redir);
    try std.testing.expectEqual(RedirType.tproxy, cfg.locals[0].udp_redir);
}

test "parse rejects unknown local protocol" {
    try std.testing.expectError(error.InvalidProtocol, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "protocol": "mixed"
        \\}
    ));
}

test "parse rejects invalid redir type" {
    try std.testing.expectError(error.InvalidRedirType, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "protocol": "redir",
        \\  "tcp_redir": "iptables"
        \\}
    ));
}

test "parse rejects tun local protocol" {
    try std.testing.expectError(error.InvalidProtocol, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "protocol": "tun"
        \\}
    ));
}

test "parse rejects invalid server weights" {
    try std.testing.expectError(error.InvalidWeight, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "tcp_weight": 1.1
        \\}
    ));

    try std.testing.expectError(error.InvalidWeight, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "udp_weight": -0.1
        \\}
    ));
}
