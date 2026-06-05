const std = @import("std");
const crypto = @import("crypto.zig");

pub const ConfigError = anyerror;
pub const server_weight_scale: u16 = 100;

pub const Mode = enum {
    tcp_only,
    tcp_and_udp,
    udp_only,

    pub fn parse(value: ?[]const u8) ConfigError!Mode {
        const v = value orelse return .tcp_only;
        if (std.ascii.eqlIgnoreCase(v, "tcp_only")) return .tcp_only;
        if (std.ascii.eqlIgnoreCase(v, "tcp_and_udp")) return .tcp_and_udp;
        if (std.ascii.eqlIgnoreCase(v, "udp_only")) return .udp_only;
        return error.InvalidMode;
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

pub const TcpBufferConfig = struct {
    incoming_sndbuf: ?u32 = null,
    incoming_rcvbuf: ?u32 = null,
    outgoing_sndbuf: ?u32 = null,
    outgoing_rcvbuf: ?u32 = null,

    pub fn hasAny(self: TcpBufferConfig) bool {
        return self.incoming_sndbuf != null or
            self.incoming_rcvbuf != null or
            self.outgoing_sndbuf != null or
            self.outgoing_rcvbuf != null;
    }

    pub fn merge(self: *TcpBufferConfig, other: TcpBufferConfig) void {
        if (other.incoming_sndbuf) |value| self.incoming_sndbuf = value;
        if (other.incoming_rcvbuf) |value| self.incoming_rcvbuf = value;
        if (other.outgoing_sndbuf) |value| self.outgoing_sndbuf = value;
        if (other.outgoing_rcvbuf) |value| self.outgoing_rcvbuf = value;
    }
};

pub const OutboundBindConfig = struct {
    ipv4: ?[]const u8 = null,
    ipv6: ?[]const u8 = null,

    pub fn hasAny(self: OutboundBindConfig) bool {
        return self.ipv4 != null or self.ipv6 != null;
    }

    pub fn merge(self: *OutboundBindConfig, other: OutboundBindConfig) void {
        if (other.ipv4) |value| self.ipv4 = value;
        if (other.ipv6) |value| self.ipv6 = value;
    }
};

pub const Server = struct {
    host: []const u8,
    port: u16,
    password: []const u8,
    key: ?[]const u8,
    method: crypto.CipherKind,
    mode: Mode,
    no_delay: bool,
    reuse_port: bool,
    ipv6_first: bool,
    tcp_buffers: TcpBufferConfig,
    outbound_bind: OutboundBindConfig,
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
    udp_host: ?[]const u8,
    udp_port: ?u16,
    mode: Mode,
    protocol: LocalProtocol,
    tcp_redir: RedirType,
    udp_redir: RedirType,
    no_delay: bool,
    reuse_port: bool,
    ipv6_first: bool,
    tcp_buffers: TcpBufferConfig,
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

    pub fn udpBindHost(self: Local) []const u8 {
        if (self.udp_port != null) return self.udp_host orelse self.host;
        return self.host;
    }

    pub fn udpBindPort(self: Local) u16 {
        return self.udp_port orelse self.port;
    }
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
    key: ?[]const u8 = null,
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
    no_delay: ?bool = null,
    reuse_port: ?bool = null,
    ipv6_first: ?bool = null,
    nofile: ?u64 = null,
    tcp_buffers: TcpBufferConfig = .{},
    outbound_bind: OutboundBindConfig = .{},

    pub fn hasAny(self: Overrides) bool {
        return self.server_host != null or
            self.server_port != null or
            self.local_host != null or
            self.local_port != null or
            self.password != null or
            self.key != null or
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
            self.plugin_opts != null or
            self.no_delay != null or
            self.reuse_port != null or
            self.ipv6_first != null or
            self.nofile != null or
            self.tcp_buffers.hasAny() or
            self.outbound_bind.hasAny();
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
    nofile: ?u64,

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
        const mode = overrides.mode orelse try parseLocalMode(protocol, null);
        const timeout = overrides.timeout_seconds orelse 300;
        const server_host = overrides.server_host orelse return error.MissingServer;
        const server_port = overrides.server_port orelse return error.MissingServerPort;
        const password = overrides.password;
        const key = overrides.key;
        if (password == null and key == null) return error.MissingPassword;
        const forward_host = overrides.forward_host;
        const forward_port = overrides.forward_port;
        if ((protocol == .tunnel or protocol == .dns) and (forward_host == null or forward_port == null)) {
            return error.MissingForwardAddress;
        }

        const servers = try a.alloc(Server, 1);
        servers[0] = .{
            .host = try a.dupe(u8, server_host),
            .port = server_port,
            .password = try a.dupe(u8, password orelse ""),
            .key = try dupeOptionalSlice(a, key),
            .method = overrides.method orelse .aes_256_gcm,
            .mode = mode,
            .no_delay = overrides.no_delay orelse false,
            .reuse_port = overrides.reuse_port orelse false,
            .ipv6_first = overrides.ipv6_first orelse false,
            .tcp_buffers = overrides.tcp_buffers,
            .outbound_bind = try dupeOutboundBind(a, overrides.outbound_bind),
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
            .udp_host = null,
            .udp_port = null,
            .mode = mode,
            .protocol = protocol,
            .tcp_redir = overrides.tcp_redir orelse RedirType.tcpDefault(),
            .udp_redir = overrides.udp_redir orelse RedirType.udpDefault(),
            .no_delay = overrides.no_delay orelse false,
            .reuse_port = overrides.reuse_port orelse false,
            .ipv6_first = overrides.ipv6_first orelse false,
            .tcp_buffers = overrides.tcp_buffers,
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
            .nofile = overrides.nofile,
        };
    }

    pub fn applyOverrides(self: *Config, overrides: Overrides) ConfigError!void {
        if (!overrides.hasAny()) return;
        const a = self.arena.allocator();
        for (self.servers) |*server| {
            if (overrides.server_host) |host| server.host = try a.dupe(u8, host);
            if (overrides.server_port) |port| server.port = port;
            if (overrides.password) |password| server.password = try a.dupe(u8, password);
            if (overrides.password != null and overrides.key == null) server.key = null;
            if (overrides.key) |key| server.key = try a.dupe(u8, key);
            if (overrides.method) |method| server.method = method;
            if (overrides.mode) |mode| server.mode = mode;
            if (overrides.acl_path) |acl_path| server.acl_path = try a.dupe(u8, acl_path);
            if (overrides.plugin) |plugin| server.plugin = try a.dupe(u8, plugin);
            if (overrides.plugin_opts) |plugin_opts| server.plugin_opts = try a.dupe(u8, plugin_opts);
            if (overrides.mode) |mode| server.plugin_mode = mode;
            if (overrides.no_delay) |no_delay| server.no_delay = no_delay;
            if (overrides.reuse_port) |reuse_port| server.reuse_port = reuse_port;
            if (overrides.ipv6_first) |ipv6_first| server.ipv6_first = ipv6_first;
            server.tcp_buffers.merge(overrides.tcp_buffers);
            server.outbound_bind.merge(try dupeOutboundBind(a, overrides.outbound_bind));
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
            if (overrides.no_delay) |no_delay| local.no_delay = no_delay;
            if (overrides.reuse_port) |reuse_port| local.reuse_port = reuse_port;
            if (overrides.ipv6_first) |ipv6_first| local.ipv6_first = ipv6_first;
            local.tcp_buffers.merge(overrides.tcp_buffers);
            if ((local.protocol == .tunnel or local.protocol == .dns) and (local.forward_host == null or local.forward_port == null)) {
                return error.MissingForwardAddress;
            }
        }
        if (overrides.timeout_seconds) |timeout| {
            self.timeout_seconds = timeout;
            self.udp_timeout_seconds = timeout;
        }
        if (overrides.nofile) |nofile| self.nofile = nofile;
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
            for (svrs.array.items) |item| {
                if (try disabledConfigEntry(item)) continue;
                try servers.append(a, try parseServer(a, item, root));
            }
        } else if (root.get("shadowsocks")) |svrs| {
            if (svrs != .array) return error.InvalidConfig;
            for (svrs.array.items) |item| {
                if (try disabledConfigEntry(item)) continue;
                try servers.append(a, try parseServer(a, item, root));
            }
        } else if (root.get("port_password")) |_| {
            try appendPortPasswordServers(a, &servers, root);
        } else if (root.get("server")) |server_value| {
            if (server_value == .array) {
                try appendClassicServerArray(a, &servers, server_value, root);
            } else {
                try servers.append(a, try parseServer(a, value, root));
            }
        } else {
            try servers.append(a, try parseServer(a, value, root));
        }
        if (servers.items.len == 0) return error.MissingServer;

        var locals = std.ArrayList(Local).empty;
        if (root.get("locals")) |items| {
            if (items != .array) return error.InvalidConfig;
            for (items.array.items) |item| {
                if (try disabledConfigEntry(item)) continue;
                try locals.append(a, try parseLocal(a, io, item, root));
            }
        } else {
            try locals.append(a, try parseLocal(a, io, value, root));
        }
        if (locals.items.len == 0) return error.MissingLocal;

        return .{
            .allocator = allocator,
            .arena = arena,
            .servers = try servers.toOwnedSlice(a),
            .locals = try locals.toOwnedSlice(a),
            .manager = try parseManager(a, root),
            .timeout_seconds = asU64(root.get("timeout")) orelse 300,
            .udp_timeout_seconds = asU64(root.get("udp_timeout")) orelse 300,
            .udp_max_associations = asUsize(root.get("udp_max_associations")),
            .nofile = try parseNofile(root.get("nofile")),
        };
    }

    fn parseServer(allocator: std.mem.Allocator, value: std.json.Value, root: std.json.ObjectMap) ConfigError!Server {
        if (value != .object) return error.InvalidConfig;
        const object = value.object;
        const default_port = parseRequiredPort(object.get("server_port") orelse root.get("server_port")) orelse return error.MissingServerPort;
        const address = try parseServerAddress(asString(object.get("server") orelse root.get("server")) orelse return error.MissingServer, default_port);
        const password = asString(object.get("password") orelse root.get("password"));
        const key = asString(object.get("key") orelse root.get("key"));
        if (password == null and key == null) return error.MissingPassword;
        return try parseServerResolved(allocator, object, root, address.host, address.port, password orelse "", key);
    }

    fn parseServerResolved(
        allocator: std.mem.Allocator,
        object: std.json.ObjectMap,
        root: std.json.ObjectMap,
        host: []const u8,
        port: u16,
        password: []const u8,
        key: ?[]const u8,
    ) ConfigError!Server {
        const method_name = asString(object.get("method") orelse root.get("method")) orelse "aes-256-gcm";
        const method = crypto.CipherKind.parse(method_name) catch return error.InvalidCipher;
        const mode = try Mode.parse(asString(object.get("mode") orelse root.get("mode")));
        return .{
            .host = try allocator.dupe(u8, host),
            .port = port,
            .password = try allocator.dupe(u8, password),
            .key = try dupeOptionalSlice(allocator, key),
            .method = method,
            .mode = mode,
            .no_delay = asBool(object.get("no_delay") orelse root.get("no_delay")) orelse false,
            .reuse_port = asBool(object.get("reuse_port") orelse root.get("reuse_port")) orelse false,
            .ipv6_first = asBool(object.get("ipv6_first") orelse root.get("ipv6_first")) orelse false,
            .tcp_buffers = try parseTcpBufferConfig(object, root),
            .outbound_bind = try parseOutboundBindConfig(allocator, object, root),
            .tcp_weight = try parseWeight(object.get("tcp_weight") orelse root.get("tcp_weight")),
            .udp_weight = try parseWeight(object.get("udp_weight") orelse root.get("udp_weight")),
            .acl_path = try dupOptionalNonEmptyString(allocator, object.get("acl") orelse root.get("acl")),
            .plugin = try dupOptionalNonEmptyString(allocator, object.get("plugin") orelse root.get("plugin")),
            .plugin_opts = try dupOptionalNonEmptyString(allocator, object.get("plugin_opts") orelse root.get("plugin_opts")),
            .plugin_args = try parseStringArray(allocator, object.get("plugin_args") orelse root.get("plugin_args")),
            .plugin_mode = try Mode.parse(asString(object.get("plugin_mode") orelse root.get("plugin_mode"))),
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
        const local_udp_port = try parseOptionalPort(object.get("local_udp_port") orelse root.get("local_udp_port"));
        return .{
            .host = try dupString(allocator, object.get("local_address") orelse root.get("local_address") orelse std.json.Value{ .string = "127.0.0.1" }),
            .port = @intCast(asU64(object.get("local_port") orelse root.get("local_port") orelse std.json.Value{ .integer = 1080 }) orelse 1080),
            .udp_host = if (local_udp_port != null) try dupOptionalNonEmptyString(allocator, object.get("local_udp_address") orelse root.get("local_udp_address")) else null,
            .udp_port = local_udp_port,
            .mode = try parseLocalMode(protocol, asString(object.get("mode") orelse root.get("mode"))),
            .protocol = protocol,
            .tcp_redir = try RedirType.parse(asString(object.get("tcp_redir") orelse root.get("tcp_redir")), RedirType.tcpDefault()),
            .udp_redir = try RedirType.parse(asString(object.get("udp_redir") orelse root.get("udp_redir")), RedirType.udpDefault()),
            .no_delay = asBool(object.get("no_delay") orelse root.get("no_delay")) orelse false,
            .reuse_port = asBool(object.get("reuse_port") orelse root.get("reuse_port")) orelse false,
            .ipv6_first = asBool(object.get("ipv6_first") orelse root.get("ipv6_first")) orelse false,
            .tcp_buffers = try parseTcpBufferConfig(object, root),
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

fn parseLocalMode(protocol: LocalProtocol, value: ?[]const u8) ConfigError!Mode {
    if (value) |v| return try Mode.parse(v);
    return switch (protocol) {
        .dns, .fake_dns => .tcp_and_udp,
        else => .tcp_only,
    };
}

fn disabledConfigEntry(value: std.json.Value) ConfigError!bool {
    if (value != .object) return false;
    const disabled = value.object.get("disabled") orelse return false;
    return asBool(disabled) orelse return error.InvalidConfig;
}

fn appendClassicServerArray(
    allocator: std.mem.Allocator,
    servers: *std.ArrayList(Server),
    server_value: std.json.Value,
    root: std.json.ObjectMap,
) ConfigError!void {
    if (server_value != .array) return error.InvalidConfig;
    const default_port = parseRequiredPort(root.get("server_port")) orelse return error.MissingServerPort;
    const password = asString(root.get("password"));
    const key = asString(root.get("key"));
    if (password == null and key == null) return error.MissingPassword;
    for (server_value.array.items) |item| {
        const address = try parseServerAddress(asString(item) orelse return error.InvalidConfig, default_port);
        try servers.append(allocator, try Config.parseServerResolved(allocator, root, root, address.host, address.port, password orelse "", key));
    }
}

fn appendPortPasswordServers(
    allocator: std.mem.Allocator,
    servers: *std.ArrayList(Server),
    root: std.json.ObjectMap,
) ConfigError!void {
    const port_password = root.get("port_password") orelse return error.InvalidConfig;
    if (port_password != .object) return error.InvalidConfig;

    const host = try firstClassicServerHost(root);
    var iterator = port_password.object.iterator();
    while (iterator.next()) |entry| {
        const port = try parsePortText(entry.key_ptr.*);
        const password = asString(entry.value_ptr.*) orelse return error.InvalidConfig;
        try servers.append(allocator, try Config.parseServerResolved(allocator, root, root, host, port, password, null));
    }
}

fn firstClassicServerHost(root: std.json.ObjectMap) ConfigError![]const u8 {
    const server_value = root.get("server") orelse return "0.0.0.0";
    if (server_value == .array) {
        if (server_value.array.items.len == 0) return "0.0.0.0";
        const address = try parseServerAddress(asString(server_value.array.items[0]) orelse return error.InvalidConfig, 1);
        return address.host;
    }
    const address = try parseServerAddress(asString(server_value) orelse return error.InvalidConfig, 1);
    return address.host;
}

fn parseRequiredPort(value: ?std.json.Value) ?u16 {
    const raw = asU64(value) orelse return null;
    if (raw == 0 or raw > std.math.maxInt(u16)) return null;
    return @intCast(raw);
}

fn parsePortText(text: []const u8) ConfigError!u16 {
    if (text.len == 0) return error.InvalidConfig;
    const port = std.fmt.parseInt(u16, text, 10) catch return error.InvalidConfig;
    if (port == 0) return error.InvalidConfig;
    return port;
}

fn parseServerAddress(address: []const u8, default_port: u16) ConfigError!HostPort {
    if (address.len == 0) return error.InvalidConfig;
    if (address[0] == '[') {
        const close = std.mem.indexOfScalar(u8, address, ']') orelse return error.InvalidConfig;
        if (close <= 1) return error.InvalidConfig;
        if (close + 1 == address.len) return .{ .host = address[1..close], .port = default_port };
        if (address[close + 1] != ':') return error.InvalidConfig;
        return .{ .host = address[1..close], .port = try parsePortText(address[close + 2 ..]) };
    }

    var colon_count: usize = 0;
    for (address) |byte| {
        if (byte == ':') colon_count += 1;
    }
    if (colon_count == 1) {
        const colon = std.mem.indexOfScalar(u8, address, ':').?;
        if (colon == 0) return error.InvalidConfig;
        if (colon + 1 == address.len) return .{ .host = address[0..colon], .port = default_port };
        return .{ .host = address[0..colon], .port = try parsePortText(address[colon + 1 ..]) };
    }

    return .{ .host = address, .port = default_port };
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

fn parseOptionalPort(value: ?std.json.Value) ConfigError!?u16 {
    if (value == null) return null;
    const port = asU64(value) orelse return error.InvalidConfig;
    if (port == 0 or port > std.math.maxInt(u16)) return error.InvalidConfig;
    return @intCast(port);
}

fn parseNofile(value: ?std.json.Value) ConfigError!?u64 {
    if (value == null) return null;
    const nofile = asU64(value) orelse return error.InvalidConfig;
    if (nofile == 0) return error.InvalidConfig;
    return nofile;
}

fn parseTcpBufferConfig(object: std.json.ObjectMap, root: std.json.ObjectMap) ConfigError!TcpBufferConfig {
    return .{
        .incoming_sndbuf = try parseTcpBufferSize(object.get("tcp_incoming_sndbuf") orelse root.get("tcp_incoming_sndbuf")),
        .incoming_rcvbuf = try parseTcpBufferSize(object.get("tcp_incoming_rcvbuf") orelse root.get("tcp_incoming_rcvbuf")),
        .outgoing_sndbuf = try parseTcpBufferSize(object.get("tcp_outgoing_sndbuf") orelse root.get("tcp_outgoing_sndbuf")),
        .outgoing_rcvbuf = try parseTcpBufferSize(object.get("tcp_outgoing_rcvbuf") orelse root.get("tcp_outgoing_rcvbuf")),
    };
}

fn parseTcpBufferSize(value: ?std.json.Value) ConfigError!?u32 {
    if (value == null) return null;
    const raw = asU64(value) orelse return error.InvalidConfig;
    if (raw == 0 or raw > std.math.maxInt(c_int)) return error.InvalidConfig;
    return @intCast(raw);
}

fn parseOutboundBindConfig(allocator: std.mem.Allocator, object: std.json.ObjectMap, root: std.json.ObjectMap) ConfigError!OutboundBindConfig {
    var bind = OutboundBindConfig{};
    if (asString(object.get("local_address") orelse root.get("local_address"))) |host| {
        try assignOutboundBindHost(allocator, &bind, host);
    }
    if (asString(object.get("local_ipv4_address") orelse root.get("local_ipv4_address"))) |host| {
        try assignOutboundBindHost(allocator, &bind, host);
    }
    if (asString(object.get("local_ipv6_address") orelse root.get("local_ipv6_address"))) |host| {
        try assignOutboundBindHost(allocator, &bind, host);
    }
    return bind;
}

fn assignOutboundBindHost(allocator: std.mem.Allocator, bind: *OutboundBindConfig, host: []const u8) ConfigError!void {
    if (host.len == 0) return;
    if (std.Io.net.IpAddress.parse(host, 0)) |address| {
        switch (address) {
            .ip4 => bind.ipv4 = try allocator.dupe(u8, host),
            .ip6 => bind.ipv6 = try allocator.dupe(u8, host),
        }
    } else |_| return error.InvalidOutboundBind;
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

fn asBool(value: ?std.json.Value) ?bool {
    const v = value orelse return null;
    return switch (v) {
        .bool => |b| b,
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

fn dupeOutboundBind(allocator: std.mem.Allocator, value: OutboundBindConfig) ConfigError!OutboundBindConfig {
    return .{
        .ipv4 = try dupeOptionalSlice(allocator, value.ipv4),
        .ipv6 = try dupeOptionalSlice(allocator, value.ipv6),
    };
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
        .string => |s| std.fmt.parseInt(u64, s, 10) catch null,
        else => null,
    };
}

fn asF64(value: ?std.json.Value) ?f64 {
    const v = value orelse return null;
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .string => |s| std.fmt.parseFloat(f64, s) catch null,
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
        \\  "local_ipv6_address": "::1",
        \\  "local_port": 1080,
        \\  "local_udp_address": "127.0.0.2",
        \\  "local_udp_port": 1081,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "mode": "tcp_and_udp",
        \\  "plugin": "v2ray-plugin",
        \\  "plugin_opts": "server;tls;host=example.com",
        \\  "plugin_args": ["--verbose", "--fast-open"],
        \\  "plugin_mode": "tcp_only",
        \\  "acl": "tests/local.acl",
        \\  "manager_address": "127.0.0.1:6001",
        \\  "no_delay": true,
        \\  "reuse_port": true,
        \\  "ipv6_first": true,
        \\  "tcp_incoming_sndbuf": 32768,
        \\  "tcp_incoming_rcvbuf": "32769",
        \\  "tcp_outgoing_sndbuf": 32770,
        \\  "tcp_outgoing_rcvbuf": "32771",
        \\  "udp_timeout": 10,
        \\  "udp_max_associations": 32,
        \\  "nofile": 4096
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
    try std.testing.expectEqualStrings("127.0.0.2", cfg.locals[0].udp_host.?);
    try std.testing.expectEqual(@as(?u16, 1081), cfg.locals[0].udp_port);
    try std.testing.expectEqualStrings("127.0.0.2", cfg.locals[0].udpBindHost());
    try std.testing.expectEqual(@as(u16, 1081), cfg.locals[0].udpBindPort());
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.locals[0].mode);
    try std.testing.expect(cfg.servers[0].no_delay);
    try std.testing.expect(cfg.locals[0].no_delay);
    try std.testing.expect(cfg.servers[0].reuse_port);
    try std.testing.expect(cfg.locals[0].reuse_port);
    try std.testing.expect(cfg.servers[0].ipv6_first);
    try std.testing.expect(cfg.locals[0].ipv6_first);
    try std.testing.expectEqual(@as(?u32, 32768), cfg.servers[0].tcp_buffers.incoming_sndbuf);
    try std.testing.expectEqual(@as(?u32, 32769), cfg.servers[0].tcp_buffers.incoming_rcvbuf);
    try std.testing.expectEqual(@as(?u32, 32770), cfg.servers[0].tcp_buffers.outgoing_sndbuf);
    try std.testing.expectEqual(@as(?u32, 32771), cfg.servers[0].tcp_buffers.outgoing_rcvbuf);
    try std.testing.expectEqual(@as(?u32, 32768), cfg.locals[0].tcp_buffers.incoming_sndbuf);
    try std.testing.expectEqual(@as(?u32, 32769), cfg.locals[0].tcp_buffers.incoming_rcvbuf);
    try std.testing.expectEqual(@as(?u32, 32770), cfg.locals[0].tcp_buffers.outgoing_sndbuf);
    try std.testing.expectEqual(@as(?u32, 32771), cfg.locals[0].tcp_buffers.outgoing_rcvbuf);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.servers[0].outbound_bind.ipv4.?);
    try std.testing.expectEqualStrings("::1", cfg.servers[0].outbound_bind.ipv6.?);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.manager.?.host);
    try std.testing.expectEqual(@as(u16, 6001), cfg.manager.?.port);
    try std.testing.expectEqual(ManagerTransport.ip, cfg.manager.?.transport);
    try std.testing.expectEqual(@as(u64, 10), cfg.udp_timeout_seconds);
    try std.testing.expectEqual(@as(?usize, 32), cfg.udp_max_associations);
    try std.testing.expectEqual(@as(?u64, 4096), cfg.nofile);
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
        .no_delay = true,
        .reuse_port = true,
        .ipv6_first = true,
        .nofile = 2048,
        .outbound_bind = .{
            .ipv4 = "127.0.0.2",
            .ipv6 = "::1",
        },
        .tcp_buffers = .{
            .incoming_sndbuf = 40960,
            .incoming_rcvbuf = 40961,
            .outgoing_sndbuf = 40962,
            .outgoing_rcvbuf = 40963,
        },
    });
    defer cfg.deinit();

    try std.testing.expectEqualStrings("198.51.100.10", cfg.servers[0].host);
    try std.testing.expectEqual(@as(u16, 8388), cfg.servers[0].port);
    try std.testing.expectEqualStrings("127.0.0.2", cfg.locals[0].host);
    try std.testing.expectEqual(@as(u16, 1081), cfg.locals[0].port);
    try std.testing.expectEqual(crypto.CipherKind.aes_128_gcm, cfg.servers[0].method);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.servers[0].mode);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.locals[0].mode);
    try std.testing.expect(cfg.servers[0].no_delay);
    try std.testing.expect(cfg.locals[0].no_delay);
    try std.testing.expect(cfg.servers[0].reuse_port);
    try std.testing.expect(cfg.locals[0].reuse_port);
    try std.testing.expect(cfg.servers[0].ipv6_first);
    try std.testing.expect(cfg.locals[0].ipv6_first);
    try std.testing.expectEqual(@as(?u32, 40960), cfg.servers[0].tcp_buffers.incoming_sndbuf);
    try std.testing.expectEqual(@as(?u32, 40961), cfg.locals[0].tcp_buffers.incoming_rcvbuf);
    try std.testing.expectEqual(@as(?u32, 40962), cfg.servers[0].tcp_buffers.outgoing_sndbuf);
    try std.testing.expectEqual(@as(?u32, 40963), cfg.locals[0].tcp_buffers.outgoing_rcvbuf);
    try std.testing.expectEqualStrings("127.0.0.2", cfg.servers[0].outbound_bind.ipv4.?);
    try std.testing.expectEqualStrings("::1", cfg.servers[0].outbound_bind.ipv6.?);
    try std.testing.expectEqual(@as(?u64, 2048), cfg.nofile);
    try std.testing.expectEqualStrings("fake-plugin", cfg.servers[0].plugin.?);
    try std.testing.expectEqualStrings("obfs=tls", cfg.servers[0].plugin_opts.?);
}

test "build config from libev-style CLI raw key override" {
    var cfg = try Config.fromOverrides(std.testing.allocator, .{
        .server_host = "198.51.100.10",
        .server_port = 8388,
        .key = "AQIDBAUGBwgJCgsMDQ4PEA==",
        .method = .aes_128_gcm,
    });
    defer cfg.deinit();

    try std.testing.expectEqualStrings("", cfg.servers[0].password);
    try std.testing.expectEqualStrings("AQIDBAUGBwgJCgsMDQ4PEA==", cfg.servers[0].key.?);
    try std.testing.expectEqual(crypto.CipherKind.aes_128_gcm, cfg.servers[0].method);
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
        .no_delay = true,
        .reuse_port = true,
        .ipv6_first = true,
        .nofile = 8192,
        .outbound_bind = .{
            .ipv4 = "127.0.0.3",
        },
        .tcp_buffers = .{
            .incoming_sndbuf = 49152,
            .incoming_rcvbuf = 49153,
            .outgoing_sndbuf = 49154,
            .outgoing_rcvbuf = 49155,
        },
    });

    try std.testing.expectEqualStrings("203.0.113.7", cfg.servers[0].host);
    try std.testing.expectEqual(@as(u16, 8443), cfg.servers[0].port);
    try std.testing.expectEqualStrings("override", cfg.servers[0].password);
    try std.testing.expectEqual(crypto.CipherKind.xchacha20_ietf_poly1305, cfg.servers[0].method);
    try std.testing.expectEqual(Mode.udp_only, cfg.servers[0].mode);
    try std.testing.expectEqual(@as(u16, 1090), cfg.locals[0].port);
    try std.testing.expectEqual(LocalProtocol.redir, cfg.locals[0].protocol);
    try std.testing.expectEqual(RedirType.tproxy, cfg.locals[0].tcp_redir);
    try std.testing.expect(cfg.servers[0].no_delay);
    try std.testing.expect(cfg.locals[0].no_delay);
    try std.testing.expect(cfg.servers[0].reuse_port);
    try std.testing.expect(cfg.locals[0].reuse_port);
    try std.testing.expect(cfg.servers[0].ipv6_first);
    try std.testing.expect(cfg.locals[0].ipv6_first);
    try std.testing.expectEqual(@as(?u32, 49152), cfg.servers[0].tcp_buffers.incoming_sndbuf);
    try std.testing.expectEqual(@as(?u32, 49153), cfg.locals[0].tcp_buffers.incoming_rcvbuf);
    try std.testing.expectEqual(@as(?u32, 49154), cfg.servers[0].tcp_buffers.outgoing_sndbuf);
    try std.testing.expectEqual(@as(?u32, 49155), cfg.locals[0].tcp_buffers.outgoing_rcvbuf);
    try std.testing.expectEqualStrings("127.0.0.3", cfg.servers[0].outbound_bind.ipv4.?);
    try std.testing.expectEqual(@as(?u64, 8192), cfg.nofile);
}

test "apply CLI password override clears configured raw key" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "key": "AQIDBAUGBwgJCgsMDQ4PEA==",
        \\  "method": "aes-128-gcm"
        \\}
    );
    defer cfg.deinit();

    try cfg.applyOverrides(.{
        .password = "override",
    });

    try std.testing.expectEqualStrings("override", cfg.servers[0].password);
    try std.testing.expect(cfg.servers[0].key == null);
}

test "apply CLI raw key override replaces configured password derivation" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-128-gcm"
        \\}
    );
    defer cfg.deinit();

    try cfg.applyOverrides(.{
        .key = "AQIDBAUGBwgJCgsMDQ4PEA==",
    });

    try std.testing.expectEqualStrings("secret", cfg.servers[0].password);
    try std.testing.expectEqualStrings("AQIDBAUGBwgJCgsMDQ4PEA==", cfg.servers[0].key.?);
}

test "parse libev classic server array" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": ["one.example", "two.example:8443", "[2001:db8::1]:9443", "2001:db8::2"],
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-128-gcm",
        \\  "mode": "tcp_and_udp"
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(@as(usize, 4), cfg.servers.len);
    try std.testing.expectEqualStrings("one.example", cfg.servers[0].host);
    try std.testing.expectEqual(@as(u16, 8388), cfg.servers[0].port);
    try std.testing.expectEqualStrings("two.example", cfg.servers[1].host);
    try std.testing.expectEqual(@as(u16, 8443), cfg.servers[1].port);
    try std.testing.expectEqualStrings("2001:db8::1", cfg.servers[2].host);
    try std.testing.expectEqual(@as(u16, 9443), cfg.servers[2].port);
    try std.testing.expectEqualStrings("2001:db8::2", cfg.servers[3].host);
    try std.testing.expectEqual(@as(u16, 8388), cfg.servers[3].port);
    try std.testing.expectEqualStrings("secret", cfg.servers[3].password);
    try std.testing.expectEqual(crypto.CipherKind.aes_128_gcm, cfg.servers[3].method);
    try std.testing.expectEqual(Mode.tcp_and_udp, cfg.servers[3].mode);
}

test "parse libev raw key without password" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "key": "AQIDBAUGBwgJCgsMDQ4PEA==",
        \\  "method": "aes-128-gcm"
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqualStrings("127.0.0.1", cfg.servers[0].host);
    try std.testing.expectEqualStrings("", cfg.servers[0].password);
    try std.testing.expectEqualStrings("AQIDBAUGBwgJCgsMDQ4PEA==", cfg.servers[0].key.?);
    try std.testing.expectEqual(crypto.CipherKind.aes_128_gcm, cfg.servers[0].method);
}

test "parse libev numeric strings" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": "8388",
        \\  "local_address": "127.0.0.1",
        \\  "local_port": "1080",
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "timeout": "60",
        \\  "udp_timeout": "12",
        \\  "nofile": "1024",
        \\  "tcp_weight": "0.5",
        \\  "udp_weight": "0.25",
        \\  "manager_address": "127.0.0.1",
        \\  "manager_port": "6001"
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(@as(u16, 8388), cfg.servers[0].port);
    try std.testing.expectEqual(@as(u16, 1080), cfg.locals[0].port);
    try std.testing.expectEqual(@as(u64, 60), cfg.timeout_seconds);
    try std.testing.expectEqual(@as(u64, 12), cfg.udp_timeout_seconds);
    try std.testing.expectEqual(@as(?u64, 1024), cfg.nofile);
    try std.testing.expectEqual(@as(u16, 50), cfg.servers[0].tcp_weight);
    try std.testing.expectEqual(@as(u16, 25), cfg.servers[0].udp_weight);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.manager.?.host);
    try std.testing.expectEqual(@as(u16, 6001), cfg.manager.?.port);
}

test "parse libev port_password entries" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "port_password": {
        \\    "8388": "first",
        \\    "8389": "second"
        \\  },
        \\  "method": "aes-256-gcm",
        \\  "manager_address": "127.0.0.1:6001"
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(@as(usize, 2), cfg.servers.len);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.servers[0].host);
    try std.testing.expectEqual(@as(u16, 8388), cfg.servers[0].port);
    try std.testing.expectEqualStrings("first", cfg.servers[0].password);
    try std.testing.expectEqual(@as(u16, 8389), cfg.servers[1].port);
    try std.testing.expectEqualStrings("second", cfg.servers[1].password);
    try std.testing.expectEqual(crypto.CipherKind.aes_256_gcm, cfg.servers[1].method);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.manager.?.host);
}

test "parse libev port_password defaults host for manager configs" {
    var cfg = try Config.parseSlice(std.testing.allocator,
        \\{
        \\  "port_password": {
        \\    "8388": "first"
        \\  },
        \\  "method": "aes-256-gcm",
        \\  "manager_address": "127.0.0.1:6001"
        \\}
    );
    defer cfg.deinit();

    try std.testing.expectEqual(@as(usize, 1), cfg.servers.len);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.servers[0].host);
    try std.testing.expectEqual(@as(u16, 8388), cfg.servers[0].port);
    try std.testing.expectEqualStrings("first", cfg.servers[0].password);
}

test "parse rejects invalid libev port_password entries" {
    try std.testing.expectError(error.InvalidConfig, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "port_password": {
        \\    "not-a-port": "first"
        \\  },
        \\  "method": "aes-256-gcm"
        \\}
    ));

    try std.testing.expectError(error.InvalidConfig, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "port_password": {
        \\    "8388": 123
        \\  },
        \\  "method": "aes-256-gcm"
        \\}
    ));
}

test "reject non-aead legacy cipher methods" {
    try std.testing.expectError(error.InvalidCipher, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "none"
        \\}
    ));

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
        \\    {"disabled": true, "server": "disabled.example", "server_port": 1},
        \\    {"server": "one.example", "server_port": 8388, "password": "one", "method": "aes-128-gcm", "tcp_weight": 0.25, "udp_weight": 0},
        \\    {"server": "two.example", "server_port": 8389, "password": "two", "method": "chacha20-ietf-poly1305", "tcp_weight": 1.0, "udp_weight": 0.5}
        \\  ],
        \\  "locals": [
        \\    {"disabled": true, "protocol": "tun"},
        \\    {
        \\      "local_address": "127.0.0.1",
        \\      "local_port": 1081,
        \\      "local_udp_address": "127.0.0.2",
        \\      "local_udp_port": 1082,
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
    try std.testing.expectEqualStrings("127.0.0.2", cfg.locals[0].udp_host.?);
    try std.testing.expectEqual(@as(?u16, 1082), cfg.locals[0].udp_port);
    try std.testing.expectEqualStrings("alice", cfg.locals[0].socks5_users[0].user_name);
}

test "parse rejects invalid local UDP port" {
    try std.testing.expectError(error.InvalidConfig, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-128-gcm",
        \\  "local_udp_port": 0
        \\}
    ));
}

test "parse rejects extended config with no enabled servers or locals" {
    try std.testing.expectError(error.MissingServer, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "servers": [
        \\    {"disabled": true, "server": "disabled.example", "server_port": 8388}
        \\  ],
        \\  "locals": [
        \\    {"local_address": "127.0.0.1", "local_port": 1081}
        \\  ]
        \\}
    ));

    try std.testing.expectError(error.MissingLocal, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "servers": [
        \\    {"server": "127.0.0.1", "server_port": 8388, "password": "secret", "method": "aes-128-gcm"}
        \\  ],
        \\  "locals": [
        \\    {"disabled": true, "protocol": "tun"}
        \\  ]
        \\}
    ));
}

test "parse rejects non-boolean disabled flag" {
    try std.testing.expectError(error.InvalidConfig, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "servers": [
        \\    {"disabled": "yes", "server": "127.0.0.1", "server_port": 8388, "password": "secret", "method": "aes-128-gcm"}
        \\  ]
        \\}
    ));
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

test "parse rejects invalid nofile" {
    try std.testing.expectError(error.InvalidConfig, Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "nofile": 0
        \\}
    ));
}
