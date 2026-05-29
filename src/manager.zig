const std = @import("std");

const config = @import("config.zig");
const netio = @import("relay/netio.zig");

const max_datagram = 8192;
const work_dir = ".zig-cache/ss-zig-manager";

const UnixAddress = extern union {
    any: std.posix.sockaddr,
    un: std.posix.sockaddr.un,
};

const Entry = struct {
    host: []const u8,
    port: u16,
    password: []const u8,
    key: ?[]const u8 = null,
    method: []const u8,
    mode: config.Mode,
    no_delay: bool = false,
    reuse_port: bool = false,
    ipv6_first: bool = false,
    tcp_buffers: config.TcpBufferConfig = .{},
    acl_path: ?[]const u8 = null,
    plugin: ?[]const u8 = null,
    plugin_opts: ?[]const u8 = null,
    plugin_args: []const []const u8 = &.{},
    plugin_mode: config.Mode = .tcp_only,
    traffic: u64,
    process: ?ManagedProcess = null,
};

const ManagedProcess = struct {
    child: std.process.Child,
    config_path: []const u8,
};

const ProcessOptions = struct {
    io: std.Io,
    env_map: *const std.process.Environ.Map,
    executable_path: []const u8,
    manager_address: config.Manager,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry),
    default_host: []const u8,
    default_method: []const u8,
    default_mode: config.Mode,
    process_options: ?ProcessOptions = null,

    pub fn init(allocator: std.mem.Allocator, cfg: *const config.Config) !Manager {
        var entries = std.ArrayList(Entry).empty;
        errdefer {
            for (entries.items) |entry| {
                freeEntryFields(allocator, entry);
            }
            entries.deinit(allocator);
        }

        const default_host = if (cfg.servers.len > 0) cfg.servers[0].host else "127.0.0.1";
        const default_method = if (cfg.servers.len > 0) cfg.servers[0].method.name() else "aes-256-gcm";
        const default_mode = if (cfg.servers.len > 0) cfg.servers[0].mode else .tcp_only;
        for (cfg.servers) |server_cfg| {
            const entry = try entryFromServer(allocator, server_cfg);
            errdefer {
                freeEntryFields(allocator, entry);
            }
            try entries.append(allocator, entry);
        }

        return .{
            .allocator = allocator,
            .entries = entries,
            .default_host = default_host,
            .default_method = default_method,
            .default_mode = default_mode,
        };
    }

    pub fn deinit(self: *Manager) void {
        while (self.entries.items.len > 0) {
            var entry = self.entries.pop().?;
            self.stopEntry(&entry);
            freeEntryFields(self.allocator, entry);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn run(self: *Manager, bind: config.Manager) !void {
        try self.startConfiguredEntries();
        return switch (bind.transport) {
            .ip => self.runIp(bind),
            .unix => self.runUnix(bind),
        };
    }

    fn runIp(self: *Manager, bind: config.Manager) !void {
        var socket = try netio.bindUdp(bind.host, bind.port, false);
        defer socket.close();

        var buffer: [max_datagram]u8 = undefined;
        while (true) {
            const packet = try socket.receiveFrom(&buffer);
            const response = self.processCommand(buffer[0..packet.len]) catch |err| switch (err) {
                error.InvalidCommand => try self.allocator.dupe(u8, "err"),
                error.PortNotAvailable => try self.allocator.dupe(u8, "port is not available"),
                else => return err,
            };
            if (response) |bytes| {
                defer self.allocator.free(bytes);
                _ = try socket.sendTo(bytes, packet.from);
            }
        }
    }

    fn runUnix(self: *Manager, bind: config.Manager) !void {
        std.Io.Dir.deleteFileAbsolute(self.process_options.?.io, bind.path) catch {};
        const fd = try openUnixDatagramSocket();
        defer closeFd(fd);
        errdefer std.Io.Dir.deleteFileAbsolute(self.process_options.?.io, bind.path) catch {};

        var bind_address = try unixAddress(bind.path);
        try bindUnixDatagram(fd, &bind_address.storage.any, bind_address.len);

        var buffer: [max_datagram]u8 = undefined;
        while (true) {
            var peer: UnixAddress = undefined;
            var peer_len: std.posix.socklen_t = @sizeOf(UnixAddress);
            const n = try recvFromUnix(fd, &buffer, &peer.any, &peer_len);
            const response = self.processCommand(buffer[0..n]) catch |err| switch (err) {
                error.InvalidCommand => try self.allocator.dupe(u8, "err"),
                error.PortNotAvailable => try self.allocator.dupe(u8, "port is not available"),
                else => return err,
            };
            if (response) |bytes| {
                defer self.allocator.free(bytes);
                try sendToUnix(fd, bytes, &peer.any, peer_len);
            }
        }
    }

    pub fn processCommand(self: *Manager, command: []const u8) !?[]u8 {
        const trimmed = std.mem.trim(u8, command, " \t\r\n\x00");
        if (trimmed.len == 0) return error.InvalidCommand;
        const action_end = actionEnd(trimmed);
        const action = trimmed[0..action_end];

        if (std.mem.eql(u8, action, "add")) {
            const response = try self.allocator.dupe(u8, "ok");
            errdefer self.allocator.free(response);
            var entry = try self.parseEntry(trimmed, true);
            errdefer {
                self.stopEntry(&entry);
                freeEntryFields(self.allocator, entry);
            }
            try self.upsert(&entry);
            return response;
        }
        if (std.mem.eql(u8, action, "remove")) {
            const entry = try self.parseEntry(trimmed, false);
            self.removePort(entry.port);
            freeEntryFields(self.allocator, entry);
            return try self.allocator.dupe(u8, "ok");
        }
        if (std.mem.eql(u8, action, "list")) {
            return try self.listResponse();
        }
        if (std.mem.eql(u8, action, "ping")) {
            return try self.pingResponse();
        }
        if (std.mem.eql(u8, action, "stat")) {
            try self.applyTraffic(trimmed);
            return null;
        }

        return error.InvalidCommand;
    }

    fn parseEntry(self: *Manager, command: []const u8, require_password: bool) !Entry {
        const value = try parsePayload(self.allocator, command);
        defer value.deinit();
        if (value.value != .object) return error.InvalidCommand;
        const object = value.value.object;
        const port = parsePort(object.get("server_port") orelse return error.InvalidCommand) orelse return error.InvalidCommand;
        const key = try dupeOptionalJsonString(self.allocator, object.get("key"));
        errdefer if (key) |value_string| self.allocator.free(value_string);

        const password = if (object.get("password")) |password_value|
            try dupeJsonString(self.allocator, password_value)
        else if (require_password and key == null)
            return error.InvalidCommand
        else
            try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(password);

        const method = if (object.get("method")) |method_value|
            try dupeJsonString(self.allocator, method_value)
        else
            try self.allocator.dupe(u8, self.default_method);
        errdefer self.allocator.free(method);

        const host = try self.allocator.dupe(u8, self.default_host);
        errdefer self.allocator.free(host);

        const plugin_name = try dupeOptionalJsonString(self.allocator, object.get("plugin"));
        errdefer if (plugin_name) |value_string| self.allocator.free(value_string);
        const plugin_opts = try dupeOptionalJsonString(self.allocator, object.get("plugin_opts"));
        errdefer if (plugin_opts) |value_string| self.allocator.free(value_string);
        const plugin_args = try dupeJsonStringArray(self.allocator, object.get("plugin_args"));
        errdefer freeStringArray(self.allocator, plugin_args);

        return .{
            .host = host,
            .port = port,
            .password = password,
            .key = key,
            .method = method,
            .mode = config.Mode.parse(jsonString(object.get("mode")) orelse @tagName(self.default_mode)),
            .no_delay = jsonBool(object.get("no_delay")) orelse false,
            .reuse_port = jsonBool(object.get("reuse_port")) orelse false,
            .ipv6_first = jsonBool(object.get("ipv6_first")) orelse false,
            .tcp_buffers = .{
                .incoming_sndbuf = jsonU32(object.get("tcp_incoming_sndbuf")),
                .incoming_rcvbuf = jsonU32(object.get("tcp_incoming_rcvbuf")),
                .outgoing_sndbuf = jsonU32(object.get("tcp_outgoing_sndbuf")),
                .outgoing_rcvbuf = jsonU32(object.get("tcp_outgoing_rcvbuf")),
            },
            .plugin = plugin_name,
            .plugin_opts = plugin_opts,
            .plugin_args = plugin_args,
            .plugin_mode = .tcp_only,
            .traffic = 0,
        };
    }

    pub fn enableProcessManagement(self: *Manager, io: std.Io, env_map: *const std.process.Environ.Map, executable_path: []const u8, manager_address: config.Manager) void {
        self.process_options = .{
            .io = io,
            .env_map = env_map,
            .executable_path = executable_path,
            .manager_address = manager_address,
        };
    }

    fn startConfiguredEntries(self: *Manager) !void {
        var i: usize = 0;
        while (i < self.entries.items.len) : (i += 1) {
            if (self.entries.items[i].process != null) continue;
            try self.startEntryProcess(&self.entries.items[i]);
        }
    }

    fn upsert(self: *Manager, entry: *Entry) !void {
        self.removePort(entry.port);
        try self.startEntryProcess(entry);
        errdefer self.stopEntry(entry);
        try self.entries.append(self.allocator, entry.*);
    }

    fn removePort(self: *Manager, port: u16) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].port == port) {
                var old = self.entries.orderedRemove(i);
                self.stopEntry(&old);
                freeEntryFields(self.allocator, old);
                return;
            }
            i += 1;
        }
    }

    fn applyTraffic(self: *Manager, command: []const u8) !void {
        const value = try parsePayload(self.allocator, command);
        defer value.deinit();
        if (value.value != .object) return error.InvalidCommand;
        var iterator = value.value.object.iterator();
        while (iterator.next()) |item| {
            const amount = jsonU64(item.value_ptr.*) orelse continue;
            const port = std.fmt.parseInt(u16, item.key_ptr.*, 10) catch continue;
            if (self.findPort(port)) |entry| {
                entry.traffic = amount;
            }
        }
    }

    fn findPort(self: *Manager, port: u16) ?*Entry {
        for (self.entries.items) |*entry| {
            if (entry.port == port) return entry;
        }
        return null;
    }

    fn startEntryProcess(self: *Manager, entry: *Entry) !void {
        const options = self.process_options orelse return;
        if (!try portAvailable(entry.*)) return error.PortNotAvailable;

        try std.Io.Dir.cwd().createDirPath(options.io, work_dir);
        const config_path = try std.fmt.allocPrint(self.allocator, "{s}/server-{d}.json", .{ work_dir, entry.port });
        errdefer self.allocator.free(config_path);

        const bytes = try renderServerConfig(self.allocator, entry.*, options.manager_address);
        defer self.allocator.free(bytes);
        try std.Io.Dir.cwd().writeFile(options.io, .{ .sub_path = config_path, .data = bytes });
        errdefer std.Io.Dir.cwd().deleteFile(options.io, config_path) catch {};

        const argv = [_][]const u8{ options.executable_path, "--server", "-c", config_path };
        const child = try std.process.spawn(options.io, .{
            .argv = &argv,
            .environ_map = options.env_map,
            .stdin = .ignore,
            .stdout = .inherit,
            .stderr = .inherit,
        });
        entry.process = .{ .child = child, .config_path = config_path };
    }

    fn stopEntry(self: *Manager, entry: *Entry) void {
        if (entry.process) |*process| {
            if (self.process_options) |options| {
                process.child.kill(options.io);
                std.Io.Dir.cwd().deleteFile(options.io, process.config_path) catch {};
            }
            self.allocator.free(process.config_path);
            entry.process = null;
        }
    }

    fn listResponse(self: *Manager) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);
        try out.append(self.allocator, '[');
        for (self.entries.items) |entry| {
            try out.appendSlice(self.allocator, "\n\t{\"server_port\":\"");
            try appendInt(&out, self.allocator, entry.port);
            try out.appendSlice(self.allocator, "\",\"password\":");
            try appendJsonString(&out, self.allocator, entry.password);
            if (entry.key) |key| {
                try out.appendSlice(self.allocator, ",\"key\":");
                try appendJsonString(&out, self.allocator, key);
            }
            try out.appendSlice(self.allocator, ",\"method\":");
            try appendJsonString(&out, self.allocator, entry.method);
            if (entry.no_delay) {
                try out.appendSlice(self.allocator, ",\"no_delay\":true");
            }
            if (entry.reuse_port) {
                try out.appendSlice(self.allocator, ",\"reuse_port\":true");
            }
            if (entry.ipv6_first) {
                try out.appendSlice(self.allocator, ",\"ipv6_first\":true");
            }
            try appendTcpBuffersCompact(&out, self.allocator, entry.tcp_buffers);
            try out.appendSlice(self.allocator, "},");
        }
        if (self.entries.items.len > 0) {
            out.items[out.items.len - 1] = '\n';
            try out.append(self.allocator, ']');
        } else {
            try out.appendSlice(self.allocator, "\n]");
        }
        return try out.toOwnedSlice(self.allocator);
    }

    fn pingResponse(self: *Manager) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "stat: {");
        for (self.entries.items) |entry| {
            try out.append(self.allocator, '"');
            try appendInt(&out, self.allocator, entry.port);
            try out.append(self.allocator, '"');
            try out.append(self.allocator, ':');
            try appendInt(&out, self.allocator, entry.traffic);
            try out.append(self.allocator, ',');
        }
        if (self.entries.items.len > 0) {
            out.items[out.items.len - 1] = '}';
        } else {
            try out.append(self.allocator, '}');
        }
        return try out.toOwnedSlice(self.allocator);
    }
};

fn entryFromServer(allocator: std.mem.Allocator, server_cfg: config.Server) !Entry {
    const host = try allocator.dupe(u8, server_cfg.host);
    errdefer allocator.free(host);
    const password = try allocator.dupe(u8, server_cfg.password);
    errdefer allocator.free(password);
    const key = try dupeOptionalBytes(allocator, server_cfg.key);
    errdefer if (key) |value| allocator.free(value);
    const method = try allocator.dupe(u8, server_cfg.method.name());
    errdefer allocator.free(method);
    const acl_path = try dupeOptionalBytes(allocator, server_cfg.acl_path);
    errdefer if (acl_path) |value| allocator.free(value);
    const plugin_name = try dupeOptionalBytes(allocator, server_cfg.plugin);
    errdefer if (plugin_name) |value| allocator.free(value);
    const plugin_opts = try dupeOptionalBytes(allocator, server_cfg.plugin_opts);
    errdefer if (plugin_opts) |value| allocator.free(value);
    const plugin_args = try dupeStringSlice(allocator, server_cfg.plugin_args);
    errdefer freeStringArray(allocator, plugin_args);
    return .{
        .host = host,
        .port = server_cfg.port,
        .password = password,
        .key = key,
        .method = method,
        .mode = server_cfg.mode,
        .no_delay = server_cfg.no_delay,
        .reuse_port = server_cfg.reuse_port,
        .ipv6_first = server_cfg.ipv6_first,
        .tcp_buffers = server_cfg.tcp_buffers,
        .acl_path = acl_path,
        .plugin = plugin_name,
        .plugin_opts = plugin_opts,
        .plugin_args = plugin_args,
        .plugin_mode = server_cfg.plugin_mode,
        .traffic = 0,
    };
}

fn freeEntryFields(allocator: std.mem.Allocator, entry: Entry) void {
    allocator.free(entry.host);
    allocator.free(entry.password);
    if (entry.key) |value| allocator.free(value);
    allocator.free(entry.method);
    if (entry.acl_path) |value| allocator.free(value);
    if (entry.plugin) |value| allocator.free(value);
    if (entry.plugin_opts) |value| allocator.free(value);
    freeStringArray(allocator, entry.plugin_args);
}

fn actionEnd(command: []const u8) usize {
    for (command, 0..) |byte, i| {
        if (std.ascii.isWhitespace(byte) or byte == ':') return i;
    }
    return command.len;
}

fn parsePayload(allocator: std.mem.Allocator, command: []const u8) !std.json.Parsed(std.json.Value) {
    const start = std.mem.indexOfScalar(u8, command, '{') orelse return error.InvalidCommand;
    return std.json.parseFromSlice(std.json.Value, allocator, command[start..], .{}) catch return error.InvalidCommand;
}

fn parsePort(value: std.json.Value) ?u16 {
    return switch (value) {
        .integer => |i| if (i >= 0) std.math.cast(u16, i) else null,
        .float => |f| if (f >= 0 and f <= std.math.maxInt(u16)) @intFromFloat(f) else null,
        .string => |s| std.fmt.parseInt(u16, s, 10) catch null,
        else => null,
    };
}

fn jsonString(value: ?std.json.Value) ?[]const u8 {
    const v = value orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn jsonBool(value: ?std.json.Value) ?bool {
    const v = value orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

fn jsonU32(value: ?std.json.Value) ?u32 {
    const v = value orelse return null;
    const raw: u64 = switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else return null,
        .float => |f| if (f >= 0 and f <= std.math.maxInt(u32)) @intFromFloat(f) else return null,
        .string => |s| std.fmt.parseInt(u32, s, 10) catch return null,
        else => return null,
    };
    if (raw == 0 or raw > std.math.maxInt(c_int)) return null;
    return @intCast(raw);
}

fn jsonU64(value: std.json.Value) ?u64 {
    return switch (value) {
        .integer => |i| if (i >= 0) @intCast(i) else null,
        .float => |f| if (f >= 0) @intFromFloat(f) else null,
        else => null,
    };
}

fn dupeJsonString(allocator: std.mem.Allocator, value: std.json.Value) ![]const u8 {
    const s = jsonString(value) orelse return error.InvalidCommand;
    return try allocator.dupe(u8, s);
}

fn dupeOptionalJsonString(allocator: std.mem.Allocator, value: ?std.json.Value) !?[]const u8 {
    const s = jsonString(value) orelse return null;
    if (s.len == 0) return null;
    return try allocator.dupe(u8, s);
}

fn dupeOptionalBytes(allocator: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    const s = value orelse return null;
    if (s.len == 0) return null;
    return try allocator.dupe(u8, s);
}

fn dupeJsonStringArray(allocator: std.mem.Allocator, value: ?std.json.Value) ![]const []const u8 {
    const v = value orelse return &.{};
    if (v != .array) return error.InvalidCommand;
    var items = std.ArrayList([]const u8).empty;
    errdefer {
        for (items.items) |item| allocator.free(item);
        items.deinit(allocator);
    }
    for (v.array.items) |item| {
        const string = try dupeJsonString(allocator, item);
        errdefer allocator.free(string);
        try items.append(allocator, string);
    }
    return try items.toOwnedSlice(allocator);
}

fn dupeStringSlice(allocator: std.mem.Allocator, values: []const []const u8) ![]const []const u8 {
    var items = std.ArrayList([]const u8).empty;
    errdefer {
        for (items.items) |item| allocator.free(item);
        items.deinit(allocator);
    }
    for (values) |value| {
        const string = try allocator.dupe(u8, value);
        errdefer allocator.free(string);
        try items.append(allocator, string);
    }
    return try items.toOwnedSlice(allocator);
}

fn freeStringArray(allocator: std.mem.Allocator, values: []const []const u8) void {
    if (values.len == 0) return;
    for (values) |value| allocator.free(value);
    allocator.free(values);
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

fn appendJsonStringArray(out: *std.ArrayList(u8), allocator: std.mem.Allocator, values: []const []const u8) !void {
    try out.append(allocator, '[');
    for (values, 0..) |value, i| {
        if (i != 0) try out.append(allocator, ',');
        try appendJsonString(out, allocator, value);
    }
    try out.append(allocator, ']');
}

fn appendTcpBuffersCompact(out: *std.ArrayList(u8), allocator: std.mem.Allocator, buffers: config.TcpBufferConfig) !void {
    if (buffers.incoming_sndbuf) |value| {
        try out.appendSlice(allocator, ",\"tcp_incoming_sndbuf\":");
        try appendInt(out, allocator, value);
    }
    if (buffers.incoming_rcvbuf) |value| {
        try out.appendSlice(allocator, ",\"tcp_incoming_rcvbuf\":");
        try appendInt(out, allocator, value);
    }
    if (buffers.outgoing_sndbuf) |value| {
        try out.appendSlice(allocator, ",\"tcp_outgoing_sndbuf\":");
        try appendInt(out, allocator, value);
    }
    if (buffers.outgoing_rcvbuf) |value| {
        try out.appendSlice(allocator, ",\"tcp_outgoing_rcvbuf\":");
        try appendInt(out, allocator, value);
    }
}

fn appendTcpBuffersPretty(out: *std.ArrayList(u8), allocator: std.mem.Allocator, buffers: config.TcpBufferConfig) !void {
    if (buffers.incoming_sndbuf) |value| {
        try out.appendSlice(allocator, ",\n  \"tcp_incoming_sndbuf\":");
        try appendInt(out, allocator, value);
    }
    if (buffers.incoming_rcvbuf) |value| {
        try out.appendSlice(allocator, ",\n  \"tcp_incoming_rcvbuf\":");
        try appendInt(out, allocator, value);
    }
    if (buffers.outgoing_sndbuf) |value| {
        try out.appendSlice(allocator, ",\n  \"tcp_outgoing_sndbuf\":");
        try appendInt(out, allocator, value);
    }
    if (buffers.outgoing_rcvbuf) |value| {
        try out.appendSlice(allocator, ",\n  \"tcp_outgoing_rcvbuf\":");
        try appendInt(out, allocator, value);
    }
}

fn portAvailable(entry: Entry) !bool {
    if (entry.mode.enableTcp()) {
        if (!try netio.canBindTcp(entry.host, entry.port)) return false;
    }
    if (entry.mode.enableUdp()) {
        if (!try netio.canBindUdp(entry.host, entry.port)) return false;
    }
    return true;
}

fn renderServerConfig(allocator: std.mem.Allocator, entry: Entry, manager_address: config.Manager) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n  \"server\":");
    try appendJsonString(&out, allocator, entry.host);
    try out.appendSlice(allocator, ",\n  \"server_port\":");
    try appendInt(&out, allocator, entry.port);
    try out.appendSlice(allocator, ",\n  \"password\":");
    try appendJsonString(&out, allocator, entry.password);
    if (entry.key) |key| {
        try out.appendSlice(allocator, ",\n  \"key\":");
        try appendJsonString(&out, allocator, key);
    }
    try out.appendSlice(allocator, ",\n  \"method\":");
    try appendJsonString(&out, allocator, entry.method);
    try out.appendSlice(allocator, ",\n  \"mode\":");
    try appendJsonString(&out, allocator, @tagName(entry.mode));
    if (entry.no_delay) {
        try out.appendSlice(allocator, ",\n  \"no_delay\":true");
    }
    if (entry.reuse_port) {
        try out.appendSlice(allocator, ",\n  \"reuse_port\":true");
    }
    if (entry.ipv6_first) {
        try out.appendSlice(allocator, ",\n  \"ipv6_first\":true");
    }
    try appendTcpBuffersPretty(&out, allocator, entry.tcp_buffers);
    try out.appendSlice(allocator, ",\n  \"manager_address\":");
    try appendJsonString(&out, allocator, manager_address.address);
    if (entry.acl_path) |acl_path| {
        try out.appendSlice(allocator, ",\n  \"acl\":");
        try appendJsonString(&out, allocator, acl_path);
    }
    if (entry.plugin) |plugin| {
        try out.appendSlice(allocator, ",\n  \"plugin\":");
        try appendJsonString(&out, allocator, plugin);
    }
    if (entry.plugin_opts) |plugin_opts| {
        try out.appendSlice(allocator, ",\n  \"plugin_opts\":");
        try appendJsonString(&out, allocator, plugin_opts);
    }
    if (entry.plugin_args.len != 0) {
        try out.appendSlice(allocator, ",\n  \"plugin_args\":");
        try appendJsonStringArray(&out, allocator, entry.plugin_args);
    }
    if (entry.plugin != null) {
        try out.appendSlice(allocator, ",\n  \"plugin_mode\":");
        try appendJsonString(&out, allocator, @tagName(entry.plugin_mode));
    }
    try out.appendSlice(allocator, "\n}\n");
    return try out.toOwnedSlice(allocator);
}

const UnixSockaddr = struct {
    storage: UnixAddress,
    len: std.posix.socklen_t,
};

fn unixAddress(path: []const u8) !UnixSockaddr {
    var storage: UnixAddress = undefined;
    storage.un = .{
        .family = std.posix.AF.UNIX,
        .path = [_]u8{0} ** @sizeOf(@TypeOf(storage.un.path)),
    };
    if (path.len == 0 or path.len >= storage.un.path.len) return error.InvalidManagerAddress;
    @memcpy(storage.un.path[0..path.len], path);
    return .{
        .storage = storage,
        .len = @intCast(@offsetOf(std.posix.sockaddr.un, "path") + path.len + 1),
    };
}

fn openUnixDatagramSocket() !std.posix.socket_t {
    while (true) {
        const rc = std.posix.system.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn bindUnixDatagram(fd: std.posix.socket_t, address: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
    while (true) {
        switch (std.posix.errno(std.posix.system.bind(fd, address, len))) {
            .SUCCESS => return,
            .INTR => continue,
            .ACCES => return error.AccessDenied,
            .ADDRINUSE => return error.AddressInUse,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .NAMETOOLONG => return error.NameTooLong,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .ROFS => return error.ReadOnlyFileSystem,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn recvFromUnix(fd: std.posix.socket_t, buffer: []u8, address: *std.posix.sockaddr, len: *std.posix.socklen_t) !usize {
    while (true) {
        const rc = std.posix.system.recvfrom(fd, buffer.ptr, buffer.len, 0, address, len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => continue,
            .BADF => return error.SocketNotConnected,
            .CONNREFUSED => return error.ConnectionRefused,
            .NOMEM, .NOBUFS => return error.SystemResources,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn sendToUnix(fd: std.posix.socket_t, bytes: []const u8, address: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = std.posix.system.sendto(fd, bytes[offset..].ptr, bytes.len - offset, 0, address, len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => offset += @intCast(rc),
            .INTR => continue,
            .AGAIN => continue,
            .ACCES => return error.AccessDenied,
            .BADF => return error.SocketNotConnected,
            .CONNREFUSED => return error.ConnectionRefused,
            .MSGSIZE => return error.MessageTooLarge,
            .NOMEM, .NOBUFS => return error.SystemResources,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn closeFd(fd: std.posix.fd_t) void {
    switch (std.posix.errno(std.posix.system.close(fd))) {
        .SUCCESS, .INTR => {},
        else => {},
    }
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    env_map: *const std.process.Environ.Map,
    executable_path: []const u8,
    cfg: *const config.Config,
) !void {
    const bind = cfg.manager orelse return error.MissingManagerAddress;
    var manager = try Manager.init(allocator, cfg);
    defer manager.deinit();
    manager.enableProcessManagement(io, env_map, executable_path, bind);
    try manager.run(bind);
}

test "manager command table supports add list stat ping remove" {
    var cfg = try config.Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "password": "secret",
        \\  "method": "aes-256-gcm",
        \\  "plugin": "fake-plugin",
        \\  "plugin_args": ["--server", "--verbose"],
        \\  "manager_address": "127.0.0.1:6001"
        \\}
    );
    defer cfg.deinit();

    var mgr = try Manager.init(std.testing.allocator, &cfg);
    defer mgr.deinit();

    const list = (try mgr.processCommand("list")).?;
    defer std.testing.allocator.free(list);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"server_port\":\"8388\"") != null);
    try std.testing.expectEqual(@as(usize, 2), mgr.entries.items[0].plugin_args.len);
    try std.testing.expectEqualStrings("--server", mgr.entries.items[0].plugin_args[0]);
    try std.testing.expectEqualStrings("--verbose", mgr.entries.items[0].plugin_args[1]);

    const add = (try mgr.processCommand("add: {\"server_port\":8390,\"password\":\"next\",\"method\":\"chacha20-ietf-poly1305\",\"plugin\":\"fake-plugin\",\"plugin_args\":[\"--client\"]}")).?;
    defer std.testing.allocator.free(add);
    try std.testing.expectEqualStrings("ok", add);
    try std.testing.expectEqual(@as(usize, 1), mgr.entries.items[1].plugin_args.len);
    try std.testing.expectEqualStrings("--client", mgr.entries.items[1].plugin_args[0]);

    try std.testing.expect((try mgr.processCommand("stat: {\"8390\":42}")) == null);
    const ping = (try mgr.processCommand("ping")).?;
    defer std.testing.allocator.free(ping);
    try std.testing.expect(std.mem.indexOf(u8, ping, "\"8390\":42") != null);

    const remove = (try mgr.processCommand("remove: {\"server_port\":\"8390\"}")).?;
    defer std.testing.allocator.free(remove);
    try std.testing.expectEqualStrings("ok", remove);

    const after = (try mgr.processCommand("list")).?;
    defer std.testing.allocator.free(after);
    try std.testing.expect(std.mem.indexOf(u8, after, "\"server_port\":\"8390\"") == null);
}

test "manager preserves configured raw keys" {
    var cfg = try config.Config.parseSlice(std.testing.allocator,
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "key": "AQIDBAUGBwgJCgsMDQ4PEA==",
        \\  "method": "aes-128-gcm",
        \\  "no_delay": true,
        \\  "reuse_port": true,
        \\  "ipv6_first": true,
        \\  "tcp_incoming_sndbuf": 57344,
        \\  "tcp_incoming_rcvbuf": 57345,
        \\  "tcp_outgoing_sndbuf": 57346,
        \\  "tcp_outgoing_rcvbuf": 57347,
        \\  "manager_address": "127.0.0.1:6001"
        \\}
    );
    defer cfg.deinit();

    var mgr = try Manager.init(std.testing.allocator, &cfg);
    defer mgr.deinit();

    const list = (try mgr.processCommand("list")).?;
    defer std.testing.allocator.free(list);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"key\":\"AQIDBAUGBwgJCgsMDQ4PEA==\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"no_delay\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"reuse_port\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"ipv6_first\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"tcp_incoming_sndbuf\":57344") != null);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"tcp_incoming_rcvbuf\":57345") != null);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"tcp_outgoing_sndbuf\":57346") != null);
    try std.testing.expect(std.mem.indexOf(u8, list, "\"tcp_outgoing_rcvbuf\":57347") != null);

    const rendered = try renderServerConfig(std.testing.allocator, mgr.entries.items[0], cfg.manager.?);
    defer std.testing.allocator.free(rendered);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"password\":\"\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"key\":\"AQIDBAUGBwgJCgsMDQ4PEA==\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"no_delay\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"reuse_port\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"ipv6_first\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"tcp_incoming_sndbuf\":57344") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"tcp_incoming_rcvbuf\":57345") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"tcp_outgoing_sndbuf\":57346") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"tcp_outgoing_rcvbuf\":57347") != null);
}
