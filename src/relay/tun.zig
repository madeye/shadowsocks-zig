const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config.zig");
const acl = @import("../security/acl.zig");
const fake_dns = @import("fake_dns.zig");

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
