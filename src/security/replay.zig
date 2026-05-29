const std = @import("std");

pub const ReplayError = error{
    NonceTooLong,
} || std.mem.Allocator.Error;

pub const SaltKey = struct {
    len: u8,
    bytes: [32]u8,

    pub fn init(nonce: []const u8) ReplayError!SaltKey {
        if (nonce.len > 32) return error.NonceTooLong;
        var key = SaltKey{ .len = @intCast(nonce.len), .bytes = [_]u8{0} ** 32 };
        @memcpy(key.bytes[0..nonce.len], nonce);
        return key;
    }
};

const SaltContext = struct {
    pub fn hash(_: SaltContext, key: SaltKey) u64 {
        var h = std.hash.Wyhash.init(key.len);
        h.update(key.bytes[0..key.len]);
        return h.final();
    }

    pub fn eql(_: SaltContext, a: SaltKey, b: SaltKey) bool {
        return a.len == b.len and std.mem.eql(u8, a.bytes[0..a.len], b.bytes[0..b.len]);
    }
};

const SaltSet = std.HashMapUnmanaged(SaltKey, void, SaltContext, std.hash_map.default_max_load_percentage);

pub const ReplayProtector = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    filters: [2]SaltSet = .{ .empty, .empty },
    current: usize = 0,
    capacity_per_filter: usize,

    pub fn init(allocator: std.mem.Allocator, capacity_per_filter: usize) ReplayProtector {
        return .{
            .allocator = allocator,
            .capacity_per_filter = @max(capacity_per_filter, 1),
        };
    }

    pub fn deinit(self: *ReplayProtector) void {
        self.filters[0].deinit(self.allocator);
        self.filters[1].deinit(self.allocator);
        self.* = undefined;
    }

    pub fn checkAndSet(self: *ReplayProtector, nonce: []const u8) ReplayError!bool {
        if (nonce.len == 0) return false;
        const key = try SaltKey.init(nonce);

        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
        defer self.mutex.unlock();

        if (self.filters[0].containsContext(key, .{}) or self.filters[1].containsContext(key, .{})) {
            return true;
        }

        if (self.filters[self.current].count() >= self.capacity_per_filter) {
            self.current = (self.current + 1) % self.filters.len;
            self.filters[self.current].clearRetainingCapacity();
        }

        try self.filters[self.current].putContext(self.allocator, key, {}, .{});
        return false;
    }
};

test "replay protector detects duplicate nonces and rotates old entries" {
    var protector = ReplayProtector.init(std.testing.allocator, 2);
    defer protector.deinit();

    try std.testing.expect(!try protector.checkAndSet("one"));
    try std.testing.expect(try protector.checkAndSet("one"));
    try std.testing.expect(!try protector.checkAndSet("two"));
    try std.testing.expect(!try protector.checkAndSet("three"));
    try std.testing.expect(try protector.checkAndSet("two"));
    try std.testing.expect(!try protector.checkAndSet("four"));
    try std.testing.expect(try protector.checkAndSet("one"));
    try std.testing.expect(!try protector.checkAndSet("five"));
    try std.testing.expect(!try protector.checkAndSet("one"));
}
