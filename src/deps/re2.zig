const std = @import("std");

const c = @cImport({
    @cInclude("re2_c_api.h");
});

pub const Error = error{
    InvalidRegex,
};

pub const Regex = struct {
    inner: *c.ss_re2_regex,

    pub fn compile(allocator: std.mem.Allocator, pattern: []const u8) Error!Regex {
        _ = allocator;
        const inner = c.ss_re2_compile(pattern.ptr, pattern.len) orelse return error.InvalidRegex;
        return .{ .inner = inner };
    }

    pub fn deinit(self: *Regex) void {
        c.ss_re2_destroy(self.inner);
        self.* = undefined;
    }

    pub fn partialMatch(self: *const Regex, text: []const u8) Error!bool {
        return c.ss_re2_partial_match(self.inner, text.ptr, text.len) != 0;
    }
};
