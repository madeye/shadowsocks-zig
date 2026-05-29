const std = @import("std");

const c = @cImport({
    @cInclude("libuv_c_api.h");
});

pub const Error = error{
    NativeLoopFailed,
};

pub fn waitReadable(fd: std.posix.fd_t, timeout_ms: u64) Error!bool {
    const rc = c.ss_uv_wait_readable(@intCast(fd), timeout_ms);
    if (rc < 0) return error.NativeLoopFailed;
    return rc != 0;
}

pub fn waitWritable(fd: std.posix.fd_t, timeout_ms: u64) Error!bool {
    const rc = c.ss_uv_wait_writable(@intCast(fd), timeout_ms);
    if (rc < 0) return error.NativeLoopFailed;
    return rc != 0;
}
