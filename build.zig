const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mod = b.addModule("shadowsocks", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    configureNativeDeps(b, mod);

    const exe = b.addExecutable(.{
        .name = "ss-zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "shadowsocks", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run ss-zig");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    configureNativeDeps(b, tests.root_module);
    const test_run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);
}

fn configureNativeDeps(b: *std.Build, module: *std.Build.Module) void {
    module.linkSystemLibrary("uv", .{ .use_pkg_config = .force });
    module.linkSystemLibrary("re2", .{ .use_pkg_config = .force });
    module.linkSystemLibrary("c++", .{});
    module.addIncludePath(b.path("src/deps"));
    module.addCSourceFiles(.{
        .files = &.{"src/deps/re2_c_api.cc"},
        .flags = &.{"-std=c++17"},
        .language = .cpp,
    });
    module.addCSourceFiles(.{
        .files = &.{"src/deps/libuv_c_api.c"},
        .language = .c,
    });
}
