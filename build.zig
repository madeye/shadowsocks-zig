const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_rocksdb = b.option(bool, "rocksdb", "Enable RocksDB-backed fake-DNS persistence") orelse false;
    const build_options = b.addOptions();
    build_options.addOption(bool, "rocksdb", enable_rocksdb);
    const mod = b.addModule("shadowsocks", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addOptions("build_options", build_options);
    configureNativeDeps(b, mod, enable_rocksdb);

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
    for ([_][]const u8{ "ss-local", "ss-server", "ss-manager", "ss-redir", "ss-tunnel", "sslocal", "ssserver", "ssmanager" }) |alias| {
        b.getInstallStep().dependOn(&b.addInstallBinFile(exe.getEmittedBin(), alias).step);
    }

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
    tests.root_module.addOptions("build_options", build_options);
    configureNativeDeps(b, tests.root_module, enable_rocksdb);
    const test_run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);
}

fn configureNativeDeps(b: *std.Build, module: *std.Build.Module, enable_rocksdb: bool) void {
    module.linkSystemLibrary("uv", .{ .use_pkg_config = .force });
    module.linkSystemLibrary("re2", .{ .use_pkg_config = .force });
    if (enable_rocksdb) {
        module.linkSystemLibrary("rocksdb", .{ .use_pkg_config = .yes });
    }
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
