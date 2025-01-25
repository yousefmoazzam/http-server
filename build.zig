const std = @import("std");

/// Constructs a build graph that will be executed by an external runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose what target to
    // build for. Here we do not override the defaults, which means any target is allowed, and
    // the default is native. Other options for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select between
    // Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not set a preferred
    // release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Create a step for unit testing. Note that this only builds the test executable but does
    // not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Create a "run step" in the build graph, to be executed when another step that depends on
    // it is evaluated. The part below that adds a "test step" will establish such a
    // dependency.
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Expose a "test step" to the `zig build` command that runs all unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
