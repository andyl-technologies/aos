"""Runs ordinary rules_rust libtest artifacts with isolated case scheduling."""

load("@aos_tools//:paths.bzl", "AOS_TOOLS")
load("@rules_rust//rust:defs.bzl", "rust_test")

def _runfile(ctx, file):
    path = file.short_path
    if path.startswith("../"):
        path = path[3:]
    else:
        path = ctx.workspace_name + "/" + path
    return '"${TEST_SRCDIR:?}/"' + _quote(path)

def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"

def _libtest_impl(ctx):
    binary = ctx.executable.binary
    if ctx.attr.jobs < 1:
        fail("test concurrency must be positive")
    script = ctx.actions.declare_file(ctx.label.name)
    command = [
        _quote(AOS_TOOLS.python), _runfile(ctx, ctx.file._runner),
        "--binary", _runfile(ctx, binary),
        "--policy", _runfile(ctx, ctx.file._policy),
        "--package", _quote(ctx.attr.package_name),
        "--jobs", str(ctx.attr.jobs),
    ]
    ctx.actions.write(script,
        "#!" + AOS_TOOLS.bash + "\nset -euo pipefail\nexec " + " ".join(command) + ' "$@"\n',
        is_executable = True)
    runfiles = ctx.runfiles(files = [
        binary, ctx.file._runner, ctx.file._policy,
        ctx.file._python, ctx.file._bash, ctx.file._tool_identity,
    ])
    runfiles = runfiles.merge(ctx.attr.binary[DefaultInfo].default_runfiles)
    environment = ctx.attr.binary[RunEnvironmentInfo].environment if RunEnvironmentInfo in ctx.attr.binary else {}
    return [
        DefaultInfo(executable = script, runfiles = runfiles),
        RunEnvironmentInfo(environment = environment),
    ]

_libtest_test = rule(
    implementation = _libtest_impl,
    test = True,
    attrs = {
        "binary": attr.label(mandatory = True, executable = True, cfg = "target"),
        "package_name": attr.string(mandatory = True),
        "jobs": attr.int(default = 4),
        "_runner": attr.label(default = "//tools/bazel/testing:runner.py", allow_single_file = True),
        "_policy": attr.label(default = "//tools/bazel/testing:policy.json", allow_single_file = True),
        "_python": attr.label(default = "@aos_tools//:python", allow_single_file = True),
        "_bash": attr.label(default = "@aos_tools//:bash", allow_single_file = True),
        "_tool_identity": attr.label(default = "@aos_tools//:closure.json", allow_single_file = True),
    },
)

def aos_rust_test(name, package_name, jobs = 4, tags = [], timeout = "long", size = "medium", args = [], **kwargs):
    """Preserves Rust compilation/runfiles while replacing only test scheduling."""
    if kwargs.get("env_inherit", []):
        fail("declare test environment through env; ambient inheritance is not supported")
    rust_test(
        name = name + "_binary",
        tags = tags + ["manual", "aos-libtest-artifact"],
        **kwargs
    )
    test_attributes = {}
    for key in ["visibility", "target_compatible_with", "exec_compatible_with"]:
        if key in kwargs:
            test_attributes[key] = kwargs[key]
    _libtest_test(
        name = name,
        binary = ":" + name + "_binary",
        package_name = package_name,
        jobs = jobs,
        tags = tags,
        timeout = timeout,
        size = size,
        args = args,
        **test_attributes
    )
