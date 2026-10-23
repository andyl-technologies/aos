"""Compiles declared source generators with explicit package identity and tools."""

# The pinned rules_rust execution rule supplies compiler cfg/env/OUT_DIR metadata.
# Compile the program ourselves so its package metadata matches ordinary targets.
load("@rules_rust//cargo/private:cargo_build_script.bzl", "cargo_build_script_runfiles", _run_build_script = "cargo_build_script")
load("@rules_rust//rust:rust_common.bzl", "BuildInfo")
load(":compile.bzl", "rust_binary")
load(":license.bzl", "license_tags")

def aos_rust_build_script(name, package, src, deps = [], data = [], tools = [], env = {}, crate_features = [], visibility = None):
    """Runs a Rust generator directly; no Cargo executable or manifest is used."""
    rust_binary(
        name = name + "_program",
        package = package,
        crate_root = src,
        srcs = [src],
        deps = deps,
        data = tools,
        crate_features = crate_features,
        tags = ["manual"],
        visibility = visibility,
    )

    cargo_build_script_runfiles(
        name = name + "_inputs",
        data = data,
        visibility = ["//visibility:private"],
    )

    _run_build_script(
        name = name,
        script = ":" + name + "_program",
        data_runfiles = ":" + name + "_inputs",
        pkg_name = package.name,
        version = package.version,
        deps = deps,
        data = data,
        tools = tools,
        build_script_env = env,
        crate_features = crate_features,
        use_default_shell_env = 0,
        tags = license_tags([], package.license_domain),
        visibility = visibility,
    )

def _generated_sources_snapshot_impl(ctx):
    directory = ctx.attr.generator[BuildInfo].out_dir
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    arguments = ctx.actions.args()
    arguments.add(ctx.file._snapshot)
    arguments.add("--directory", directory.path)
    arguments.add("--output", output)
    for filename in ctx.attr.files:
        if not filename.endswith((".rs", ".bin")) or any([part in ["", ".", ".."] for part in filename.split("/")]):
            fail("generated source or descriptor must have an unambiguous relative path: " + filename)
        arguments.add("--file", filename)
    ctx.actions.run(
        executable = ctx.file._python,
        arguments = [arguments],
        inputs = [directory, ctx.file._snapshot, ctx.file._tool_identity],
        outputs = [output],
        mnemonic = "AosGeneratedSourcesSnapshot",
        use_default_shell_env = False,
    )
    return [DefaultInfo(files = depset([output]))]

aos_generated_sources_snapshot = rule(
    implementation = _generated_sources_snapshot_impl,
    attrs = {
        "generator": attr.label(mandatory = True, providers = [BuildInfo]),
        "files": attr.string_list(mandatory = True),
        "_snapshot": attr.label(default = "//tools/bazel/metadata:snapshot_generated_sources.py", allow_single_file = True),
        "_python": attr.label(default = "@aos_tools//:python", allow_single_file = True, cfg = "exec"),
        "_tool_identity": attr.label(default = "@aos_tools//:closure.json", allow_single_file = True, cfg = "exec"),
    },
    doc = "Retains digests of an exact generator output inventory for independent source parity checks.",
)
