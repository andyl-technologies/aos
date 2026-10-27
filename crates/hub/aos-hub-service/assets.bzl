"""Retains the exact browser assets staged by the service's source generator."""

load("@rules_rust//rust:rust_common.bzl", "BuildInfo")

def _console_assets_snapshot_impl(ctx):
    directory = ctx.attr.generator[BuildInfo].out_dir
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    arguments = ctx.actions.args()
    arguments.add(ctx.file._snapshot)
    arguments.add("--directory", directory.path)
    arguments.add("--output", output)
    for filename in ["hub-console.js", "hub-console_bg.wasm", "hub-console.css"]:
        arguments.add("--file", filename)
    ctx.actions.run(
        executable = ctx.file._python,
        arguments = [arguments],
        inputs = [directory, ctx.file._snapshot, ctx.file._tool_identity],
        outputs = [output],
        mnemonic = "AosConsoleAssetsSnapshot",
        use_default_shell_env = False,
    )
    return [DefaultInfo(files = depset([output]))]

console_assets_snapshot = rule(
    implementation = _console_assets_snapshot_impl,
    attrs = {
        "generator": attr.label(mandatory = True, providers = [BuildInfo]),
        "_snapshot": attr.label(default = "//tools/bazel/metadata:snapshot_generated_sources.py", allow_single_file = True),
        "_python": attr.label(default = "@aos_tools//:python", allow_single_file = True, cfg = "exec"),
        "_tool_identity": attr.label(default = "@aos_tools//:closure.json", allow_single_file = True, cfg = "exec"),
    },
    doc = "Requires exactly three staged console assets and hashes their bytes for parity checks.",
)
