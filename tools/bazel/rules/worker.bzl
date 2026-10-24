"""Bundles the Worker and all content-addressed assets with declared tools."""

load(":license.bzl", "AosLicenseInfo", "aos_license_aspect", "check_domains", "license_tags")

def _directory(files, expected):
    actual = sorted([file.basename for file in files])
    if actual != sorted(expected):
        fail("Worker bundle input inventory differs: expected " + str(expected) + ", received " + str(actual))
    directories = {file.dirname: True for file in files}
    if len(directories) != 1:
        fail("Worker bundle inputs must share their declared directory")
    return files[0].dirname

def _worker_bundle_impl(ctx):
    for target in [ctx.attr.wasm, ctx.attr.static_assets] + ctx.attr.console:
        check_domains(ctx.label, ctx.attr.license_domain, target[AosLicenseInfo].domains.to_list())
    static = _directory(ctx.files.static_assets, ["style.css", "app.js", "theme.js", "Geist-Variable.woff2", "GeistMono-Variable.woff2", "OFL.txt"])
    console = _directory(ctx.files.console, ["hub-console.js", "hub-console_bg.wasm", "hub-console.css"])
    templates = _directory(ctx.files._templates, ["glue.js", "shim.js", "rewrite.mjs"])
    javascript = ctx.actions.declare_file(ctx.label.name + "/shim.mjs")
    wasm = ctx.actions.declare_file(ctx.label.name + "/index.wasm")
    assets = ctx.actions.declare_directory(ctx.label.name + "/assets")
    arguments = ctx.actions.args()
    arguments.add_all(["--wasm", ctx.file.wasm.path, "--templates", templates, "--static", static, "--console", console])
    arguments.add_all(["--shim", javascript.path, "--output-wasm", wasm.path, "--assets", assets.path])
    if ctx.attr.test_hooks:
        arguments.add("--test-hooks")
    ctx.actions.run(
        executable = ctx.file._bundler,
        arguments = [arguments],
        inputs = depset([ctx.file.wasm, ctx.file._closure] + ctx.files.static_assets + ctx.files.console + ctx.files._templates),
        outputs = [javascript, wasm, assets],
        env = {"LANG": "C", "LC_ALL": "C"},
        mnemonic = "AosWorkerBundle",
    )
    return [
        DefaultInfo(files = depset([javascript, wasm, assets])),
        OutputGroupInfo(worker_javascript = depset([javascript]), worker_wasm = depset([wasm]), worker_assets = depset([assets])),
    ]

_worker_bundle = rule(
    implementation = _worker_bundle_impl,
    attrs = {
        "wasm": attr.label(mandatory = True, allow_single_file = [".wasm"], aspects = [aos_license_aspect]),
        "static_assets": attr.label(mandatory = True, aspects = [aos_license_aspect]),
        "console": attr.label_list(mandatory = True, aspects = [aos_license_aspect]),
        "test_hooks": attr.bool(default = False),
        "license_domain": attr.string(mandatory = True),
        "_templates": attr.label_list(default = ["//tools/bazel/worker:glue.js", "//tools/bazel/worker:shim.js", "//tools/bazel/worker:rewrite.mjs"], allow_files = True),
        "_bundler": attr.label(default = "@aos_worker_tools//:bin/bundle-worker", allow_single_file = True, cfg = "exec"),
        "_closure": attr.label(default = "@aos_worker_tools//:closure.json", allow_single_file = True, cfg = "exec"),
    },
)

def aos_worker_bundle(name, license_domain = "apache-host", tags = [], **kwargs):
    """Declares the full deployment, rejecting production builds with test hooks."""
    _worker_bundle(name = name, license_domain = license_domain, tags = license_tags(tags, license_domain), **kwargs)
