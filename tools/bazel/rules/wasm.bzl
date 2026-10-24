"""Produces browser bindings using the declared source-built wasm-bindgen tool."""

load(":license.bzl", "aos_license_aspect", "check_domains", "AosLicenseInfo", "license_tags")

def _wasm_bindgen_impl(ctx):
    check_domains(ctx.label, ctx.attr.license_domain, ctx.attr.wasm[AosLicenseInfo].domains.to_list())
    name = ctx.attr.output_name
    if not name or not all([character in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in name.elems()]):
        fail("browser output_name must be a nonempty file stem")
    javascript = ctx.actions.declare_file(ctx.label.name + "/" + name + ".js")
    wasm = ctx.actions.declare_file(ctx.label.name + "/" + name + "_bg.wasm")
    declarations = []
    if ctx.attr.typescript:
        declarations = [
            ctx.actions.declare_file(ctx.label.name + "/" + name + ".d.ts"),
            ctx.actions.declare_file(ctx.label.name + "/" + name + "_bg.wasm.d.ts"),
        ]
    arguments = ctx.actions.args()
    arguments.add(ctx.file.wasm)
    arguments.add_all(["--target", "web"])
    if not ctx.attr.typescript:
        arguments.add("--no-typescript")
    arguments.add("--out-name", name)
    arguments.add("--out-dir", javascript.dirname)
    ctx.actions.run(
        executable = ctx.file._bindgen,
        arguments = [arguments],
        inputs = [ctx.file.wasm, ctx.file._closure],
        outputs = [javascript, wasm] + declarations,
        env = {"LANG": "C", "LC_ALL": "C"},
        mnemonic = "AosWasmBindgen",
    )
    return [
        DefaultInfo(files = depset([javascript, wasm] + declarations)),
        OutputGroupInfo(browser_javascript = depset([javascript]), browser_wasm = depset([wasm]), browser_typescript = depset(declarations)),
    ]

_aos_wasm_bindgen = rule(
    implementation = _wasm_bindgen_impl,
    attrs = {
        "wasm": attr.label(mandatory = True, allow_single_file = [".wasm"], aspects = [aos_license_aspect]),
        "output_name": attr.string(mandatory = True),
        "typescript": attr.bool(default = False),
        "license_domain": attr.string(mandatory = True),
        "_bindgen": attr.label(default = "@aos_wasm_tools//:bin/wasm-bindgen", allow_single_file = True, cfg = "exec"),
        "_closure": attr.label(default = "@aos_wasm_tools//:closure.json", allow_single_file = True, cfg = "exec"),
    },
)

def aos_wasm_bindgen(name, wasm, output_name, typescript = False, license_domain = "apache-host", tags = [], **kwargs):
    """Declares JS and Wasm outputs without allowing tool discovery or downloads."""
    _aos_wasm_bindgen(
        name = name,
        wasm = wasm,
        output_name = output_name,
        typescript = typescript,
        license_domain = license_domain,
        tags = license_tags(tags, license_domain),
        **kwargs
    )

def _browser_dist_impl(ctx):
    check_domains(ctx.label, ctx.attr.license_domain, ctx.attr.bindings[AosLicenseInfo].domains.to_list())
    files = ctx.attr.bindings[DefaultInfo].files.to_list()
    javascript = [file for file in files if file.basename.endswith(".js")]
    wasm = [file for file in files if file.basename.endswith(".wasm")]
    if len(javascript) != 1 or len(wasm) != 1:
        fail("browser distribution requires one JavaScript and one Wasm binding")
    stem = javascript[0].basename[:-3]
    if wasm[0].basename != stem + "_bg.wasm":
        fail("browser binding filenames must share their generated stem")
    declarations = {file.basename: file for file in files if file.basename.endswith(".d.ts")}
    if len(files) != 2 + len(declarations) or (declarations and sorted(declarations) != [stem + ".d.ts", stem + "_bg.wasm.d.ts"]):
        fail("browser bindings contain an incomplete or unexpected artifact set")

    distribution = ctx.actions.declare_directory(ctx.label.name + ".dist")
    arguments = ctx.actions.args()
    arguments.add(ctx.file._packager)
    arguments.add("--javascript", javascript[0])
    arguments.add("--wasm", wasm[0])
    arguments.add("--stylesheet", ctx.file.stylesheet)
    arguments.add("--output", distribution.path)
    if declarations:
        arguments.add("--typescript", declarations[stem + ".d.ts"])
        arguments.add("--wasm-typescript", declarations[stem + "_bg.wasm.d.ts"])
    ctx.actions.run(
        executable = ctx.file._python,
        arguments = [arguments],
        inputs = files + [ctx.file.stylesheet, ctx.file._packager, ctx.file._tool_identity],
        outputs = [distribution],
        env = {"LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        mnemonic = "AosBrowserDist",
    )
    return [DefaultInfo(files = depset([distribution]))]

_aos_browser_dist = rule(
    implementation = _browser_dist_impl,
    attrs = {
        "bindings": attr.label(mandatory = True, aspects = [aos_license_aspect]),
        "stylesheet": attr.label(mandatory = True, allow_single_file = [".css"]),
        "license_domain": attr.string(mandatory = True),
        "_python": attr.label(default = "@aos_tools//:python", allow_single_file = True, cfg = "exec"),
        "_tool_identity": attr.label(default = "@aos_tools//:closure.json", allow_single_file = True, cfg = "exec"),
        "_packager": attr.label(default = "//tools/bazel/metadata:package_browser_assets.py", allow_single_file = True, cfg = "exec"),
    },
)

def aos_browser_dist(name, bindings, stylesheet, license_domain = "apache-host", tags = [], **kwargs):
    """Packages an immutable registry-compatible browser distribution."""
    _aos_browser_dist(
        name = name,
        bindings = bindings,
        stylesheet = stylesheet,
        license_domain = license_domain,
        tags = license_tags(tags, license_domain),
        **kwargs
    )
