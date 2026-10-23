"""Produces browser bindings using the declared source-built wasm-bindgen tool."""

load(":license.bzl", "aos_license_aspect", "check_domains", "AosLicenseInfo", "license_tags")

def _wasm_bindgen_impl(ctx):
    check_domains(ctx.label, ctx.attr.license_domain, ctx.attr.wasm[AosLicenseInfo].domains.to_list())
    name = ctx.attr.output_name
    if not name or not all([character in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in name.elems()]):
        fail("browser output_name must be a nonempty file stem")
    javascript = ctx.actions.declare_file(ctx.label.name + "/" + name + ".js")
    wasm = ctx.actions.declare_file(ctx.label.name + "/" + name + "_bg.wasm")
    arguments = ctx.actions.args()
    arguments.add(ctx.file.wasm)
    arguments.add_all(["--target", "web", "--no-typescript"])
    arguments.add("--out-name", name)
    arguments.add("--out-dir", javascript.dirname)
    ctx.actions.run(
        executable = ctx.file._bindgen,
        arguments = [arguments],
        inputs = [ctx.file.wasm, ctx.file._closure],
        outputs = [javascript, wasm],
        env = {"LANG": "C", "LC_ALL": "C"},
        mnemonic = "AosWasmBindgen",
    )
    return [
        DefaultInfo(files = depset([javascript, wasm])),
        OutputGroupInfo(browser_javascript = depset([javascript]), browser_wasm = depset([wasm])),
    ]

_aos_wasm_bindgen = rule(
    implementation = _wasm_bindgen_impl,
    attrs = {
        "wasm": attr.label(mandatory = True, allow_single_file = [".wasm"], aspects = [aos_license_aspect]),
        "output_name": attr.string(mandatory = True),
        "license_domain": attr.string(mandatory = True),
        "_bindgen": attr.label(default = "@aos_wasm_tools//:bin/wasm-bindgen", allow_single_file = True, cfg = "exec"),
        "_closure": attr.label(default = "@aos_wasm_tools//:closure.json", allow_single_file = True, cfg = "exec"),
    },
)

def aos_wasm_bindgen(name, wasm, output_name, license_domain = "apache-host", tags = [], **kwargs):
    """Declares JS and Wasm outputs without allowing tool discovery or downloads."""
    _aos_wasm_bindgen(
        name = name,
        wasm = wasm,
        output_name = output_name,
        license_domain = license_domain,
        tags = license_tags(tags, license_domain),
        **kwargs
    )
