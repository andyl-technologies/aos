"""Exports crate_universe specifications for explicit dependency updates."""

def _specifications_impl(ctx):
    packages = {}
    for name, encoded in ctx.attr.packages.items():
        specification = json.decode(encoded)
        packages[name] = {key.replace("_", "-"): value for key, value in specification.items()}
    annotations = {}
    for name, encoded in ctx.attr.annotations.items():
        version, settings = json.decode(encoded)
        annotations[name + " " + version] = settings
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    specification = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
    ctx.actions.write(specification, json.encode({
        "schema_version": 1,
        "family": ctx.attr.family,
        "packages": packages,
        "annotations": annotations,
        "feature_variants": {name: json.decode(value) for name, value in ctx.attr.feature_variants.items()},
        "permissive_crates": ctx.attr.permissive_crates,
        "platforms": ctx.attr.platforms,
        "license_domain": ctx.attr.license_domain,
        "approved_licenses": ctx.attr.approved_licenses,
        "host_only_licenses": ctx.attr.host_only_licenses,
    }) + "\n")
    contracts = [ctx.file.definition, ctx.file._rules, ctx.file._exporter]
    arguments = ctx.actions.args()
    arguments.add(ctx.file._exporter)
    arguments.add("--input", specification)
    arguments.add("--output", output)
    for source in contracts:
        arguments.add("--contract")
        arguments.add(source.short_path)
        arguments.add(source)
    ctx.actions.run(
        executable = ctx.file._python,
        arguments = [arguments],
        inputs = depset([specification, ctx.file._exporter, ctx.file._tool_identity] + contracts),
        outputs = [output],
        env = {"LANG": "C", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
        mnemonic = "AosCrateSpecifications",
    )
    return [DefaultInfo(files = depset([output]))]

aos_crate_specifications = rule(
    implementation = _specifications_impl,
    attrs = {
        "family": attr.string(mandatory = True),
        "definition": attr.label(mandatory = True, allow_single_file = True),
        "packages": attr.string_dict(mandatory = True),
        "annotations": attr.string_dict(),
        "feature_variants": attr.string_dict(),
        "permissive_crates": attr.string_list(),
        "approved_licenses": attr.string_list(),
        "host_only_licenses": attr.string_list(),
        "platforms": attr.string_list(mandatory = True),
        "license_domain": attr.string(default = "apache-host", values = ["apache-host", "permissive-protocol", "gpl-qemu"]),
        "_python": attr.label(default = "@aos_tools//:python", allow_single_file = True, cfg = "exec"),
        "_tool_identity": attr.label(default = "@aos_tools//:closure.json", allow_single_file = True, cfg = "exec"),
        "_rules": attr.label(default = "//tools/bazel/rules:crates.bzl", allow_single_file = True),
        "_exporter": attr.label(default = "//tools/bazel/metadata:export_specs.py", allow_single_file = True),
    },
)
