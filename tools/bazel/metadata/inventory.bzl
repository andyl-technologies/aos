"""Exports source and dependency metadata from configured first-party targets."""

load("@rules_rust//rust:defs.bzl", "rust_common")

AosInventoryInfo = provider(fields = ["reports"])

def _first_party(label):
    return str(label).startswith("@@//") or str(label).startswith("//")

def _label(label):
    value = str(label)
    return value[2:] if value.startswith("@@//") else value

def _inventory_impl(target, ctx):
    if ctx.rule == None:
        return [AosInventoryInfo(reports = depset())]
    transitive = []
    dependencies = {}
    for name in dir(ctx.rule.attr):
        value = getattr(ctx.rule.attr, name)
        values = value if type(value) == "list" else value.keys() if type(value) == "dict" else [value]
        for dependency in values:
            if type(dependency) == "Target":
                dependencies[_label(dependency.label)] = True
                if AosInventoryInfo in dependency:
                    transitive.append(dependency[AosInventoryInfo].reports)
    external = not _first_party(target.label)
    if external and "rust" not in ctx.rule.kind:
        return [AosInventoryInfo(reports = depset(transitive = transitive))]
    sources = {}
    generated = {}
    for name in dir(ctx.rule.files):
        for source in getattr(ctx.rule.files, name):
            if _first_party(source.owner):
                if source.is_source:
                    sources[source.short_path] = True
                else:
                    generated[source.short_path] = _label(source.owner)
    report = ctx.actions.declare_file(ctx.label.name + ".aos-target.json")
    # The provider also covers inferred roots and libtest crates inherited from
    # libraries/binaries. The optional crate_root attribute does not cover them.
    crate_root = target[rust_common.crate_info].root if rust_common.crate_info in target else None
    ctx.actions.write(report, json.encode({
        "schema_version": 1,
        "external": external,
        "label": _label(target.label),
        "kind": ctx.rule.kind,
        "build_file": ctx.build_file_path,
        "sources": sorted(sources.keys()),
        "generated_inputs": generated,
        "dependencies": sorted(dependencies.keys()),
        "features": getattr(ctx.rule.attr, "crate_features", []),
        "edition": getattr(ctx.rule.attr, "edition", ""),
        "crate_name": getattr(ctx.rule.attr, "crate_name", ""),
        "crate_root": crate_root.short_path if crate_root != None else "",
        "version": getattr(ctx.rule.attr, "version", ""),
        "rustc_flags": getattr(ctx.rule.attr, "rustc_flags", []),
        "rustc_env": getattr(ctx.rule.attr, "rustc_env", {}),
        "copts": getattr(ctx.rule.attr, "copts", []),
        "defines": getattr(ctx.rule.attr, "defines", []),
        "tags": getattr(ctx.rule.attr, "tags", []),
        "target_cpu": ctx.var.get("TARGET_CPU", ctx.var.get("CPU", "")),
    }) + "\n")
    reports = depset([report], transitive = transitive)
    return [AosInventoryInfo(reports = reports), OutputGroupInfo(aos_inventory = reports)]

aos_inventory_aspect = aspect(
    implementation = _inventory_impl,
    attr_aspects = ["*"],
    # A dependency may select an output label rather than its generating rule.
    # Follow it back to capture generator scripts and data as source inputs.
    apply_to_generating_rules = True,
)
