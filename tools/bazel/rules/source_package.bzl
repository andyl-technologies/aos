"""Declares package ownership and source inputs for repository-wide audits."""

AosSourceCatalogInfo = provider(fields = ["packages", "sources"])

def _source_package_impl(ctx):
    sources = ctx.files.srcs
    data = ctx.files.data
    if not sources:
        fail("source package must own at least one source file")
    for source in sources + data:
        if not source.is_source or source.owner.package != ctx.label.package or not source.short_path.startswith(ctx.label.package + "/"):
            fail("source package may only own checked-in files beneath its package: " + source.short_path)
    identity = json.decode(ctx.attr.identity)
    identity["directory"] = ctx.label.package
    identity["sources"] = sorted([source.short_path for source in sources])
    return [
        DefaultInfo(files = depset(sources), runfiles = ctx.runfiles(files = sources + data)),
        AosSourceCatalogInfo(packages = [identity], sources = depset(sources)),
    ]

_source_package = rule(
    implementation = _source_package_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".rs"], mandatory = True),
        "data": attr.label_list(allow_files = True),
        "identity": attr.string(mandatory = True),
    },
)

def aos_source_package(name, package, srcs, data = [], **kwargs):
    """Exports source ownership from the same identity as compilation targets."""
    _source_package(
        name = name,
        srcs = srcs,
        data = data,
        identity = json.encode({
            "name": package.name,
            "version": package.version,
            "edition": package.edition,
            "license": package.license_expression,
            "license_domain": package.license_domain,
        }),
        **kwargs
    )

def _package_name(package):
    return package["name"]

def _source_catalog_impl(ctx):
    packages = []
    names = {}
    directories = {}
    sources = []
    for target in ctx.attr.packages:
        catalog = target[AosSourceCatalogInfo]
        sources.append(catalog.sources)
        for package in catalog.packages:
            if package["name"] in names or package["directory"] in directories:
                fail("duplicate source package name or directory: " + package["name"])
            names[package["name"]] = True
            directories[package["directory"]] = True
            packages.append(package)
    if not packages:
        fail("source catalog must contain at least one package")
    manifest = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(manifest, json.encode({
        "schema_version": 1,
        "packages": sorted(packages, key = _package_name),
    }) + "\n")
    source_files = depset(transitive = sources)
    # Package loading may require fixtures even when only Rust ownership is
    # queried. Retain those inputs without adding them to the Rust catalog.
    runfiles = ctx.runfiles(files = [manifest], transitive_files = source_files).merge_all([
        target[DefaultInfo].default_runfiles
        for target in ctx.attr.packages
    ])
    return [
        DefaultInfo(
            files = depset([manifest]),
            runfiles = runfiles,
        ),
        AosSourceCatalogInfo(packages = packages, sources = source_files),
        OutputGroupInfo(aos_source_files = source_files),
    ]

aos_source_catalog = rule(
    implementation = _source_catalog_impl,
    attrs = {"packages": attr.label_list(providers = [AosSourceCatalogInfo])},
    doc = "Collects declared source ownership and runtime audit inputs without compiling packages.",
)
