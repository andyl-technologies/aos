"""Declares the complete installed artifact set of a Nix package."""

AosPackageInfo = provider(fields = ["manifest", "artifacts"])

def _destination(value):
    if not value or value.startswith("/") or "\\" in value:
        fail("package destination must be a relative POSIX path: " + value)
    if any([part in ["", ".", ".."] for part in value.split("/")]):
        fail("package destination contains an invalid component: " + value)
    return value

def _package_impl(ctx):
    entries = []
    outputs = []
    destinations = {}
    for target, destination in ctx.attr.artifacts.items():
        destination = _destination(destination)
        if destination in destinations:
            fail("duplicate package destination: " + destination)
        destinations[destination] = True
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1 or files[0].is_directory:
            fail("each package artifact must select exactly one file: " + str(target.label))
        output = ctx.actions.declare_file(ctx.label.name + ".files/" + destination)
        executable = destination in ctx.attr.executables
        ctx.actions.symlink(output = output, target_file = files[0], is_executable = executable)
        outputs.append(output)
        entries.append({
            "destination": destination,
            "source": ctx.label.name + ".files/" + destination,
            "mode": "0755" if executable else "0644",
        })
    for destination in ctx.attr.executables:
        if destination not in destinations:
            fail("executable destination is not a declared artifact: " + destination)
    manifest = ctx.actions.declare_file(ctx.label.name + ".aos-package.json")
    label = str(ctx.label)
    if label.startswith("@@//"):
        label = label[2:]
    ctx.actions.write(manifest, json.encode({
        "schema_version": 1,
        "label": label,
        "name": ctx.attr.package_name,
        "version": ctx.attr.version,
        "license": ctx.attr.license_expression,
        "license_domain": ctx.attr.license_domain,
        "artifacts": sorted(entries, key = _artifact_destination),
    }) + "\n")
    return [
        DefaultInfo(files = depset([manifest] + outputs)),
        AosPackageInfo(manifest = manifest, artifacts = depset(outputs)),
        OutputGroupInfo(aos_package = depset([manifest] + outputs)),
    ]

def _artifact_destination(entry):
    return entry["destination"]

aos_package = rule(
    implementation = _package_impl,
    attrs = {
        "artifacts": attr.label_keyed_string_dict(mandatory = True, allow_files = True),
        "executables": attr.string_list(),
        "package_name": attr.string(mandatory = True),
        "version": attr.string(mandatory = True),
        "license_expression": attr.string(mandatory = True),
        "license_domain": attr.string(mandatory = True, values = ["apache-host", "permissive-protocol", "gpl-qemu"]),
    },
)
