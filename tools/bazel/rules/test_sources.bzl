"""Materializes declared repository source data for recursive contract audits."""

load(":license.bzl", "license_tags")

def _repository_test_sources_impl(ctx):
    output = ctx.actions.declare_directory(ctx.label.name + ".root")
    arguments = ctx.actions.args()
    arguments.add(ctx.file._copy)
    arguments.add("--source", ctx.file.manifest.dirname + "/source")
    arguments.add("--manifest", ctx.file.manifest)
    arguments.add("--output", output.path)
    ctx.actions.run(
        executable = ctx.file._python,
        arguments = [arguments],
        inputs = depset(
            [ctx.file.manifest, ctx.file._copy, ctx.file._tool_identity],
            transitive = [ctx.attr.sources[DefaultInfo].files],
        ),
        outputs = [output],
        mnemonic = "AosRepositoryTestSources",
        use_default_shell_env = False,
    )
    return [DefaultInfo(files = depset([output]), runfiles = ctx.runfiles(files = [output]))]

_repository_test_sources = rule(
    implementation = _repository_test_sources_impl,
    attrs = {
        "manifest": attr.label(mandatory = True, allow_single_file = True),
        "sources": attr.label(mandatory = True),
        "_copy": attr.label(default = "//tools/bazel/metadata:copy_repository_test_sources.py", allow_single_file = True),
        "_python": attr.label(default = "@aos_tools//:python", allow_single_file = True, cfg = "exec"),
        "_tool_identity": attr.label(default = "@aos_tools//:closure.json", allow_single_file = True, cfg = "exec"),
    },
)

def aos_repository_test_sources(name, manifest, sources, license_domain = "apache-host", tags = [], **kwargs):
    """Creates regular-file test data without linking or executing audited code."""
    _repository_test_sources(
        name = name,
        manifest = manifest,
        sources = sources,
        testonly = True,
        tags = license_tags(tags, license_domain),
        **kwargs
    )
