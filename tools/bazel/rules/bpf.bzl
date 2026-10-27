"""Compiles BPF objects with immutable AOS tools, retaining BTF and CO-RE data."""

load("@aos_bpf_tools//:paths.bzl", "BPF_TOOLS")
load(":license.bzl", "license_tags")

def _bpf_object_impl(ctx):
    unstripped = ctx.actions.declare_file(ctx.label.name + ".debug.o")
    output = ctx.actions.declare_file(ctx.label.name + ".o")
    arguments = ctx.actions.args()
    arguments.add_all([
        "-target", "bpf", "-O2", "-g",
        "-D__TARGET_ARCH_" + BPF_TOOLS.architecture,
        "-I" + BPF_TOOLS.kernel_headers,
        "-I" + BPF_TOOLS.libbpf_headers,
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        # BTF records source locations too. A sandbox's private working
        # directory must never become part of a kernel policy artifact.
        "-fdebug-compilation-dir=.",
        "-c", ctx.file.src.path, "-o", unstripped.path,
    ])
    ctx.actions.run(
        executable = ctx.file._clang,
        arguments = [arguments],
        inputs = depset([ctx.file.src, ctx.file._closure] + ctx.files._headers),
        outputs = [unstripped],
        env = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1"},
        mnemonic = "AosBpfCompile",
        progress_message = "Compiling BPF policy %{label}",
    )
    # llvm-strip -g removes DWARF, whose include paths are build inputs, while
    # keeping the BTF types, source lines, and relocations needed by libbpf.
    ctx.actions.run(
        executable = ctx.file._strip,
        arguments = ["-g", "-o", output.path, unstripped.path],
        inputs = [unstripped, ctx.file._closure],
        outputs = [output],
        env = {"LANG": "C", "LC_ALL": "C"},
        mnemonic = "AosBpfStrip",
    )
    return [DefaultInfo(files = depset([output]))]

_aos_bpf_object = rule(
    implementation = _bpf_object_impl,
    attrs = {
        "src": attr.label(mandatory = True, allow_single_file = [".bpf.c"]),
        "_clang": attr.label(default = "@aos_bpf_tools//:bin/clang", allow_single_file = True, cfg = "exec"),
        "_strip": attr.label(default = "@aos_bpf_tools//:bin/llvm-strip", allow_single_file = True, cfg = "exec"),
        "_closure": attr.label(default = "@aos_bpf_tools//:closure.json", allow_single_file = True, cfg = "exec"),
        "_headers": attr.label(default = "@aos_bpf_tools//:headers"),
    },
)

def aos_bpf_object(name, src, license_domain, tags = [], **kwargs):
    """Declares an explicitly licensed BPF object without compiler discovery."""
    # The BPF instruction set is shared, but tracing register layouts depend
    # on the kernel architecture. Reject a different configured target rather
    # than silently using this native Nix binding's __TARGET_ARCH definition.
    _aos_bpf_object(
        name = name,
        src = src,
        tags = license_tags(tags, license_domain),
        target_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:" + ("x86_64" if BPF_TOOLS.architecture == "x86" else "aarch64"),
        ],
        **kwargs
    )
