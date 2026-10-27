"""Declares package lint coverage after every Rust compilation is defined."""

load("@rules_rust//rust:defs.bzl", "rust_clippy")

visibility("public")

def aos_package_clippy(name):
    """Checks every owned Rust compilation, including feature and test copies.

    Call this at the end of the package's BUILD file. Inspecting declarations
    keeps lint coverage aligned with new integration tests and controller
    copies without maintaining a second compilation target list.
    """
    kinds = ["rust_library", "rust_binary", "rust_proc_macro", "rust_shared_library", "rust_static_library", "rust_test"]
    targets = sorted([
        ":" + target
        for target, attributes in native.existing_rules().items()
        if attributes["kind"] in kinds
    ])
    if not targets:
        fail("package lint root requires declared Rust compilations")
    rust_clippy(name = name, testonly = True, deps = targets)
