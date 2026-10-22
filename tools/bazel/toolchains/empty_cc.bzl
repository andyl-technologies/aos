"""Provides empty allocator metadata without selecting a C/C++ toolchain."""

load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _empty_cc_info_impl(_ctx):
    return [CcInfo()]

# Pure Rust WASM links its allocator from the target standard library. An empty
# cc_library would still demand an unrelated target C/C++ compiler at analysis.
empty_cc_info = rule(implementation = _empty_cc_info_impl)
