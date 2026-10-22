"""Constructs immutable fixture variants for semantic cache invalidation."""

import argparse
from pathlib import Path


def replace(root, filename, original, replacement):
    path = root / filename
    text = path.read_text()
    if text.count(original) != 1:
        raise ValueError(f"fixture mutation no longer applies: {filename}: {original}")
    path.write_text(text.replace(original, replacement))


def mutate(root, variant, cpu=None):
    """Changes exactly the selected semantic input in a fixture snapshot."""
    if variant == "header":
        replace(root, "library.h", "HEADER_OFFSET 0", "HEADER_OFFSET 1")
    elif variant == "cpp-source":
        replace(root, "library.cc", "return AOS_FIXTURE_VALUE", "return 1 + AOS_FIXTURE_VALUE")
    elif variant == "rust-source":
        replace(root, "lib.rs", "fixture_generated::answer()", "1 + fixture_generated::answer()")
    elif variant == "generated-input":
        replace(root, "value.txt", "42", "43")
    elif variant == "generator-environment":
        replace(root, "BUILD.bazel", '"AOS_FIXTURE_OFFSET": "0"', '"AOS_FIXTURE_OFFSET": "1"')
    elif variant in {"feature", "rust-flags"}:
        setting = 'crate_features = ["extra"],' if variant == "feature" else 'rustc_flags = ["-Copt-level=1"],'
        replace(root, "BUILD.bazel", 'crate_name = "fixture_library",', 'crate_name = "fixture_library",\n    ' + setting)
    elif variant == "link-flags":
        replace(root, "BUILD.bazel", 'name = "cpp_app",', 'name = "cpp_app",\n    linkopts = ["-Wl,--no-undefined"],')
    elif variant in {"rust-cpu", "rust-cpu-baseline"}:
        if cpu not in {"x86_64", "aarch64"}:
            raise ValueError("CPU invalidation requires an explicit supported execution CPU")
        feature = "sse4.2" if cpu == "x86_64" else "crc"
        replace(root, "lib.rs", "fixture_generated::answer()",
                'fixture_generated::answer() + u32::from(cfg!(target_feature = "' + feature + '"))')
        if variant == "rust-cpu":
            selected_cpu = "x86-64-v2" if cpu == "x86_64" else "cortex-a72"
            replace(root, "BUILD.bazel", 'crate_name = "fixture_library",',
                    'crate_name = "fixture_library",\n    rustc_flags = ["-Ctarget-cpu=' + selected_cpu + '"],')
    elif variant in {"sysroot", "sysroot-baseline"}:
        replace(root, "library.cc", '#include "library.h"', '#include "library.h"\n#include <aos-cache-probe.h>')
        replace(root, "library.cc", "return AOS_FIXTURE_VALUE", "return AOS_CACHE_SYSROOT_VALUE")
    elif variant == "pgo-generate":
        for name in ["rust_library", "rust_app", "native_app"]:
            replace(root, "BUILD.bazel", 'name = "' + name + '",',
                    'name = "' + name + '",\n    rustc_flags = ["-Cprofile-generate"],')
    elif variant in {"pgo", "pgo-baseline"}:
        replace(root, "BUILD.bazel", 'name = "rust_library",',
                'name = "rust_library",\n    compile_data = ["cache.profdata"],\n'
                '    rustc_flags = ["-Copt-level=2", "-Cprofile-use=$(location :cache.profdata)"],')
    elif variant != "tool-closure":
        raise ValueError(f"unsupported cache fixture variant: {variant}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--variant", required=True)
    parser.add_argument("--cpu", choices=["x86_64", "aarch64"])
    options = parser.parse_args()
    mutate(options.root / "tools/bazel/tests/fixture", options.variant, options.cpu)
