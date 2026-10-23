"""Keeps the daemon's four Cargo feature graphs coherent across library edges.

Development dependencies belong to the selected daemon package. They enable
engine and QEMU test APIs without enabling dependencies' own development
features. Recovery changes the store and campaign crate identities throughout
that same graph, including indirect references through the control libraries.
"""

load(":compile.bzl", "rust_library")

DAEMON_VARIANTS = {
    "": [],
    "_test_support": ["test-support"],
    "_recovery_faults": ["destructive-recovery-faults"],
    "_all_features": ["destructive-recovery-faults", "test-support"],
}

_PACKAGE_PATHS = {
    "engine": "//crates/crucible/engine/crucible-engine",
    "session": "//crates/crucible/control/crucible-session",
    "api": "//crates/crucible/control/crucible-control-api",
    "client": "//crates/crucible/control/crucible-control-client",
    "server": "//crates/crucible/control/crucible-control-server",
    "qemu": "//crates/crucible/qemu/crucible-qemu-host",
    "s3": "//crates/crucible/storage/crucible-store-s3",
    "campaign": "//crates/crucible/engine/crucible-campaign",
    "store": "//crates/crucible/storage/crucible-store",
}

_LIBRARY_EDGES = {
    "engine": ["campaign", "store"],
    "session": ["engine"],
    "api": ["engine", "session"],
    "client": ["engine", "session", "api"],
    "server": ["engine", "session", "api", "client"],
    "qemu": ["engine"],
    "s3": ["store"],
}

def daemon_dependencies(names, suffix, development = False):
    """Returns one consistent set of Rust library identities for a daemon root."""
    result = []
    recovery = "destructive-recovery-faults" in DAEMON_VARIANTS[suffix]
    for name in names:
        if name in ["campaign", "store"]:
            target = "lib_recovery_faults" if recovery else "lib"
        else:
            target = ("lib_for_daemon_tests" if development else "lib_for_daemon") + suffix
        result.append(_PACKAGE_PATHS[name] + ":" + target)
    return result

def _features(component, features, development):
    support = "test-support" in features
    if component == "engine":
        return ["default", "test-double", "test-support"] if development or support else ["default"]
    if component == "qemu":
        return ["default", "test-support"] if development or support else ["default"]
    if component == "server":
        return ["default", "test-support"] if support else ["default"]
    return ["default"] if component == "session" else []

def daemon_dependency_libraries(component, package, sources, common_deps, compile_data = []):
    """Declares production and development libraries for the selected daemon graph."""
    for development in [False, True]:
        for suffix, features in DAEMON_VARIANTS.items():
            crate_features = _features(component, features, development)
            extra_deps = []
            if component == "engine" and "test-double" in crate_features:
                extra_deps = ["//crates/crucible/protocol/crucible-qemu-shmem:lib"]
            rust_library(
                name = ("lib_for_daemon_tests" if development else "lib_for_daemon") + suffix,
                testonly = development,
                package = package,
                lint_config = "//tools/bazel/rules:workspace_lints",
                crate_name = package.name.replace("-", "_"),
                crate_root = "src/lib.rs",
                srcs = sources,
                compile_data = compile_data,
                crate_features = crate_features,
                deps = common_deps + daemon_dependencies(_LIBRARY_EDGES[component], suffix, development) + extra_deps,
            )
