"""Keeps daemon and CLI consumer features coherent across library edges.

Development dependencies belong to the selected daemon package. They enable
engine and QEMU test APIs without enabling dependencies' own development
features. Recovery changes the store and campaign crate identities throughout
that same graph, including indirect references through the control libraries.
CLI test-double consumers additionally enable session test doubles throughout
the graph, without enabling the daemon's independent test-support feature.
"""

load(":compile.bzl", "rust_library")

DAEMON_VARIANTS = {
    "": [],
    "_test_support": ["test-support"],
    "_recovery_faults": ["destructive-recovery-faults"],
    "_all_features": ["destructive-recovery-faults", "test-support"],
}

_PACKAGE_PATHS = {
    "engine": "//crates/crucible/crucible-engine",
    "session": "//crates/crucible/crucible-session",
    "api": "//crates/crucible/crucible-control-api",
    "client": "//crates/crucible/crucible-control-client",
    "server": "//crates/crucible/crucible-control-server",
    "qemu": "//crates/crucible/crucible-qemu-host",
    "s3": "//crates/crucible/crucible-store-s3",
    "campaign": "//crates/crucible/crucible-campaign",
    "store": "//crates/crucible/crucible-store",
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

def _library_target(suffix, development, session_test_double):
    prefix = "lib_for_daemon_tests" if development else "lib_for_daemon"
    return prefix + ("_session_test_double" if session_test_double else "") + suffix

def daemon_dependencies(names, suffix, development = False, session_test_double = False):
    """Returns one consistent set of Rust library identities for a daemon root."""
    result = []
    recovery = "destructive-recovery-faults" in DAEMON_VARIANTS[suffix]
    for name in names:
        if name in ["campaign", "store"]:
            target = "lib_recovery_faults" if recovery else "lib"
        else:
            target = _library_target(suffix, development, session_test_double)
        result.append(_PACKAGE_PATHS[name] + ":" + target)
    return result

def _features(component, features, development, session_test_double):
    support = "test-support" in features
    if component == "engine":
        if development or support:
            return ["default", "test-double", "test-support"]
        return ["default", "test-double"] if session_test_double else ["default"]
    if component == "qemu":
        return ["default", "test-support"] if development or support else ["default"]
    if component == "server":
        return ["default", "test-support"] if support else ["default"]
    if component == "session":
        return ["default", "test-double"] if session_test_double else ["default"]
    return []

def daemon_dependency_libraries(component, package, sources, common_deps, compile_data = [], extra_features = []):
    """Declares production and development libraries for the selected daemon graph."""
    for session_test_double in [False, True]:
        for development in [False, True]:
            for suffix, features in DAEMON_VARIANTS.items():
                crate_features = _features(component, features, development, session_test_double)
                extra_deps = []
                if component == "engine" and "test-double" in crate_features:
                    extra_deps = ["//crates/crucible/crucible-qemu-shmem:lib"]
                rust_library(
                    name = _library_target(suffix, development, session_test_double),
                    testonly = development,
                    package = package,
                    lint_config = "//tools/bazel/rules:workspace_lints",
                    crate_name = package.name.replace("-", "_"),
                    crate_root = "src/lib.rs",
                    srcs = sources,
                    compile_data = compile_data,
                    crate_features = crate_features + extra_features,
                    deps = common_deps + daemon_dependencies(_LIBRARY_EDGES[component], suffix, development, session_test_double) + extra_deps,
                )

def daemon_session_test_double_libraries(package, sources, common_deps, library_names):
    """Declares daemon libraries for CLI roots that enable session test doubles."""
    for development in [False, True]:
        for suffix, features in DAEMON_VARIANTS.items():
            rust_library(
                name = ("lib_for_tests" if development else "lib") + "_session_test_double" + suffix,
                testonly = development,
                package = package,
                lint_config = "//tools/bazel/rules:workspace_lints",
                crate_name = package.name.replace("-", "_"),
                crate_root = "src/lib.rs",
                srcs = sources,
                crate_features = ["default"] + features,
                deps = common_deps + daemon_dependencies(library_names, suffix, development, session_test_double = True),
            )
