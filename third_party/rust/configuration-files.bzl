"""Pins the configuration file handler's production and fixture dependencies."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

CONFIGURATION_FILES_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "process"]),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
}

CONFIGURATION_FILES_TESTS_PACKAGES = dict(
    CONFIGURATION_FILES_PACKAGES,
    tempfile = crate.spec(version = "=3.27.0"),
    toml = crate.spec(version = "=0.8.23"),
)

# Match native Cargo compilations rather than the union of foreign-only
# tempfile and TOML dependencies in the cross-platform source lock.
CONFIGURATION_FILES_TESTS_FEATURE_VARIANTS = {
    "indexmap": json.encode({
        "version": "2.14.0",
        "resolved_features": ["default", "serde", "std"],
        "features": ["default", "std"],
    }),
    "proc-macro2": json.encode({
        "version": "1.0.106",
        "resolved_features": ["default", "proc-macro"],
        "features": ["proc-macro"],
    }),
    "quote": json.encode({
        "version": "1.0.46",
        "resolved_features": ["default", "proc-macro"],
        "features": ["proc-macro"],
    }),
    "serde": json.encode({
        "version": "1.0.228",
        "resolved_features": ["alloc", "default", "derive", "rc", "serde_derive", "std"],
        "features": ["default", "derive", "rc", "serde_derive", "std"],
    }),
    "serde_core": json.encode({
        "version": "1.0.228",
        "resolved_features": ["alloc", "rc", "result", "std"],
        "features": ["rc", "result", "std"],
    }),
    "syn": json.encode({
        "version": "2.0.118",
        "resolved_features": ["clone-impls", "default", "derive", "full", "parsing", "printing", "proc-macro"],
        "features": ["clone-impls", "derive", "parsing", "printing", "proc-macro"],
    }),
}
