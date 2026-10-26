"""Pins the portable core and temporary-file fixtures used by the sysctl handler."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

KERNEL_TUNABLE_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "thiserror": crate.spec(version = "=2.0.18"),
}

KERNEL_TUNABLE_TESTS_PACKAGES = dict(
    KERNEL_TUNABLE_PACKAGES,
    tempfile = crate.spec(version = "=3.27.0"),
)

# Foreign-only tempfile dependencies resolve the full Syn parser. Native
# procedural macros retain Cargo's actual derive-only parser compilation.
KERNEL_TUNABLE_TESTS_FEATURE_VARIANTS = {
    # The multi-platform tempfile lock also enables Serde allocation features
    # that are absent from Cargo's actual native compiler invocations.
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
        "features": ["clone-impls", "default", "derive", "parsing", "printing", "proc-macro"],
    }),
}
