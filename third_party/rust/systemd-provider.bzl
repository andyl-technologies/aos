"""Pins the installed systemd handlers and boot-runtime dependency features."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

SYSTEMD_PROVIDER_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "base64": crate.spec(version = "=0.22.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures-util": crate.spec(version = "=0.3.32"),
    "hex": crate.spec(version = "=0.4.3"),
    "humantime": crate.spec(version = "=2.3.0"),
    "regex": crate.spec(version = "=1.12.4"),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "net", "process"]),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt-multi-thread", "signal", "sync", "time"]),
    "toml": crate.spec(version = "=0.8.23"),
    "tracing": crate.spec(version = "=0.1.44"),
    "zbus": crate.spec(version = "=5.15.0", default_features = False, features = ["tokio"]),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

# Match the native target and execution units from the independent Cargo oracle.
SYSTEMD_PROVIDER_FEATURE_VARIANTS = {
    "indexmap": json.encode({
        "version": "2.14.0",
        "resolved_features": [
            "default",
            "serde",
            "std"
        ],
        "features": [
            "default",
            "std"
        ]
    }),
    "serde": json.encode({
        "version": "1.0.228",
        "resolved_features": [
            "alloc",
            "default",
            "derive",
            "rc",
            "serde_derive",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "derive",
            "rc",
            "serde_derive",
            "std"
        ],
        "exec_features": [
            "default",
            "derive",
            "serde_derive",
            "std"
        ]
    }),
    "serde_core": json.encode({
        "version": "1.0.228",
        "resolved_features": [
            "alloc",
            "rc",
            "result",
            "std"
        ],
        "features": [
            "alloc",
            "rc",
            "result",
            "std"
        ],
        "exec_features": [
            "result",
            "std"
        ]
    }),
    "syn": json.encode({
        "version": "2.0.118",
        "resolved_features": [
            "clone-impls",
            "default",
            "derive",
            "extra-traits",
            "fold",
            "full",
            "parsing",
            "printing",
            "proc-macro",
            "visit",
            "visit-mut"
        ],
        "features": [
            "clone-impls",
            "default",
            "derive",
            "extra-traits",
            "full",
            "parsing",
            "printing",
            "proc-macro"
        ],
        "exec_features": [
            "clone-impls",
            "default",
            "derive",
            "extra-traits",
            "fold",
            "full",
            "parsing",
            "printing",
            "proc-macro",
            "visit-mut"
        ]
    }),
}
