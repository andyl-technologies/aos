"""Pins registry SPA dependencies and preserves Cargo compiler feature roles."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

REGISTRY_WEB_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "base64": crate.spec(version = "=0.22.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(features = ["pkcs8"], version = "=2.2.0"),
    "flate2": crate.spec(default_features = False, features = ["rust_backend"], version = "=1.1.9"),
    "gloo-net": crate.spec(default_features = False, features = ["http"], version = "=0.6.0"),
    "hex": crate.spec(version = "=0.4.3"),
    "leptos": crate.spec(features = ["csr"], version = "=0.7.8"),
    "leptos_router": crate.spec(version = "=0.7.8"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(features = ["derive", "rc"], version = "=1.0.228"),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(features = ["compress"], version = "=0.10.9"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "toml": crate.spec(version = "=0.8.23"),
    "wasm-bindgen": crate.spec(version = "=0.2.126"),
    "wasm-bindgen-futures": crate.spec(version = "=0.4.76"),
}

# Generator dependencies and browser/native target libraries retain their own units.
REGISTRY_WEB_FEATURE_VARIANTS = {
    "indexmap": json.encode({
        "features": [
            "default",
            "std"
        ],
        "resolved_features": [
            "default",
            "serde",
            "std"
        ],
        "version": "2.14.0"
    }),
    "serde": json.encode({
        "exec_features": [
            "default",
            "derive",
            "serde_derive",
            "std"
        ],
        "features": [
            "default",
            "derive",
            "rc",
            "serde_derive",
            "std"
        ],
        "resolved_features": [
            "alloc",
            "default",
            "derive",
            "rc",
            "serde_derive",
            "std"
        ],
        "version": "1.0.228"
    }),
    "serde_core": json.encode({
        "exec_features": [
            "result",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "rc",
            "result",
            "std"
        ],
        "resolved_features": [
            "alloc",
            "default",
            "rc",
            "result",
            "std"
        ],
        "version": "1.0.228"
    }),
    "syn": json.encode({
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
            "proc-macro",
            "visit",
            "visit-mut"
        ],
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
        "version": "2.0.118"
    }),
}

REGISTRY_WEB_WASM_FEATURE_VARIANTS = {
    # Cargo compiles this macro dependency on the execution platform without
    # Serde, even though the resolver includes Serde on native target platforms.
    "indexmap": json.encode({
        "version": "2.14.0",
        "features": ["default", "std"],
        "resolved_features": ["default", "std"],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": ["serde"],
            "x86_64-unknown-linux-gnu": ["serde"],
        },
    }),
    "serde": json.encode({
        "exec_features": [
            "default",
            "derive",
            "serde_derive",
            "std"
        ],
        "features": [
            "default",
            "derive",
            "rc",
            "serde_derive",
            "std"
        ],
        "resolved_features": [
            "default",
            "derive",
            "rc",
            "serde_derive",
            "std"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "alloc"
            ],
            "x86_64-unknown-linux-gnu": [
                "alloc"
            ]
        },
        "version": "1.0.228"
    }),
    "serde_core": json.encode({
        "exec_features": [
            "result",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "rc",
            "result",
            "std"
        ],
        "resolved_features": [
            "alloc",
            "default",
            "rc",
            "result",
            "std"
        ],
        "version": "1.0.228"
    }),
    "syn": json.encode({
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
            "proc-macro",
            "visit",
            "visit-mut"
        ],
        "resolved_features": [
            "clone-impls",
            "default",
            "derive",
            "extra-traits",
            "full",
            "parsing",
            "printing",
            "proc-macro",
            "visit",
            "visit-mut"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "fold"
            ],
            "x86_64-unknown-linux-gnu": [
                "fold"
            ]
        },
        "version": "2.0.118"
    }),
}
