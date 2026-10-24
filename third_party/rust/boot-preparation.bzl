"""Pins boot preparation dependency roots and compiled feature roles."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

BOOT_PREPARATION_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.13.0"),
    "aws-sdk-s3": crate.spec(version = "=1.155.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.7.0"),
    "base64": crate.spec(version = "=0.22.1"),
    "bytes": crate.spec(version = "=1.11.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures-util": crate.spec(version = "=0.3.32"),
    "hex": crate.spec(version = "=0.4.3"),
    "humantime": crate.spec(version = "=2.3.0"),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "net", "process"]),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5"),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "time"]),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "toml": crate.spec(version = "=0.8.23"),
    "tracing": crate.spec(version = "=0.1.44"),
    "url": crate.spec(version = "=2.5.8"),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

BOOT_PREPARATION_MINIMAL_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.13.0"),
    "aws-sdk-s3": crate.spec(version = "=1.155.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.7.0"),
    "base64": crate.spec(version = "=0.22.1"),
    "bytes": crate.spec(version = "=1.11.1"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "futures-util": crate.spec(version = "=0.3.32"),
    "hex": crate.spec(version = "=0.4.3"),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "net", "process"]),
    "schemars": crate.spec(version = "=1.2.2"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5"),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "time"]),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "url": crate.spec(version = "=2.5.8"),
}

# Cargo keeps generator and target compilation features distinct.
# Guard resolver unions against the retained compiled Cargo units.
BOOT_PREPARATION_FEATURE_VARIANTS = {
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
}

BOOT_PREPARATION_MINIMAL_FEATURE_VARIANTS = {
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
}
