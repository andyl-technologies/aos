"""Pins hub-db dependency roots and compiled feature roles."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

HUB_DB_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "base64": crate.spec(version = "=0.22.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["runtime-tokio", "sqlite"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt-multi-thread", "signal", "sync", "time"]),
    "toml": crate.spec(version = "=0.8.23"),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "zeroize": crate.spec(version = "=1.9.0"),
}

HUB_DB_TESTS_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "base64": crate.spec(version = "=0.22.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures-util": crate.spec(version = "=0.3.32"),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "rusqlite": crate.spec(version = "=0.32.1"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["runtime-tokio", "sqlite"]),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt-multi-thread", "signal", "sync", "test-util", "time"]),
    "toml": crate.spec(version = "=0.8.23"),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "zeroize": crate.spec(version = "=1.9.0"),
}

HUB_DB_ALL_FEATURES_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "base64": crate.spec(version = "=0.22.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["mysql", "postgres", "runtime-tokio", "sqlite"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt-multi-thread", "signal", "sync", "time"]),
    "toml": crate.spec(version = "=0.8.23"),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "zeroize": crate.spec(version = "=1.9.0"),
}

HUB_DB_ALL_FEATURES_TESTS_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "base64": crate.spec(version = "=0.22.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures-util": crate.spec(version = "=0.3.32"),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "rusqlite": crate.spec(version = "=0.32.1"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["mysql", "postgres", "runtime-tokio", "sqlite"]),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt-multi-thread", "signal", "sync", "test-util", "time"]),
    "toml": crate.spec(version = "=0.8.23"),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "zeroize": crate.spec(version = "=1.9.0"),
}

# Cargo resolves a union of generator and target features. Preserve the
# distinct compiled units observed in each retained Cargo baseline.
HUB_DB_FEATURE_VARIANTS = {
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
    "sqlx-core": json.encode({
        "version": "0.8.6",
        "resolved_features": [
            "_rt-tokio",
            "any",
            "crc",
            "default",
            "migrate",
            "offline",
            "serde",
            "sha2",
            "tokio",
            "tokio-stream"
        ],
        "features": [
            "_rt-tokio",
            "crc",
            "default",
            "migrate",
            "offline",
            "serde",
            "sha2",
            "tokio",
            "tokio-stream"
        ]
    }),
}

HUB_DB_TESTS_FEATURE_VARIANTS = {
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
    "sqlx-core": json.encode({
        "version": "0.8.6",
        "resolved_features": [
            "_rt-tokio",
            "any",
            "crc",
            "default",
            "migrate",
            "offline",
            "serde",
            "sha2",
            "tokio",
            "tokio-stream"
        ],
        "features": [
            "_rt-tokio",
            "crc",
            "default",
            "migrate",
            "offline",
            "serde",
            "sha2",
            "tokio",
            "tokio-stream"
        ]
    }),
}

HUB_DB_ALL_FEATURES_FEATURE_VARIANTS = {
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
    "sqlx-core": json.encode({
        "version": "0.8.6",
        "resolved_features": [
            "_rt-tokio",
            "any",
            "crc",
            "default",
            "json",
            "migrate",
            "offline",
            "serde",
            "serde_json",
            "sha2",
            "tokio",
            "tokio-stream"
        ],
        "features": [
            "_rt-tokio",
            "crc",
            "default",
            "json",
            "migrate",
            "offline",
            "serde",
            "serde_json",
            "sha2",
            "tokio",
            "tokio-stream"
        ]
    }),
}

HUB_DB_ALL_FEATURES_TESTS_FEATURE_VARIANTS = {
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
    "sqlx-core": json.encode({
        "version": "0.8.6",
        "resolved_features": [
            "_rt-tokio",
            "any",
            "crc",
            "default",
            "json",
            "migrate",
            "offline",
            "serde",
            "serde_json",
            "sha2",
            "tokio",
            "tokio-stream"
        ],
        "features": [
            "_rt-tokio",
            "crc",
            "default",
            "json",
            "migrate",
            "offline",
            "serde",
            "serde_json",
            "sha2",
            "tokio",
            "tokio-stream"
        ]
    }),
}
