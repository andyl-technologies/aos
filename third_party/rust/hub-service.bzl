"""Pins hub-service dependency roots and compiled feature roles."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

HUB_SERVICE_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "axum": crate.spec(version = "=0.8.9", default_features = False, features = ["form", "json", "query"]),
    "base64": crate.spec(version = "=0.22.1"),
    "ciborium": crate.spec(version = "=0.2.2"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures-util": crate.spec(version = "=0.3.32"),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "jwt-rustcrypto": crate.spec(version = "=0.2.1"),
    "md-5": crate.spec(version = "=0.11.0"),
    "p256": crate.spec(version = "=0.13.2", features = ["ecdsa"]),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "rsa": crate.spec(version = "=0.9.10", features = ["sha2"]),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["runtime-tokio", "sqlite"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt-multi-thread", "signal", "sync", "time"]),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "zeroize": crate.spec(version = "=1.9.0"),
}

HUB_SERVICE_TESTS_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.8.17"),
    "aws-sdk-s3": crate.spec(version = "=1.134.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.3.16"),
    "axum": crate.spec(version = "=0.8.9", default_features = False, features = ["form", "http1", "json", "query", "tokio"]),
    "base64": crate.spec(version = "=0.22.1"),
    "bytes": crate.spec(version = "=1.11.1"),
    "ciborium": crate.spec(version = "=0.2.2"),
    "clap": crate.spec(version = "=4.6.1", features = ["derive", "env"]),
    "console": crate.spec(version = "=0.15.11"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures": crate.spec(version = "=0.3.32"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "git2": crate.spec(version = "=0.21.0", default_features = False, features = ["https", "ssh", "unstable-sha256", "vendored-libgit2"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "indicatif": crate.spec(version = "=0.17.11"),
    "jwt-rustcrypto": crate.spec(version = "=0.2.1"),
    "libc": crate.spec(version = "=0.2.186"),
    "md-5": crate.spec(version = "=0.11.0"),
    "p256": crate.spec(version = "=0.13.2", features = ["ecdsa"]),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "rand": crate.spec(version = "=0.9.4"),
    "rayon": crate.spec(version = "=1.12.0"),
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rsa": crate.spec(version = "=0.9.10", features = ["sha2"]),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "net", "process"]),
    "rustls-native-certs": crate.spec(version = "=0.8.3"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha1": crate.spec(version = "=0.10.6"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["runtime-tokio", "sqlite"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5", features = ["vendored-openssl"]),
    "tar": crate.spec(version = "=0.4.46"),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "test-util", "time"]),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "zeroize": crate.spec(version = "=1.9.0"),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

HUB_SERVICE_ALL_FEATURES_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "axum": crate.spec(version = "=0.8.9", default_features = False, features = ["form", "json", "query"]),
    "base64": crate.spec(version = "=0.22.1"),
    "ciborium": crate.spec(version = "=0.2.2"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures-util": crate.spec(version = "=0.3.32"),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "jwt-rustcrypto": crate.spec(version = "=0.2.1"),
    "md-5": crate.spec(version = "=0.11.0"),
    "p256": crate.spec(version = "=0.13.2", features = ["ecdsa"]),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "rsa": crate.spec(version = "=0.9.10", features = ["sha2"]),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["mysql", "postgres", "runtime-tokio", "sqlite"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt-multi-thread", "signal", "sync", "time"]),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "zeroize": crate.spec(version = "=1.9.0"),
}

HUB_SERVICE_ALL_FEATURES_TESTS_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.8.17"),
    "aws-sdk-s3": crate.spec(version = "=1.134.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.3.16"),
    "axum": crate.spec(version = "=0.8.9", default_features = False, features = ["form", "http1", "json", "query", "tokio"]),
    "base64": crate.spec(version = "=0.22.1"),
    "bytes": crate.spec(version = "=1.11.1"),
    "ciborium": crate.spec(version = "=0.2.2"),
    "clap": crate.spec(version = "=4.6.1", features = ["derive", "env"]),
    "console": crate.spec(version = "=0.15.11"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures": crate.spec(version = "=0.3.32"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "git2": crate.spec(version = "=0.21.0", default_features = False, features = ["https", "ssh", "unstable-sha256", "vendored-libgit2"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "indicatif": crate.spec(version = "=0.17.11"),
    "jwt-rustcrypto": crate.spec(version = "=0.2.1"),
    "libc": crate.spec(version = "=0.2.186"),
    "md-5": crate.spec(version = "=0.11.0"),
    "p256": crate.spec(version = "=0.13.2", features = ["ecdsa"]),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "rand": crate.spec(version = "=0.9.4"),
    "rayon": crate.spec(version = "=1.12.0"),
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rsa": crate.spec(version = "=0.9.10", features = ["sha2"]),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "net", "process"]),
    "rustls-native-certs": crate.spec(version = "=0.8.3"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha1": crate.spec(version = "=0.10.6"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["mysql", "postgres", "runtime-tokio", "sqlite"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5", features = ["vendored-openssl"]),
    "tar": crate.spec(version = "=0.4.46"),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "test-util", "time"]),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "zeroize": crate.spec(version = "=1.9.0"),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

# Cargo resolves a union of generator and target features. Preserve the
# distinct compiled units observed in each retained Cargo baseline.
HUB_SERVICE_FEATURE_VARIANTS = {
    "bytes": json.encode({
        "version": "1.11.1",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": []
    }),
    "either": json.encode({
        "version": "1.16.0",
        "resolved_features": [
            "default",
            "serde",
            "std",
            "use_std"
        ],
        "features": [
            "default",
            "serde",
            "std"
        ],
        "exec_features": [
            "std",
            "use_std"
        ]
    }),
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
    "libc": json.encode({
        "version": "0.2.186",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": []
    }),
    "prost": json.encode({
        "version": "0.13.5",
        "resolved_features": [
            "default",
            "derive",
            "prost-derive",
            "std"
        ],
        "features": [
            "default",
            "derive",
            "std"
        ],
        "exec_features": [
            "default",
            "derive",
            "prost-derive",
            "std"
        ]
    }),
    "regex": json.encode({
        "version": "1.12.4",
        "resolved_features": [
            "default",
            "perf",
            "perf-backtrack",
            "perf-cache",
            "perf-dfa",
            "perf-inline",
            "perf-literal",
            "perf-onepass",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "features": [
            "default",
            "perf",
            "perf-backtrack",
            "perf-cache",
            "perf-dfa",
            "perf-inline",
            "perf-literal",
            "perf-onepass",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "exec_features": [
            "std",
            "unicode-bool"
        ]
    }),
    "regex-automata": json.encode({
        "version": "0.4.14",
        "resolved_features": [
            "alloc",
            "dfa-onepass",
            "hybrid",
            "meta",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf-inline",
            "perf-literal",
            "perf-literal-multisubstring",
            "perf-literal-substring",
            "std",
            "syntax",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary"
        ],
        "features": [
            "alloc",
            "dfa-onepass",
            "hybrid",
            "meta",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf-inline",
            "perf-literal",
            "perf-literal-multisubstring",
            "perf-literal-substring",
            "std",
            "syntax",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary"
        ],
        "exec_features": [
            "alloc",
            "meta",
            "nfa-pikevm",
            "nfa-thompson",
            "std",
            "syntax",
            "unicode-bool"
        ]
    }),
    "regex-syntax": json.encode({
        "version": "0.8.11",
        "resolved_features": [
            "default",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "features": [
            "default",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "exec_features": [
            "std",
            "unicode-bool"
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

HUB_SERVICE_TESTS_FEATURE_VARIANTS = {
    "bytes": json.encode({
        "version": "1.11.1",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": []
    }),
    "either": json.encode({
        "version": "1.16.0",
        "resolved_features": [
            "default",
            "serde",
            "std",
            "use_std"
        ],
        "features": [
            "default",
            "serde",
            "std"
        ],
        "exec_features": [
            "std",
            "use_std"
        ]
    }),
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
    "linux-raw-sys": json.encode({
        "version": "0.12.1",
        "resolved_features": [
            "auxvec",
            "elf",
            "errno",
            "general",
            "if_ether",
            "ioctl",
            "net",
            "netlink",
            "no_std",
            "prctl",
            "xdp"
        ],
        "features": [
            "auxvec",
            "elf",
            "errno",
            "general",
            "if_ether",
            "ioctl",
            "net",
            "netlink",
            "no_std",
            "prctl",
            "xdp"
        ],
        "exec_features": [
            "auxvec",
            "elf",
            "errno",
            "general",
            "ioctl",
            "no_std"
        ]
    }),
    "prost": json.encode({
        "version": "0.13.5",
        "resolved_features": [
            "default",
            "derive",
            "prost-derive",
            "std"
        ],
        "features": [
            "default",
            "derive",
            "std"
        ],
        "exec_features": [
            "default",
            "derive",
            "prost-derive",
            "std"
        ]
    }),
    "regex": json.encode({
        "version": "1.12.4",
        "resolved_features": [
            "default",
            "perf",
            "perf-backtrack",
            "perf-cache",
            "perf-dfa",
            "perf-inline",
            "perf-literal",
            "perf-onepass",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "features": [
            "default",
            "perf",
            "perf-backtrack",
            "perf-cache",
            "perf-dfa",
            "perf-inline",
            "perf-literal",
            "perf-onepass",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "exec_features": [
            "std",
            "unicode-bool"
        ]
    }),
    "regex-automata": json.encode({
        "version": "0.4.14",
        "resolved_features": [
            "alloc",
            "dfa-onepass",
            "hybrid",
            "meta",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf-inline",
            "perf-literal",
            "perf-literal-multisubstring",
            "perf-literal-substring",
            "std",
            "syntax",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary"
        ],
        "features": [
            "alloc",
            "dfa-onepass",
            "hybrid",
            "meta",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf-inline",
            "perf-literal",
            "perf-literal-multisubstring",
            "perf-literal-substring",
            "std",
            "syntax",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary"
        ],
        "exec_features": [
            "alloc",
            "meta",
            "nfa-pikevm",
            "nfa-thompson",
            "std",
            "syntax",
            "unicode-bool"
        ]
    }),
    "regex-syntax": json.encode({
        "version": "0.8.11",
        "resolved_features": [
            "default",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "features": [
            "default",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "exec_features": [
            "std",
            "unicode-bool"
        ]
    }),
    "rustix": json.encode({
        "version": "1.1.4",
        "resolved_features": [
            "alloc",
            "default",
            "event",
            "fs",
            "net",
            "process",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "event",
            "fs",
            "net",
            "process",
            "std"
        ],
        "exec_features": [
            "alloc",
            "default",
            "fs",
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

HUB_SERVICE_ALL_FEATURES_FEATURE_VARIANTS = {
    "bitflags": json.encode({
        "version": "2.13.0",
        "resolved_features": [
            "serde",
            "serde_core",
            "std"
        ],
        "features": [
            "serde",
            "serde_core"
        ],
        "exec_features": [
            "std"
        ]
    }),
    "bytes": json.encode({
        "version": "1.11.1",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": []
    }),
    "either": json.encode({
        "version": "1.16.0",
        "resolved_features": [
            "default",
            "serde",
            "std",
            "use_std"
        ],
        "features": [
            "default",
            "serde",
            "std"
        ],
        "exec_features": [
            "std",
            "use_std"
        ]
    }),
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
    "libc": json.encode({
        "version": "0.2.186",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": []
    }),
    "prost": json.encode({
        "version": "0.13.5",
        "resolved_features": [
            "default",
            "derive",
            "prost-derive",
            "std"
        ],
        "features": [
            "default",
            "derive",
            "std"
        ],
        "exec_features": [
            "default",
            "derive",
            "prost-derive",
            "std"
        ]
    }),
    "regex": json.encode({
        "version": "1.12.4",
        "resolved_features": [
            "default",
            "perf",
            "perf-backtrack",
            "perf-cache",
            "perf-dfa",
            "perf-inline",
            "perf-literal",
            "perf-onepass",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "features": [
            "default",
            "perf",
            "perf-backtrack",
            "perf-cache",
            "perf-dfa",
            "perf-inline",
            "perf-literal",
            "perf-onepass",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "exec_features": [
            "std",
            "unicode-bool"
        ]
    }),
    "regex-automata": json.encode({
        "version": "0.4.14",
        "resolved_features": [
            "alloc",
            "dfa-onepass",
            "hybrid",
            "meta",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf-inline",
            "perf-literal",
            "perf-literal-multisubstring",
            "perf-literal-substring",
            "std",
            "syntax",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary"
        ],
        "features": [
            "alloc",
            "dfa-onepass",
            "hybrid",
            "meta",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf-inline",
            "perf-literal",
            "perf-literal-multisubstring",
            "perf-literal-substring",
            "std",
            "syntax",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary"
        ],
        "exec_features": [
            "alloc",
            "meta",
            "nfa-pikevm",
            "nfa-thompson",
            "std",
            "syntax",
            "unicode-bool"
        ]
    }),
    "regex-syntax": json.encode({
        "version": "0.8.11",
        "resolved_features": [
            "default",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "features": [
            "default",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "exec_features": [
            "std",
            "unicode-bool"
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

HUB_SERVICE_ALL_FEATURES_TESTS_FEATURE_VARIANTS = {
    "bitflags": json.encode({
        "version": "2.13.0",
        "resolved_features": [
            "serde",
            "serde_core",
            "std"
        ],
        "features": [
            "serde",
            "serde_core",
            "std"
        ],
        "exec_features": [
            "std"
        ]
    }),
    "bytes": json.encode({
        "version": "1.11.1",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": []
    }),
    "either": json.encode({
        "version": "1.16.0",
        "resolved_features": [
            "default",
            "serde",
            "std",
            "use_std"
        ],
        "features": [
            "default",
            "serde",
            "std"
        ],
        "exec_features": [
            "std",
            "use_std"
        ]
    }),
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
    "linux-raw-sys": json.encode({
        "version": "0.12.1",
        "resolved_features": [
            "auxvec",
            "elf",
            "errno",
            "general",
            "if_ether",
            "ioctl",
            "net",
            "netlink",
            "no_std",
            "prctl",
            "xdp"
        ],
        "features": [
            "auxvec",
            "elf",
            "errno",
            "general",
            "if_ether",
            "ioctl",
            "net",
            "netlink",
            "no_std",
            "prctl",
            "xdp"
        ],
        "exec_features": [
            "auxvec",
            "elf",
            "errno",
            "general",
            "ioctl",
            "no_std"
        ]
    }),
    "prost": json.encode({
        "version": "0.13.5",
        "resolved_features": [
            "default",
            "derive",
            "prost-derive",
            "std"
        ],
        "features": [
            "default",
            "derive",
            "std"
        ],
        "exec_features": [
            "default",
            "derive",
            "prost-derive",
            "std"
        ]
    }),
    "regex": json.encode({
        "version": "1.12.4",
        "resolved_features": [
            "default",
            "perf",
            "perf-backtrack",
            "perf-cache",
            "perf-dfa",
            "perf-inline",
            "perf-literal",
            "perf-onepass",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "features": [
            "default",
            "perf",
            "perf-backtrack",
            "perf-cache",
            "perf-dfa",
            "perf-inline",
            "perf-literal",
            "perf-onepass",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "exec_features": [
            "std",
            "unicode-bool"
        ]
    }),
    "regex-automata": json.encode({
        "version": "0.4.14",
        "resolved_features": [
            "alloc",
            "dfa-onepass",
            "hybrid",
            "meta",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf-inline",
            "perf-literal",
            "perf-literal-multisubstring",
            "perf-literal-substring",
            "std",
            "syntax",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary"
        ],
        "features": [
            "alloc",
            "dfa-onepass",
            "hybrid",
            "meta",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf-inline",
            "perf-literal",
            "perf-literal-multisubstring",
            "perf-literal-substring",
            "std",
            "syntax",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary"
        ],
        "exec_features": [
            "alloc",
            "meta",
            "nfa-pikevm",
            "nfa-thompson",
            "std",
            "syntax",
            "unicode-bool"
        ]
    }),
    "regex-syntax": json.encode({
        "version": "0.8.11",
        "resolved_features": [
            "default",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "features": [
            "default",
            "std",
            "unicode",
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment"
        ],
        "exec_features": [
            "std",
            "unicode-bool"
        ]
    }),
    "rustix": json.encode({
        "version": "1.1.4",
        "resolved_features": [
            "alloc",
            "default",
            "event",
            "fs",
            "net",
            "process",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "event",
            "fs",
            "net",
            "process",
            "std"
        ],
        "exec_features": [
            "alloc",
            "default",
            "fs",
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
