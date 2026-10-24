"""Pins release-coordination dependency roots and reviewed compiler roles."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

# Production and tests compile the same dependency feature units.
RELEASE_COORDINATION_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.13.0"),
    "aws-sdk-s3": crate.spec(version = "=1.155.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.7.0"),
    "base64": crate.spec(version = "=0.22.1"),
    "bytes": crate.spec(version = "=1.11.1"),
    "console": crate.spec(version = "=0.15.11"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures": crate.spec(version = "=0.3.32"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "git2": crate.spec(version = "=0.21.0", default_features = False, features = ["https", "ssh", "unstable-sha256", "vendored-libgit2"]),
    "hex": crate.spec(version = "=0.4.3"),
    "http": crate.spec(version = "=1.4.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "indicatif": crate.spec(version = "=0.17.11"),
    "libc": crate.spec(version = "=0.2.186"),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "rand": crate.spec(version = "=0.9.4"),
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "process"]),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha1": crate.spec(version = "=0.10.6"),
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

# Cargo resolver output unions build and target features. Retain the compiled
# units independently, including each unit's own build-script configuration.
RELEASE_COORDINATION_FEATURE_VARIANTS = {
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
            "std",
            "use_std"
        ],
        "features": [],
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
            "ioctl",
            "no_std",
            "prctl"
        ],
        "features": [
            "auxvec",
            "elf",
            "errno",
            "general",
            "ioctl",
            "no_std",
            "prctl"
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
            "process",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "event",
            "fs",
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
}
