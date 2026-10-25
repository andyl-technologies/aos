"""Pins CLI dependency roots and compiled feature roles."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

AOS_CLI_TESTS_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "alejandra": crate.spec(version = "=3.1.0"),
    "anyhow": crate.spec(version = "=1.0.103"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.13.0"),
    "aws-sdk-s3": crate.spec(version = "=1.155.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.7.0"),
    "axum": crate.spec(version = "=0.8.9", features = ["form", "json", "macros", "query"]),
    "base64": crate.spec(version = "=0.22.1"),
    "buffa": crate.spec(version = "=0.9.2"),
    "bytes": crate.spec(version = "=1.11.1"),
    "bzip2-rs": crate.spec(version = "=0.1.2"),
    "ciborium": crate.spec(version = "=0.2.2"),
    "clap": crate.spec(version = "=4.6.1", features = ["derive", "env"]),
    "clap_complete": crate.spec(version = "=4.6.5"),
    "connectrpc": crate.spec(version = "=0.9.1", features = ["axum", "client", "client-tls", "server"]),
    "connectrpc-build": crate.spec(version = "=0.9.0"),
    "console": crate.spec(version = "=0.15.11"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "crossterm": crate.spec(version = "=0.29.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures": crate.spec(version = "=0.3.32"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "git2": crate.spec(version = "=0.21.0", default_features = False, features = ["https", "ssh", "unstable-sha256", "vendored-libgit2"]),
    "glob": crate.spec(version = "=0.3.3"),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "http-body": crate.spec(version = "=1.0.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "humantime-serde": crate.spec(version = "=1.1.1"),
    "http-body-util": crate.spec(version = "=0.1.3"),
    "hyper-util": crate.spec(version = "=0.1.20", features = ["http1", "http2", "server-auto", "service", "tokio"]),
    "ignore": crate.spec(version = "=0.4.25"),
    "indicatif": crate.spec(version = "=0.17.11"),
    "jsonwebtoken": crate.spec(version = "=9.3.1"),
    "jwt-rustcrypto": crate.spec(version = "=0.2.1"),
    "libc": crate.spec(version = "=0.2.186"),
    "lzma-rs": crate.spec(version = "=0.3.0"),
    "md-5": crate.spec(version = "=0.11.0"),
    "p256": crate.spec(version = "=0.13.2", features = ["ecdsa"]),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "rand": crate.spec(version = "=0.9.4"),
    "ratatui": crate.spec(version = "=0.30.2"),
    "rayon": crate.spec(version = "=1.12.0"),
    "rcgen": crate.spec(version = "=0.14.8"),
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rnix": crate.spec(version = "=0.10.2"),
    "rsa": crate.spec(version = "=0.9.10", features = ["sha2"]),
    "rusqlite": crate.spec(version = "=0.32.1"),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "net", "process"]),
    "rustls": crate.spec(version = "=0.23.46"),
    "rustls-native-certs": crate.spec(version = "=0.8.3"),
    "rustls-pemfile": crate.spec(version = "=2.2.0"),
    "rustls-pki-types": crate.spec(version = "=1.14.1"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha1": crate.spec(version = "=0.10.6"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["runtime-tokio", "sqlite"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5"),
    "tar": crate.spec(version = "=0.4.46"),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "time"]),
    "tokio-rustls": crate.spec(version = "=0.26.4"),
    "tokio-stream": crate.spec(version = "=0.1.18", features = ["sync"]),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tower": crate.spec(version = "=0.5.3", features = ["util"]),
    "tower-http": crate.spec(version = "=0.6.11", features = ["catch-panic", "cors", "limit", "trace"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "xz2": crate.spec(version = "=0.1.7", features = ["static"]),
    "webpki-roots": crate.spec(version = "=1.0.10"),
    "zeroize": crate.spec(version = "=1.9.0"),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

AOS_CLI_FLEET_TESTS_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "alejandra": crate.spec(version = "=3.1.0"),
    "anyhow": crate.spec(version = "=1.0.103"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.13.0"),
    "aws-sdk-s3": crate.spec(version = "=1.155.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.7.0"),
    "axum": crate.spec(version = "=0.8.9", features = ["form", "json", "macros", "query"]),
    "base64": crate.spec(version = "=0.22.1"),
    "buffa": crate.spec(version = "=0.9.2"),
    "bytes": crate.spec(version = "=1.11.1"),
    "bzip2-rs": crate.spec(version = "=0.1.2"),
    "ciborium": crate.spec(version = "=0.2.2"),
    "clap": crate.spec(version = "=4.6.1", features = ["derive", "env"]),
    "clap_complete": crate.spec(version = "=4.6.5"),
    "connectrpc": crate.spec(version = "=0.9.1", features = ["axum", "client", "client-tls", "server"]),
    "connectrpc-build": crate.spec(version = "=0.9.0"),
    "console": crate.spec(version = "=0.15.11"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "crossterm": crate.spec(version = "=0.29.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures": crate.spec(version = "=0.3.32"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "git2": crate.spec(version = "=0.21.0", default_features = False, features = ["https", "ssh", "unstable-sha256", "vendored-libgit2"]),
    "glob": crate.spec(version = "=0.3.3"),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "http-body": crate.spec(version = "=1.0.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "humantime-serde": crate.spec(version = "=1.1.1"),
    "http-body-util": crate.spec(version = "=0.1.3"),
    "hyper-util": crate.spec(version = "=0.1.20", features = ["http1", "http2", "server-auto", "service", "tokio"]),
    "ignore": crate.spec(version = "=0.4.25"),
    "indicatif": crate.spec(version = "=0.17.11"),
    "jsonwebtoken": crate.spec(version = "=9.3.1"),
    "jwt-rustcrypto": crate.spec(version = "=0.2.1"),
    "libc": crate.spec(version = "=0.2.186"),
    "lzma-rs": crate.spec(version = "=0.3.0"),
    "md-5": crate.spec(version = "=0.11.0"),
    "p256": crate.spec(version = "=0.13.2", features = ["ecdsa"]),
    "password-hash": crate.spec(version = "=0.5.0", features = ["getrandom"]),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "rand": crate.spec(version = "=0.9.4"),
    "ratatui": crate.spec(version = "=0.30.2"),
    "rayon": crate.spec(version = "=1.12.0"),
    "rcgen": crate.spec(version = "=0.14.8"),
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rnix": crate.spec(version = "=0.10.2"),
    "rsa": crate.spec(version = "=0.9.10", features = ["sha2"]),
    "rusqlite": crate.spec(version = "=0.32.1"),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "net", "process"]),
    "rustls": crate.spec(version = "=0.23.46"),
    "rustls-native-certs": crate.spec(version = "=0.8.3"),
    "rustls-pemfile": crate.spec(version = "=2.2.0"),
    "rustls-pki-types": crate.spec(version = "=1.14.1"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha1": crate.spec(version = "=0.10.6"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["runtime-tokio", "sqlite"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5"),
    "tar": crate.spec(version = "=0.4.46"),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "time"]),
    "tokio-rustls": crate.spec(version = "=0.26.4"),
    "tokio-stream": crate.spec(version = "=0.1.18", features = ["sync"]),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tower": crate.spec(version = "=0.5.3", features = ["util"]),
    "tower-http": crate.spec(version = "=0.6.11", features = ["catch-panic", "cors", "limit", "trace"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "xz2": crate.spec(version = "=0.1.7", features = ["static"]),
    "webpki-roots": crate.spec(version = "=1.0.10"),
    "zeroize": crate.spec(version = "=1.9.0"),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

AOS_CLI_PRODUCTION_PACKAGES = {
    "alejandra": crate.spec(version = "=3.1.0"),
    "anyhow": crate.spec(version = "=1.0.103"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.13.0"),
    "aws-sdk-s3": crate.spec(version = "=1.155.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.7.0"),
    "axum": crate.spec(version = "=0.8.9", features = ["macros"]),
    "base64": crate.spec(version = "=0.22.1"),
    "buffa": crate.spec(version = "=0.9.2"),
    "bytes": crate.spec(version = "=1.11.1"),
    "clap": crate.spec(version = "=4.6.1", features = ["derive", "env"]),
    "clap_complete": crate.spec(version = "=4.6.5"),
    "connectrpc": crate.spec(version = "=0.9.1", features = ["axum", "client", "client-tls", "server"]),
    "connectrpc-build": crate.spec(version = "=0.9.0"),
    "console": crate.spec(version = "=0.15.11"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "crossterm": crate.spec(version = "=0.29.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures": crate.spec(version = "=0.3.32"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "git2": crate.spec(version = "=0.21.0", default_features = False, features = ["https", "ssh", "unstable-sha256", "vendored-libgit2"]),
    "glob": crate.spec(version = "=0.3.3"),
    "hex": crate.spec(version = "=0.4.3"),
    "http": crate.spec(version = "=1.4.1"),
    "http-body": crate.spec(version = "=1.0.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "humantime-serde": crate.spec(version = "=1.1.1"),
    "http-body-util": crate.spec(version = "=0.1.3"),
    "hyper-util": crate.spec(version = "=0.1.20", features = ["http1", "http2", "server-auto", "service", "tokio"]),
    "ignore": crate.spec(version = "=0.4.25"),
    "indicatif": crate.spec(version = "=0.17.11"),
    "jsonwebtoken": crate.spec(version = "=9.3.1"),
    "libc": crate.spec(version = "=0.2.186"),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "rand": crate.spec(version = "=0.9.4"),
    "ratatui": crate.spec(version = "=0.30.2"),
    "rayon": crate.spec(version = "=1.12.0"),
    "rcgen": crate.spec(version = "=0.14.8"),
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rnix": crate.spec(version = "=0.10.2"),
    "rusqlite": crate.spec(version = "=0.32.1"),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "net", "process"]),
    "rustls": crate.spec(version = "=0.23.46"),
    "rustls-native-certs": crate.spec(version = "=0.8.3"),
    "rustls-pemfile": crate.spec(version = "=2.2.0"),
    "rustls-pki-types": crate.spec(version = "=1.14.1"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha1": crate.spec(version = "=0.10.6"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5"),
    "tar": crate.spec(version = "=0.4.46"),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "time"]),
    "tokio-rustls": crate.spec(version = "=0.26.4"),
    "tokio-stream": crate.spec(version = "=0.1.18", features = ["sync"]),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "toml": crate.spec(version = "=0.8.23"),
    "tower": crate.spec(version = "=0.5.3", features = ["util"]),
    "tower-http": crate.spec(version = "=0.6.11", features = ["cors", "trace"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "webpki-roots": crate.spec(version = "=1.0.10"),
    "zeroize": crate.spec(version = "=1.9.0"),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

# Cargo resolves a union of generator and target features. Preserve the
# distinct compiled units observed in each retained Cargo baseline.
AOS_CLI_TESTS_FEATURE_VARIANTS = {
    "base64": json.encode({
        "version": "0.22.1",
        "resolved_features": [
            "alloc",
            "default",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "std"
        ],
        "exec_features": [
            "alloc"
        ]
    }),
    "bytes": json.encode({
        "version": "1.11.1",
        "resolved_features": [
            "default",
            "serde",
            "std"
        ],
        "features": [
            "default",
            "serde",
            "std"
        ],
        "exec_features": [
            "std"
        ]
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
            "std",
            "use_std"
        ],
        "exec_features": [
            "std",
            "use_std"
        ]
    }),
    "hashbrown": json.encode({
        "version": "0.15.5",
        "resolved_features": [
            "allocator-api2",
            "default",
            "default-hasher",
            "equivalent",
            "inline-more",
            "raw-entry",
            "serde"
        ],
        "features": [
            "allocator-api2",
            "default",
            "default-hasher",
            "equivalent",
            "inline-more",
            "raw-entry",
            "serde"
        ],
        "exec_features": [
            "default-hasher",
            "serde"
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
    "memchr": json.encode({
        "version": "2.8.2",
        "resolved_features": [
            "alloc",
            "default",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "std"
        ],
        "exec_features": [
            "alloc",
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
            "nfa",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf",
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
            "nfa",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf",
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
            "std",
            "stdio",
            "termios"
        ],
        "features": [
            "alloc",
            "default",
            "event",
            "fs",
            "net",
            "process",
            "std",
            "stdio",
            "termios"
        ],
        "exec_features": [
            "alloc",
            "default",
            "fs",
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
            "alloc",
            "derive",
            "serde_derive",
            "std"
        ]
    }),
    "serde_core": json.encode({
        "version": "1.0.228",
        "resolved_features": [
            "alloc",
            "default",
            "rc",
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
        "exec_features": [
            "alloc",
            "result",
            "std"
        ]
    }),
    "serde_json": json.encode({
        "version": "1.0.150",
        "resolved_features": [
            "alloc",
            "default",
            "raw_value",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "raw_value",
            "std"
        ],
        "exec_features": [
            "alloc",
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
    "thiserror": json.encode({
        "version": "2.0.18",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": [
            "std"
        ]
    }),
}

AOS_CLI_FLEET_TESTS_FEATURE_VARIANTS = {
    "base64": json.encode({
        "version": "0.22.1",
        "resolved_features": [
            "alloc",
            "default",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "std"
        ],
        "exec_features": [
            "alloc"
        ]
    }),
    "bytes": json.encode({
        "version": "1.11.1",
        "resolved_features": [
            "default",
            "serde",
            "std"
        ],
        "features": [
            "default",
            "serde",
            "std"
        ],
        "exec_features": [
            "std"
        ]
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
            "std",
            "use_std"
        ],
        "exec_features": [
            "std",
            "use_std"
        ]
    }),
    "hashbrown": json.encode({
        "version": "0.15.5",
        "resolved_features": [
            "allocator-api2",
            "default",
            "default-hasher",
            "equivalent",
            "inline-more",
            "raw-entry",
            "serde"
        ],
        "features": [
            "allocator-api2",
            "default",
            "default-hasher",
            "equivalent",
            "inline-more",
            "raw-entry",
            "serde"
        ],
        "exec_features": [
            "default-hasher",
            "serde"
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
    "memchr": json.encode({
        "version": "2.8.2",
        "resolved_features": [
            "alloc",
            "default",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "std"
        ],
        "exec_features": [
            "alloc",
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
            "nfa",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf",
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
            "nfa",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf",
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
            "std",
            "stdio",
            "termios"
        ],
        "features": [
            "alloc",
            "default",
            "event",
            "fs",
            "net",
            "process",
            "std",
            "stdio",
            "termios"
        ],
        "exec_features": [
            "alloc",
            "default",
            "fs",
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
            "alloc",
            "derive",
            "serde_derive",
            "std"
        ]
    }),
    "serde_core": json.encode({
        "version": "1.0.228",
        "resolved_features": [
            "alloc",
            "default",
            "rc",
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
        "exec_features": [
            "alloc",
            "result",
            "std"
        ]
    }),
    "serde_json": json.encode({
        "version": "1.0.150",
        "resolved_features": [
            "alloc",
            "default",
            "raw_value",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "raw_value",
            "std"
        ],
        "exec_features": [
            "alloc",
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
    "thiserror": json.encode({
        "version": "2.0.18",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": [
            "std"
        ]
    }),
}

AOS_CLI_PRODUCTION_FEATURE_VARIANTS = {
    "base64": json.encode({
        "version": "0.22.1",
        "resolved_features": [
            "alloc",
            "default",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "std"
        ],
        "exec_features": [
            "alloc"
        ]
    }),
    "bytes": json.encode({
        "version": "1.11.1",
        "resolved_features": [
            "default",
            "serde",
            "std"
        ],
        "features": [
            "default",
            "serde",
            "std"
        ],
        "exec_features": [
            "std"
        ]
    }),
    "hashbrown": json.encode({
        "version": "0.15.5",
        "resolved_features": [
            "default-hasher",
            "serde"
        ],
        "features": [
            "default-hasher",
            "serde"
        ],
        "exec_features": [
            "default-hasher",
            "serde"
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
    "memchr": json.encode({
        "version": "2.8.2",
        "resolved_features": [
            "alloc",
            "default",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "std"
        ],
        "exec_features": [
            "alloc",
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
            "nfa",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf",
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
            "nfa",
            "nfa-backtrack",
            "nfa-pikevm",
            "nfa-thompson",
            "perf",
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
            "std",
            "stdio",
            "termios"
        ],
        "features": [
            "alloc",
            "default",
            "event",
            "fs",
            "net",
            "process",
            "std",
            "stdio",
            "termios"
        ],
        "exec_features": [
            "alloc",
            "default",
            "fs",
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
            "alloc",
            "derive",
            "serde_derive",
            "std"
        ]
    }),
    "serde_core": json.encode({
        "version": "1.0.228",
        "resolved_features": [
            "alloc",
            "default",
            "rc",
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
        "exec_features": [
            "alloc",
            "result",
            "std"
        ]
    }),
    "serde_json": json.encode({
        "version": "1.0.150",
        "resolved_features": [
            "alloc",
            "default",
            "raw_value",
            "std"
        ],
        "features": [
            "alloc",
            "default",
            "raw_value",
            "std"
        ],
        "exec_features": [
            "alloc",
            "std"
        ]
    }),
    "thiserror": json.encode({
        "version": "2.0.18",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "exec_features": [
            "std"
        ]
    }),
}
