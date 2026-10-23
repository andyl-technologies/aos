"""Pins Worker dependency roots and compiled feature roles."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

HUB_WORKER_TESTS_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.8.17"),
    "aws-sdk-s3": crate.spec(version = "=1.134.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.3.16"),
    "axum": crate.spec(version = "=0.8.9", features = ["form", "json", "macros", "query"]),
    "base64": crate.spec(version = "=0.22.1"),
    "bytes": crate.spec(version = "=1.11.1"),
    "bzip2-rs": crate.spec(version = "=0.1.2"),
    "ciborium": crate.spec(version = "=0.2.2"),
    "clap": crate.spec(version = "=4.6.1", features = ["derive", "env"]),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "form_urlencoded": crate.spec(version = "=1.2.2"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "git2": crate.spec(version = "=0.21.0", default_features = False, features = ["https", "ssh", "unstable-sha256", "vendored-libgit2"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "js-sys": crate.spec(version = "=0.3.103"),
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
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rsa": crate.spec(version = "=0.9.10", features = ["sha2"]),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "process"]),
    "rustls-pemfile": crate.spec(version = "=2.2.0"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "send_wrapper": crate.spec(version = "=0.6.0", features = ["futures"]),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde-wasm-bindgen": crate.spec(version = "=0.6.5"),
    "serde_json": crate.spec(version = "=1.0.150", features = ["raw_value"]),
    "sha1": crate.spec(version = "=0.10.6"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["runtime-tokio", "sqlite"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5", features = ["vendored-openssl"]),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "time"]),
    "tokio-rustls": crate.spec(version = "=0.26.4"),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tower": crate.spec(version = "=0.5.3", features = ["util"]),
    "tower-http": crate.spec(version = "=0.6.11", features = ["catch-panic", "cors", "limit", "trace"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "wasm-bindgen": crate.spec(version = "=0.2.126"),
    "wasm-bindgen-futures": crate.spec(version = "=0.4.76"),
    "worker": crate.spec(version = "=0.8.5", features = ["queue"]),
    "worker-sys": crate.spec(version = "=0.8.5"),
    "zeroize": crate.spec(version = "=1.9.0"),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

HUB_WORKER_ALL_FEATURES_TESTS_PACKAGES = {
    "aes-gcm": crate.spec(version = "=0.10.3"),
    "anyhow": crate.spec(version = "=1.0.102"),
    "argon2": crate.spec(version = "=0.5.3"),
    "async-trait": crate.spec(version = "=0.1.89"),
    "aws-config": crate.spec(version = "=1.8.17"),
    "aws-sdk-s3": crate.spec(version = "=1.134.0", default_features = False, features = ["default-https-client", "http-1x", "rt-tokio", "sigv4a"]),
    "aws-types": crate.spec(version = "=1.3.16"),
    "axum": crate.spec(version = "=0.8.9", features = ["form", "json", "macros", "query"]),
    "base64": crate.spec(version = "=0.22.1"),
    "bytes": crate.spec(version = "=1.11.1"),
    "bzip2-rs": crate.spec(version = "=0.1.2"),
    "ciborium": crate.spec(version = "=0.2.2"),
    "clap": crate.spec(version = "=4.6.1", features = ["derive", "env"]),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "digest": crate.spec(version = "=0.10.7"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "form_urlencoded": crate.spec(version = "=1.2.2"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "git2": crate.spec(version = "=0.21.0", default_features = False, features = ["https", "ssh", "unstable-sha256", "vendored-libgit2"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "js-sys": crate.spec(version = "=0.3.103"),
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
    "regex": crate.spec(version = "=1.12.4"),
    "reqwest": crate.spec(version = "=0.12.28", default_features = False, features = ["json", "rustls-tls-native-roots", "stream"]),
    "rsa": crate.spec(version = "=0.9.10", features = ["sha2"]),
    "rustix": crate.spec(version = "=1.1.4", features = ["event", "fs", "process"]),
    "rustls-pemfile": crate.spec(version = "=2.2.0"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "send_wrapper": crate.spec(version = "=0.6.0", features = ["futures"]),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde-wasm-bindgen": crate.spec(version = "=0.6.5"),
    "serde_json": crate.spec(version = "=1.0.150", features = ["raw_value"]),
    "sha1": crate.spec(version = "=0.10.6"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "sqlx": crate.spec(version = "=0.8.6", default_features = False, features = ["runtime-tokio", "sqlite"]),
    "ssh-key": crate.spec(version = "=0.6.7", default_features = False, features = ["ed25519", "std"]),
    "ssh2": crate.spec(version = "=0.9.5", features = ["vendored-openssl"]),
    "tempfile": crate.spec(version = "=3.27.0"),
    "thiserror": crate.spec(version = "=2.0.18"),
    "tokio": crate.spec(version = "=1.52.3", features = ["fs", "io-std", "io-util", "macros", "net", "process", "rt", "rt-multi-thread", "signal", "sync", "time"]),
    "tokio-rustls": crate.spec(version = "=0.26.4"),
    "tokio-util": crate.spec(version = "=0.7.18", features = ["io"]),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tower": crate.spec(version = "=0.5.3", features = ["util"]),
    "tower-http": crate.spec(version = "=0.6.11", features = ["catch-panic", "cors", "limit", "trace"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["serde", "v4"]),
    "wasm-bindgen": crate.spec(version = "=0.2.126"),
    "wasm-bindgen-futures": crate.spec(version = "=0.4.76"),
    "worker": crate.spec(version = "=0.8.5", features = ["queue"]),
    "worker-sys": crate.spec(version = "=0.8.5"),
    "zeroize": crate.spec(version = "=1.9.0"),
    "zstd": crate.spec(version = "=0.13.3", features = ["zstdmt"]),
}

HUB_WORKER_WASM_PACKAGES = {
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
    "form_urlencoded": crate.spec(version = "=1.2.2"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "getrandom": crate.spec(version = "=0.2.17", features = ["js"]),
    "getrandom_03": crate.spec(version = "=0.3.4", package = "getrandom", features = ["wasm_js"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "js-sys": crate.spec(version = "=0.3.103"),
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
    "send_wrapper": crate.spec(version = "=0.6.0", features = ["futures"]),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde-wasm-bindgen": crate.spec(version = "=0.6.5"),
    "serde_json": crate.spec(version = "=1.0.150", features = ["raw_value"]),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tower": crate.spec(version = "=0.5.3", features = ["util"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["js", "serde", "v4"]),
    "wasm-bindgen": crate.spec(version = "=0.2.126"),
    "wasm-bindgen-futures": crate.spec(version = "=0.4.76"),
    "worker": crate.spec(version = "=0.8.5", features = ["queue"]),
    "worker-sys": crate.spec(version = "=0.8.5"),
    "zeroize": crate.spec(version = "=1.9.0"),
}

HUB_WORKER_WASM_DO_E2E_PACKAGES = {
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
    "form_urlencoded": crate.spec(version = "=1.2.2"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "getrandom": crate.spec(version = "=0.2.17", features = ["js"]),
    "getrandom_03": crate.spec(version = "=0.3.4", package = "getrandom", features = ["wasm_js"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "js-sys": crate.spec(version = "=0.3.103"),
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
    "send_wrapper": crate.spec(version = "=0.6.0", features = ["futures"]),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde-wasm-bindgen": crate.spec(version = "=0.6.5"),
    "serde_json": crate.spec(version = "=1.0.150", features = ["raw_value"]),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tower": crate.spec(version = "=0.5.3", features = ["util"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["js", "serde", "v4"]),
    "wasm-bindgen": crate.spec(version = "=0.2.126"),
    "wasm-bindgen-futures": crate.spec(version = "=0.4.76"),
    "worker": crate.spec(version = "=0.8.5", features = ["queue"]),
    "worker-sys": crate.spec(version = "=0.8.5"),
    "zeroize": crate.spec(version = "=1.9.0"),
}

HUB_WORKER_WASM_ALL_FEATURES_PACKAGES = {
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
    "form_urlencoded": crate.spec(version = "=1.2.2"),
    "futures-util": crate.spec(version = "=0.3.32"),
    "getrandom": crate.spec(version = "=0.2.17", features = ["js"]),
    "getrandom_03": crate.spec(version = "=0.3.4", package = "getrandom", features = ["wasm_js"]),
    "hex": crate.spec(version = "=0.4.3"),
    "hmac": crate.spec(version = "=0.12.1"),
    "http": crate.spec(version = "=1.4.1"),
    "humantime": crate.spec(version = "=2.3.0"),
    "js-sys": crate.spec(version = "=0.3.103"),
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
    "send_wrapper": crate.spec(version = "=0.6.0", features = ["futures"]),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde-wasm-bindgen": crate.spec(version = "=0.6.5"),
    "serde_json": crate.spec(version = "=1.0.150", features = ["raw_value"]),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "toml": crate.spec(version = "=0.8.23"),
    "toml_edit": crate.spec(version = "=0.22.27"),
    "tower": crate.spec(version = "=0.5.3", features = ["util"]),
    "tracing": crate.spec(version = "=0.1.44"),
    "unicode-normalization": crate.spec(version = "=0.1.25"),
    "url": crate.spec(version = "=2.5.8"),
    "uuid": crate.spec(version = "=1.23.1", features = ["js", "serde", "v4"]),
    "wasm-bindgen": crate.spec(version = "=0.2.126"),
    "wasm-bindgen-futures": crate.spec(version = "=0.4.76"),
    "worker": crate.spec(version = "=0.8.5", features = ["queue"]),
    "worker-sys": crate.spec(version = "=0.8.5"),
    "zeroize": crate.spec(version = "=1.9.0"),
}

# Cargo resolves a union of generator and target features. Preserve the
# distinct compiled units observed in each retained Cargo baseline.
HUB_WORKER_TESTS_FEATURE_VARIANTS = {
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
    "futures-core": json.encode({
        "version": "0.3.32",
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
    "futures-util": json.encode({
        "version": "0.3.32",
        "resolved_features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "exec_features": [
            "alloc",
            "slab",
            "std"
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
    "slab": json.encode({
        "version": "0.4.12",
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
    "web-sys": json.encode({
        "version": "0.3.103",
        "resolved_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "exec_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "ReadableStream",
            "ReadableStreamDefaultReader",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "TransformStream",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ]
    }),
}

HUB_WORKER_ALL_FEATURES_TESTS_FEATURE_VARIANTS = {
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
    "futures-core": json.encode({
        "version": "0.3.32",
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
    "futures-util": json.encode({
        "version": "0.3.32",
        "resolved_features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "exec_features": [
            "alloc",
            "slab",
            "std"
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
    "slab": json.encode({
        "version": "0.4.12",
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
    "web-sys": json.encode({
        "version": "0.3.103",
        "resolved_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "exec_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "ReadableStream",
            "ReadableStreamDefaultReader",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "TransformStream",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ]
    }),
}

HUB_WORKER_WASM_FEATURE_VARIANTS = {
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
    "futures-core": json.encode({
        "version": "0.3.32",
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
    "futures-util": json.encode({
        "version": "0.3.32",
        "resolved_features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "exec_features": [
            "alloc",
            "slab",
            "std"
        ]
    }),
    "indexmap": json.encode({
        "version": "2.14.0",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "serde"
            ],
            "x86_64-unknown-linux-gnu": [
                "serde"
            ]
        }
    }),
    "itertools": json.encode({
        "version": "0.14.0",
        "resolved_features": [
            "use_alloc"
        ],
        "features": [
            "default",
            "use_alloc",
            "use_std"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default",
                "use_std"
            ],
            "x86_64-unknown-linux-gnu": [
                "default",
                "use_std"
            ]
        }
    }),
    "proc-macro2": json.encode({
        "version": "1.0.106",
        "resolved_features": [
            "proc-macro"
        ],
        "features": [
            "default",
            "proc-macro"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default"
            ],
            "x86_64-unknown-linux-gnu": [
                "default"
            ]
        }
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
    "quote": json.encode({
        "version": "1.0.46",
        "resolved_features": [
            "proc-macro"
        ],
        "features": [
            "default",
            "proc-macro"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default"
            ],
            "x86_64-unknown-linux-gnu": [
                "default"
            ]
        }
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
    "syn": json.encode({
        "version": "2.0.118",
        "resolved_features": [
            "clone-impls",
            "default",
            "derive",
            "full",
            "parsing",
            "printing",
            "proc-macro"
        ],
        "features": [
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
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "extra-traits",
                "fold",
                "visit",
                "visit-mut"
            ],
            "x86_64-unknown-linux-gnu": [
                "extra-traits",
                "fold",
                "visit",
                "visit-mut"
            ]
        }
    }),
    "web-sys": json.encode({
        "version": "0.3.103",
        "resolved_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "exec_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "ReadableStream",
            "ReadableStreamDefaultReader",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "TransformStream",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ]
    }),
}

HUB_WORKER_WASM_DO_E2E_FEATURE_VARIANTS = {
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
    "futures-core": json.encode({
        "version": "0.3.32",
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
    "futures-util": json.encode({
        "version": "0.3.32",
        "resolved_features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "exec_features": [
            "alloc",
            "slab",
            "std"
        ]
    }),
    "indexmap": json.encode({
        "version": "2.14.0",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "serde"
            ],
            "x86_64-unknown-linux-gnu": [
                "serde"
            ]
        }
    }),
    "itertools": json.encode({
        "version": "0.14.0",
        "resolved_features": [
            "use_alloc"
        ],
        "features": [
            "default",
            "use_alloc",
            "use_std"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default",
                "use_std"
            ],
            "x86_64-unknown-linux-gnu": [
                "default",
                "use_std"
            ]
        }
    }),
    "proc-macro2": json.encode({
        "version": "1.0.106",
        "resolved_features": [
            "proc-macro"
        ],
        "features": [
            "default",
            "proc-macro"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default"
            ],
            "x86_64-unknown-linux-gnu": [
                "default"
            ]
        }
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
    "quote": json.encode({
        "version": "1.0.46",
        "resolved_features": [
            "proc-macro"
        ],
        "features": [
            "default",
            "proc-macro"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default"
            ],
            "x86_64-unknown-linux-gnu": [
                "default"
            ]
        }
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
    "syn": json.encode({
        "version": "2.0.118",
        "resolved_features": [
            "clone-impls",
            "default",
            "derive",
            "full",
            "parsing",
            "printing",
            "proc-macro"
        ],
        "features": [
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
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "extra-traits",
                "fold",
                "visit",
                "visit-mut"
            ],
            "x86_64-unknown-linux-gnu": [
                "extra-traits",
                "fold",
                "visit",
                "visit-mut"
            ]
        }
    }),
    "web-sys": json.encode({
        "version": "0.3.103",
        "resolved_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "exec_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "ReadableStream",
            "ReadableStreamDefaultReader",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "TransformStream",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ]
    }),
}

HUB_WORKER_WASM_ALL_FEATURES_FEATURE_VARIANTS = {
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
    "futures-core": json.encode({
        "version": "0.3.32",
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
    "futures-util": json.encode({
        "version": "0.3.32",
        "resolved_features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "features": [
            "alloc",
            "async-await",
            "async-await-macro",
            "default",
            "futures-io",
            "futures-macro",
            "futures-sink",
            "io",
            "memchr",
            "sink",
            "slab",
            "std"
        ],
        "exec_features": [
            "alloc",
            "slab",
            "std"
        ]
    }),
    "indexmap": json.encode({
        "version": "2.14.0",
        "resolved_features": [
            "default",
            "std"
        ],
        "features": [
            "default",
            "std"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "serde"
            ],
            "x86_64-unknown-linux-gnu": [
                "serde"
            ]
        }
    }),
    "itertools": json.encode({
        "version": "0.14.0",
        "resolved_features": [
            "use_alloc"
        ],
        "features": [
            "default",
            "use_alloc",
            "use_std"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default",
                "use_std"
            ],
            "x86_64-unknown-linux-gnu": [
                "default",
                "use_std"
            ]
        }
    }),
    "proc-macro2": json.encode({
        "version": "1.0.106",
        "resolved_features": [
            "proc-macro"
        ],
        "features": [
            "default",
            "proc-macro"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default"
            ],
            "x86_64-unknown-linux-gnu": [
                "default"
            ]
        }
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
    "quote": json.encode({
        "version": "1.0.46",
        "resolved_features": [
            "proc-macro"
        ],
        "features": [
            "default",
            "proc-macro"
        ],
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "default"
            ],
            "x86_64-unknown-linux-gnu": [
                "default"
            ]
        }
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
    "syn": json.encode({
        "version": "2.0.118",
        "resolved_features": [
            "clone-impls",
            "default",
            "derive",
            "full",
            "parsing",
            "printing",
            "proc-macro"
        ],
        "features": [
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
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "extra-traits",
                "fold",
                "visit",
                "visit-mut"
            ],
            "x86_64-unknown-linux-gnu": [
                "extra-traits",
                "fold",
                "visit",
                "visit-mut"
            ]
        }
    }),
    "web-sys": json.encode({
        "version": "0.3.103",
        "resolved_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "QueuingStrategy",
            "ReadableByteStreamController",
            "ReadableStream",
            "ReadableStreamByobReader",
            "ReadableStreamByobRequest",
            "ReadableStreamDefaultController",
            "ReadableStreamDefaultReader",
            "ReadableStreamGetReaderOptions",
            "ReadableStreamReadResult",
            "ReadableStreamReaderMode",
            "ReadableStreamType",
            "ReadableWritablePair",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "StreamPipeOptions",
            "TransformStream",
            "TransformStreamDefaultController",
            "Transformer",
            "UnderlyingSink",
            "UnderlyingSource",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultController",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ],
        "exec_features": [
            "AbortController",
            "AbortSignal",
            "BinaryType",
            "Blob",
            "Cache",
            "CacheQueryOptions",
            "CacheStorage",
            "CloseEvent",
            "ErrorEvent",
            "Event",
            "EventTarget",
            "File",
            "FormData",
            "Headers",
            "MessageEvent",
            "Performance",
            "ProgressEvent",
            "ReadableStream",
            "ReadableStreamDefaultReader",
            "Request",
            "RequestCache",
            "RequestInit",
            "RequestRedirect",
            "Response",
            "ResponseInit",
            "TransformStream",
            "WebSocket",
            "WorkerGlobalScope",
            "WritableStream",
            "WritableStreamDefaultWriter",
            "console",
            "default",
            "std"
        ]
    }),
}
