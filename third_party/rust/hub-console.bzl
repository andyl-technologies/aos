"""Pins hub-console dependency roots and compiled feature roles."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

HUB_CONSOLE_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "base64": crate.spec(version = "=0.22.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "hex": crate.spec(version = "=0.4.3"),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "regex": crate.spec(version = "=1.12.4"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "toml": crate.spec(version = "=0.8.23"),
}

HUB_CONSOLE_WASM_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.103"),
    "base64": crate.spec(version = "=0.22.1"),
    "crc32fast": crate.spec(version = "=1.5.0"),
    "ed25519-dalek": crate.spec(version = "=2.2.0", features = ["pkcs8"]),
    "flate2": crate.spec(version = "=1.1.9", default_features = False, features = ["rust_backend"]),
    "futures": crate.spec(version = "=0.3.32"),
    "gloo-net": crate.spec(version = "=0.6.0", default_features = False, features = ["http"]),
    "hex": crate.spec(version = "=0.4.3"),
    "js-sys": crate.spec(version = "=0.3.103"),
    "leptos": crate.spec(version = "=0.7.8", features = ["csr"]),
    "pbjson": crate.spec(version = "=0.7.0"),
    "pbjson-build": crate.spec(version = "=0.7.0"),
    "prost": crate.spec(version = "=0.13.5"),
    "prost-build": crate.spec(version = "=0.13.5"),
    "prost-types": crate.spec(version = "=0.13.5"),
    "regex": crate.spec(version = "=1.12.4"),
    "schemars": crate.spec(version = "=1.2.2"),
    "semver": crate.spec(version = "=1.0.28"),
    "serde": crate.spec(version = "=1.0.228", features = ["derive", "rc"]),
    "serde_json": crate.spec(version = "=1.0.150"),
    "sha2": crate.spec(version = "=0.10.9", features = ["compress"]),
    "thiserror": crate.spec(version = "=2.0.18"),
    "toml": crate.spec(version = "=0.8.23"),
    "wasm-bindgen": crate.spec(version = "=0.2.126"),
    "wasm-bindgen-futures": crate.spec(version = "=0.4.76"),
    "web-sys": crate.spec(version = "=0.3.103", features = ["Blob", "Element", "File", "FileList", "History", "HtmlInputElement", "MouseEvent"]),
}

# Cargo resolves a union of generator and target features. Preserve the
# distinct compiled units observed in each retained Cargo baseline.
HUB_CONSOLE_FEATURE_VARIANTS = {
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
}

HUB_CONSOLE_WASM_FEATURE_VARIANTS = {
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
        "resolved_selects": {
            "aarch64-unknown-linux-gnu": [
                "fold"
            ],
            "x86_64-unknown-linux-gnu": [
                "fold"
            ]
        },
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
        ]
    }),
}
