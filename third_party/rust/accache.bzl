"""Pins the standalone compiler-cache workspace independently of application crates."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

ACCACHE_PACKAGES = {
    "anyhow": crate.spec(version = "=1.0.104"),
    "hex": crate.spec(version = "=0.4.3"),
    "itertools": crate.spec(version = "=0.14.0"),
    "log": crate.spec(version = "=0.4.34"),
    "prost": crate.spec(version = "=0.13.5"),
    "rustix": crate.spec(features = ["fs"], version = "=1.1.5"),
    "serde": crate.spec(features = ["derive"], version = "=1.0.229"),
    "serde_json": crate.spec(version = "=1.0.151"),
    "sha2": crate.spec(version = "=0.10.9"),
    "shlex": crate.spec(version = "=2.0.1"),
    "temp-env": crate.spec(version = "=0.3.6"),
    "tempfile": crate.spec(version = "=3.27.0"),
}
