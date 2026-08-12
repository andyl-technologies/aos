//! Nix `lang.sh` conformance test modules.

use std::path::{Path, PathBuf};

mod fixture_tests;
mod flag_tests;
mod pinned_cases;
mod regression_tests;
mod support;
mod upstream_tests;

fn fixture_lang_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("lang")
}

fn fixture_corepkgs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("corepkgs")
}
