//! Locates the native libssh2 selected by the AOS build environment.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=AOS_LIBSSH2_PREFIX");

    let expected_prefix = env::var_os("AOS_LIBSSH2_PREFIX")
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("AOS_LIBSSH2_PREFIX must select the packaged libssh2"));
    let library = pkg_config::Config::new()
        .atleast_version("1.11.1")
        .probe("libssh2")
        .unwrap_or_else(|error| panic!("failed to locate packaged libssh2: {error}"));

    let expected_include_path = expected_prefix.join("include");
    let expected_library_path = expected_prefix.join("lib");

    require_path("include", &library.include_paths, &expected_include_path);
    require_path("library", &library.link_paths, &expected_library_path);

    println!("cargo:include={}", expected_include_path.display());
}

fn require_path(kind: &str, paths: &[PathBuf], expected_path: &Path) {
    if !paths.iter().any(|path| path == expected_path) {
        panic!(
            "packaged libssh2 did not report its {kind} path {}",
            expected_path.display()
        );
    }
}
