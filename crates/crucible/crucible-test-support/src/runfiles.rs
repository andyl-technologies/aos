//! Resolves declared executables for integration-test subprocesses.
//!
//! Cargo supplies absolute executable paths. Bazel supplies paths relative to
//! the workspace inside its declared runfiles tree; resolving them before a
//! subprocess changes directory keeps both execution models consistent.

use std::path::{Path, PathBuf};

/// Resolves a compiler-declared executable through the test runfiles tree.
///
/// Absolute paths are returned unchanged. Relative paths resolve beneath
/// `TEST_SRCDIR/TEST_WORKSPACE` when both environment variables are present;
/// otherwise they retain their original working-directory-relative meaning.
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
///
/// use crucible_test_support::runfiles::binary_path;
///
/// assert_eq!(binary_path("/declared/bin/tool"), Path::new("/declared/bin/tool"));
/// ```
pub fn binary_path(compiled_path: &str) -> PathBuf {
    let path = Path::new(compiled_path);
    if path.is_absolute() {
        return path.to_path_buf();
    }

    match (
        std::env::var_os("TEST_SRCDIR"),
        std::env::var_os("TEST_WORKSPACE"),
    ) {
        (Some(runfiles), Some(workspace)) => PathBuf::from(runfiles).join(workspace).join(path),
        _ => path.to_path_buf(),
    }
}
