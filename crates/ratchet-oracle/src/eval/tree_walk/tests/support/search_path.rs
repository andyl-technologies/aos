//! Tree-walk test support: search-path fixtures and assertions.

use super::super::*;
use super::*;

pub(crate) fn search_path_options(prefix: &[u8], path: &Path) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::new();
    options
        .add_nix_path_entry(prefix.to_vec(), path.as_os_str().as_bytes().to_vec())
        .expect("search path entry configures");
    options
}

pub(crate) fn relative_search_path_options(
    base: &Path,
    prefix: &[u8],
    path: &[u8],
) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::with_search_path_base(base.as_os_str().as_bytes().to_vec())
        .expect("search-path base is absolute");
    options
        .add_nix_path_entry(prefix.to_vec(), path.to_vec())
        .expect("relative search path entry configures");
    options
}

pub(crate) fn search_path_fixture() -> (PathBuf, PathBuf, PathBuf) {
    let root = unique_temp_dir("find-file");
    let nixpkgs = root.join("nixpkgs");
    let subdir = nixpkgs.join("subdir");
    fs::create_dir_all(&subdir).expect("search path fixture creates");
    fs::write(nixpkgs.join("default.nix"), b"{ }").expect("default file writes");
    (root, nixpkgs, subdir)
}

pub(crate) fn resolved_search_path_entry(prefix: &[u8], path: &Path) -> ResolvedSearchPathEntry {
    ResolvedSearchPathEntry {
        prefix: prefix.to_vec(),
        path: path.as_os_str().as_bytes().to_vec(),
    }
}

pub(crate) fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

pub(crate) fn path_value_bytes(evaluator: &TreeWalk, value: Value) -> Vec<u8> {
    evaluator
        .heap()
        .get_path(value)
        .expect("value is a heap-owned path")
        .bytes()
        .to_vec()
}

pub(crate) fn assert_search_path_not_found(error: TreeWalkError, expected_lookup: &[u8]) {
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::SearchPathNotFound { lookup, .. }
                if lookup == expected_lookup
        ),
        "unexpected error: {error:?}"
    );
}
