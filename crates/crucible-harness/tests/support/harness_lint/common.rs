//! Shared support for `common`.

use super::*;

pub(super) const REDUCTION_PATH_PACKAGES: &[&str] = &[
    "crucible-sim",
    "crucible-assert",
    "crucible",
    "crucible-protocol",
    "crucible-device",
    "crucible-session",
];
pub(super) const NONDETERMINISTIC_BOUNDARY_PACKAGES: &[&str] =
    &["crucible-daemon", "crucible-cli", "crucible-qemu"];
pub(super) const BINARY_BOUNDARY_PACKAGE: &str = "crucible-cli";
pub(super) const BINARY_BOUNDARY_ROOT: &str = "src/main.rs";
pub(super) const CLIPPY_DISALLOWED_METHODS: &[&str] = &[
    "std::time::Instant::now",
    "std::time::Instant::elapsed",
    "std::time::SystemTime::now",
    "rand::thread_rng",
    "rand::rng",
    "rand::random",
    "getrandom::getrandom",
];
pub(super) const CLIPPY_DISALLOWED_TYPES: &[&str] = &[
    "std::collections::HashMap",
    "std::collections::HashSet",
    "std::collections::hash_map::DefaultHasher",
    "std::collections::hash_map::RandomState",
];
pub(super) const CLIPPY_DENY_LINTS: &[&str] = &[
    "all",
    "disallowed_methods",
    "disallowed_types",
    "expect_used",
    "float_arithmetic",
    "unwrap_used",
];
pub(super) const HASH_ITERATION_METHODS: &[&str] = &[
    "iter",
    "iter_mut",
    "keys",
    "values",
    "values_mut",
    "drain",
    "into_iter",
    "into_keys",
    "into_values",
    "extract_if",
    "retain",
    "difference",
    "intersection",
    "symmetric_difference",
    "union",
];
pub(super) const LINT_ALLOW_PREFIX: &str = "crucible-lint: allow ";
pub(super) const LINT_ALLOW_SEPARATOR: &str = " -- ";
pub(super) const LINT_RULES: &[&str] = &[
    "host-wall-clock",
    "host-monotonic-time",
    "thread-global-rng",
    "host-rng",
    "unordered-map-set",
    "default-random-hasher",
    "nondeterministic-select",
    "hash-iteration",
    "unordered-select",
    "clippy-disallowed-method",
    "clippy-disallowed-type",
    "rust-allow",
    "panic-shortcut",
    "erased-error",
    "direct-diagnostic",
    "stringly-error",
    "host-nondeterminism-state",
];

pub(super) fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent() {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

pub(super) fn repo_root() -> PathBuf {
    let workspace = workspace_root();
    match workspace.parent() {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible workspace root has no repository parent"),
    }
}

pub(super) fn rust_sources(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut sources = Vec::new();
    collect_rust_sources(dir, &mut sources)?;
    sources.sort();
    Ok(sources)
}

pub(super) fn collect_rust_sources(
    dir: &Path,
    sources: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            sources.push(path);
        }
    }
    Ok(())
}

pub(super) fn is_binary_boundary_source(package: &str, package_dir: &Path, source: &Path) -> bool {
    package == BINARY_BOUNDARY_PACKAGE
        && matches!(
            source.strip_prefix(package_dir),
            Ok(relative) if relative == Path::new(BINARY_BOUNDARY_ROOT)
        )
}
