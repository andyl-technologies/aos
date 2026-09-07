//! Source-size guard for the RFC-0010 Crucible workspace.

use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

const PRODUCTION_RUST_LINE_LIMIT: usize = 3_000;
const TEST_RUST_LINE_LIMIT: usize = 4_000;
// Existing cohesive modules that crossed the repository-wide threshold are
// capped at their reviewed size so new growth still fails closed while their
// follow-up splits can proceed independently.
const SOURCE_LINE_DEBT: &[(&str, usize)] = &[
    ("crucible-api/src/vm_lifecycle/checkpoint_store.rs", 3_217),
    ("crucible-cas/src/content_store/tests.rs", 5_357),
];

#[test]
fn crucible_rust_sources_stay_human_sized() -> Result<(), Box<dyn Error>> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crucible crate must live below the workspace crates directory")?;
    let mut oversized = Vec::new();

    for entry in fs::read_dir(crates_dir)? {
        let entry = entry?;
        let path = entry.path();
        let is_crucible_crate = path.is_dir()
            && path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name == "crucible" || name.starts_with("crucible-"));
        if is_crucible_crate {
            collect_oversized_rust_sources(&path, crates_dir, &mut oversized)?;
        }
    }

    oversized.sort();
    assert!(
        oversized.is_empty(),
        "Crucible Rust sources must be split by responsibility:\n{}",
        oversized.join("\n"),
    );
    Ok(())
}

fn collect_oversized_rust_sources(
    directory: &Path,
    crates_dir: &Path,
    oversized: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_oversized_rust_sources(&path, crates_dir, oversized)?;
            continue;
        }
        if path.extension() != Some(OsStr::new("rs")) {
            continue;
        }

        let line_count = fs::read_to_string(&path)?.lines().count();
        let default_limit = if is_test_source(&path) {
            TEST_RUST_LINE_LIMIT
        } else {
            PRODUCTION_RUST_LINE_LIMIT
        };
        let relative = path.strip_prefix(crates_dir).unwrap_or(&path);
        let relative_string = relative.to_string_lossy();
        let limit = SOURCE_LINE_DEBT
            .iter()
            .find_map(|(debt_path, debt_limit)| {
                (relative_string == *debt_path).then_some(*debt_limit)
            })
            .unwrap_or(default_limit);
        if line_count > limit {
            oversized.push(format!(
                "{}: {line_count} lines (limit {limit})",
                relative.display(),
            ));
        } else if limit > default_limit && line_count <= default_limit {
            oversized.push(format!(
                "{}: stale source-size debt cap {limit}; observed {line_count}",
                relative.display(),
            ));
        }
    }
    Ok(())
}

fn is_test_source(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == OsStr::new("tests"))
        || path.file_name() == Some(OsStr::new("tests.rs"))
        || path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.ends_with("_test.rs"))
}
