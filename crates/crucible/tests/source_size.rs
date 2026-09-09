//! Source-size guard for the RFC-0010 Crucible workspace.

use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

// These coarse ceilings supplement the authoritative content-bound reviews in
// `tests/crucible/engineering-hygiene-baseline.txt`. They catch large new files
// even when this package's tests run without the full hygiene gate.
const PRODUCTION_RUST_LINE_LIMIT: usize = 3_000;
const TEST_RUST_LINE_LIMIT: usize = 4_000;
// Existing cohesive modules above a supplemental ceiling are admitted only at
// the line count recorded by their authoritative content-bound review.
const REVIEWED_SOURCE_LINE_DEBT: &[&str] = &["crucible-cas/src/content_store/tests.rs"];

#[test]
fn crucible_rust_sources_stay_human_sized() -> Result<(), Box<dyn Error>> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crucible crate must live below the workspace crates directory")?;
    let repo_root = crates_dir
        .parent()
        .ok_or("workspace crates directory must live below the repository root")?;
    let hygiene_baseline =
        fs::read_to_string(repo_root.join("tests/crucible/engineering-hygiene-baseline.txt"))?;
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
            collect_oversized_rust_sources(&path, crates_dir, &hygiene_baseline, &mut oversized)?;
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
    hygiene_baseline: &str,
    oversized: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_oversized_rust_sources(&path, crates_dir, hygiene_baseline, oversized)?;
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
        let limit = if REVIEWED_SOURCE_LINE_DEBT.contains(&relative_string.as_ref()) {
            reviewed_test_line_count(hygiene_baseline, &relative_string)?
        } else {
            default_limit
        };
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

fn reviewed_test_line_count(
    hygiene_baseline: &str,
    relative_path: &str,
) -> Result<usize, Box<dyn Error>> {
    let review_path = format!("crates/{relative_path}");
    let prefix = format!("shape-review|{review_path}|");
    let mut matching_reviews = hygiene_baseline
        .lines()
        .filter(|line| line.starts_with(&prefix));
    let review = matching_reviews
        .next()
        .ok_or_else(|| format!("missing authoritative source review for {review_path}"))?;
    if matching_reviews.next().is_some() {
        return Err(format!("duplicate authoritative source review for {review_path}").into());
    }

    let fields = review.split('|').collect::<Vec<_>>();
    if fields.len() != 7 || fields[3] != "tests" {
        return Err(format!("invalid authoritative test-source review for {review_path}").into());
    }

    Ok(fields[4].parse()?)
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
