//! Enforces the RFC-0007 §2 source-file-size standard as a `cargo test` gate.
//!
//! RFC-0007 `docs/rfcs/0007-nix-evaluator/27-engineering-standards.md` §2 sets a
//! hard cap of ~1000 lines per `.rs` file: exceeding it "means split into a
//! `mod/` directory" of concern-focused submodules. That rule previously lived
//! only in prose, with no mechanical enforcement — so an autonomous,
//! goal-directed contributor with no error in its loop grew one file past 30,000
//! lines. This test moves the cap into the `cargo test` loop, where it surfaces
//! as a failure that must be cleared before the change lands.
//!
//! To exempt a file, add it to [`ALLOWLIST`] with a written justification — the
//! exemption is a deliberate, reviewable decision, not a silent bypass.

use std::fs;
use std::path::Path;

/// Hard line cap per source file (RFC-0007 §2). The soft target is ~400–500.
const MAX_LINES: usize = 1000;

/// Files exempt from [`MAX_LINES`], each justified.
///
/// Paths are relative to `src/`, slash-separated.
///
/// - `eval/tree_walk/error_kind.rs` is a single exhaustive `TreeWalkErrorKind`
///   enum. Splitting one error enum would fragment the parity-relevant
///   error-class surface (§4 — "merging or renaming a variant ... is a parity
///   event"), so the §2 "a cohesive unit beats a contrived split" exception
///   applies: one indivisible type, one file.
const ALLOWLIST: &[&str] = &["eval/tree_walk/error_kind.rs"];

/// Fails when any `src/**.rs` file exceeds the RFC-0007 §2 line cap.
///
/// # Panics
///
/// Panics (the intended test failure) listing every offending file and its line
/// count, with remediation guidance.
#[test]
fn no_source_file_exceeds_line_cap() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders: Vec<(String, usize)> = Vec::new();
    collect_offenders(&src, &src, &mut offenders);
    offenders.sort();

    assert!(
        offenders.is_empty(),
        "the following source files exceed the RFC-0007 §2 hard cap of {MAX_LINES} \
         lines.\nSplit each into a `mod/` directory of concern-focused submodules \
         (soft target ~400-500 lines), or — only for a genuinely indivisible unit \
         — add a justified entry to ALLOWLIST in tests/source_file_size.rs:\n{}",
        offenders
            .iter()
            .map(|(rel, lines)| format!("  {rel}: {lines} lines"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Recursively records `.rs` files under `dir` whose line count exceeds the cap,
/// skipping any path in [`ALLOWLIST`]. Paths are reported relative to `root`.
fn collect_offenders(root: &Path, dir: &Path, offenders: &mut Vec<(String, usize)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_offenders(root, &path, offenders);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWLIST.contains(&rel.as_str()) {
            continue;
        }
        let lines = fs::read_to_string(&path)
            .map(|text| text.lines().count())
            .unwrap_or(0);
        if lines > MAX_LINES {
            offenders.push((rel, lines));
        }
    }
}
