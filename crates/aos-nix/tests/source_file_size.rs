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
/// Paths are crate-qualified and relative to the workspace `crates/` directory,
/// slash-separated (e.g. `ratchet-oracle/src/...`).
///
/// - `ratchet-oracle/src/eval/tree_walk/error_kind.rs` is a single exhaustive
///   `TreeWalkErrorKind` enum. Splitting one error enum would fragment the
///   parity-relevant error-class surface (§4 — "merging or renaming a variant
///   ... is a parity event"), so the §2 "a cohesive unit beats a contrived
///   split" exception applies: one indivisible type, one file.
/// - `ratchet-oracle/src/eval/heap/errors.rs` is the single exhaustive
///   `EvalHeapError` enum (plus its constructor helpers), split out of
///   `heap/mod.rs`. The same §4 parity-surface rationale as `error_kind.rs`
///   applies: one indivisible type, one file.
/// - `ratchet-runtime-ffi/src/safety.rs` is the reviewed-unsafe DISCIPLINE
///   MANIFEST: the per-file token allowlists, boundary-count pins, and
///   SAFETY-comment assertions that gate every unsafe line in the JIT/FFI
///   band. Its length is proportional to the reviewed surface, and its value
///   is the single-file audit view — a reviewer diffs one file to see every
///   allowlisted boundary change. Splitting it would scatter exactly what it
///   exists to concentrate, and relocating pin definitions is itself a
///   security-sensitive re-home. Team-lead ruling: exempt as a cohesive unit.
const ALLOWLIST: &[&str] = &[
    "ratchet-oracle/src/eval/tree_walk/error_kind.rs",
    "ratchet-oracle/src/eval/heap/errors.rs",
    "ratchet-runtime-ffi/src/safety.rs",
];

/// True for a workspace crate dir governed by the RFC-0007 §2 cap: the Nix
/// dialect band (`aos-nix`, `aos-nix-*`) and the engine band (`ratchet-*`).
/// Other workspace crates (`aos`, `aos-core`, ...) are outside this RFC's scope.
fn is_rfc0007_crate(name: &str) -> bool {
    name == "aos-nix" || name.starts_with("aos-nix-") || name.starts_with("ratchet-")
}

/// Fails when any `src/**.rs` file in an RFC-0007 crate exceeds the §2 line cap.
///
/// Scans every `aos-nix*` / `ratchet-*` crate under the workspace `crates/`
/// directory, so the cap follows code as it is re-layered across crates
/// (Phase 1b) rather than being escaped by moving a file to a new crate.
///
/// # Panics
///
/// Panics (the intended test failure) listing every offending file and its line
/// count, with remediation guidance.
#[test]
fn no_source_file_exceeds_line_cap() {
    // CARGO_MANIFEST_DIR is `crates/aos-nix`; its parent is the workspace
    // `crates/` directory holding every member crate.
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aos-nix crate dir has a parent (the workspace crates/ dir)")
        .to_path_buf();

    let mut offenders: Vec<(String, usize)> = Vec::new();
    let members = fs::read_dir(&crates_dir).expect("read workspace crates/ dir");
    for member in members.flatten() {
        let name = member.file_name().to_string_lossy().into_owned();
        if !member.path().is_dir() || !is_rfc0007_crate(&name) {
            continue;
        }
        let src = member.path().join("src");
        collect_offenders(&crates_dir, &src, &mut offenders);
    }
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
