//! Enforces the RFC-0007 §2 source-file-size standard as a ratcheted test gate.
//!
//! RFC-0007 `docs/rfcs/0007-nix-evaluator/27-engineering-standards.md` §2 sets a
//! hard cap of ~1000 lines per new `.rs` file: exceeding it "means split into a
//! `mod/` directory" of concern-focused submodules. Files inherited above that
//! cap are pinned at their exact current size in [`MIGRATION_CEILINGS`], so that
//! debt cannot grow and every reduction must lower the pin. The combination is
//! an honest migration ratchet: a hard cap for new work, plus explicit,
//! monotonically shrinking inherited debt.
//!
//! To exempt a file, add it to [`ALLOWLIST`] with a written justification — the
//! exemption is a deliberate, reviewable decision, not a silent bypass.

use std::fs;
use std::path::Path;

/// Hard line cap for new and otherwise-unledgered files (RFC-0007 §2).
///
/// The soft target is ~400–500 lines. Files carrying inherited migration debt
/// have an exact, non-increasing ceiling in [`MIGRATION_CEILINGS`].
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

/// Oversized files inherited from the RFC-0007 evaluator integration branch.
///
/// These ceilings make the pre-existing split debt explicit without allowing
/// any file to grow. New files and files absent from this ledger remain subject
/// to [`MAX_LINES`]; reducing a ceiling is encouraged when a file is split.
const MIGRATION_CEILINGS: &[(&str, usize)] = &[
    ("aos-nix/src/jit/engine.rs", 1016),
    ("aos-nix/src/jit/thunk_install/tests.rs", 1034),
    ("ratchet-core/src/analysis/promise_region.rs", 1318),
    ("ratchet-core/src/analysis/semantic_slice.rs", 1503),
    ("ratchet-core/src/analysis/tests/strictness.rs", 1109),
    ("ratchet-core/src/grin_region.rs", 1303),
    ("ratchet-core/src/ir/mod.rs", 1024),
    ("ratchet-core/src/mixed_machine.rs", 3626),
    ("ratchet-core/src/mixed_machine/execution.rs", 1014),
    ("ratchet-core/src/mixed_machine/oracle_lower.rs", 1295),
    ("ratchet-core/src/stg.rs", 1390),
    ("ratchet-jit/src/cranelift/mixed_superblock.rs", 3572),
    ("ratchet-jit/src/lower/lambda_chain/tests.rs", 1006),
    ("ratchet-oracle/src/eval/env.rs", 1060),
    ("ratchet-oracle/src/eval/heap/arena.rs", 1118),
    ("ratchet-oracle/src/eval/heap/arena/values.rs", 1597),
    ("ratchet-oracle/src/eval/heap/census.rs", 2167),
    ("ratchet-oracle/src/eval/heap/flat_values.rs", 1029),
    ("ratchet-oracle/src/eval/heap/flat_values/closures.rs", 1013),
    (
        "ratchet-oracle/src/eval/heap/flat_values/evacuated_closures.rs",
        1381,
    ),
    (
        "ratchet-oracle/src/eval/heap/flat_values/evacuated_permanent.rs",
        1463,
    ),
    (
        "ratchet-oracle/src/eval/heap/flat_values/thunk_heads.rs",
        1216,
    ),
    ("ratchet-oracle/src/eval/heap/mod.rs", 1068),
    (
        "ratchet-oracle/src/eval/heap/packed_collection_lane.rs",
        1904,
    ),
    ("ratchet-oracle/src/eval/heap/packed_generation.rs", 1335),
    (
        "ratchet-oracle/src/eval/heap/packed_rotation_prepare.rs",
        1069,
    ),
    ("ratchet-oracle/src/eval/heap/packed_string_lane.rs", 1122),
    ("ratchet-oracle/src/eval/heap/packed_thunk_lane.rs", 2373),
    (
        "ratchet-oracle/src/eval/heap/roots/field_write_helpers.rs",
        1023,
    ),
    ("ratchet-oracle/src/eval/heap/shared_backend.rs", 1001),
    ("ratchet-oracle/src/eval/heap/thunk.rs", 1094),
    ("ratchet-oracle/src/eval/tree_walk/alloc_intern.rs", 1106),
    (
        "ratchet-oracle/src/eval/tree_walk/alloc_intern/force_thunk.rs",
        1651,
    ),
    ("ratchet-oracle/src/eval/tree_walk/api.rs", 1341),
    ("ratchet-oracle/src/eval/tree_walk/coerce_paths.rs", 1030),
    ("ratchet-oracle/src/eval/tree_walk/demand_machine.rs", 1043),
    (
        "ratchet-oracle/src/eval/tree_walk/demand_region_shadow_probe.rs",
        1539,
    ),
    ("ratchet-oracle/src/eval/tree_walk/eval_apply.rs", 1009),
    ("ratchet-oracle/src/eval/tree_walk/eval_core/memo.rs", 1866),
    ("ratchet-oracle/src/eval/tree_walk/eval_derivation.rs", 1036),
    ("ratchet-oracle/src/eval/tree_walk/eval_import.rs", 1182),
    ("ratchet-oracle/src/eval/tree_walk/eval_load.rs", 1069),
    (
        "ratchet-oracle/src/eval/tree_walk/eval_primop_apply.rs",
        1413,
    ),
    (
        "ratchet-oracle/src/eval/tree_walk/force_shape_census.rs",
        1051,
    ),
    ("ratchet-oracle/src/eval/tree_walk/memo.rs", 1748),
    (
        "ratchet-oracle/src/eval/tree_walk/native_continuation_shadow.rs",
        2403,
    ),
    ("ratchet-oracle/src/eval/tree_walk/options.rs", 1044),
    (
        "ratchet-oracle/src/eval/tree_walk/outcome/eval_stats.rs",
        1103,
    ),
    (
        "ratchet-oracle/src/eval/tree_walk/tests/attrs_2/thunks/part_1.rs",
        1068,
    ),
    (
        "ratchet-oracle/src/eval/tree_walk/tests/builtins_list_3.rs",
        1729,
    ),
    ("ratchet-oracle/src/eval/tree_walk/tests/memo_l0.rs", 1026),
    (
        "ratchet-oracle/src/eval/tree_walk/tests/options/part_11.rs",
        1537,
    ),
    ("ratchet-value/src/heap/flat.rs", 1232),
    ("ratchet-value/src/heap/flat/tests/part_1.rs", 1267),
    ("ratchet-value/src/heap/reservation/mod.rs", 1534),
    ("ratchet-value/src/value/compressed.rs", 1048),
];

/// True for a workspace crate dir governed by the RFC-0007 §2 cap: the Nix
/// dialect band (`aos-nix`, `aos-nix-*`) and the engine band (`ratchet-*`).
/// Other workspace crates (`aos`, `aos-core`, ...) are outside this RFC's scope.
fn is_rfc0007_crate(name: &str) -> bool {
    name == "aos-nix" || name.starts_with("aos-nix-") || name.starts_with("ratchet-")
}

/// Ensures inherited ceilings stay exact, unique, and removable after splits.
///
/// # Panics
///
/// Panics when the migration ledger is stale or contains an invalid entry.
#[test]
fn migration_ceilings_are_exact_and_well_formed() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aos-nix crate dir has a parent (the workspace crates/ dir)");
    let mut previous = None;

    for (rel, ceiling) in MIGRATION_CEILINGS {
        if let Some(previous) = previous {
            assert!(
                previous < *rel,
                "migration ceilings must be unique and sorted: {previous} before {rel}"
            );
        }
        previous = Some(*rel);

        let crate_name = rel
            .split_once('/')
            .map(|(name, _)| name)
            .expect("migration ceiling path is crate-qualified");
        assert!(
            is_rfc0007_crate(crate_name),
            "migration ceiling is outside the RFC-0007 crate set: {rel}"
        );
        assert!(
            *ceiling > MAX_LINES,
            "remove migration ceiling once a file reaches the hard cap: {rel}"
        );

        let path = crates_dir.join(rel);
        let lines = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read migration-ceiling file {rel}: {error}"))
            .lines()
            .count();
        assert_eq!(
            lines, *ceiling,
            "lower the pinned migration ceiling whenever inherited debt shrinks: {rel}"
        );
    }
}

/// Enforces the hard cap and exact inherited-debt ceilings across RFC-0007 crates.
///
/// Scans every `aos-nix*` / `ratchet-*` crate under the workspace `crates/`
/// directory. New and unledgered files may not exceed [`MAX_LINES`]; inherited
/// oversized files may not exceed their exact ceiling in [`MIGRATION_CEILINGS`].
/// The policy follows code as it is re-layered across crates (Phase 1b) rather
/// than being escaped by moving a file to a new crate.
///
/// # Panics
///
/// Panics (the intended test failure) listing every offending file and its line
/// count, with remediation guidance.
#[test]
fn source_files_obey_hard_cap_or_pinned_migration_ceiling() {
    // CARGO_MANIFEST_DIR is `crates/aos-nix`; its parent is the workspace
    // `crates/` directory holding every member crate.
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aos-nix crate dir has a parent (the workspace crates/ dir)")
        .to_path_buf();

    let mut offenders: Vec<(String, usize, usize)> = Vec::new();
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
        "the following source files exceed their RFC-0007 §2 line ceiling.\n\
         Split each into a `mod/` directory of concern-focused submodules \
         (soft target ~400-500 lines), or — only for a genuinely indivisible unit \
         — add a justified entry to ALLOWLIST in tests/source_file_size.rs. \
         Migration ceilings pin inherited debt and must never be raised:\n{}",
        offenders
            .iter()
            .map(|(rel, lines, ceiling)| { format!("  {rel}: {lines} lines (ceiling {ceiling})") })
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Recursively records `.rs` files under `dir` whose line count exceeds the cap,
/// skipping any path in [`ALLOWLIST`]. Paths are reported relative to `root`.
fn collect_offenders(root: &Path, dir: &Path, offenders: &mut Vec<(String, usize, usize)>) {
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
        let ceiling = MIGRATION_CEILINGS
            .iter()
            .find_map(|(baseline, ceiling)| (*baseline == rel).then_some(*ceiling))
            .unwrap_or(MAX_LINES);
        if lines > ceiling {
            offenders.push((rel, lines, ceiling));
        }
    }
}
