//! Guards the production evaluator against workload-specific execution paths.
//!
//! Optimizations may inspect lowered semantics, effects, and runtime value
//! shapes. They must not recognize a benchmark by its source file, exact source
//! bytes, fixed lowered coordinates, or a benchmark-specific environment door.

use std::fs;
use std::path::{Path, PathBuf};

/// Returns every evaluator source or manifest beneath `root` in deterministic order.
fn evaluator_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            let mut children = fs::read_dir(&path)
                .expect("evaluator source directory is readable")
                .map(|entry| entry.expect("evaluator source entry is readable").path())
                .collect::<Vec<_>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        } else if path
            .extension()
            .is_some_and(|extension| extension == "rs" || extension == "toml")
        {
            sources.push(path);
        }
    }
    sources.sort();
    sources
}

/// Returns whether a line compares a lowered coordinate with a numeric literal.
fn has_fixed_lowered_coordinate(line: &str) -> bool {
    let reads_coordinate = line.contains(".pattern().as_u32()")
        || line.contains(".body().as_u32()")
        || line.contains(".frame().as_u32()");
    reads_coordinate
        && [" == ", " != "].iter().any(|operator| {
            line.split_once(operator)
                .and_then(|(_, right)| right.trim_start().chars().next())
                .is_some_and(|first| first.is_ascii_digit())
        })
}

/// Returns whether Rust source embeds a Nix input, including multiline macros.
fn embeds_nix_source(source: &str) -> bool {
    ["include_bytes!", "include_str!"].iter().any(|needle| {
        let mut remainder = source;
        while let Some(offset) = remainder.find(needle) {
            let invocation = &remainder[offset..remainder.len().min(offset.saturating_add(512))];
            if invocation
                .find(");")
                .map_or(invocation, |end| &invocation[..end])
                .contains(".nix")
            {
                return true;
            }
            remainder = &remainder[offset + needle.len()..];
        }
        false
    })
}

#[test]
fn production_evaluator_has_no_workload_pinned_execution_admission() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .expect("ratchet-oracle is inside the crates workspace");
    let roots = [
        manifest.join("src"),
        manifest.join("Cargo.toml"),
        workspace.join("aos-nix/src"),
        workspace.join("aos-nix/Cargo.toml"),
        workspace.join("aos/src"),
        workspace.join("aos/Cargo.toml"),
        workspace.join("ratchet-core/src"),
        workspace.join("ratchet-value/src"),
    ];
    let forbidden_literals = [
        concat!("AOS_NIX_", "FINAL_CONFIG_TRIE_CANARY"),
        concat!("AOS_NIX_", "DEDUP_STRING_LIST_CANARY"),
        concat!("AOS_NIX_", "PACKED_PORTAL_CUTOVER"),
        concat!("AOS_NIX_", "EXEC176_WEAK_PURGE"),
        concat!("AOS_NIX_", "FINAL_FORCE_RESUME_ORDINAL"),
        concat!("AOS_NIX_", "NESTED_NONMOVING_PROOF_ORDINAL"),
        concat!("AOS_NIX_", "NESTED_NONMOVING_RETIREMENT_REPORT_ORDINAL"),
        concat!("AOS_NIX_", "YOUNG_INCREMENT_PROJECTION_ORDINAL"),
        concat!("AOS_NIX_", "NONMOVING_RECLAIM_MODULE"),
        concat!("FinalForce", "PortalSuspend"),
        concat!("/lib/", "modules.nix"),
        concat!("option_map_", "fold_probe"),
        concat!("trusted_", "reference"),
        "14_030_054_434",
        "5_826_183_736",
        "10_523_952_238",
        "3_858_165_127",
        "239_054_848",
        "226_492_416",
        "15_254",
    ];
    let mut violations = Vec::new();

    for root in roots {
        for path in evaluator_sources(&root) {
            let source = fs::read_to_string(&path).expect("evaluator source is UTF-8");
            if embeds_nix_source(&source) {
                violations.push(format!("{}: embeds a Nix source", path.display()));
            }
            for (index, line) in source.lines().enumerate() {
                let forbidden_literal = forbidden_literals
                    .iter()
                    .find(|literal| line.contains(**literal));
                if has_fixed_lowered_coordinate(line) || forbidden_literal.is_some() {
                    violations.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "workload-pinned evaluator code is forbidden:\n{}",
        violations.join("\n")
    );
}
