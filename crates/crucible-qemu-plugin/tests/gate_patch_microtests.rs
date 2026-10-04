//! Checks the atomic QEMU patch and its gate:patch-microtests contract.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const ATOMIC_PATCH: &str = "crucible-qemu-11.1.1.patch";

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let mut current = std::env::current_dir()?;
    loop {
        if current.join("crates/Cargo.toml").is_file()
            && current.join("tests/crucible/default.nix").is_file()
        {
            return Ok(current);
        }
        if !current.pop() {
            return Err("could not locate workspace root".into());
        }
    }
}

fn read(root: &Path, path: &str) -> Result<String, Box<dyn Error>> {
    Ok(fs::read_to_string(root.join(path))?)
}

fn assert_contains(source: &str, needle: &str) {
    assert!(
        source.contains(needle),
        "expected to find {} in checked source",
        needle
    );
}

#[test]
fn gate_patch_microtests_covers_atomic_qemu_artifact() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let patch_dir = root.join("pkgs/emulation/qemu-patches");
    let patch_files = fs::read_dir(&patch_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".patch"))
        .collect::<Vec<_>>();
    assert_eq!(patch_files, [ATOMIC_PATCH]);

    let descriptor = read(&root, "pkgs/emulation/qemu-patches/_atomic-patch.nix")?;
    assert_contains(&descriptor, &format!("file = \"{ATOMIC_PATCH}\";"));
    for field in [
        "sha256 = ",
        "commit = ",
        "tree = ",
        "baseCommit = ",
        "bundleSha256 = ",
    ] {
        assert_contains(&descriptor, field);
    }
    let repository_gate = read(&root, "tests/crucible/_qemu-atomic-patch-repository.nix")?;
    for evidence in [
        "bundle commit must contain exactly one embedded gpgsig header",
        "bundle commit must contain exactly one matching DCO sign-off",
        "bundle commit does not regenerate the checked atomic patch",
    ] {
        assert_contains(&repository_gate, evidence);
    }

    let qemu_nix = read(&root, "pkgs/emulation/qemu.nix")?;
    assert_contains(
        &qemu_nix,
        "atomicPatch ? import ./qemu-patches/_atomic-patch.nix",
    );
    assert_contains(&qemu_nix, "< ${atomicPatchPath}");
    assert_contains(&qemu_nix, "qemu_atomic_patch_hash=${atomicPatchHash}");

    let aggregate = read(&root, "tests/crucible/phase2-patch-microtests.nix")?;
    for evidence in [
        "gate=gate:patch-microtests",
        "evidence_scope=atomic-apply-commit-tree-build-behavior",
        "apply_commit_tree_verified=true",
        "bundle_matches_patch_commit=true",
        "atomic_patch_regenerated_exactly=true",
        "atomic_patch_live_checkpoint_delta_gate_passed=true",
        "stock_qemu_lacks_atomic_exports=true",
        "qemu_inert_depends_on_patch_microtests=true",
    ] {
        assert_contains(&aggregate, evidence);
    }
    Ok(())
}
