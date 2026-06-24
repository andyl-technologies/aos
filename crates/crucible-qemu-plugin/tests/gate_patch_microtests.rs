//! Checks the aggregate `gate:patch-microtests` wiring.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED_PATCHES: &[&str] = &[
    "0001-add-crucible-rr-fingerprint-helpers.patch",
    "0002-crucible-icount-no-realtime.patch",
    "0003-crucible-no-warp-with-plugin.patch",
    "0004-crucible-deterministic-qemu-entropy.patch",
    "0005-crucible-clock-deadline.patch",
];

#[test]
fn gate_patch_microtests_covers_carried_qemu_patch_series() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let patch_dir = root.join("pkgs/emulation/qemu-patches");
    let carried_patches = patch_files(&patch_dir)?;
    let expected_patches = EXPECTED_PATCHES.iter().copied().collect::<BTreeSet<_>>();

    assert_eq!(
        carried_patches, expected_patches,
        "the Cargo gate target must be updated when the carried QEMU patch series changes"
    );

    let aggregate = fs::read_to_string(root.join("tests/crucible/phase2-patch-microtests.nix"))?;
    assert_contains(&aggregate, "gate=gate:patch-microtests");
    assert_contains(&aggregate, "every_carried_patch_has_microtest=true");
    assert_contains(
        &aggregate,
        "every_microtest_has_stock_negative_control=true",
    );

    for patch in EXPECTED_PATCHES {
        assert_contains(&aggregate, patch);
        assert_contains(&aggregate, "grep -q '^patch=${test.patch}$' \"$result\"");
        assert_contains(&aggregate, "grep -q '^patched_fixture_exercised=true$'");
        assert_contains(&aggregate, "grep -q '^stock_negative_control=true$'");
    }

    Ok(())
}

#[test]
fn per_patch_microtests_publish_required_evidence() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let per_patch_checks = [
        (
            "tests/crucible/phase1-rr-fingerprint-helpers.nix",
            "tests/crucible/phase1-rr-fingerprint-helpers.c",
            "0001-add-crucible-rr-fingerprint-helpers.patch",
        ),
        (
            "tests/crucible/phase1-icount-no-realtime.nix",
            "tests/crucible/phase1-icount-no-realtime.c",
            "0002-crucible-icount-no-realtime.patch",
        ),
        (
            "tests/crucible/phase1-no-warp-with-plugin.nix",
            "tests/crucible/phase1-no-warp-with-plugin.c",
            "0003-crucible-no-warp-with-plugin.patch",
        ),
        (
            "tests/crucible/phase1-qemu-deterministic-entropy.nix",
            "tests/crucible/phase1-qemu-deterministic-entropy.c",
            "0004-crucible-deterministic-qemu-entropy.patch",
        ),
        (
            "tests/crucible/phase1-clock-deadline.nix",
            "tests/crucible/phase1-clock-deadline.c",
            "0005-crucible-clock-deadline.patch",
        ),
    ];

    for (nix_path, c_path, patch) in per_patch_checks {
        let nix_source = fs::read_to_string(root.join(nix_path))?;
        let c_source = fs::read_to_string(root.join(c_path))?;

        assert_contains(&nix_source, "gate=gate:patch-microtests");
        assert_contains(&nix_source, &format!("patch={patch}"));
        assert_contains(&nix_source, "patched_fixture_exercised=true");
        assert_contains(&nix_source, "stock_negative_control");
        assert_contains(&nix_source, "patch --batch --fuzz=0 -p1");
        assert_contains(&c_source, "stock_negative_control");
    }

    Ok(())
}

fn patch_files(path: &Path) -> Result<BTreeSet<&'static str>, Box<dyn Error>> {
    let mut patches = BTreeSet::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".patch") {
            let patch = EXPECTED_PATCHES
                .iter()
                .copied()
                .find(|expected| *expected == name);
            if let Some(patch) = patch {
                patches.insert(patch);
            } else {
                panic!("unexpected carried QEMU patch `{name}`");
            }
        }
    }
    Ok(patches)
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find `{needle}` in checked source"
    );
}

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
