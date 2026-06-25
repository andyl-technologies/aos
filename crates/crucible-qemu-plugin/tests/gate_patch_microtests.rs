//! Checks the aggregate `gate:patch-microtests` wiring.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED_PATCHES: &[&str] = &[
    "0001-crucible-sim-accel.patch",
    "0002-crucible-rr-fingerprint-helpers.patch",
    "0003-crucible-icount-no-realtime.patch",
    "0004-crucible-no-warp-with-plugin.patch",
    "0005-crucible-det-glib-prng.patch",
    "0006-crucible-clock-deadline.patch",
    "0007-crucible-block-rtc-read.patch",
    "0008-crucible-det-getrandom.patch",
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
    assert_contains(
        &aggregate,
        "qemuPatchSeries = import ./phase2-qemu-patch-series.nix",
    );
    assert_contains(&aggregate, "tar -xf ${qemuPackage.src}");
    assert_contains(&aggregate, "patch --batch --forward --fuzz=0 -p1");
    assert_contains(&aggregate, "test -x ${qemuPackage}/bin/qemu-system-x86_64");
    assert_contains(&aggregate, "patch_series_gate_passed=true");
    assert_contains(&aggregate, "apply_clean_pinned_qemu=true");
    assert_contains(&aggregate, "patched_qemu_package_build_passed=true");
    assert_contains(&aggregate, "qemu_package=${qemuPackage}");
    assert_contains(&aggregate, "qemu_package_version=${qemuPackage.version}");
    assert_contains(&aggregate, "qemu_inert_gate_wired=true");
    assert_contains(&aggregate, "qemu_inert_depends_on_patch_microtests=true");
    assert_contains(
        &aggregate,
        "every_microtest_keyed_to_patched_qemu_package=true",
    );
    assert_contains(&aggregate, "every_carried_patch_has_microtest=true");
    assert_contains(
        &aggregate,
        "every_microtest_has_stock_negative_control=true",
    );

    let default_checks = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    assert_contains(&default_checks, "patchMicrotestsCheck = import");
    assert_contains(
        &default_checks,
        "qemuInert = import ./phase2-qemu-inert.nix",
    );
    assert_contains(
        &default_checks,
        "attrPath = \"checks.crucible.phase2.gates.qemuInert\";",
    );
    assert_contains(&default_checks, "patchMicrotests = patchMicrotestsCheck;");

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
            "tests/crucible/phase1-sim-accel.nix",
            "",
            "0001-crucible-sim-accel.patch",
        ),
        (
            "tests/crucible/phase1-rr-fingerprint-helpers.nix",
            "tests/crucible/phase1-rr-fingerprint-helpers.c",
            "0002-crucible-rr-fingerprint-helpers.patch",
        ),
        (
            "tests/crucible/phase1-icount-no-realtime.nix",
            "tests/crucible/phase1-icount-no-realtime.c",
            "0003-crucible-icount-no-realtime.patch",
        ),
        (
            "tests/crucible/phase1-no-warp-with-plugin.nix",
            "tests/crucible/phase1-no-warp-with-plugin.c",
            "0004-crucible-no-warp-with-plugin.patch",
        ),
        (
            "tests/crucible/phase1-qemu-deterministic-entropy.nix",
            "tests/crucible/phase1-qemu-deterministic-entropy.c",
            "0005-crucible-det-glib-prng.patch",
        ),
        (
            "tests/crucible/phase1-clock-deadline.nix",
            "tests/crucible/phase1-clock-deadline.c",
            "0006-crucible-clock-deadline.patch",
        ),
        (
            "tests/crucible/phase1-block-rtc-read.nix",
            "tests/crucible/phase1-block-rtc-read.c",
            "0007-crucible-block-rtc-read.patch",
        ),
        (
            "tests/crucible/phase1-qemu-deterministic-getrandom.nix",
            "tests/crucible/phase1-qemu-deterministic-entropy.c",
            "0008-crucible-det-getrandom.patch",
        ),
    ];

    for (nix_path, c_path, patch) in per_patch_checks {
        let nix_source = fs::read_to_string(root.join(nix_path))?;

        assert_contains(&nix_source, "gate=gate:patch-microtests");
        assert_contains(&nix_source, &format!("patch={patch}"));
        assert_contains(&nix_source, "patched_fixture_exercised=true");
        assert_contains(&nix_source, "stock_negative_control");
        assert_contains(&nix_source, "qemuPackage ?");
        assert_contains(&nix_source, "qemu_package=${qemuPackage}");
        assert_contains(&nix_source, "qemu_package_version=${qemuPackage.version}");
        assert_contains(&nix_source, "patch --batch --fuzz=0 -p1");
        if !c_path.is_empty() {
            let c_source = fs::read_to_string(root.join(c_path))?;
            assert_contains(&c_source, "stock_negative_control");
        }
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
