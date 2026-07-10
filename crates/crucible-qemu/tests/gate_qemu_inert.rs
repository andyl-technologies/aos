//! Checks the implemented `gate:qemu-inert` wiring.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

#[test]
fn gate_qemu_inert_runs_reference_vs_patched_corpus() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let qemu_nix = fs::read_to_string(root.join("pkgs/emulation/qemu.nix"))?;
    let packages = fs::read_to_string(root.join("pkgs/default.nix"))?;
    let default_checks = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    let inert_gate = fs::read_to_string(root.join("tests/crucible/phase2-qemu-inert.nix"))?;
    let patch_microtests =
        fs::read_to_string(root.join("tests/crucible/phase2-patch-microtests.nix"))?;
    let spec = fs::read_to_string(root.join("docs/rfcs/0010-crucible/11-qemu-patches.md"))?;

    assert_contains(&qemu_nix, "applyCruciblePatches ? false");
    assert_contains(&qemu_nix, "patchPhase =");
    assert_contains(&packages, "pname = \"qemu-crucible\";");
    assert_contains(&packages, "applyCruciblePatches = true");
    assert_contains(&packages, "qemu-crucible-reference");
    assert_contains(&packages, "applyCruciblePatches = false");

    assert_contains(
        &default_checks,
        "qemuInert = import ./phase2-qemu-inert.nix",
    );
    assert_contains(
        &default_checks,
        "patchMicrotests = patchMicrotests.rawGate;",
    );
    assert_contains(&patch_microtests, "qemuInertImplementedGateWired =");

    assert_contains(&inert_gate, "referenceQemu ? pkgs.qemu-crucible-reference");
    assert_contains(&inert_gate, "patchedQemu ? pkgs.qemu-crucible");
    assert_contains(
        &inert_gate,
        "PATCH_MICROTESTS_RESULT = \"${patchMicrotests}/result\"",
    );
    assert_contains(&inert_gate, "plugin_loaded=false");
    assert_contains(&inert_gate, "sim_accel_selected=false");
    assert_contains(&inert_gate, "run_boot_case reference-tcg");
    assert_contains(&inert_gate, "run_boot_case reference-icount");
    assert_contains(&inert_gate, "probe_qmp_surface reference");
    assert_contains(&inert_gate, "probe_migration_stream reference");
    assert_contains(&inert_gate, "probe_snapshot_surface reference");
    assert_contains(&inert_gate, "reference_vs_patched_boot_tcg_identical=true");
    assert_contains(
        &inert_gate,
        "reference_vs_patched_boot_plain_icount_identical=true",
    );
    assert_contains(&inert_gate, "qmp_introspection_surface_identical=true");
    assert_contains(&inert_gate, "migration_stream_identical=true");
    assert_contains(&inert_gate, "snapshot_restore_surface_identical=true");

    assert_contains(&spec, "**T-PATCH-3**");
    assert_contains(&spec, "checks.crucible.phase2.gates.qemuInert");
    assert_contains(&spec, "unpatched reference QEMU");

    Ok(())
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
