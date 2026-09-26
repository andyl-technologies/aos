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

    assert_contains(&qemu_nix, "applyCruciblePatch ? false");
    assert_contains(&qemu_nix, "patchPhase =");
    assert_contains(&packages, "pname = \"qemu-crucible\";");
    assert_contains(&packages, "applyCruciblePatch = true");
    assert_contains(&packages, "qemu-crucible-reference");
    assert_contains(&packages, "applyCruciblePatch = false");

    assert_contains(
        &default_checks,
        "qemuInert = import ./phase2-qemu-inert.nix",
    );
    assert_contains(
        &default_checks,
        "patchMicrotests = patchMicrotests.rawGate;",
    );
    assert_contains(
        &patch_microtests,
        "qemu_inert_gate_dependency=gate:qemu-inert->gate:patch-microtests",
    );

    assert_contains(&inert_gate, "referenceQemu ? pkgs.qemu-crucible-reference");
    assert_contains(&inert_gate, "patchedQemu ? pkgs.qemu-crucible");
    assert_contains(&inert_gate, "PATCH_MICROTESTS_RESULT =");
    assert_contains(&inert_gate, "then \"${selectedPatchMicrotests}/result\"");
    assert_contains(
        &inert_gate,
        "else \"${selectedPatchMicrotests}/raw-result\";",
    );
    assert_contains(&inert_gate, "plugin_loaded=false");
    assert_contains(&inert_gate, "sim_accel_selected=false");
    assert_contains(&inert_gate, "run_boot_case reference-tcg");
    assert_contains(&inert_gate, "run_boot_case patched-tcg");
    assert_contains(&inert_gate, "probe_qmp_surface reference");
    assert_contains(&inert_gate, "probe_migration_stream reference");
    assert_contains(&inert_gate, "compare_files qmp-command-set-delta");
    assert_contains(&inert_gate, "reference_vs_patched_boot_tcg_identical=true");
    assert_contains(&inert_gate, "reference_vs_patched_device_io_identical=true");
    assert_contains(&inert_gate, "qmp_upstream_command_set_identical=true");
    assert_contains(
        &inert_gate,
        "qmp_introspection_surface_identical_after_control_extension=true",
    );
    assert_contains(
        &inert_gate,
        "qmp_crucible_control_extension_sim_off_rejected_without_run_state_change=true",
    );
    assert_contains(&inert_gate, "migration_stream_identical=true");
    assert_contains(&inert_gate, "compare_files boot-tcg-raw");
    assert_contains(&inert_gate, "compare_files execution-output-tcg");
    assert_contains(&inert_gate, "printk.time=0");
    assert_contains(
        &inert_gate,
        "exercise_serial_normalization_negative_control",
    );
    assert_contains(&inert_gate, "status=complete");
    assert_contains(
        &inert_gate,
        "taskIds ? [\"T-DET-23\" \"T-HARN-21\" \"T-PATCH-3\"]",
    );
    assert_contains(&inert_gate, "openTaskIds ? []");

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
