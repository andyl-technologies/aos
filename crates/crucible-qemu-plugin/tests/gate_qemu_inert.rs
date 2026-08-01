//! Plugin-half checks for `gate:qemu-inert`.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

#[test]
fn gate_qemu_inert_plugin_half_is_backed_by_phase_check() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let plugin_inertness =
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/inertness.rs"))?;
    let phase_check = fs::read_to_string(root.join("tests/crucible/phase2-plugin-qemu-inert.nix"))?;
    let spec = fs::read_to_string(root.join("docs/rfcs/0010-crucible/12-qemu-plugin.md"))?;

    assert_contains(&spec, "- [x] **T-PLUG-23**");
    assert_contains(&spec, "contributes plugin-half evidence for [PLUG-49]");
    assert_contains(&spec, "full real-QEMU corpus is");
    assert_contains(&plugin_inertness, "PluginInertnessObservation::sim_off");
    assert_contains(&plugin_inertness, "PluginArgumentWhenSimulationOff");
    assert_contains(
        &plugin_inertness,
        "PatchCapabilitiesInvokedWhenSimulationOff",
    );
    assert_contains(&plugin_inertness, "time_control_requests");
    assert_contains(&plugin_inertness, "coverage_callback_registrations");
    assert_contains(&plugin_inertness, "whitebox_trap_registrations");
    assert_contains(
        &phase_check,
        "plugin_sim_off_observation_has_no_load_or_effects",
    );
    assert_contains(
        &phase_check,
        "plugin_sim_off_rejects_every_load_or_effect_vector",
    );
    assert_contains(
        &phase_check,
        "full_real_qemu_corpus=checks.crucible.phase2.gates.qemuInert",
    );
    assert_contains(&phase_check, "phase2-qemu-inert.nix");

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
