//! Checks the plugin-owned terminal-diagnostic half of `gate:single-vm-fingerprint`.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

#[test]
fn gate_single_vm_fingerprint_owns_terminal_state_export() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let args = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/args.rs"))?;
    let state_dump =
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/args/state_dump.rs"))?;
    let dump = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/raw_state_dump.rs"))?;
    let gate =
        fs::read_to_string(root.join("tests/crucible/phase2-qemu-live-plugin-fingerprint.nix"))?;

    assert!(args.contains("StateDumpWithoutFingerprint"));
    assert!(args.contains("let state_dump = state_dump::parse(&parsed, fingerprint)?"));
    assert!(state_dump.contains("target_icount == 0"));
    assert!(state_dump.contains("!output_path.is_absolute()"));
    assert!(dump.contains("qemu_plugin_crucible_request_terminal_pause"));
    assert!(dump.contains("qemu_plugin_crucible_guest_ram_regions"));
    assert!(dump.contains("qemu_plugin_crucible_vmstate_snapshot_begin"));
    assert!(dump.contains("resolve_qemu_read_vcpu_regs_symbol"));
    assert!(gate.contains("exports both sides' complete raw state"));

    Ok(())
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
