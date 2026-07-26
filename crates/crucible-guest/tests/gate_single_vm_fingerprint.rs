//! Checks the guest-owned non-instrumentation half of `gate:single-vm-fingerprint`.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

#[test]
fn gate_single_vm_fingerprint_uses_an_unmodified_guest() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let gate =
        fs::read_to_string(root.join("tests/crucible/phase2-qemu-live-plugin-fingerprint.nix"))?;
    let runner = fs::read_to_string(
        root.join("crates/crucible-qemu/src/single_vm_fingerprint/plugin_live_runner.rs"),
    )?;
    let spec =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/24-determinism-harness-testing.md"))?;

    assert!(gate.contains("GUEST_KERNEL = builtins.toString pkgs.linux"));
    assert!(gate.contains("GUEST_INITRD = \"${idleInitramfs}/initrd.img\""));
    assert!(!gate.contains("pkgs.crucible-guest"));
    assert!(spec.contains("- [x] **T-HARN-7**"));
    assert!(spec.contains("ordinary pass boots one unmodified"));
    assert!(!runner.contains("Whitebox"));

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
