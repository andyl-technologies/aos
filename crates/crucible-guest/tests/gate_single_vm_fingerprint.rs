//! Checks the guest-owned non-instrumentation half of `gate:single-vm-fingerprint`.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

#[test]
fn gate_single_vm_fingerprint_uses_an_unmodified_guest() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let gate = fs::read_to_string(root.join("tests/crucible/phase0-s11.nix"))?;
    let spec =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/24-determinism-harness-testing.md"))?;

    assert!(gate.contains("KERNEL = builtins.toString pkgs.linux"));
    assert!(!gate.contains("pkgs.crucible-guest"));
    assert!(spec.contains("- [x] **T-HARN-7**"));
    assert!(spec.contains("ordinary pass boots one unmodified"));

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
