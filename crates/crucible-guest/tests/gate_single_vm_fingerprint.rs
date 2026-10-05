//! Checks the guest-owned non-instrumentation half of `gate:single-vm-fingerprint`.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

#[test]
fn gate_single_vm_fingerprint_uses_an_unmodified_guest() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let gate =
        fs::read_to_string(root.join("tests/crucible/phase1-production-fingerprint-sample.nix"))?;
    let flight =
        fs::read_to_string(root.join("tests/crucible/phase7-production-rust-plugin-flight.nix"))?;
    let spec =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/24-determinism-harness-testing.md"))?;

    assert!(gate.contains("import ./phase7-production-rust-plugin-flight.nix"));
    assert!(flight.contains("${pkgs.linux}/boot/vmlinuz-*"));
    assert!(!flight.contains("pkgs.crucible-guest"));
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
