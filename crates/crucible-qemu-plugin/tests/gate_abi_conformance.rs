//! Plugin I/O-wire evidence for `gate:abi-conformance`.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn gate_abi_conformance_covers_plugin_io_wire_fuzzing() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let plugin_lib = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/lib.rs"))?;
    let io_wire_fuzz =
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/io_wire_fuzz.rs"))?;
    let block_io = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/block_io.rs"))?;
    let ninep_io = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/ninep_io.rs"))?;
    let phase_check =
        fs::read_to_string(root.join("tests/crucible/phase2-protocol-codec-fuzz.nix"))?;
    let harness_spec =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/24-determinism-harness-testing.md"))?;

    assert_contains(&plugin_lib, "pub mod io_wire_fuzz;");
    assert_contains(&plugin_lib, "run_io_wire_fuzz_target");
    assert_contains(&plugin_lib, "IO_WIRE_FUZZ_REGRESSION_CORPUS");
    assert_contains(&plugin_lib, "handle_ninep_wire_fuzz_message");

    assert_contains(
        &block_io,
        "pub fn decode(payload: &[u8]) -> Result<(u32, Self), BlockWireError>",
    );
    assert_contains(&block_io, "UnknownOperation");
    assert_contains(&block_io, "RequestCountExceedsPayload");

    assert_contains(&ninep_io, "pub struct NinePWireMessage");
    assert_contains(&ninep_io, "pub struct NinePWireHandlerOutcome");
    assert_contains(
        &ninep_io,
        "pub fn decode_with_msize(frame: &[u8], msize: u32)",
    );
    assert_contains(&ninep_io, "pub fn handle_ninep_wire_fuzz_message");
    assert_contains(&ninep_io, "ninep_lerror");

    assert_contains(&io_wire_fuzz, "pub const NINEP_FUZZ_MSIZE");
    assert_contains(&io_wire_fuzz, "pub const IO_WIRE_FUZZ_REGRESSION_CORPUS");
    assert_contains(&io_wire_fuzz, "run_io_wire_fuzz_target_with_msize");
    assert_contains(&io_wire_fuzz, "assert_io_wire_fuzz_corpus");
    assert_contains(&io_wire_fuzz, "assert_decode_encode_roundtrip");
    assert_contains(&io_wire_fuzz, "assert_clean_reject_or_deterministic_decode");
    assert_contains(&io_wire_fuzz, "assert_well_formed_9p_error_response");
    assert_contains(&io_wire_fuzz, "regression_corpus");

    assert_contains(&phase_check, "run-qemu-plugin-io-wire-fuzz");
    assert_contains(&phase_check, "crucible-qemu-plugin::io_wire_fuzz");
    assert_contains(&harness_spec, "- [x] **T-HARN-19**");
    assert_contains(&harness_spec, "filesystem semantics");

    run_plugin_io_wire_fuzz_unit_target(&root)?;

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

fn run_plugin_io_wire_fuzz_unit_target(root: &Path) -> Result<(), Box<dyn Error>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(root)
        .args([
            "test",
            "--frozen",
            "--offline",
            "--manifest-path",
            "crates/Cargo.toml",
            "-p",
            "crucible-qemu-plugin",
            "--lib",
            "io_wire_fuzz",
            "--",
            "--test-threads=1",
        ])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("plugin I/O wire fuzz unit target failed with status {status}").into())
    }
}
