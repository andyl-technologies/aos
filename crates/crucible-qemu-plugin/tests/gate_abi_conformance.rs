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

#[test]
fn gate_abi_conformance_covers_whitebox_doorbell_instruction_abi() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let protocol_lib = fs::read_to_string(root.join("crates/crucible-protocol/src/lib.rs"))?;
    let protocol_doorbell =
        fs::read_to_string(root.join("crates/crucible-protocol/src/doorbell_abi.rs"))?;
    let plugin_lib = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/lib.rs"))?;
    let plugin_whitebox =
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/whitebox_doorbell.rs"))?;
    let guest_lib = fs::read_to_string(root.join("crates/crucible-guest/src/lib.rs"))?;
    let phase_check =
        fs::read_to_string(root.join("tests/crucible/phase4-guest-host-doorbell-abi.nix"))?;
    let guest_host_spec =
        fs::read_to_string(root.join("docs/rfcs/0010-crucible/16-guest-host-channel.md"))?;

    assert_contains(&protocol_lib, "mod doorbell_abi;");
    assert_contains(&protocol_lib, "WhiteboxDoorbellTrapAbi");
    assert_contains(
        &protocol_doorbell,
        "pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = 3;",
    );
    assert_contains(
        &protocol_doorbell,
        "pub const WHITEBOX_DOORBELL_X86_64_RESERVED_PORT: u16 = 0x00e7;",
    );
    assert_contains(
        &protocol_doorbell,
        "pub const WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE: u16 = 0x04c1;",
    );
    assert_contains(&protocol_doorbell, "WhiteboxDoorbellTrapAbi::Aarch64Hlt");
    assert_contains(
        &protocol_doorbell,
        "doorbell_abi_x86_64_vector_freezes_out_imm8_al",
    );
    assert_contains(
        &protocol_doorbell,
        "doorbell_abi_aarch64_vector_freezes_hlt_immediate",
    );

    assert_contains(&plugin_lib, "WHITEBOX_DOORBELL_ABIS");
    assert_contains(&plugin_whitebox, "pub use crucible_protocol");
    assert_contains(
        &plugin_whitebox,
        "pub const fn from_abi(trap: WhiteboxDoorbellTrapAbi)",
    );
    assert_contains(&plugin_whitebox, "WhiteboxDoorbellTrap::Aarch64Hlt");
    assert!(
        !plugin_whitebox.contains("pub const fn new(\n        mode: PluginSwitch"),
        "doorbell state must not expose an arbitrary public trap constructor"
    );

    assert_contains(&guest_lib, "WHITEBOX_DOORBELL_ABIS");
    assert_contains(&guest_lib, "WhiteboxDoorbellTrapAbi");

    assert_contains(&phase_check, "checks.crucible.phase4.guestHostDoorbellAbi");
    assert_contains(&phase_check, "gate=gate:abi-conformance");
    assert_contains(&guest_host_spec, "- [x] **T-GHC-5**");
    assert_contains(&guest_host_spec, "x86_64   out 0xe7,al");
    assert_contains(&guest_host_spec, "aarch64  hlt #0x04c1");

    run_doorbell_abi_unit_targets(&root)?;

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

fn run_doorbell_abi_unit_targets(root: &Path) -> Result<(), Box<dyn Error>> {
    run_cargo_test(
        root,
        &[
            "test",
            "--frozen",
            "--offline",
            "--manifest-path",
            "crates/Cargo.toml",
            "-p",
            "crucible-protocol",
            "doorbell_abi",
            "--",
            "--test-threads=1",
        ],
    )?;
    run_cargo_test(
        root,
        &[
            "test",
            "--frozen",
            "--offline",
            "--manifest-path",
            "crates/Cargo.toml",
            "-p",
            "crucible-qemu-plugin",
            "--lib",
            "whitebox_doorbell",
            "--",
            "--test-threads=1",
        ],
    )
}

fn run_plugin_io_wire_fuzz_unit_target(root: &Path) -> Result<(), Box<dyn Error>> {
    run_cargo_test(
        root,
        &[
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
        ],
    )
}

fn run_cargo_test(root: &Path, args: &[&str]) -> Result<(), Box<dyn Error>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let nested_target = std::env::temp_dir().join("crucible-gate-abi-conformance-target");
    let status = Command::new(cargo)
        .current_dir(root)
        .env("CARGO_TARGET_DIR", nested_target)
        .args(args)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo test target failed with status {status}: {args:?}").into())
    }
}
