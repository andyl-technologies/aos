//! Exercises scratch admission before either inherited private JSON frame.
//!
//! Authenticated prefixes are inert test DATA. A successful prefix read grants
//! only its original parent-channel scope, never a Source or native readiness.

use super::*;
use crate::reference_packet::service::native_startup::{
    PacketNativeInvocationPreambleData, PacketNativeStartupAllocationRow,
    PacketNativeStartupPreambleData, encode_original_native_invocation_preamble_data,
    encode_original_native_startup_preamble_data,
    original_native_birth_startup_counter_scratch_data,
    original_native_invocation_counter_scratch_data, original_native_private_bootstrap_floor_data,
};
use crucible_node_format::U64;
use std::{
    io::Write,
    os::unix::net::UnixStream,
    process::{Command, Stdio},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD_CASE: &str = "CRUCIBLE_NATIVE_PREFIX_SCRATCH_CHILD";
const CHILD_TEST: &str = "reference_packet::service::ack_emitter::native_boot::bootstrap::admitted::counter_tests::inherited_prefix_child";

#[test]
fn startup_prefix_admits_scratch_before_private_frames() -> TestResult {
    exercise_prefix(false)
}

#[test]
fn invocation_prefix_admits_scratch_before_private_frames() -> TestResult {
    exercise_prefix(true)
}

fn exercise_prefix(invocation: bool) -> TestResult {
    let scratch = original_native_birth_startup_counter_scratch_data()
        + if invocation {
            original_native_invocation_counter_scratch_data()
        } else {
            0
        };
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(original_native_private_bootstrap_floor_data()? as u64),
        maximum_simultaneous_transient_bytes: U64::new(
            crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
                65_536,
            )?
            .canonical_pass_requested_bytes()? as u64,
        ),
        declared_counter_scratch_bytes: U64::new(scratch as u64),
    };
    let key = [7; 32];

    for case in ["exact", "private_short", "native_short"] {
        let mut private = row;
        let mut native = row;
        let available = scratch - 1;
        if case.starts_with("private") {
            private.declared_counter_scratch_bytes = U64::new(available as u64);
        } else if case.starts_with("native") {
            native.declared_counter_scratch_bytes = U64::new(available as u64);
        }
        let data = PacketNativeStartupPreambleData {
            controller_pid: u64::from(std::process::id()),
            controller_uid: u64::from(rustix::process::geteuid().as_raw()),
            launch_bytes: 1,
            maximum_boot_bytes: 65_536,
            birth_id: blake3::derive_key("source-owned.packet-canonical-ack-birth/5", &key),
            launch_digest: [0; 32],
            source_digest: [0; 32],
            registration_digest: [0; 32],
            private_launch_digest: [0; 32],
            private_bootstrap: private,
            native_birth: native,
            restore_prepare: None,
        };
        let prefix = if invocation {
            encode_original_native_invocation_preamble_data(
                &PacketNativeInvocationPreambleData {
                    controller_pid: data.controller_pid,
                    controller_uid: data.controller_uid,
                    launch_bytes: data.launch_bytes,
                    maximum_boot_bytes: data.maximum_boot_bytes,
                    birth_id: data.birth_id,
                    launch_digest: data.launch_digest,
                    source_digest: data.source_digest,
                    registration_digest: data.registration_digest,
                    private_launch_digest: data.private_launch_digest,
                    private_bootstrap: data.private_bootstrap,
                    native_birth: data.native_birth,
                    restore_prepare: data.restore_prepare,
                },
                &key,
            )?
        } else {
            encode_original_native_startup_preamble_data(&data, &key)?
        };
        let (mut parent, inherited) = UnixStream::pair()?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
            .env(CHILD_CASE, format!("{invocation}:{case}"))
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(inherited)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn()?;
        drop(command);

        // No launch or boot frame follows: admission must use only this actual
        // authenticated prefix, before constructing either decoded child.
        parent.write_all(&prefix)?;
        parent.shutdown(std::net::Shutdown::Write)?;
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "{invocation}:{case}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
#[ignore = "Re-executed only with the original parent's inherited socket"]
fn inherited_prefix_child() -> TestResult {
    let selected = std::env::var(CHILD_CASE)?;
    let (invocation, case) = selected.split_once(':').ok_or("prefix case absent")?;
    let result = if invocation == "true" {
        OriginalNativeStartupBootstrap::read_invocation(&rustix::stdio::stdin())
    } else {
        OriginalNativeStartupBootstrap::read_original(&rustix::stdio::stdin())
    };

    if case == "exact" {
        let owner = result?;
        owner.ensure_original()?;
        assert!(!owner.native_issued);
        assert!(!owner.failed);
    } else {
        assert!(
            matches!(result, Err(ProviderError::ResourceExhausted(reason))
            if reason == if invocation == "true" {
                "native invocation counter window"
            } else {
                "native startup counter window"
            })
        );
    }
    Ok(())
}
