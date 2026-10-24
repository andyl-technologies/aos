//! Checks failed original14 decoding and claims over an inherited parent socket.
//!
//! Prefix and boot fixtures are inert DATA. The child never constructs a Source,
//! opaque Recipe/Initial, native boot or readiness; its wrong key forces refusal.

use super::*;
use crate::reference_packet::service::native_startup::{
    PacketNativeStartupAllocationRow, PacketNativeStartupPreambleData,
    encode_original_native_startup_preamble_data,
    original_native_birth_startup_counter_scratch_data,
    original_native_private_bootstrap_floor_data,
};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    process::{Command, Stdio},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD_CASE: &str = "CRUCIBLE_ORIGINAL14_RETAINED_BOOT_CHILD";
const CHILD_TEST: &str = "reference_packet::service::ack_emitter::native_boot::boot::startup_tests::inherited_boot_refusal_child";

#[test]
fn original_boot_refusals_retain_the_actual_attempt_and_spend_retry() -> TestResult {
    let key = [7; 32];
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(original_native_private_bootstrap_floor_data()? as u64),
        maximum_simultaneous_transient_bytes: U64::new(512 * 1024),
        declared_counter_scratch_bytes: U64::new(
            original_native_birth_startup_counter_scratch_data() as u64,
        ),
    };
    let prefix = encode_original_native_startup_preamble_data(
        &PacketNativeStartupPreambleData {
            controller_pid: u64::from(std::process::id()),
            controller_uid: u64::from(rustix::process::geteuid().as_raw()),
            launch_bytes: 1,
            maximum_boot_bytes: 65_536,
            birth_id: blake3::derive_key("source-owned.packet-canonical-ack-birth/5", &key),
            launch_digest: [0; 32],
            source_digest: [0; 32],
            registration_digest: [0; 32],
            private_launch_digest: [0; 32],
            private_bootstrap: row,
            native_birth: row,
            restore_prepare: None,
        },
        &key,
    )?;

    for case in [
        "credit",
        "decode",
        "nested_decode",
        "identifier_decode",
        "literal",
        "claim",
    ] {
        let (mut parent, inherited) = UnixStream::pair()?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
            .env(CHILD_CASE, case)
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(inherited)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let process = command.spawn()?;
        drop(command);
        parent.write_all(&prefix)?;
        parent.shutdown(std::net::Shutdown::Write)?;
        let output = process.wait_with_output()?;

        assert!(
            output.status.success(),
            "{case}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
#[ignore = "Re-executed only with the original parent's inherited socket"]
fn inherited_boot_refusal_child() -> TestResult {
    let case = std::env::var(CHILD_CASE)?;
    let mut selected = crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::selected_launch(false);
    let launch: PacketNative5SourceLaunch = serde_json::from_value(selected["launch"].take())?;
    let mut value = if case == "credit" {
        serde_json::Value::String("x".repeat(65_536))
    } else if case == "decode" {
        serde_json::json!({})
    } else {
        serde_json::json!({
            "schema": crate::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA,
            "private_key": Bytes::new(vec![29; 32]),
            "birth_id": Bytes::new(vec![0; 32]),
            "source_birth": {"incomplete": "retained source payload"},
            "expected_host_registration": {"incomplete": "retained host payload"},
            "private_launch": "private-data",
            "host_executable": canonical::content_ref(b"inert", "application/test")?,
        })
    };
    if case == "nested_decode" {
        value["host_executable"]["length"] = serde_json::json!("18446744073709551616");
    } else if case == "identifier_decode" {
        value["private_launch"] = serde_json::json!("invalid identifier");
    } else if case == "literal" {
        value["source_birth"]["nested"] = serde_json::json!({
            "$serde_json::private::RawValue": "not JSON"
        });
    }
    let raw_body = canonical::canonical_json(&value)?;
    let launch_body = b"retained launch payload".to_vec();
    let launch_pointer = launch_body.as_ptr();
    let mut attempt = None;
    let mut completed = None;
    let mut startup =
        super::super::bootstrap::admitted::OriginalNativeStartupBootstrap::read_original(
            &rustix::stdio::stdin(),
        )?;

    let result = NativeAckBoot::prepare_original_startup_into(
        OriginalNativeBootValue {
            value: &value,
            body: &raw_body,
        },
        &launch,
        launch_body,
        &mut startup,
        &mut attempt,
        &mut completed,
    );

    assert!(result.is_err());
    let decoded = matches!(case.as_str(), "claim" | "literal");
    if decoded {
        assert!(matches!(
            result,
            Err(ProviderError::Correlation(
                "original native startup preamble data"
            ))
        ));
    }
    assert!(startup.failed);
    assert!(startup.ensure_original().is_err());
    assert!(completed.is_none());
    let retained = attempt.as_ref().ok_or("boot attempt absent")?;
    assert_eq!(retained.launch_body.as_ptr(), launch_pointer);
    assert_eq!(retained.launch_body, b"retained launch payload");
    assert_eq!(startup.native_issued, decoded);
    let source_pointer = if decoded {
        let data = retained.data.as_ref().ok_or("decoded boot absent")?;
        assert_eq!(data.private_key.as_slice(), &[29; 32]);
        assert_eq!(
            data.expected_host_registration["incomplete"],
            "retained host payload"
        );
        assert_eq!(data.source_birth["incomplete"], "retained source payload");
        if case == "literal" {
            assert_eq!(
                data.source_birth["nested"]["$serde_json::private::RawValue"],
                "not JSON"
            );
        }
        Some(
            data.source_birth["incomplete"]
                .as_str()
                .ok_or("source payload absent")?
                .as_ptr(),
        )
    } else {
        assert!(retained.data.is_none());
        None
    };

    let retry = NativeAckBoot::prepare_original_startup_into(
        OriginalNativeBootValue {
            value: &value,
            body: &raw_body,
        },
        &launch,
        Vec::new(),
        &mut startup,
        &mut attempt,
        &mut completed,
    );

    assert!(matches!(
        retry,
        Err(ProviderError::Conflict("native ACK boot already attempted"))
    ));
    let retained = attempt.as_ref().ok_or("retry replaced attempt")?;
    assert_eq!(retained.launch_body.as_ptr(), launch_pointer);
    if let Some(source_pointer) = source_pointer {
        assert_eq!(
            retained
                .data
                .as_ref()
                .ok_or("retry lost decoded boot")?
                .source_birth["incomplete"]
                .as_str()
                .ok_or("retry lost source payload")?
                .as_ptr(),
            source_pointer
        );
    }
    assert!(startup.failed);
    assert!(completed.is_none());
    Ok(())
}
