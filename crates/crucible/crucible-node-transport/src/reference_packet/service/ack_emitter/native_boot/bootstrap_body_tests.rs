//! Exercises literal child correlation after authenticating the original parent.
//!
//! The wire DTOs are inert DATA. Their retained-only floor cannot fund native
//! construction, so even the canonical control must refuse before readiness.

use super::*;
use crate::reference_packet::service::native_startup::*;
use crucible_node_format::{Bytes, U64, canonical};
use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    process::{Command, Stdio},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD_CASE: &str = "CRUCIBLE_NATIVE_CHILD_LITERAL_REFUSAL";
const CHILD_TEST: &str = "reference_packet::service::ack_emitter::native_boot::bootstrap::body_tests::inherited_body_child";

#[test]
fn startup_claim_checks_original_canonical_child_literals() -> TestResult {
    exercise_claim(false)
}

#[test]
fn invocation_claim_checks_original_canonical_child_literals() -> TestResult {
    exercise_claim(true)
}

fn exercise_claim(invocation: bool) -> TestResult {
    let mut selected = crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::initial_selected_launch(false);
    selected["launch"]["controller_pid"] = json!(std::process::id().to_string());
    selected["launch"]["controller_uid"] = json!(rustix::process::geteuid().as_raw().to_string());
    let launch_value = selected["launch"].take();
    let launch: PacketNative5SourceLaunch = serde_json::from_value(launch_value.clone())?;
    let purpose = PacketNativeInvocationPurposeData::original_execution_data(&launch)?;
    let launch_value = serde_json::to_value(&launch)?;
    let launch_value = if invocation {
        json!({"schema_version": 6, "invocation": purpose, "launch": launch_value})
    } else {
        launch_value
    };
    let launch_body = canonical::canonical_json(&launch_value)?;
    let mut source = crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::source_birth(&launch);
    for name in [
        "complete_restore_selection",
        "restore_input_emitter_selection",
        "capture_allocation_selection",
        "fresh_restore_allocation_selection",
        "report_startup_allocation",
        "native_startup_allocation",
    ] {
        source[name] = Value::Null;
    }
    source["schema"] = json!(if invocation {
        PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA
    } else {
        PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA
    });
    if invocation {
        source["invocation"] = serde_json::to_value(&purpose)?;
    }
    let registration = json!({"inert": "host registration"});
    let key = [7; 32];
    let birth_id = blake3::derive_key("source-owned.packet-canonical-ack-birth/5", &key);
    let boot = json!({
        "schema": if invocation { PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA }
                  else { PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA },
        "private_key": Bytes::new(key.to_vec()),
        "birth_id": Bytes::new(birth_id.to_vec()),
        "source_birth": source,
        "expected_host_registration": registration,
        "private_launch": "private-data",
        "host_executable": launch.controller_executable.clone(),
    });
    let canonical_boot = canonical::canonical_json(&boot)?;
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(original_native_private_bootstrap_floor_data()? as u64),
        maximum_simultaneous_transient_bytes: U64::new(
            crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
                1024 * 1024 + 512 * 1024,
            )?.canonical_pass_requested_bytes()? as u64,
        ),
        declared_counter_scratch_bytes: U64::new((original_native_birth_startup_counter_scratch_data()
            + if invocation { original_native_invocation_counter_scratch_data() } else { 0 }) as u64),
    };

    for case in ["canonical", "source_whitespace", "registration_whitespace"] {
        let mut body = canonical_boot.clone();
        if case != "canonical" {
            let key = if case == "source_whitespace" {
                b"\"source_birth\":".as_slice()
            } else {
                b"\"expected_host_registration\":".as_slice()
            };
            let offset = body
                .windows(key.len())
                .position(|window| window == key)
                .ok_or("selected child absent")?
                + key.len();
            assert_eq!(body[offset], b'{');
            body.insert(offset + 1, b' ');
        }
        // The strict parsed DTO and its canonical digests are identical. Only
        // the actual retained child literal differs in the negative controls.
        assert_eq!(canonical::parse_json(&body, usize::MAX)?, boot);
        let data = PacketNativeStartupPreambleData {
            controller_pid: u64::from(std::process::id()),
            controller_uid: u64::from(rustix::process::geteuid().as_raw()),
            launch_bytes: u32::try_from(launch_body.len())?,
            maximum_boot_bytes: 512 * 1024,
            birth_id,
            launch_digest: *blake3::hash(&launch_body).as_bytes(),
            source_digest: *blake3::hash(&canonical::canonical_json(&source)?).as_bytes(),
            registration_digest: *blake3::hash(&canonical::canonical_json(&registration)?)
                .as_bytes(),
            private_launch_digest: *blake3::hash(b"private-data").as_bytes(),
            private_bootstrap: row,
            native_birth: row,
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
                    private_bootstrap: row,
                    native_birth: row,
                    restore_prepare: None,
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

        let write_result = (|| -> TestResult {
            parent.write_all(&prefix)?;
            for frame in [&launch_body, &body] {
                parent.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
                parent.write_all(frame)?;
            }
            parent.shutdown(std::net::Shutdown::Write)?;
            Ok(())
        })();
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "{invocation}:{case}: write={write_result:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        write_result?;
    }
    Ok(())
}

#[test]
#[ignore = "Re-executed only with the original parent's inherited socket"]
fn inherited_body_child() -> TestResult {
    let selected = std::env::var(CHILD_CASE)?;
    let (invocation, case) = selected.split_once(':').ok_or("body case absent")?;
    let startup = if invocation == "true" {
        admitted::OriginalNativeStartupBootstrap::read_invocation(&rustix::stdio::stdin())?
    } else {
        admitted::OriginalNativeStartupBootstrap::read_original(&rustix::stdio::stdin())?
    };
    let cut = OriginalNative5BirthCut::from_original_preparser_cut(startup.original_cut)?;
    let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        1024 * 1024 + 512 * 1024 + 8,
        2,
    )?));
    let stream = super::super::owned_read::OriginalPrivateBootstrapStream {
        original: OriginalPrivateBootstrapInput::Inherited(rustix::stdio::stdin()),
        cut: Some(cut),
    };
    let mut reader = FrameReader::with_limits(
        stream,
        startup.maximum_launch_bytes.max(startup.maximum_boot_bytes),
        64,
    )?;
    reader.install_originals(Rc::clone(&bank));
    let mut owner = Bootstrap {
        reader,
        literals: bank,
        launch_value: None,
        launch_bytes: Vec::new(),
        launch: None,
        boot_value: None,
        boot: None,
        startup_attempt: None,
        startup: Some(startup),
    };

    let result = owner.prepare(Path::new("/not-opened-by-private-refusal-flight"));
    if case == "canonical" {
        assert!(
            matches!(
                result,
                Err(ProviderError::Correlation(
                    "original native startup allocation data"
                ))
            ),
            "{:?}",
            result.as_ref().err()
        );
    } else {
        assert!(
            matches!(
                result,
                Err(ProviderError::Correlation(
                    "native startup canonical child literal differs"
                ))
            ),
            "{:?}",
            result.as_ref().err()
        );
    }
    let startup = owner.startup.as_ref().ok_or("startup absent")?;
    assert!(startup.failed);
    assert!(startup.native_issued);
    assert!(owner.boot_value.is_some());
    assert!(owner.startup_attempt.is_some());
    assert!(owner.boot.is_none(), "unadmitted native boot allocation");
    let (pointer, length) = {
        let retained = owner.literals.try_borrow()?;
        let frame = retained.frame(1).ok_or("retained boot literal absent")?;
        assert!(frame.complete);
        assert_eq!(frame.transferred, frame.bytes.len());
        (frame.bytes.as_ptr(), frame.bytes.len())
    };

    assert!(
        owner
            .prepare(Path::new("/not-opened-by-private-refusal-flight"))
            .is_err()
    );
    let retained = owner.literals.try_borrow()?;
    let frame = retained.frame(1).ok_or("retry lost boot literal")?;
    assert_eq!(frame.bytes.as_ptr(), pointer);
    assert_eq!(frame.bytes.len(), length);
    assert!(owner.startup.as_ref().ok_or("retry lost startup")?.failed);
    Ok(())
}
