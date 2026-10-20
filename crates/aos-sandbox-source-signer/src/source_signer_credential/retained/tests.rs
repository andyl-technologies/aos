//! Exercises real fixed credential reads without constructing a Native original.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use aos_sandbox_ledger_replay::source_signer_data::{
    SourceHoldReadbackErrorV1, encode_source_hold_readback_signer_credential_v1,
};

use super::*;

fn write_pair(directory: &Path, seed: [u8; 32]) {
    let key = SigningKey::from_bytes(&seed);
    let pin = encode_source_hold_readback_signer_credential_v1(4, &key.verifying_key()).expect("pin");
    fs::write(directory.join(SEED_NAME), seed).expect("seed");
    fs::set_permissions(directory.join(SEED_NAME), fs::Permissions::from_mode(0o600)).expect("private seed");
    fs::write(directory.join(PIN_NAME), pin).expect("pin");
}

#[test]
fn selected_capture_keeps_actual_files_and_pinned_key() {
    let directory = tempfile::tempdir().expect("directory");
    write_pair(directory.path(), [7; 32]);
    let mut capture = SourceSignerCredentialCaptureV1::new();

    capture.capture_once(directory.path()).expect("matching credentials");
    let (key, generation) = capture.signing_inputs().expect("completed inputs");
    assert_eq!(generation, 4);
    assert_eq!(key.verifying_key(), SigningKey::from_bytes(&[7; 32]).verifying_key());
    assert!(matches!(capture.seed.view().open, Some(Ok(_))));
    assert!(matches!(capture.pin.view().open, Some(Ok(_))));
    assert!(capture.failure().is_none());

    assert!(capture.capture_once(directory.path()).is_err());
    assert!(capture.signing_inputs().is_none());
    assert!(matches!(capture.seed.view().open, Some(Ok(_))));
    assert!(matches!(capture.pin.view().open, Some(Ok(_))));
}

#[test]
fn invalid_pin_keeps_both_original_reads_and_the_exact_decoder_cause() {
    let directory = tempfile::tempdir().expect("directory");
    write_pair(directory.path(), [7; 32]);
    fs::write(directory.path().join(PIN_NAME), [0; 80]).expect("bad pin");
    let mut capture = SourceSignerCredentialCaptureV1::new();

    assert!(capture.capture_once(directory.path()).is_err());
    assert!(capture.signing_inputs().is_none());
    assert!(matches!(capture.seed.view().open, Some(Ok(_))));
    assert!(matches!(capture.pin.view().open, Some(Ok(_))));
    assert!(capture.failure().expect("decoder cause").downcast_ref::<SourceHoldReadbackErrorV1>().is_some());
}

#[test]
fn failed_seed_stops_before_pin_and_retains_the_actual_open_error() {
    let directory = tempfile::tempdir().expect("directory");
    let mut capture = SourceSignerCredentialCaptureV1::new();

    assert!(capture.capture_once(directory.path()).is_err());
    assert!(matches!(capture.seed.view().open, Some(Err(rustix::io::Errno::NOENT))));
    assert!(capture.pin.view().open.is_none());
    assert!(capture.failure().expect("native cause").downcast_ref::<rustix::io::Errno>().is_some());
    assert!(capture.signing_inputs().is_none());
}


#[test]
fn short_seed_refuses_before_reading_the_pin() {
    let directory = tempfile::tempdir().expect("directory");
    write_pair(directory.path(), [7; 32]);
    fs::write(directory.path().join(SEED_NAME), [7; 31]).expect("short seed");
    let mut capture = SourceSignerCredentialCaptureV1::new();

    assert!(capture.capture_once(directory.path()).is_err());

    assert!(capture.signing_inputs().is_none());
    assert!(capture.seed.failure().is_some());
    assert!(capture.pin.view().open.is_none());
    assert!(capture.failure().is_some());
}

#[test]
fn zero_seed_retains_both_reads_without_releasing_signing_inputs() {
    let directory = tempfile::tempdir().expect("directory");
    write_pair(directory.path(), [7; 32]);
    fs::write(directory.path().join(SEED_NAME), [0; 32]).expect("zero seed");
    let mut capture = SourceSignerCredentialCaptureV1::new();

    assert!(capture.capture_once(directory.path()).is_err());

    assert!(capture.signing_inputs().is_none());
    assert!(matches!(capture.seed.view().open, Some(Ok(_))));
    assert!(matches!(capture.pin.view().open, Some(Ok(_))));
    assert!(capture.validation.failure().is_some());
}

#[test]
fn mismatched_role_pin_retains_the_actual_comparison_failure() {
    let directory = tempfile::tempdir().expect("directory");
    write_pair(directory.path(), [7; 32]);
    let foreign_pin = encode_source_hold_readback_signer_credential_v1(
        4, &SigningKey::from_bytes(&[8; 32]).verifying_key(),
    ).expect("foreign pin");
    fs::write(directory.path().join(PIN_NAME), foreign_pin).expect("mismatched pin");
    let mut capture = SourceSignerCredentialCaptureV1::new();

    assert!(capture.capture_once(directory.path()).is_err());

    assert!(capture.signing_inputs().is_none());
    assert!(matches!(capture.seed.view().open, Some(Ok(_))));
    assert!(matches!(capture.pin.view().open, Some(Ok(_))));
    assert!(capture.failure().expect("comparison cause")
        .downcast_ref::<SourceSignerCredentialErrorV1>().is_some());
}

#[test]
fn public_seed_permissions_refuse_before_reading_the_pin() {
    let directory = tempfile::tempdir().expect("directory");
    write_pair(directory.path(), [7; 32]);
    fs::set_permissions(directory.path().join(SEED_NAME), fs::Permissions::from_mode(0o644))
        .expect("unsafe seed mode");
    let mut capture = SourceSignerCredentialCaptureV1::new();

    assert!(capture.capture_once(directory.path()).is_err());

    assert!(capture.signing_inputs().is_none());
    assert!(capture.seed.failure().is_some());
    assert!(capture.pin.view().open.is_none());
    assert!(capture.failure().is_some());
}
