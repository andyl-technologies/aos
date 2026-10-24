//! Ordinary controls for fixed-profile validation and bounded parent collection.

use super::supervision::collect;
use super::*;
use std::io::Cursor;

fn limits() -> LinuxPureWorkerLimits {
    LinuxPureWorkerLimits {
        memory_bytes: 1,
        address_space_bytes: 1,
        cpu_seconds: 1,
        descriptors: 16,
        disk_bytes: 1024,
        inodes: 1,
        input_bytes: 1,
        elements: 1,
        bank_bytes: 1,
        diagnostic_bytes: 1,
        stdout_bytes: 1,
        stderr_bytes: 1,
        wall_seconds: 1,
    }
}

#[test]
fn actual_limit_fields_refuse_unrepresentable_and_zero_controls() {
    let selected = limits();
    assert!(selected.validate().is_ok());
    let mut invalid = selected;
    invalid.descriptors = 15;
    assert!(invalid.validate().is_err());
    invalid = selected;
    invalid.inodes = 65_537;
    assert!(invalid.validate().is_err());
    invalid = selected;
    invalid.wall_seconds = i64::MAX as u64 + 1;
    assert!(invalid.validate().is_err());
    invalid = selected;
    invalid.input_bytes = 0;
    assert!(invalid.validate().is_err());
}

#[test]
fn opaque_attempt_equality_is_occurrence_not_layout() {
    let first = LinuxPureWorkerAttemptIdentity(Arc::new(AttemptIdentity));
    assert_eq!(first, first.clone());
    assert_ne!(
        first,
        LinuxPureWorkerAttemptIdentity(Arc::new(AttemptIdentity))
    );
}

#[test]
fn oversized_stream_does_not_grow_retained_output() {
    let mut reader = Some(Cursor::new(vec![42; 17]));
    let mut output = vec![7];
    assert_eq!(
        collect(&mut reader, &mut output, 17),
        Err(LinuxPureWorkerFailure::StdoutLimit)
    );
    assert_eq!(output, [7]);
}

#[test]
fn exact_stream_bound_preserves_binary_bytes_and_eof() {
    let mut reader = Some(Cursor::new(vec![0, 255, 128, 10]));
    let mut output = Vec::new();
    assert_eq!(collect(&mut reader, &mut output, 4), Ok(()));
    assert_eq!(output, [0, 255, 128, 10]);
    assert_eq!(collect(&mut reader, &mut output, 4), Ok(()));
    assert!(reader.is_none());
}

#[test]
fn broad_runtime_roots_refuse_before_opening_artifacts() {
    let result = LinuxPureWorkerProgram::open(
        Path::new("/not-an-artifact"),
        Path::new("/not-a-worker"),
        &[PathBuf::from("/nix/store")],
        [0; 32],
        [1; 32],
    );
    assert!(matches!(result, Err(LinuxPureWorkerError::Configuration)));
}

#[test]
fn shared_installation_uses_safe_send_and_sync_types() {
    fn requires_send_sync<T: Send + Sync>() {}
    requires_send_sync::<LinuxPureWorkerProgram>();
    requires_send_sync::<LinuxPureWorkerProgramIdentity>();
    requires_send_sync::<LinuxPureWorkerAttempt>();
    requires_send_sync::<LinuxPureWorkerCompletion>();
}
