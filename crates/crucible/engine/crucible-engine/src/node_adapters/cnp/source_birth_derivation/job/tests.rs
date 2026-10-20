//! Exercises actual owned failure causes and the pre-loan workspace producer.
//!
//! These controls mint no installation, attempt, completion or Source authority.

use super::*;
use std::error::Error;

#[test]
fn owned_runtime_failure_keeps_original_string_and_does_not_render_it() {
    let mut message = String::with_capacity(128);
    message.push_str("private operational diagnostic");
    let pointer = message.as_ptr();
    let capacity = message.capacity();
    let failure = SourceBirthJobFailure::Runtime(RuntimeError::SchedulerRefused(message));

    assert_eq!(failure.to_string(), "SourceBirth original guard refused");
    let SourceBirthJobFailure::Runtime(RuntimeError::SchedulerRefused(message)) = &failure else {
        panic!("original typed cause was replaced");
    };
    assert_eq!(message.as_ptr(), pointer);
    assert_eq!(message.capacity(), capacity);
    assert!(
        failure
            .source()
            .unwrap()
            .downcast_ref::<RuntimeError>()
            .is_some()
    );
}

#[test]
fn concrete_input_failure_keeps_original_linux_cause_and_static_outer_message() {
    let failure = SourceBirthJobFailure::Export {
        error: ExportError::Io(std::io::ErrorKind::WriteZero.into()),
        input: Some(LinuxPureWorkerError::InputLimit),
    };

    assert_eq!(
        failure.to_string(),
        "SourceBirth original input export failed"
    );
    assert!(
        failure
            .source()
            .unwrap()
            .downcast_ref::<ExportError>()
            .is_some()
    );
    assert!(matches!(
        failure,
        SourceBirthJobFailure::Export {
            input: Some(LinuxPureWorkerError::InputLimit),
            ..
        }
    ));
}

#[test]
fn workspace_geometry_precedes_allocation_and_empty_budget_cannot_traverse_array() {
    use crate::node_adapters::cnp::source_birth_derivation::literal_value::{self, StreamLimits};
    assert!(ExportWorkspace::requested_bytes(usize::MAX).is_err());
    let mut workspace = ExportWorkspace::new(0).unwrap();
    assert_eq!(
        workspace.retained_bytes(),
        ExportWorkspace::requested_bytes(0).unwrap()
    );
    let input = serde_json::json!([0]);
    let mut output = Vec::new();
    let limits = StreamLimits {
        maximum_wire_bytes: 1024,
        maximum_values: 16,
    };
    assert!(literal_value::write_value_in(&input, &mut output, limits, &mut workspace).is_err());
    assert_eq!(
        workspace.retained_bytes(),
        ExportWorkspace::requested_bytes(0).unwrap()
    );
}
