//! Canonical trace gold bytes and hashes across borrowed nested projections.

use super::*;

#[test]
fn nested_actions_preserve_prefixes_hex_and_no_trailing_newline() {
    let action = Action::Group(vec![
        Action::Fail {
            reason: String::from("é\n"),
        },
        Action::Group(vec![Action::CreateSavepoint { label: None }, Action::Pass]),
    ]);
    let expected = concat!(
        "chosen=group\nchosen.actions=2\n",
        "chosen.action.0=fail\nchosen.action.0.reason.bytes_len=3\n",
        "chosen.action.0.reason.bytes=c3a90a\n",
        "chosen.action.1=group\nchosen.action.1.actions=2\n",
        "chosen.action.1.action.0=create-savepoint\n",
        "chosen.action.1.action.0.label.present=false\n",
        "chosen.action.1.action.1=pass",
    );
    assert_eq!(
        external_action_material(&"chosen", &action).to_string(),
        expected
    );
}

#[test]
fn borrowed_fault_observations_preserve_original_target_identity_material() {
    use crate::model::{
        FaultCoordinate, FaultObjectId, FaultObservation, FaultObservationKind, ResolvedFaultTarget,
    };
    let identity = ContentHash::from_bytes(b"target");
    let binding = FaultObjectId::parse("memory-controller")
        .unwrap_or_else(|error| panic!("fixture binding: {error}"));
    for target in [
        None,
        Some(ResolvedFaultTarget::BlockRange {
            device: identity,
            start_byte: 19,
            length_bytes: 4097,
        }),
    ] {
        for retired in [None, Some(u64::MAX)] {
            let observation = FaultObservation {
                semantic_version: 3,
                kind: FaultObservationKind::EffectApplied,
                coordinate: FaultCoordinate {
                    virtual_ticks: 123,
                    retired_instructions: retired,
                },
                binding: Some(binding.clone()),
                target: target.clone(),
                opportunity: Some(identity),
                evidence: ContentHash::from_bytes(b"evidence"),
            };
            assert_eq!(
                observation.canonical_display().to_string(),
                observation.canonical_material()
            );
        }
    }
}

#[test]
fn streamed_reproduction_hash_matches_exact_export_bytes() -> Result<(), EngineError> {
    let _decoding = crate::test_support::fixture_decode_scope(1024 * 1024)
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    let entries = [SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 17 },
        "lifetime\n水",
    )?];
    let bytes = external_formal_trace_bytes(&entries)?;
    assert_eq!(
        external_formal_trace_hash(&entries)?,
        ContentHash::from_bytes(&bytes)
    );
    assert!(!bytes.ends_with(b"\n"));
    assert!(
        std::str::from_utf8(&bytes).is_ok_and(|text| text.contains("entry.payload_end\nentry_end"))
    );
    Ok(())
}
