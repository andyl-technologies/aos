//! Retained phase revision, rollback, overflow, and canonical restore tests.

use super::*;

fn revision(state: &BlockFaultState) -> u64 {
    state
        .observation_revision()
        .unwrap_or_else(|error| panic!("immutable owner revision: {error}"))
        .get()
}

#[test]
fn pipeline_deadline_changes_before_any_response_exists() {
    let mut state = BlockFaultState::write_through(32);
    let request = BlockRequest::read(7, 0, 4);
    let directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
    let before = revision(&state);

    state
        .defer_execution(&request, 10, 30, directive)
        .unwrap_or_else(|error| panic!("retain execution phase: {error}"));

    assert_eq!(state.next_execution_deadline_ticks(), Some(30));
    assert!(state.next_execution_opportunity(29).is_none());
    assert_eq!(
        state.next_execution_opportunity(30).map(|o| o.request),
        Some(request)
    );
    assert_eq!(revision(&state), before + 1);
}

#[test]
fn immutable_queries_and_exact_no_op_polling_preserve_revision() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::write_through(32);
    let before = state.clone();

    for _ in 0..3 {
        assert!(state.next_execution_opportunity(30).is_none());
        state
            .require_directives(false)
            .unwrap_or_else(|error| panic!("no-op configuration: {error}"));
        assert!(
            state
                .resume_execution_to(&base, &mut durable, 30)
                .unwrap_or_else(|error| panic!("no-op pipeline probe: {error}"))
                .is_empty()
        );
        assert!(
            state
                .drain_service_outcomes()
                .unwrap_or_else(|error| panic!("empty drain: {error}"))
                .is_empty()
        );
    }

    assert_eq!(state, before);
    assert_eq!(durable, CowOverlay::new());
}

#[test]
fn exhaustion_refuses_before_phase_and_external_payload_effects() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::write_through(32);
    state.observation_revision = NonZeroU64::MAX;
    let before = state.clone();
    let request = BlockRequest::write(7, 0, vec![0x5a; 4]);
    let directive = ResolvedBlockFaultDirective::fault_free(&request, 32);

    assert!(state.defer_execution(&request, 10, 30, directive).is_err());
    assert!(
        state
            .apply_external_write(&base, &mut durable, 7, 10, 20, 0, vec![0x5a; 4])
            .is_err()
    );
    assert!(state.require_directives(true).is_err());
    assert!(
        state
            .replace_retained_state(BlockFaultState::write_through(32))
            .is_err()
    );

    assert_eq!(state, before);
    assert_eq!(durable, CowOverlay::new());
}

#[test]
fn nested_entry_reserves_once_and_partial_error_retains_revision() {
    let mut state = BlockFaultState::write_through(32);
    let before = revision(&state);

    let result: Result<(), DeviceError> = state.with_observation_mutation(|state| {
        assert!(state.observation_revision().is_err());
        assert_eq!(
            state.to_canonical_bytes(),
            Err(BlockFaultStateCodecError::Invalid)
        );
        state.require_directives(true)?;
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "test interrupted after actual configuration mutation",
        })
    });

    assert!(result.is_err());
    assert!(state.execution_required);
    assert_eq!(revision(&state), before + 1);
}

#[test]
fn clean_refusal_does_not_create_a_poll_dependent_revision() {
    let mut state = BlockFaultState::write_through(32);
    let before = state.clone();

    assert!(
        state
            .record_array_dirty_range(0, u64::MAX, vec![1], 30)
            .is_err()
    );

    assert_eq!(state, before);
}

#[test]
fn trusted_compute_rollback_retains_observed_phase_revision() {
    let mut state = BlockFaultState::write_through(32);
    let checkpoint = state.clone();
    state
        .require_directives(true)
        .unwrap_or_else(|error| panic!("change phase requirement: {error}"));
    let live_revision = revision(&state);

    state.restore_compute_transaction(checkpoint);

    assert!(!state.execution_required);
    assert_eq!(revision(&state), live_revision);
}

#[test]
fn trusted_replacement_advances_from_live_owner_not_saved_counter() {
    let mut state = BlockFaultState::write_through(32);
    let checkpoint = state.clone();
    state
        .require_directives(true)
        .unwrap_or_else(|error| panic!("change phase requirement: {error}"));
    let live_revision = revision(&state);

    state
        .replace_retained_state(checkpoint)
        .unwrap_or_else(|error| panic!("replace trusted rollback state: {error}"));

    assert!(!state.execution_required);
    assert_eq!(revision(&state), live_revision + 1);
}

#[test]
fn repeated_cold_restore_preserves_revision_and_rejects_old_envelope() {
    let mut state = BlockFaultState::write_through(32);
    state
        .require_directives(true)
        .unwrap_or_else(|error| panic!("change phase requirement: {error}"));
    let original_revision = revision(&state);
    let bytes = state
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode owner: {error}"));

    for _ in 0..3 {
        state = BlockFaultState::from_canonical_bytes(&bytes, 32)
            .unwrap_or_else(|error| panic!("restore owner: {error}"));
        assert_eq!(revision(&state), original_revision);
        assert_eq!(
            state
                .to_canonical_bytes()
                .unwrap_or_else(|error| panic!("reencode owner: {error}")),
            bytes
        );
    }
    let mut old = bytes;
    old[b"crucible.block-fault-state.v".len()] = b'3';
    assert_eq!(
        BlockFaultState::from_canonical_bytes(&old, 32),
        Err(BlockFaultStateCodecError::Version)
    );
}

#[test]
fn mandatory_revision_cannot_be_omitted_or_zero_in_a_current_snapshot() {
    let state = BlockFaultState::write_through(32);
    let bytes = state
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode owner: {error}"));
    let prefix = b"crucible.block-fault-state.v4\0";
    let value: ciborium::Value = ciborium::de::from_reader(&bytes[prefix.len()..])
        .unwrap_or_else(|error| panic!("decode fixture fields: {error}"));
    let ciborium::Value::Map(fields) = value else {
        panic!("state encoding is a map");
    };

    for zero in [false, true] {
        let mut fields = fields.clone();
        let index = fields
            .iter()
            .position(|(key, _)| key.as_text() == Some("observation_revision"))
            .unwrap_or_else(|| panic!("mandatory revision field exists"));
        if zero {
            fields[index].1 = ciborium::Value::Integer(0.into());
        } else {
            fields.remove(index);
        }
        let mut forged = prefix.to_vec();
        ciborium::ser::into_writer(&ciborium::Value::Map(fields), &mut forged)
            .unwrap_or_else(|error| panic!("encode malformed fixture: {error}"));

        assert!(BlockFaultState::from_canonical_bytes(&forged, 32).is_err());
    }
}
