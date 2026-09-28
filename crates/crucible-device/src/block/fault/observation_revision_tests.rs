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

fn cached_fragment() -> (BlockFaultState, BaseImage, CowOverlay) {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut config = BlockDurabilityConfig::write_through(32);
    config.atomic_write_bytes = 4;
    config.volatile_cache_bytes = 32;
    config.cache_entries = 8;
    config.completion_durability = BlockCompletionDurability::VolatileCacheAccepted;
    let mut state = BlockFaultState::new(config)
        .unwrap_or_else(|error| panic!("bounded cache configuration: {error}"));
    state
        .apply_external_write(&base, &mut durable, 7, 10, 20, 0, vec![0x5a; 4])
        .unwrap_or_else(|error| panic!("actual retained cache fragment: {error}"));
    assert_eq!(state.volatile_entries().len(), 1);
    assert_eq!(durable, CowOverlay::new());
    (state, base, durable)
}

#[test]
fn absent_graph_commit_refuses_before_any_durable_payload_write() {
    let (mut state, base, mut durable) = cached_fragment();
    state
        .persistence
        .commit_lost(0)
        .unwrap_or_else(|error| panic!("remove graph node: {error}"));
    let before = state.clone();

    let result =
        state.with_observation_mutation(|state| state.persist_sequence(&base, &mut durable, 0, 30));

    assert!(result.is_err());
    assert_eq!(state, before);
    assert_eq!(durable, CowOverlay::new());
}

#[test]
fn layer_accounting_refuses_before_any_durable_payload_write() {
    let (mut state, base, mut durable) = cached_fragment();
    state.volatile_bytes = 0;
    let before = state.clone();

    let result =
        state.with_observation_mutation(|state| state.persist_sequence(&base, &mut durable, 0, 30));

    assert!(result.is_err());
    assert_eq!(state, before);
    assert_eq!(durable, CowOverlay::new());
}

#[test]
fn physical_destination_refuses_before_any_durable_payload_write() {
    let (mut state, _, mut durable) = cached_fragment();
    let short_base = BaseImage::new(vec![0; 2]);
    let before = state.clone();

    let result = state.with_observation_mutation(|state| {
        state.persist_sequence(&short_base, &mut durable, 0, 30)
    });

    assert!(result.is_err());
    assert_eq!(state, before);
    assert_eq!(durable, CowOverlay::new());
}

#[test]
fn actual_payload_effect_followed_by_refusal_retains_reserved_revision() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::write_through(32);
    let before = revision(&state);

    let result: Result<(), DeviceError> = state.with_observation_mutation(|state| {
        // Exercise the defensive external-effect marker with the actual
        // overlay operation and a later refusal, without retained field edits.
        state.observation_external_effect = true;
        durable.write(&base, 0, &[0x5a; 4])?;
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "test refusal after durable payload effect",
        })
    });

    assert!(result.is_err());
    assert_eq!(
        durable
            .read(&base, 0, 4)
            .unwrap_or_else(|error| panic!("read actual effect: {error}")),
        vec![0x5a; 4]
    );
    assert_eq!(revision(&state), before + 1);
}

#[test]
fn rebuild_poll_changes_only_when_the_actual_deadline_changes() {
    let mut state = BlockFaultState::write_through(32);
    state
        .record_array_dirty_range(0, 0, vec![0x5a; 4], 10)
        .unwrap_or_else(|error| panic!("dirty range: {error}"));
    let before = revision(&state);

    assert!(
        state
            .next_array_rebuild_opportunity(10, 4, 1_000_000_000, None)
            .unwrap_or_else(|error| panic!("schedule actual rebuild: {error}"))
            .is_none()
    );
    assert_eq!(revision(&state), before + 1);
    let scheduled = state.clone();
    assert!(
        state
            .next_array_rebuild_opportunity(10, 4, 1_000_000_000, None)
            .unwrap_or_else(|error| panic!("unchanged probe: {error}"))
            .is_none()
    );
    assert_eq!(state, scheduled);

    let deadline = state
        .next_array_rebuild_deadline_ticks()
        .unwrap_or_else(|| panic!("retained deadline"));
    assert!(
        state
            .next_array_rebuild_opportunity(deadline, 4, 1_000_000_000, None)
            .unwrap_or_else(|error| panic!("ready probe: {error}"))
            .is_some()
    );
    assert_eq!(state, scheduled);
}

#[test]
fn dependency_blocked_graph_commit_refuses_before_any_durable_payload_write() {
    let (mut state, base, mut durable) = cached_fragment();
    state
        .apply_external_write(&base, &mut durable, 8, 11, 21, 0, vec![0x6b; 4])
        .unwrap_or_else(|error| panic!("dependent cache fragment: {error}"));
    assert!(!state.persistence.is_ready(1));
    let before = state.clone();

    let result =
        state.with_observation_mutation(|state| state.persist_sequence(&base, &mut durable, 1, 30));

    assert!(result.is_err());
    assert_eq!(state, before);
    assert_eq!(durable, CowOverlay::new());
}

fn registered_flash_read_owner() -> (BlockFaultState, ResolvedBlockFlashRule) {
    use crate::block::flash::{
        ResolvedBlockFlashProgramErase, ResolvedBlockFlashReadDisturb, ResolvedBlockFlashRetention,
    };

    let rule = ResolvedBlockFlashRule {
        contributor: [1; 32],
        choice_key: [2; 32],
        erase_block_bytes: 8,
        program_page_bytes: 4,
        endurance_cycles: 100,
        retention: ResolvedBlockFlashRetention {
            minimum_age_nanos: 1,
            wear_age_nanos: 0,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        read_disturb: ResolvedBlockFlashReadDisturb {
            read_threshold: 10,
            neighbor_pages: 1,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        program_erase: ResolvedBlockFlashProgramErase {
            program_probability_millionths: 0,
            erase_probability_millionths: 0,
            worn_probability_millionths: 0,
            partial_program: false,
            partial_erase: false,
        },
    };
    let mut state = BlockFaultState::write_through(32);
    state
        .flash
        .read(
            &BlockRequest::read(1, 0, 1),
            0,
            32,
            std::slice::from_ref(&rule),
            &mut [0],
        )
        .unwrap_or_else(|error| panic!("register actual flash page: {error}"));
    (state, rule)
}

#[test]
fn zero_length_selected_flash_read_tracks_actual_page_counter_changes() {
    for offset in [0, 1] {
        let (mut state, rule) = registered_flash_read_owner();
        let base = BaseImage::new(vec![0; 32]);
        let mut durable = CowOverlay::new();
        let request = BlockRequest::read(2, offset, 0);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
        directive.persistence_media_rules = vec![rule.clone()];
        let before = state.clone();

        let (response, wait) = state
            .with_observation_mutation(|state| {
                state.execute_wire(&base, &mut durable, &request, &directive)
            })
            .unwrap_or_else(|error| panic!("actual zero-length read: {error}"));

        assert_eq!(response.status, BlockStatus::Ok);
        assert_eq!(wait, 0);
        assert_eq!(
            state.flash.continuations()[&rule.contributor].pages[&0].reads_since_disturb,
            2
        );
        assert_ne!(state.flash, before.flash);
        assert_eq!(revision(&state), revision(&before) + 1);
        let mut expected = before;
        expected.flash = state.flash.clone();
        expected.observation_revision = state.observation_revision;
        assert_eq!(
            state, expected,
            "only actual flash state and its revision change"
        );
        assert_eq!(durable, CowOverlay::new());
    }
}

#[test]
fn zero_length_flash_read_at_nonzero_page_boundary_preserves_revision() {
    let (mut state, rule) = registered_flash_read_owner();
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let request = BlockRequest::read(2, rule.program_page_bytes, 0);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
    directive.persistence_media_rules = vec![rule];
    let before = state.clone();

    let (response, _) = state
        .with_observation_mutation(|state| {
            state.execute_wire(&base, &mut durable, &request, &directive)
        })
        .unwrap_or_else(|error| panic!("actual empty page range: {error}"));

    assert_eq!(response.status, BlockStatus::Ok);
    assert_eq!(state, before);
    assert_eq!(durable, CowOverlay::new());
}
