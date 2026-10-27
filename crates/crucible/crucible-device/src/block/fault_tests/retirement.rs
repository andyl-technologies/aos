//! Retirement of media and flash continuations no action can name again.
//!
//! These tests show that retirement keeps every live or still-referenced
//! continuation, and that a pruned state answers every later request exactly
//! like the unpruned state, including across checkpoint/restore.

use std::collections::BTreeSet;

use super::*;

const SUPERSEDED: [u8; 32] = [0x31; 32];
const CURRENT: [u8; 32] = [0x32; 32];

/// A latent read rule that fails from its third selected access.
fn latent(contributor: [u8; 32]) -> ResolvedBlockMediaRule {
    ResolvedBlockMediaRule {
        contributor,
        start: 8,
        length: 8,
        state: crate::block::BlockMediaRangeState::Latent,
        operations: vec![BlockOp::Read],
        count_threshold: Some(3),
        time_threshold_nanos: None,
    }
}

fn read_with(
    state: &mut BlockFaultState,
    base: &BaseImage,
    durable: &mut CowOverlay,
    request_id: u32,
    rule: &ResolvedBlockMediaRule,
) -> BlockResponse {
    response(
        state,
        base,
        durable,
        &BlockRequest::read(request_id, 8, 4),
        |directive| directive.media_rules.push(rule.clone()),
    )
}

fn retire(state: &mut BlockFaultState, live: &[[u8; 32]]) -> usize {
    state
        .retire_inactive_media_contributors(&live.iter().copied().collect::<BTreeSet<_>>())
        .unwrap_or_else(|error| panic!("retirement should run: {error}"))
}

fn round_trip(state: &BlockFaultState) -> BlockFaultState {
    let bytes = state
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode retired state: {error}"));
    let restored = BlockFaultState::from_canonical_bytes(&bytes, 32)
        .unwrap_or_else(|error| panic!("decode retired state: {error}"));
    assert_eq!(
        restored
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("re-encode retired state: {error}")),
        bytes
    );
    restored
}

#[test]
fn retirement_keeps_live_and_referenced_continuations() {
    let base = BaseImage::new(vec![0x5a; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::Durable);
    let superseded = latent(SUPERSEDED);
    read_with(&mut state, &base, &mut durable, 1, &superseded);

    // A directive installed before the binding was re-upserted still names
    // the superseded contributor, so its counter must survive.
    let pending = BlockRequest::read(2, 8, 4);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&pending, 32);
    directive.media_rules.push(superseded.clone());
    state
        .install(pending.identity(), directive)
        .unwrap_or_else(|error| panic!("pending directive installs: {error}"));
    assert_eq!(retire(&mut state, &[CURRENT]), 0);

    let computed = state
        .execute(&base, &mut durable, &pending, 0)
        .unwrap_or_else(|error| panic!("pending directive executes: {error}"));
    assert!(computed.primary.is_some());
    assert_eq!(state.media_state().rules()[&SUPERSEDED].access_count, 2);

    // A live contributor is kept even when nothing references it.
    assert_eq!(retire(&mut state, &[SUPERSEDED]), 0);
    assert_eq!(retire(&mut state, &[CURRENT]), 1);
    assert!(state.media_state().rules().is_empty());
    assert_eq!(retire(&mut state, &[]), 0);
}

#[test]
fn retirement_without_candidates_leaves_the_observation_revision() {
    let base = BaseImage::new(vec![0x5a; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::Durable);
    read_with(&mut state, &base, &mut durable, 1, &latent(CURRENT));
    let before = state.clone();

    assert_eq!(retire(&mut state, &[CURRENT]), 0);
    assert_eq!(state, before);
}

#[test]
fn pruned_media_state_answers_like_the_unpruned_state() {
    let base = BaseImage::new(vec![0x5a; 32]);
    let mut durable = CowOverlay::new();
    let mut unpruned = state(BlockCompletionDurability::Durable);
    for request_id in 1..=2 {
        read_with(
            &mut unpruned,
            &base,
            &mut durable,
            request_id,
            &latent(SUPERSEDED),
        );
    }
    let mut pruned = unpruned.clone();
    assert_eq!(retire(&mut pruned, &[CURRENT]), 1);
    let mut restored = round_trip(&pruned);
    let mut pruned_durable = durable.clone();
    let mut restored_durable = durable.clone();

    // The re-upserted binding starts its own counter in every copy.
    let current = latent(CURRENT);
    for request_id in 10..15 {
        let expected = read_with(&mut unpruned, &base, &mut durable, request_id, &current);
        let from_pruned = read_with(
            &mut pruned,
            &base,
            &mut pruned_durable,
            request_id,
            &current,
        );
        let from_restored = read_with(
            &mut restored,
            &base,
            &mut restored_durable,
            request_id,
            &current,
        );
        assert_eq!(from_pruned, expected, "request {request_id}");
        assert_eq!(from_restored, expected, "request {request_id}");
    }
    assert_eq!(
        unpruned.media_state().rules()[&CURRENT],
        pruned.media_state().rules()[&CURRENT]
    );
    assert_eq!(unpruned.media_state().rules()[&SUPERSEDED].access_count, 2);
    assert_eq!(pruned, restored);
}

#[test]
fn pruned_flash_state_reads_like_the_unpruned_state() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut unpruned = state(BlockCompletionDurability::Durable);
    let read = BlockRequest::read(52, 0, 4);
    let mut active = ResolvedBlockFaultDirective::fault_free(&read, 32);
    active.execution_ticks = 1_010;
    active.persistence_media_rules = vec![ResolvedBlockFlashRule {
        contributor: SUPERSEDED,
        choice_key: [6; 32],
        erase_block_bytes: 8,
        program_page_bytes: 4,
        endurance_cycles: 10,
        retention: crate::block::flash::ResolvedBlockFlashRetention {
            minimum_age_nanos: 1,
            wear_age_nanos: 0,
            bit_probability_millionths: 1_000_000,
            maximum_changed_bits: 1,
        },
        read_disturb: crate::block::flash::ResolvedBlockFlashReadDisturb {
            read_threshold: 100,
            neighbor_pages: 1,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        program_erase: crate::block::flash::ResolvedBlockFlashProgramErase {
            program_probability_millionths: 0,
            erase_probability_millionths: 0,
            worn_probability_millionths: 0,
            partial_program: false,
            partial_erase: false,
        },
    }];
    unpruned
        .install(read.identity(), active)
        .unwrap_or_else(|error| panic!("active flash read installs: {error}"));
    unpruned
        .execute(&base, &mut durable, &read, 1_000)
        .unwrap_or_else(|error| panic!("active flash read executes: {error}"));
    assert!(
        !unpruned.flash_state().continuations()[&SUPERSEDED]
            .changed_bytes
            .is_empty()
    );

    let mut pruned = unpruned.clone();
    assert_eq!(retire(&mut pruned, &[]), 1);
    assert!(pruned.flash_state().continuations().is_empty());
    assert_eq!(
        pruned.flash_state().residual_changed_bytes(),
        &unpruned.flash_state().continuations()[&SUPERSEDED].changed_bytes
    );
    let mut restored = round_trip(&pruned);
    let mut pruned_durable = durable.clone();
    let mut restored_durable = durable.clone();

    // Plain writes never heal changed cells, so later reads still match.
    let write = BlockRequest::write(60, 0, vec![0x0f; 8]);
    let full_read = BlockRequest::read(61, 0, 32);
    for request in [&write, &full_read] {
        let expected = response(&mut unpruned, &base, &mut durable, request, |_| {});
        let from_pruned = response(&mut pruned, &base, &mut pruned_durable, request, |_| {});
        let from_restored = response(&mut restored, &base, &mut restored_durable, request, |_| {});
        assert_eq!(from_pruned, expected);
        assert_eq!(from_restored, expected);
    }
    assert_eq!(pruned, restored);
}
