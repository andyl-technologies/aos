//! Tests extracted from the adjacent production module.

use super::*;

fn rule() -> ResolvedBlockFlashRule {
    ResolvedBlockFlashRule {
        contributor: [1; 32],
        choice_key: [2; 32],
        erase_block_bytes: 4096,
        program_page_bytes: 512,
        endurance_cycles: 10,
        retention: ResolvedBlockFlashRetention {
            minimum_age_nanos: 10,
            wear_age_nanos: 0,
            bit_probability_millionths: 1_000_000,
            maximum_changed_bits: 1,
        },
        read_disturb: ResolvedBlockFlashReadDisturb {
            read_threshold: 2,
            neighbor_pages: 1,
            bit_probability_millionths: 1_000_000,
            maximum_changed_bits: 1,
        },
        program_erase: ResolvedBlockFlashProgramErase {
            program_probability_millionths: 0,
            erase_probability_millionths: 0,
            worn_probability_millionths: 0,
            partial_program: false,
            partial_erase: false,
        },
    }
}

#[test]
fn retention_and_disturb_are_sparse_persistent_and_restorable() {
    let mut state = BlockFlashState::default();
    let write = BlockRequest::write(1, 512, vec![0; 512]);
    let programmed = state
        .program(&write, 5, 8192, &[rule()])
        .unwrap_or_else(|error| panic!("program should succeed: {error}"));
    assert!(!programmed.failed);

    let read = BlockRequest::read(2, 512, 512);
    let mut first = vec![0; 512];
    state
        .read(&read, 15, 8192, &[rule()], &mut first)
        .unwrap_or_else(|error| panic!("retention read should succeed: {error}"));
    state
        .apply_persistent_read(read.offset, &mut first)
        .unwrap_or_else(|error| panic!("cell changes should apply: {error}"));
    assert_ne!(first, vec![0; 512]);

    let checkpoint = state.clone();
    checkpoint
        .validate_restore(8192)
        .unwrap_or_else(|error| panic!("checkpoint should validate: {error}"));
    let mut second = vec![0; 512];
    state
        .read(&read, 15, 8192, &[rule()], &mut second)
        .unwrap_or_else(|error| panic!("disturb read should succeed: {error}"));
    assert_ne!(state, checkpoint);
}

#[test]
fn failed_program_applies_only_the_keyed_prefix() {
    let mut failing = rule();
    failing.program_erase.program_probability_millionths = 1_000_000;
    failing.program_erase.partial_program = true;
    let mut state = BlockFlashState::default();
    let request = BlockRequest::write(3, 0, vec![0; 512]);
    let outcome = state
        .program(&request, 0, 8192, &[failing])
        .unwrap_or_else(|error| panic!("program resolution should succeed: {error}"));
    assert!(outcome.failed);
    assert_eq!(outcome.spans.len(), 1);
    assert!(outcome.spans[0].length > 0 && outcome.spans[0].length <= 512);
}

#[test]
fn partial_erase_is_request_wide_checkpointed_and_counts_wear_once() {
    let mut partial = rule();
    partial.erase_block_bytes = 8;
    partial.program_page_bytes = 4;
    partial.program_erase.erase_probability_millionths = 1_000_000;
    partial.program_erase.partial_erase = true;
    let contributors = [partial.contributor];
    let mut state = BlockFlashState::default();
    state
        .register_rules(16, &[partial])
        .unwrap_or_else(|error| panic!("flash rule should register: {error}"));

    let first = state
        .erase_fragment_registered(7, 0, 8, 0, &[0xff; 4], 11, 16, &contributors)
        .unwrap_or_else(|error| panic!("first erase fragment should resolve: {error}"));
    assert!(first.failed);
    let checkpoint = state.clone();
    checkpoint
        .validate_restore(16)
        .unwrap_or_else(|error| panic!("mid-erase checkpoint should validate: {error}"));

    let second = state
        .erase_fragment_registered(7, 0, 8, 4, &[0xff; 4], 11, 16, &contributors)
        .unwrap_or_else(|error| panic!("second erase fragment should resolve: {error}"));
    let mut restored = checkpoint;
    let replayed = restored
        .erase_fragment_registered(7, 0, 8, 4, &[0xff; 4], 11, 16, &contributors)
        .unwrap_or_else(|error| panic!("restored erase fragment should resolve: {error}"));

    assert_eq!(second, replayed);
    assert_eq!(state, restored);
    let continuation = &state.continuations()[&contributors[0]];
    assert_eq!(continuation.erase_blocks[&0].erase_count, 1);
    assert_eq!(continuation.erase_blocks[&0].last_erase_nanos, 11);
    assert!(continuation.erase_decisions.is_empty());
    let applied = first
        .spans
        .iter()
        .chain(&second.spans)
        .map(|span| span.length)
        .sum::<u64>();
    assert!((1..=8).contains(&applied));
}

#[test]
fn erase_uses_worn_probability_at_the_endurance_boundary() {
    let mut wearing = rule();
    wearing.erase_block_bytes = 8;
    wearing.program_page_bytes = 4;
    wearing.endurance_cycles = 1;
    wearing.program_erase.erase_probability_millionths = 0;
    wearing.program_erase.worn_probability_millionths = 1_000_000;
    wearing.program_erase.partial_erase = false;
    let contributors = [wearing.contributor];
    let mut state = BlockFlashState::default();
    state
        .register_rules(16, &[wearing])
        .unwrap_or_else(|error| panic!("flash rule should register: {error}"));

    let healthy = state
        .erase_fragment_registered(8, 0, 8, 0, &[0xff; 8], 1, 16, &contributors)
        .unwrap_or_else(|error| panic!("healthy erase should resolve: {error}"));
    let worn = state
        .erase_fragment_registered(9, 0, 8, 0, &[0xff; 8], 2, 16, &contributors)
        .unwrap_or_else(|error| panic!("worn erase should resolve: {error}"));

    assert!(!healthy.failed);
    assert_eq!(healthy.spans[0].length, 8);
    assert!(worn.failed);
    assert!(worn.spans.is_empty());
    assert_eq!(
        state.continuations()[&contributors[0]].erase_blocks[&0].erase_count,
        2
    );
}

#[test]
fn erase_rejects_unaligned_complete_requests_without_mutation() {
    let mut aligned = rule();
    aligned.erase_block_bytes = 8;
    aligned.program_page_bytes = 4;
    let contributors = [aligned.contributor];
    let mut state = BlockFlashState::default();
    state
        .register_rules(16, &[aligned])
        .unwrap_or_else(|error| panic!("flash rule should register: {error}"));
    let before = state.clone();

    assert!(matches!(
        state.erase_fragment_registered(10, 4, 8, 4, &[0xff; 4], 0, 16, &contributors,),
        Err(DeviceError::InvalidBlockFaultDirective { .. })
    ));
    assert_eq!(state, before);
}
