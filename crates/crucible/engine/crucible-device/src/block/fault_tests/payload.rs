//! Exact discard, torn-write, misdirection, and media-read regressions.

use super::*;

#[test]
fn latent_media_failure_changes_future_real_request_results() {
    let base = BaseImage::new(vec![0x5a; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::Durable);
    let rule = ResolvedBlockMediaRule {
        contributor: [0x31; 32],
        start: 8,
        length: 8,
        state: crate::block::BlockMediaRangeState::Latent,
        operations: vec![BlockOp::Read],
        count_threshold: Some(2),
        time_threshold_nanos: None,
    };

    let first = BlockRequest::read(40, 8, 4);
    let first_response = response(&mut state, &base, &mut durable, &first, |directive| {
        directive.media_rules.push(rule.clone());
    });
    assert_eq!(first_response.status, BlockStatus::Ok);

    let second = BlockRequest::read(41, 8, 4);
    let second_response = response(&mut state, &base, &mut durable, &second, |directive| {
        directive.media_rules.push(rule);
    });
    assert_eq!(second_response.status, BlockStatus::Error);
    assert_eq!(
        second_response.error_code(),
        Ok(BlockErrorCode::MediumError)
    );
    assert_eq!(state.media_state().rules()[&[0x31; 32]].access_count, 2);
}

fn discard_state(semantics: BlockDiscardSemantics) -> BlockFaultState {
    BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 1,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 4,
        discard_semantics: semantics,
        volatile_cache_bytes: 0,
        cache_entries: 0,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::Durable,
    })
    .unwrap_or_else(|error| panic!("valid discard state: {error}"))
}

#[test]
fn discard_readback_contracts_mutate_real_future_reads() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let discard = BlockRequest::discard(50, 8, 4);

    let mut zero_state = discard_state(BlockDiscardSemantics::DeterministicZero);
    let mut zero_durable = CowOverlay::new();
    assert_eq!(
        response(&mut zero_state, &base, &mut zero_durable, &discard, |_| {}).status,
        BlockStatus::Ok
    );
    assert_eq!(
        read(&mut zero_state, &base, &mut zero_durable, 51, 8, 4),
        vec![0; 4]
    );

    let mut old_state = discard_state(BlockDiscardSemantics::ReadsOldData);
    let mut old_durable = CowOverlay::new();
    response(&mut old_state, &base, &mut old_durable, &discard, |_| {});
    assert_eq!(
        read(&mut old_state, &base, &mut old_durable, 51, 8, 4),
        b"ijkl"
    );

    let mut first_state = discard_state(BlockDiscardSemantics::UndefinedKeyed);
    let mut first_durable = CowOverlay::new();
    response(
        &mut first_state,
        &base,
        &mut first_durable,
        &discard,
        |_| {},
    );
    let first = read(&mut first_state, &base, &mut first_durable, 51, 8, 4);
    let mut replay_state = discard_state(BlockDiscardSemantics::UndefinedKeyed);
    let mut replay_durable = CowOverlay::new();
    response(
        &mut replay_state,
        &base,
        &mut replay_durable,
        &discard,
        |_| {},
    );
    assert_eq!(
        read(&mut replay_state, &base, &mut replay_durable, 51, 8, 4),
        first
    );
    assert_ne!(first, b"ijkl");
}

#[test]
fn discard_rejects_unsupported_or_misaligned_ranges_without_mutation() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut configured = discard_state(BlockDiscardSemantics::DeterministicZero);
    let mut durable = CowOverlay::new();
    let before = durable.clone();
    let request = BlockRequest::discard(60, 2, 4);
    let result = response(&mut configured, &base, &mut durable, &request, |_| {});
    assert_eq!(result.error_code(), Ok(BlockErrorCode::InvalidRange));
    assert_eq!(durable, before);

    let mut unsupported = state(BlockCompletionDurability::Durable);
    let request = BlockRequest::discard(61, 4, 4);
    let result = response(&mut unsupported, &base, &mut durable, &request, |_| {});
    assert_eq!(result.error_code(), Ok(BlockErrorCode::InvalidRange));
    assert_eq!(durable, before);
}

#[test]
fn lost_torn_and_misdirected_writes_mutate_exact_bytes() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::Durable);

    let lost = BlockRequest::write(1, 0, b"XXXXXXXX".to_vec());
    response(&mut state, &base, &mut durable, &lost, |directive| {
        directive.write_disposition = BlockFaultWriteDisposition::Lost;
    });
    assert_eq!(read(&mut state, &base, &mut durable, 2, 0, 8), b"abcdefgh");

    let torn = BlockRequest::write(3, 0, b"12345678".to_vec());
    response(&mut state, &base, &mut durable, &torn, |directive| {
        directive.write_disposition = BlockFaultWriteDisposition::Torn {
            spans: vec![
                BlockFaultByteSpan {
                    start: 0,
                    length: 2,
                },
                BlockFaultByteSpan {
                    start: 4,
                    length: 2,
                },
            ],
        };
    });
    assert_eq!(read(&mut state, &base, &mut durable, 4, 0, 8), b"12cd56gh");

    let misdirected = BlockRequest::write(5, 0, b"WXYZ".to_vec());
    response(&mut state, &base, &mut durable, &misdirected, |directive| {
        directive.write_disposition = BlockFaultWriteDisposition::Misdirected {
            destination: BlockFaultMisdirectionDestination::AttachedDevice,
            destination_offset: 8,
        };
    });
    assert_eq!(read(&mut state, &base, &mut durable, 6, 8, 4), b"WXYZ");
}

#[test]
fn acknowledged_lost_and_torn_fragments_permanently_bound_durability() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut main_state = state(BlockCompletionDurability::Durable);
    response(
        &mut main_state,
        &base,
        &mut durable,
        &BlockRequest::write(1, 0, b"GOOD".to_vec()),
        |_| {},
    );
    assert_eq!(main_state.actual_durable_frontier(), 4);
    response(
        &mut main_state,
        &base,
        &mut durable,
        &BlockRequest::write(2, 4, b"NO".to_vec()),
        |directive| directive.write_disposition = BlockFaultWriteDisposition::Lost,
    );
    response(
        &mut main_state,
        &base,
        &mut durable,
        &BlockRequest::flush(3),
        |_| {},
    );
    assert_eq!(main_state.next_cache_sequence, 6);
    assert_eq!(main_state.first_lost_sequence, Some(4));
    assert_eq!(main_state.actual_durable_frontier(), 4);
    assert_eq!(main_state.reported_durable_frontier(), 4);

    let mut torn_state = state(BlockCompletionDurability::Durable);
    let mut torn_durable = CowOverlay::new();
    response(
        &mut torn_state,
        &base,
        &mut torn_durable,
        &BlockRequest::write(4, 0, b"WXYZ".to_vec()),
        |directive| {
            directive.write_disposition = BlockFaultWriteDisposition::Torn {
                spans: vec![
                    BlockFaultByteSpan {
                        start: 0,
                        length: 1,
                    },
                    BlockFaultByteSpan {
                        start: 2,
                        length: 1,
                    },
                ],
            };
        },
    );
    assert_eq!(torn_state.next_cache_sequence, 4);
    assert_eq!(torn_state.first_lost_sequence, Some(1));
    assert_eq!(torn_state.actual_durable_frontier(), 1);
    assert_eq!(torn_state.reported_durable_frontier(), 1);
}
