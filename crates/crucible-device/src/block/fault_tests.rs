//! Tests for block fault state, durability, and recovery behavior.

use super::*;

#[path = "fault_tests/resource_usage.rs"]
mod resource_usage;

fn state(durability: BlockCompletionDurability) -> BlockFaultState {
    BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 1,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 64,
        cache_entries: 64,
        controller_buffer_bytes: 64,
        controller_entries: 64,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: durability,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"))
}

#[test]
fn external_write_dependency_uses_the_destination_completion_policy() {
    for durability in [
        BlockCompletionDurability::ControllerAccepted,
        BlockCompletionDurability::VolatileCacheAccepted,
        BlockCompletionDurability::Durable,
    ] {
        let base = BaseImage::new(vec![0; 32]);
        let mut durable = CowOverlay::new();
        let mut storage = state(durability);
        let (required_durability, required_frontier) = storage
            .apply_external_write(&base, &mut durable, 7, 11, 13, 0, vec![0x5a; 4])
            .unwrap_or_else(|error| panic!("external write should apply: {error}"));
        assert_eq!(required_durability, durability);
        assert_eq!(required_frontier, 4);
        if durability != BlockCompletionDurability::Durable {
            assert!(
                storage.completion_frontier(durability) >= required_frontier,
                "controller and cache acceptance must not wait for media"
            );
        }
    }
}

fn reset_transition() -> ResolvedBlockControllerTransition {
    ResolvedBlockControllerTransition {
        failure_result: BlockFaultResult::Offline,
        unadmitted: BlockTransitionUnadmitted::Reject,
        queued: BlockTransitionPending::Fail,
        executing: BlockTransitionPending::RetryPreserveId,
        resolved: BlockTransitionResolved::Complete,
        completed_undelivered: BlockTransitionUndelivered::Complete,
        controller_buffer: BlockTransitionState::Preserve,
        volatile_cache: BlockTransitionState::Preserve,
        request_ids: BlockTransportRequestIds::NewEpochFromZero,
        duplicate_history: BlockTransitionState::Lose,
        topology: BlockTransitionTopology::ReenumerateDeclared,
        recovery_nanos: 50,
    }
}

fn response(
    state: &mut BlockFaultState,
    base: &BaseImage,
    durable: &mut CowOverlay,
    request: &BlockRequest,
    mutate: impl FnOnce(&mut ResolvedBlockFaultDirective),
) -> BlockResponse {
    let mut directive = ResolvedBlockFaultDirective::fault_free(request, base.len());
    mutate(&mut directive);
    state
        .install(request.identity(), directive)
        .unwrap_or_else(|error| panic!("directive installs: {error}"));
    let computed = state
        .execute(base, durable, request, 0)
        .unwrap_or_else(|error| panic!("request executes: {error}"));
    let primary = computed
        .primary
        .unwrap_or_else(|| panic!("test request unexpectedly retained"));
    BlockResponse::decode(&primary.payload)
        .unwrap_or_else(|error| panic!("response decodes: {error}"))
}

fn read(
    state: &mut BlockFaultState,
    base: &BaseImage,
    durable: &mut CowOverlay,
    request_id: u32,
    offset: u64,
    count: u32,
) -> Vec<u8> {
    response(
        state,
        base,
        durable,
        &BlockRequest::read(request_id, offset, count),
        |_| {},
    )
    .data
}

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

#[test]
fn volatile_cache_flush_lie_loss_and_honest_flush_track_both_frontiers() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);
    let write = BlockRequest::write(1, 0, b"CACHE".to_vec());
    response(&mut state, &base, &mut durable, &write, |_| {});
    assert_eq!(read(&mut state, &base, &mut durable, 2, 0, 5), b"CACHE");
    assert_eq!(durable.read(&base, 0, 5).unwrap_or_default(), b"abcde");

    let lie = BlockRequest::flush(3);
    response(&mut state, &base, &mut durable, &lie, |directive| {
        directive.flush_disposition = BlockFaultFlushDisposition::Lie;
    });
    assert_eq!(state.actual_durable_frontier(), 0);
    assert_eq!(state.reported_durable_frontier(), 5);

    state
        .lose_volatile(&[0, 1, 2, 3, 4])
        .unwrap_or_else(|error| panic!("live cache entry is lost: {error}"));
    assert_eq!(read(&mut state, &base, &mut durable, 4, 0, 5), b"abcde");

    let second = BlockRequest::write(5, 0, b"SOLID".to_vec());
    response(&mut state, &base, &mut durable, &second, |_| {});
    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::flush(6),
        |_| {},
    );
    assert!(state.volatile_entries().is_empty());
    // A lost sequence is a permanent hole in the exact durability
    // frontier, even after later writes are honestly flushed.
    assert_eq!(state.actual_durable_frontier(), 0);
    assert_eq!(state.reported_durable_frontier(), 0);
    assert_eq!(durable.read(&base, 0, 5).unwrap_or_default(), b"SOLID");
}

#[test]
fn controller_accepted_writes_remain_a_distinct_durability_layer() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::ControllerAccepted);
    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(1, 4, b"CTRL".to_vec()),
        |_| {},
    );
    assert_eq!(state.controller_entries().len(), 4);
    assert!(state.volatile_entries().is_empty());
    assert_eq!(durable.read(&base, 4, 4).unwrap_or_default(), b"efgh");
    assert_eq!(read(&mut state, &base, &mut durable, 2, 4, 4), b"CTRL");

    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::flush(3),
        |_| {},
    );
    assert!(state.controller_entries().is_empty());
    assert!(state.volatile_entries().is_empty());
    assert_eq!(durable.read(&base, 4, 4).unwrap_or_default(), b"CTRL");
    assert_eq!(state.actual_durable_frontier(), 4);
    assert_eq!(state.reported_durable_frontier(), 4);
}

#[test]
fn read_transforms_and_stalled_completion_are_checkpointable() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);
    let read_request = BlockRequest::read(1, 0, 4);
    let transformed = response(
        &mut state,
        &base,
        &mut durable,
        &read_request,
        |directive| {
            directive
                .read_transforms
                .push(BlockFaultReadTransform::Xor {
                    offset: 1,
                    mask: vec![0xff, 0x01],
                });
        },
    );
    assert_eq!(transformed.data, vec![b'a', b'b' ^ 0xff, b'c' ^ 0x01, b'd']);

    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(2, 8, b"held".to_vec()),
        |_| {},
    );
    let flush = BlockRequest::flush(3);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&flush, base.len());
    directive.flush_disposition = BlockFaultFlushDisposition::Stall;
    directive.retain_completion = true;
    directive.retention_timeout_response = Some(BlockResponse::error(
        flush.request_id,
        BlockErrorCode::Timeout,
    ));
    directive.retention_timeout_nanos = Some(100);
    directive.retention_recovery_event = Some([7; 32]);
    directive.retention_recovery_after_nanos = Some(0);
    directive.retention_recovery_after_sequence = Some(0);
    state
        .install(flush.identity(), directive)
        .unwrap_or_else(|error| panic!("directive installs: {error}"));
    let computed = state
        .execute(&base, &mut durable, &flush, 0)
        .unwrap_or_else(|error| panic!("flush executes: {error}"));
    assert!(computed.primary.is_none());
    assert_eq!(state.reported_durable_frontier(), 0);
    let checkpoint = state.clone();
    assert_eq!(
        checkpoint.retained_completions(),
        state.retained_completions()
    );
    assert_eq!(
        checkpoint
            .retained_completion(flush.identity())
            .map(|held| held.identity.request_id),
        Some(flush.request_id)
    );
    assert!(state.retained_timeouts_due(99).is_empty());
    assert_eq!(state.retained_timeouts_due(100), vec![flush.identity()]);
    assert!(state.retained_recoveries_for([7; 32], 0, 0).is_empty());
    assert_eq!(
        state.retained_recoveries_for([7; 32], 0, 1),
        vec![flush.identity()]
    );
    assert_eq!(
        state.retained_recoveries_for([7; 32], 50, 0),
        vec![flush.identity()]
    );
    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(4, 12, b"later".to_vec()),
        |_| {},
    );
    let released = state
        .resolve_retained_completion(
            &base,
            &mut durable,
            flush.identity(),
            BlockRetainedRelease::Recovery {
                event_nanos: 50,
                event_sequence: 0,
            },
            50,
        )
        .unwrap_or_else(|error| panic!("retained completion recovers: {error}"))
        .unwrap_or_else(|| panic!("recovery persistence should complete immediately"));
    let released = BlockResponse::decode(&released.payload)
        .unwrap_or_else(|error| panic!("released response decodes: {error}"));
    assert_eq!(released.status, BlockStatus::Ok);
    assert_eq!(state.reported_durable_frontier(), 4);
    assert_eq!(state.actual_durable_frontier(), 4);
    assert_eq!(state.volatile_entries().len(), 5);
    assert_eq!(durable.read(&base, 8, 4).unwrap_or_default(), b"held");
    assert_eq!(durable.read(&base, 12, 5).unwrap_or_default(), b"mnopq");
}

#[test]
fn stalled_flush_timeout_does_not_persist_or_report_cached_writes() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);
    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(1, 8, b"held".to_vec()),
        |_| {},
    );
    let flush = BlockRequest::flush(2);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&flush, base.len());
    directive.flush_disposition = BlockFaultFlushDisposition::Stall;
    directive.retain_completion = true;
    directive.retention_timeout_response = Some(BlockResponse::error(
        flush.request_id,
        BlockErrorCode::Timeout,
    ));
    directive.retention_timeout_nanos = Some(100);
    state
        .install(flush.identity(), directive)
        .unwrap_or_else(|error| panic!("directive installs: {error}"));
    let computed = state
        .execute(&base, &mut durable, &flush, 99)
        .unwrap_or_else(|error| panic!("flush executes: {error}"));
    assert!(computed.primary.is_none());
    let retained = state
        .retained_completion(flush.identity())
        .unwrap_or_else(|| panic!("completion is retained"));
    assert_eq!(retained.request_icount, 99);
    assert_eq!(retained.persist_through_on_recovery, Some(4));

    let released = state
        .resolve_retained_completion(
            &base,
            &mut durable,
            flush.identity(),
            BlockRetainedRelease::Timeout,
            100,
        )
        .unwrap_or_else(|error| panic!("retained completion times out: {error}"))
        .unwrap_or_else(|| panic!("timeout should release immediately"));
    let released = BlockResponse::decode(&released.payload)
        .unwrap_or_else(|error| panic!("released response decodes: {error}"));
    assert_eq!(released.status, BlockStatus::Error);
    assert_eq!(state.reported_durable_frontier(), 0);
    assert_eq!(state.actual_durable_frontier(), 0);
    assert_eq!(state.volatile_entries().len(), 4);
    assert_eq!(durable.read(&base, 8, 4).unwrap_or_default(), b"ijkl");
}

#[test]
fn stalled_flush_recovery_waits_for_delayed_persistence() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);
    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(1, 8, b"held".to_vec()),
        |directive| {
            directive.execution_nanos = 10;
            directive.persistence_admitted_nanos = 10;
            directive
                .persistence_transforms
                .push(ResolvedBlockPersistenceTransform {
                    contributor: [7; 32],
                    ordering_group: [6; 32],
                    ordering: crate::block::BlockPersistenceOrdering::Preserve,
                    delay_nanos: 100,
                    preserve_barriers: true,
                });
        },
    );
    let flush = BlockRequest::flush(2);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&flush, base.len());
    directive.execution_nanos = 20;
    directive.flush_disposition = BlockFaultFlushDisposition::Stall;
    directive.retain_completion = true;
    directive.retention_timeout_response = Some(BlockResponse::error(
        flush.request_id,
        BlockErrorCode::Timeout,
    ));
    directive.retention_timeout_nanos = Some(200);
    directive.retention_recovery_event = Some([7; 32]);
    directive.retention_recovery_after_nanos = Some(20);
    directive.retention_recovery_after_sequence = Some(0);
    state
        .install(flush.identity(), directive)
        .unwrap_or_else(|error| panic!("directive installs: {error}"));
    let computed = state
        .execute(&base, &mut durable, &flush, 20)
        .unwrap_or_else(|error| panic!("flush executes: {error}"));
    assert!(computed.primary.is_none());

    let pending = state
        .resolve_retained_completion(
            &base,
            &mut durable,
            flush.identity(),
            BlockRetainedRelease::Recovery {
                event_nanos: 50,
                event_sequence: 0,
            },
            50,
        )
        .unwrap_or_else(|error| panic!("recovery starts persistence: {error}"));
    assert!(pending.is_none());
    assert!(state.retained_completion(flush.identity()).is_some());
    assert_eq!(state.reported_durable_frontier(), 0);
    assert_eq!(durable.read(&base, 8, 4).unwrap_or_default(), b"ijkl");

    state
        .persist_due(&base, &mut durable, 110)
        .unwrap_or_else(|error| panic!("delayed persistence completes: {error}"));
    let released = state
        .resolve_retained_completion(
            &base,
            &mut durable,
            flush.identity(),
            BlockRetainedRelease::Recovery {
                event_nanos: 50,
                event_sequence: 0,
            },
            110,
        )
        .unwrap_or_else(|error| panic!("recovery completion releases: {error}"))
        .unwrap_or_else(|| panic!("durable recovery must release"));
    let released = BlockResponse::decode(&released.payload)
        .unwrap_or_else(|error| panic!("released response decodes: {error}"));
    assert_eq!(released.status, BlockStatus::Ok);
    assert!(state.retained_completion(flush.identity()).is_none());
    assert_eq!(state.reported_durable_frontier(), 4);
    assert_eq!(durable.read(&base, 8, 4).unwrap_or_default(), b"held");
}

#[test]
fn cache_admission_failure_is_transactional() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 1,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 3,
        cache_entries: 1,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 2,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"));
    let request = BlockRequest::write(1, 0, b"four".to_vec());
    let directive = ResolvedBlockFaultDirective::fault_free(&request, base.len());
    state
        .install(request.identity(), directive)
        .unwrap_or_else(|error| panic!("directive installs: {error}"));
    let before_durable = durable.clone();
    let computed = state
        .execute(&base, &mut durable, &request, 0)
        .unwrap_or_else(|error| panic!("write returns a guest-visible error: {error}"));
    let response = computed
        .primary
        .and_then(|response| BlockResponse::decode(&response.payload).ok())
        .unwrap_or_else(|| panic!("write produces one decodable response"));
    assert_eq!(response.status, BlockStatus::Error);
    assert!(state.volatile_entries().is_empty());
    assert_eq!(durable, before_durable);
}

#[test]
fn pending_durability_continuation_tracks_acknowledged_cache_write() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);

    assert!(!state.has_pending_durability_continuation());
    let write = BlockRequest::write(1, 8, b"cache".to_vec());
    let completed = response(&mut state, &base, &mut durable, &write, |_| {});
    assert_eq!(completed.status, BlockStatus::Ok);
    assert!(state.has_pending_durability_continuation());
    assert_eq!(durable.read(&base, 8, 5).unwrap_or_default(), b"ijklm");

    let flush = BlockRequest::flush(2);
    let completed = response(&mut state, &base, &mut durable, &flush, |_| {});
    assert_eq!(completed.status, BlockStatus::Ok);
    assert!(!state.has_pending_durability_continuation());
    assert_eq!(durable.read(&base, 8, 5).unwrap_or_default(), b"cache");
}

#[test]
fn cache_rejection_rolls_back_partially_schedulable_evictions() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 8,
        cache_entries: 2,
        controller_buffer_bytes: 4,
        controller_entries: 1,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::ControllerAccepted,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"));
    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(1, 0, b"aaaa".to_vec()),
        |_| {},
    );
    let cache = ResolvedBlockCachePolicy {
        capacity_bytes: 8,
        eviction: BlockFaultCacheEviction::Fifo,
        dirty_eviction: BlockFaultDirtyEviction::Persist,
        power_loss_protected: false,
    };
    for (request_id, offset) in [(2, 0), (3, 8)] {
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(request_id, offset, vec![b'x'; 4]),
            |directive| directive.cache_policy = Some(cache),
        );
    }
    let before_state = state.clone();
    let before_durable = durable.clone();
    let rejected = response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(4, 16, vec![b'y'; 8]),
        |directive| directive.cache_policy = Some(cache),
    );

    assert_eq!(rejected.error_code(), Ok(BlockFaultResult::Busy));
    assert_eq!(state, before_state);
    assert_eq!(durable, before_durable);
}

#[test]
fn cache_policy_persists_fifo_victims_before_admission() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 8,
        cache_entries: 2,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::Durable,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"));
    let policy = ResolvedBlockCachePolicy {
        capacity_bytes: 8,
        eviction: BlockFaultCacheEviction::Fifo,
        dirty_eviction: BlockFaultDirtyEviction::Persist,
        power_loss_protected: false,
    };
    for (request_id, offset, bytes) in [(1, 0, b"aaaa"), (2, 4, b"bbbb"), (3, 8, b"cccc")] {
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(request_id, offset, bytes.to_vec()),
            |directive| directive.cache_policy = Some(policy),
        );
    }
    assert_eq!(state.volatile_entries().len(), 2);
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"aaaa");
    assert_eq!(durable.read(&base, 4, 4).unwrap_or_default(), b"efgh");
    assert_eq!(
        read(&mut state, &base, &mut durable, 4, 0, 12),
        b"aaaabbbbcccc"
    );
}

#[test]
fn cache_dirty_eviction_preserves_the_authored_typed_failure() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 4,
        cache_entries: 1,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::Durable,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"));
    let persist = ResolvedBlockCachePolicy {
        capacity_bytes: 4,
        eviction: BlockFaultCacheEviction::Fifo,
        dirty_eviction: BlockFaultDirtyEviction::Persist,
        power_loss_protected: false,
    };
    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(1, 0, b"aaaa".to_vec()),
        |directive| directive.cache_policy = Some(persist),
    );
    let failed = response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(2, 4, b"bbbb".to_vec()),
        |directive| {
            directive.cache_policy = Some(ResolvedBlockCachePolicy {
                dirty_eviction: BlockFaultDirtyEviction::Fail(BlockFaultResult::NoSpace),
                ..persist
            });
        },
    );
    assert_eq!(failed.status, BlockStatus::Error);
    assert_eq!(failed.error_code(), Ok(BlockFaultResult::NoSpace));
    assert_eq!(state.volatile_entries().len(), 1);
    assert_eq!(read(&mut state, &base, &mut durable, 3, 0, 8), b"aaaaefgh");
}

#[test]
fn cache_policy_lru_reads_change_the_exact_victim() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 8,
        cache_entries: 2,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::Durable,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"));
    let policy = ResolvedBlockCachePolicy {
        capacity_bytes: 8,
        eviction: BlockFaultCacheEviction::Lru,
        dirty_eviction: BlockFaultDirtyEviction::Persist,
        power_loss_protected: false,
    };
    for (request_id, offset, bytes) in [(1, 0, b"aaaa"), (2, 4, b"bbbb")] {
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(request_id, offset, bytes.to_vec()),
            |directive| directive.cache_policy = Some(policy),
        );
    }
    assert_eq!(read(&mut state, &base, &mut durable, 3, 0, 4), b"aaaa");
    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(4, 8, b"cccc".to_vec()),
        |directive| directive.cache_policy = Some(policy),
    );
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"abcd");
    assert_eq!(durable.read(&base, 4, 4).unwrap_or_default(), b"bbbb");
    assert_eq!(
        read(&mut state, &base, &mut durable, 5, 0, 12),
        b"aaaabbbbcccc"
    );
}

#[test]
fn cache_lru_tracks_visible_bytes_and_preserves_overlap_dependencies() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 10,
        cache_entries: 3,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::Durable,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"));
    let policy = ResolvedBlockCachePolicy {
        capacity_bytes: 6,
        eviction: BlockFaultCacheEviction::Lru,
        dirty_eviction: BlockFaultDirtyEviction::Persist,
        power_loss_protected: false,
    };
    for (request_id, offset, bytes) in [(1, 0, b"aaaa".as_slice()), (2, 0, b"BB".as_slice())] {
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(request_id, offset, bytes.to_vec()),
            |directive| directive.cache_policy = Some(policy),
        );
    }
    let old_access = state.volatile_entries()[&0].last_access_sequence;
    let new_access = state.volatile_entries()[&1].last_access_sequence;
    assert_eq!(read(&mut state, &base, &mut durable, 3, 2, 2), b"aa");
    assert!(state.volatile_entries()[&0].last_access_sequence > old_access);
    assert_eq!(
        state.volatile_entries()[&1].last_access_sequence,
        new_access
    );

    response(
        &mut state,
        &base,
        &mut durable,
        &BlockRequest::write(4, 8, b"cccc".to_vec()),
        |directive| directive.cache_policy = Some(policy),
    );
    assert!(!state.volatile_entries().contains_key(&0));
    assert!(state.volatile_entries().contains_key(&1));
    assert_eq!(read(&mut state, &base, &mut durable, 5, 0, 4), b"BBaa");
}

#[test]
fn cache_loss_candidates_distinguish_power_loss_from_protection_failure() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 8,
        cache_entries: 2,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::Durable,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"));
    for (request_id, offset, protected) in [(1, 0, false), (2, 4, true)] {
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(request_id, offset, vec![b'x'; 4]),
            |directive| {
                directive.cache_policy = Some(ResolvedBlockCachePolicy {
                    capacity_bytes: 8,
                    eviction: BlockFaultCacheEviction::Fifo,
                    dirty_eviction: BlockFaultDirtyEviction::Persist,
                    power_loss_protected: protected,
                });
            },
        );
    }
    assert_eq!(state.volatile_loss_candidates(false), vec![0]);
    assert_eq!(state.volatile_loss_candidates(true), vec![0, 1]);
    let ordinary_loss = state.volatile_loss_candidates(false);
    state
        .lose_volatile(&ordinary_loss)
        .unwrap_or_else(|error| panic!("ordinary power-loss subset is live: {error}"));
    assert_eq!(state.volatile_loss_candidates(true), vec![1]);
}

#[test]
fn persistence_delay_defers_durable_bytes_and_flush_truth_until_due() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let mut state = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 8,
        cache_entries: 2,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"));
    let write = BlockRequest::write(1, 0, b"zzzz".to_vec());
    let mut directive = ResolvedBlockFaultDirective::fault_free(&write, base.len());
    directive.execution_nanos = 10;
    directive.persistence_admitted_nanos = 10;
    directive.cache_policy = Some(ResolvedBlockCachePolicy {
        capacity_bytes: 8,
        eviction: BlockFaultCacheEviction::WritebackSequence,
        dirty_eviction: BlockFaultDirtyEviction::Persist,
        power_loss_protected: false,
    });
    directive
        .persistence_transforms
        .push(ResolvedBlockPersistenceTransform {
            contributor: [7; 32],
            ordering_group: [6; 32],
            ordering: crate::block::BlockPersistenceOrdering::Preserve,
            delay_nanos: 100,
            preserve_barriers: true,
        });
    state
        .install(write.identity(), directive)
        .unwrap_or_else(|error| panic!("write directive: {error}"));
    state
        .execute(&base, &mut durable, &write, 10)
        .unwrap_or_else(|error| panic!("cached write: {error}"));

    let flush = BlockRequest::flush(2);
    let mut flush_directive = ResolvedBlockFaultDirective::fault_free(&flush, base.len());
    flush_directive.execution_nanos = 20;
    state
        .install(flush.identity(), flush_directive)
        .unwrap_or_else(|error| panic!("flush directive: {error}"));
    let computed = state
        .execute(&base, &mut durable, &flush, 20)
        .unwrap_or_else(|error| panic!("delayed flush: {error}"));
    assert_eq!(computed.additional_latency_nanos, 90);
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"abcd");
    assert_eq!(state.reported_durable_frontier(), 0);
    assert!(state.media_queue_entries().contains_key(&0));

    state
        .persist_due(&base, &mut durable, 109)
        .unwrap_or_else(|error| panic!("pre-deadline service: {error}"));
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"abcd");
    state
        .persist_due(&base, &mut durable, 110)
        .unwrap_or_else(|error| panic!("deadline service: {error}"));
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"zzzz");
    assert_eq!(state.reported_durable_frontier(), 1);
    assert!(state.media_queue_entries().is_empty());
}

#[test]
fn duplicate_directive_rejection_preserves_the_original() {
    let request = BlockRequest::read(7, 0, 4);
    let mut state = state(BlockCompletionDurability::Durable);
    let original = ResolvedBlockFaultDirective::fault_free(&request, 32);
    let mut replacement = original.clone();
    replacement.error_result = Some(BlockFaultResult::IoError);
    state
        .install(request.identity(), original.clone())
        .unwrap_or_else(|error| panic!("first directive installs: {error}"));
    assert_eq!(
        state.install(request.identity(), replacement),
        Err(DeviceError::DuplicateBlockFaultDirective {
            request_id: request.request_id
        })
    );
    assert_eq!(state.pending.get(&request.identity()), Some(&original));
}

#[test]
fn duplicate_resolution_uses_checked_primary_relative_delays() {
    let request = BlockRequest::read(7, 0, 4);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
    directive
        .configure_duplicate_completions(request.request_id, 3, 11, BlockDuplicatePolicy::Ignore)
        .unwrap_or_else(|error| panic!("duplicate policy resolves: {error}"));
    assert_eq!(
        directive
            .duplicate_completions
            .iter()
            .map(ResolvedBlockDuplicateCompletion::gap_nanos)
            .collect::<Vec<_>>(),
        vec![11, 22, 33]
    );
    directive
        .append_duplicate_completions(request.request_id, 2, 7, BlockDuplicatePolicy::Ignore)
        .unwrap_or_else(|error| panic!("duplicate contribution appends: {error}"));
    assert_eq!(
        directive
            .duplicate_completions
            .iter()
            .map(ResolvedBlockDuplicateCompletion::gap_nanos)
            .collect::<Vec<_>>(),
        vec![11, 22, 33, 40, 47]
    );
    let before = directive.duplicate_completions.clone();
    assert!(
        directive
            .append_duplicate_completions(
                request.request_id,
                2,
                u64::MAX,
                BlockDuplicatePolicy::Ignore,
            )
            .is_err()
    );
    assert_eq!(directive.duplicate_completions, before);
}

#[test]
fn duplicate_reset_encodes_the_exact_live_transport_transition() {
    let request = BlockRequest::write(7, 0, b"data".to_vec());
    let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
    directive
        .configure_duplicate_completions(
            request.request_id,
            1,
            11,
            BlockDuplicatePolicy::Reset(reset_transition()),
        )
        .unwrap_or_else(|error| panic!("duplicate policy resolves: {error}"));
    let mut state = state(BlockCompletionDurability::Durable);
    state
        .install(request.identity(), directive)
        .unwrap_or_else(|error| panic!("reset directive installs: {error}"));
    let computed = state
        .execute(
            &BaseImage::new(vec![0; 32]),
            &mut CowOverlay::new(),
            &request,
            0,
        )
        .unwrap_or_else(|error| panic!("reset request executes: {error}"));
    assert_eq!(computed.additional.len(), 1);
    let reset = BlockResponse::decode(&computed.additional[0].response.payload)
        .unwrap_or_else(|error| panic!("reset response decodes: {error}"))
        .transport_reset_directive()
        .unwrap_or_else(|error| panic!("reset payload decodes: {error}"));
    assert_eq!(reset.next_epoch, 1);
    assert_eq!(reset.recovery_nanos, 50);
    assert!(reset.reenumerate_declared);
    assert!(!reset.preserve_duplicate_history);
}

#[test]
fn duplicate_ignore_and_protocol_error_produce_exact_additional_completions() {
    let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
    let mut durable = CowOverlay::new();
    let request = BlockRequest::read(7, 0, 4);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
    directive
        .configure_duplicate_completions(request.request_id, 1, 11, BlockDuplicatePolicy::Ignore)
        .unwrap_or_else(|error| panic!("ignore policy resolves: {error}"));
    let mut state = state(BlockCompletionDurability::Durable);
    state
        .install(request.identity(), directive)
        .unwrap_or_else(|error| panic!("ignore directive installs: {error}"));
    let computed = state
        .execute(&base, &mut durable, &request, 0)
        .unwrap_or_else(|error| panic!("ignore directive executes: {error}"));
    let primary = computed
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("primary response should exist"));
    assert_eq!(computed.additional.len(), 1);
    assert_eq!(computed.additional[0].gap_nanos, 11);
    let ignored = BlockResponse::decode(&computed.additional[0].response.payload)
        .unwrap_or_else(|error| panic!("ignored duplicate should decode: {error}"));
    assert_eq!(ignored.status, BlockStatus::DuplicateIgnored);
    assert_eq!(ignored.identity(), request.identity());
    assert!(ignored.data.is_empty());
    assert_ne!(&computed.additional[0].response, primary);

    let request = BlockRequest::read(8, 0, 4);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
    directive
        .configure_duplicate_completions(
            request.request_id,
            1,
            17,
            BlockDuplicatePolicy::ProtocolError(BlockResponse::error(
                request.request_id,
                BlockErrorCode::IoError,
            )),
        )
        .unwrap_or_else(|error| panic!("protocol-error policy resolves: {error}"));
    state
        .install(request.identity(), directive)
        .unwrap_or_else(|error| panic!("protocol-error directive installs: {error}"));
    let computed = state
        .execute(&base, &mut durable, &request, 0)
        .unwrap_or_else(|error| panic!("protocol-error directive executes: {error}"));
    assert_eq!(computed.additional.len(), 1);
    assert_eq!(computed.additional[0].gap_nanos, 17);
    let protocol_error = BlockResponse::decode(&computed.additional[0].response.payload)
        .unwrap_or_else(|error| panic!("duplicate protocol error should decode: {error}"));
    assert_eq!(protocol_error.status, BlockStatus::DuplicateProtocolError);
    assert_eq!(
        computed.additional[0].response.status,
        ResponseStatus::Error
    );
}

#[test]
fn timeout_and_duplicate_responses_must_fit_one_transport_frame() {
    let request = BlockRequest::flush(9);
    let oversized = BlockResponse {
        status: BlockStatus::Error,
        epoch: request.epoch,
        request_id: request.request_id,
        data: vec![0; crucible_shmem::MAX_FRAME_DATA],
    };
    let mut retained = ResolvedBlockFaultDirective::fault_free(&request, 32);
    retained.flush_disposition = BlockFaultFlushDisposition::Stall;
    retained.retain_completion = true;
    retained.retention_timeout_response = Some(oversized.clone());
    assert!(matches!(
        state(BlockCompletionDurability::Durable).install(request.identity(), retained),
        Err(DeviceError::InvalidBlockFaultDirective { .. })
    ));

    let read = BlockRequest::read(10, 0, 1);
    let mut duplicate = ResolvedBlockFaultDirective::fault_free(&read, 32);
    duplicate
        .configure_duplicate_completions(
            read.request_id,
            1,
            1,
            BlockDuplicatePolicy::ProtocolError(BlockResponse {
                request_id: read.request_id,
                ..oversized
            }),
        )
        .unwrap_or_else(|error| panic!("duplicate policy resolves before install: {error}"));
    assert!(matches!(
        state(BlockCompletionDurability::Durable).install(read.identity(), duplicate),
        Err(DeviceError::InvalidBlockFaultDirective { .. })
    ));
}

#[test]
fn persistence_opportunity_applies_checkpointed_partial_flash_program() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 32,
        cache_entries: 8,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 32,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    })
    .unwrap_or_else(|error| panic!("flash test state should build: {error}"));
    let write = BlockRequest::write(41, 0, vec![0xaa; 4]);
    let directive = ResolvedBlockFaultDirective::fault_free(&write, 32);
    storage
        .install(write.identity(), directive)
        .unwrap_or_else(|error| panic!("write directive should install: {error}"));
    storage
        .execute(&base, &mut durable, &write, 0)
        .unwrap_or_else(|error| panic!("cached write should execute: {error}"));
    storage
        .schedule_volatile_persistence(0)
        .unwrap_or_else(|error| panic!("write should enter media queue: {error}"));
    storage.require_persistence_media_directives(true);
    let opportunity = storage
        .next_persistence_opportunity(0)
        .unwrap_or_else(|| panic!("persistence opportunity should be ready"));
    let flash_rule = ResolvedBlockFlashRule {
        contributor: [3; 32],
        choice_key: [4; 32],
        erase_block_bytes: 8,
        program_page_bytes: 4,
        endurance_cycles: 10,
        retention: super::super::flash::ResolvedBlockFlashRetention {
            minimum_age_nanos: 1,
            wear_age_nanos: 0,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        read_disturb: super::super::flash::ResolvedBlockFlashReadDisturb {
            read_threshold: 10,
            neighbor_pages: 1,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        program_erase: super::super::flash::ResolvedBlockFlashProgramErase {
            program_probability_millionths: 1_000_000,
            erase_probability_millionths: 0,
            worn_probability_millionths: 0,
            partial_program: true,
            partial_erase: false,
        },
    };
    storage
        .install_persistence_media_directive(ResolvedBlockPersistenceMediaDirective {
            opportunity: opportunity.clone(),
            flash_rules: vec![flash_rule],
        })
        .unwrap_or_else(|error| panic!("flash directive should install: {error}"));
    storage
        .validate_restore(32)
        .unwrap_or_else(|error| panic!("pre-persist checkpoint should validate: {error}"));
    storage
        .persist_due(&base, &mut durable, 0)
        .unwrap_or_else(|error| panic!("flash persistence should execute: {error}"));
    let outcomes = storage.drain_persistence_media_outcomes();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].opportunity, opportunity);
    assert!(outcomes[0].media_failed);
    assert_eq!(outcomes[0].applied_spans.len(), 1);
    let programmed = outcomes[0].applied_spans[0].length as usize;
    let materialized = durable.materialize(&base);
    assert_eq!(&materialized[..programmed], &vec![0xaa; programmed]);
    assert_eq!(&materialized[programmed..4], &vec![0; 4 - programmed]);
}

#[test]
fn flash_discard_applies_one_request_wide_partial_erase() {
    let base = BaseImage::new(vec![0xaa; 16]);
    let mut durable = CowOverlay::new();
    let mut storage = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 16,
        atomic_write_bytes: 4,
        maximum_request_bytes: 16,
        discard_granularity_bytes: 4,
        discard_semantics: BlockDiscardSemantics::ReadsOldData,
        volatile_cache_bytes: 16,
        cache_entries: 4,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 16,
        retained_versions: 4,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    })
    .unwrap_or_else(|error| panic!("flash discard state should build: {error}"));
    let discard = BlockRequest::discard(42, 0, 8);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&discard, 16);
    directive.persistence_media_rules = vec![ResolvedBlockFlashRule {
        contributor: [7; 32],
        choice_key: [8; 32],
        erase_block_bytes: 8,
        program_page_bytes: 4,
        endurance_cycles: 10,
        retention: super::super::flash::ResolvedBlockFlashRetention {
            minimum_age_nanos: 1,
            wear_age_nanos: 0,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        read_disturb: super::super::flash::ResolvedBlockFlashReadDisturb {
            read_threshold: 10,
            neighbor_pages: 1,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        program_erase: super::super::flash::ResolvedBlockFlashProgramErase {
            program_probability_millionths: 0,
            erase_probability_millionths: 1_000_000,
            worn_probability_millionths: 0,
            partial_program: false,
            partial_erase: true,
        },
    }];
    storage
        .install(discard.identity(), directive)
        .unwrap_or_else(|error| panic!("discard directive should install: {error}"));
    storage
        .execute(&base, &mut durable, &discard, 0)
        .unwrap_or_else(|error| panic!("discard should enter the volatile cache: {error}"));
    storage
        .schedule_volatile_persistence(0)
        .unwrap_or_else(|error| panic!("first fragment should enter media: {error}"));
    storage
        .schedule_volatile_persistence(1)
        .unwrap_or_else(|error| panic!("second fragment should enter media: {error}"));
    storage
        .validate_restore(16)
        .unwrap_or_else(|error| panic!("queued discard checkpoint should validate: {error}"));
    storage
        .persist_due(&base, &mut durable, 0)
        .unwrap_or_else(|error| panic!("flash erase should persist: {error}"));

    let outcomes = storage.drain_persistence_media_outcomes();
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.iter().all(|outcome| outcome.media_failed));
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.opportunity.operation == BlockOp::Discard)
    );
    let erased = outcomes
        .iter()
        .flat_map(|outcome| &outcome.applied_spans)
        .map(|span| span.length)
        .sum::<u64>();
    assert!((1..=8).contains(&erased));
    let materialized = durable.materialize(&base);
    assert_eq!(
        &materialized[..usize::try_from(erased).unwrap_or(0)],
        &vec![0xff; usize::try_from(erased).unwrap_or(0)]
    );
    assert_eq!(
        &materialized[usize::try_from(erased).unwrap_or(0)..8],
        &vec![0xaa; 8 - usize::try_from(erased).unwrap_or(0)]
    );
    let continuation = &storage.flash_state().continuations()[&[7; 32]];
    assert_eq!(continuation.erase_blocks[&0].erase_count, 1);
    assert!(continuation.erase_decisions.is_empty());
}

#[test]
fn flash_retention_changes_survive_effect_deactivation_and_restore() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = state(BlockCompletionDurability::Durable);
    let read = BlockRequest::read(52, 0, 4);
    let mut active = ResolvedBlockFaultDirective::fault_free(&read, 32);
    active.execution_nanos = 10;
    active.persistence_media_rules = vec![ResolvedBlockFlashRule {
        contributor: [5; 32],
        choice_key: [6; 32],
        erase_block_bytes: 8,
        program_page_bytes: 4,
        endurance_cycles: 10,
        retention: super::super::flash::ResolvedBlockFlashRetention {
            minimum_age_nanos: 1,
            wear_age_nanos: 0,
            bit_probability_millionths: 1_000_000,
            maximum_changed_bits: 1,
        },
        read_disturb: super::super::flash::ResolvedBlockFlashReadDisturb {
            read_threshold: 100,
            neighbor_pages: 1,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        program_erase: super::super::flash::ResolvedBlockFlashProgramErase {
            program_probability_millionths: 0,
            erase_probability_millionths: 0,
            worn_probability_millionths: 0,
            partial_program: false,
            partial_erase: false,
        },
    }];
    storage
        .install(read.identity(), active)
        .unwrap_or_else(|error| panic!("active flash read should install: {error}"));
    let changed = storage
        .execute(&base, &mut durable, &read, 0)
        .unwrap_or_else(|error| panic!("active flash read should execute: {error}"));
    let changed = BlockResponse::decode(
        &changed
            .primary
            .unwrap_or_else(|| panic!("read should complete"))
            .payload,
    )
    .unwrap_or_else(|error| panic!("read response should decode: {error}"));
    assert_ne!(changed.data, vec![0; 4]);

    storage
        .validate_restore(32)
        .unwrap_or_else(|error| panic!("flash continuation should restore: {error}"));
    let inactive_read = BlockRequest::read(53, 0, 4);
    storage
        .install(
            inactive_read.identity(),
            ResolvedBlockFaultDirective::fault_free(&inactive_read, 32),
        )
        .unwrap_or_else(|error| panic!("inactive read should install: {error}"));
    let persisted = storage
        .execute(&base, &mut durable, &inactive_read, 0)
        .unwrap_or_else(|error| panic!("inactive read should execute: {error}"));
    let persisted = BlockResponse::decode(
        &persisted
            .primary
            .unwrap_or_else(|| panic!("read should complete"))
            .payload,
    )
    .unwrap_or_else(|error| panic!("read response should decode: {error}"));
    assert_eq!(persisted.data, changed.data);
}

#[test]
fn staged_execution_does_not_mutate_before_the_exact_decision() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = state(BlockCompletionDurability::Durable);
    storage.require_execution_opportunities(true);
    let request = BlockRequest::write(61, 4, b"stage".to_vec());
    let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
    admission.request_sequence = 900;
    admission.execution_nanos = 17;
    storage
        .install(request.identity(), admission)
        .unwrap_or_else(|error| panic!("admission directive should install: {error}"));

    let computed = storage
        .execute(&base, &mut durable, &request, 3)
        .unwrap_or_else(|error| panic!("request should enter staged execution: {error}"));
    assert!(computed.primary.is_none());
    assert_eq!(durable.read(&base, 4, 5).unwrap_or_default(), vec![0; 5]);
    assert!(storage.next_execution_opportunity(16).is_none());
    let opportunity = storage
        .next_execution_opportunity(17)
        .unwrap_or_else(|| panic!("exact execution opportunity should be visible"));
    assert_eq!(opportunity.request_sequence, 900);
    assert_eq!(opportunity.request, request);
    assert_eq!(opportunity.request_icount, 3);
    assert_eq!(opportunity.ready_nanos, 17);
    storage
        .validate_restore(32)
        .unwrap_or_else(|error| panic!("pre-decision checkpoint should validate: {error}"));

    let mut execution = ResolvedBlockFaultDirective::fault_free(&request, 32);
    execution.request_sequence = 900;
    execution.execution_nanos = 18;
    assert!(matches!(
        storage.install_execution_directive(ResolvedBlockExecutionDirective {
            opportunity: opportunity.clone(),
            directive: execution.clone(),
        }),
        Err(DeviceError::InvalidBlockFaultDirective { .. })
    ));
    execution.execution_nanos = 17;
    storage
        .install_execution_directive(ResolvedBlockExecutionDirective {
            opportunity,
            directive: execution,
        })
        .unwrap_or_else(|error| panic!("execution directive should install: {error}"));
    storage
        .validate_restore(32)
        .unwrap_or_else(|error| panic!("post-decision checkpoint should validate: {error}"));
    assert!(
        storage
            .resume_execution_to(&base, &mut durable, 16)
            .unwrap_or_else(|error| panic!("early resume should succeed: {error}"))
            .is_empty()
    );
    let released = storage
        .resume_execution_to(&base, &mut durable, 17)
        .unwrap_or_else(|error| panic!("exact resume should succeed: {error}"));
    assert!(released.is_empty());
    let persistence = storage
        .next_request_persistence_opportunity(17)
        .unwrap_or_else(|| panic!("persist opportunity should be visible"));
    let mut persisted = persistence.resolved.clone();
    persisted.execution_nanos = 17;
    storage
        .install_request_persistence_directive(ResolvedBlockRequestPersistenceDirective {
            opportunity: persistence,
            directive: persisted,
        })
        .unwrap_or_else(|error| panic!("persist directive should install: {error}"));
    let released = storage
        .resume_request_persistence_to(&base, &mut durable, 17)
        .unwrap_or_else(|error| panic!("persist resume should succeed: {error}"));
    assert!(released.is_empty());
    let delivery = storage
        .next_delivery_opportunity(17)
        .unwrap_or_else(|| panic!("delivery opportunity should be visible"));
    let delivered = delivery.resolved.clone();
    storage
        .install_delivery_directive(ResolvedBlockDeliveryDirective {
            opportunity: delivery,
            directive: delivered,
        })
        .unwrap_or_else(|error| panic!("delivery directive should install: {error}"));
    let released = storage
        .resume_delivery_to(17)
        .unwrap_or_else(|error| panic!("delivery resume should succeed: {error}"));
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].finished_nanos, 17);
    assert_eq!(durable.read(&base, 4, 5).unwrap_or_default(), b"stage");
    assert!(storage.next_execution_opportunity(u64::MAX).is_none());
}

#[test]
fn durable_delivery_waits_for_the_exact_physical_media_decision() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = state(BlockCompletionDurability::Durable);
    storage.require_execution_opportunities(true);
    storage.require_persistence_media_directives(true);
    let request = BlockRequest::write(63, 0, b"sync".to_vec());
    let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
    admission.request_sequence = 902;
    admission.execution_nanos = 17;
    storage
        .install(request.identity(), admission)
        .unwrap_or_else(|error| panic!("admission directive should install: {error}"));
    storage
        .execute(&base, &mut durable, &request, 3)
        .unwrap_or_else(|error| panic!("request should enter staged execution: {error}"));

    let execution = storage
        .next_execution_opportunity(17)
        .unwrap_or_else(|| panic!("execution opportunity should be visible"));
    storage
        .install_execution_directive(ResolvedBlockExecutionDirective {
            directive: execution.admission.clone(),
            opportunity: execution,
        })
        .unwrap_or_else(|error| panic!("execution directive should install: {error}"));
    storage
        .resume_execution_to(&base, &mut durable, 17)
        .unwrap_or_else(|error| panic!("execution should reach persistence: {error}"));

    let persistence = storage
        .next_request_persistence_opportunity(17)
        .unwrap_or_else(|| panic!("request persistence should be visible"));
    let mut persisted = persistence.resolved.clone();
    persisted.persistence_admitted_nanos = 17;
    persisted.cache_policy = Some(ResolvedBlockCachePolicy {
        capacity_bytes: 64,
        eviction: BlockFaultCacheEviction::WritebackSequence,
        dirty_eviction: BlockFaultDirtyEviction::Persist,
        power_loss_protected: false,
    });
    persisted
        .persistence_transforms
        .push(ResolvedBlockPersistenceTransform {
            contributor: [7; 32],
            ordering_group: [6; 32],
            ordering: crate::block::BlockPersistenceOrdering::Preserve,
            delay_nanos: 100,
            preserve_barriers: true,
        });
    storage
        .install_request_persistence_directive(ResolvedBlockRequestPersistenceDirective {
            opportunity: persistence,
            directive: persisted,
        })
        .unwrap_or_else(|error| panic!("request persistence should install: {error}"));
    storage
        .resume_request_persistence_to(&base, &mut durable, 17)
        .unwrap_or_else(|error| panic!("request mutation should execute: {error}"));

    assert!(storage.next_delivery_opportunity(u64::MAX).is_none());
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), vec![0; 4]);
    storage
        .validate_restore(32)
        .unwrap_or_else(|error| panic!("pre-media checkpoint should validate: {error}"));
    let mut media_count = 0;
    while let Some(media) = storage.next_persistence_opportunity(117) {
        storage
            .install_persistence_media_directive(ResolvedBlockPersistenceMediaDirective {
                opportunity: media,
                flash_rules: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("physical persistence should install: {error}"));
        storage
            .persist_due(&base, &mut durable, 117)
            .unwrap_or_else(|error| panic!("physical persistence should execute: {error}"));
        media_count += 1;
    }
    assert_eq!(media_count, 4);

    let delivery = storage
        .next_delivery_opportunity(117)
        .unwrap_or_else(|| panic!("delivery should follow actual durability"));
    storage
        .install_delivery_directive(ResolvedBlockDeliveryDirective {
            directive: delivery.resolved.clone(),
            opportunity: delivery,
        })
        .unwrap_or_else(|error| panic!("delivery directive should install: {error}"));
    let released = storage
        .resume_delivery_to(117)
        .unwrap_or_else(|error| panic!("durable completion should publish: {error}"));
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].finished_nanos, 117);
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"sync");
}

#[test]
fn queue_service_release_creates_the_execution_opportunity() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = state(BlockCompletionDurability::Durable);
    storage.require_execution_opportunities(true);
    let request = BlockRequest::write(62, 0, b"work".to_vec());
    let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
    admission.request_sequence = 901;
    admission.execution_nanos = 10;
    admission.service_rules = vec![ResolvedBlockServiceRule {
        contributor: [7; 32],
        bytes_per_second: 4,
        iops: None,
        queue_depth: 1,
        discipline: super::super::service::BlockServiceDiscipline::Fifo,
        classes: Vec::new(),
        rebuild_shares_service: false,
    }];
    storage
        .install(request.identity(), admission)
        .unwrap_or_else(|error| panic!("service directive should install: {error}"));
    let queued = storage
        .execute(&base, &mut durable, &request, 1)
        .unwrap_or_else(|error| panic!("request should queue: {error}"));
    assert!(queued.primary.is_none());
    assert!(storage.next_execution_opportunity(u64::MAX).is_none());

    let finished = 1_000_000_010;
    assert!(
        storage
            .advance_service_to(&base, &mut durable, finished - 1)
            .unwrap_or_else(|error| panic!("early service advance should succeed: {error}"))
            .is_empty()
    );
    assert!(storage.next_execution_opportunity(finished - 1).is_none());
    assert!(
        storage
            .advance_service_to(&base, &mut durable, finished)
            .unwrap_or_else(|error| panic!("service release should succeed: {error}"))
            .is_empty()
    );
    let opportunity = storage
        .next_execution_opportunity(finished)
        .unwrap_or_else(|| panic!("released request should expose execution"));
    assert_eq!(opportunity.request_sequence, 901);
    assert_eq!(opportunity.ready_nanos, finished);
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), vec![0; 4]);
    storage
        .validate_restore(32)
        .unwrap_or_else(|error| panic!("service-release checkpoint should validate: {error}"));
}

#[test]
fn service_evidence_precedes_same_nanos_persistence_it_triggers() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 4,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 32,
        cache_entries: 8,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 32,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    })
    .unwrap_or_else(|error| panic!("ordered-outcome state should build: {error}"));
    let cached = BlockRequest::write(70, 0, b"data".to_vec());
    storage
        .install(
            cached.identity(),
            ResolvedBlockFaultDirective::fault_free(&cached, 32),
        )
        .unwrap_or_else(|error| panic!("cached write should install: {error}"));
    storage
        .execute(&base, &mut durable, &cached, 0)
        .unwrap_or_else(|error| panic!("cached write should execute: {error}"));
    let finished = 1_000_000_010;

    let serviced = BlockRequest::read(71, 0, 4);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&serviced, 32);
    directive.execution_nanos = 10;
    directive.service_rules = vec![ResolvedBlockServiceRule {
        contributor: [9; 32],
        bytes_per_second: 4,
        iops: None,
        queue_depth: 1,
        discipline: super::super::service::BlockServiceDiscipline::Fifo,
        classes: Vec::new(),
        rebuild_shares_service: false,
    }];
    storage
        .install(serviced.identity(), directive)
        .unwrap_or_else(|error| panic!("serviced read should install: {error}"));
    storage
        .execute(&base, &mut durable, &serviced, 0)
        .unwrap_or_else(|error| panic!("serviced read should queue: {error}"));
    storage
        .schedule_volatile_persistence(0)
        .unwrap_or_else(|error| panic!("cached write should schedule: {error}"));
    storage
        .advance_service_to(&base, &mut durable, finished)
        .unwrap_or_else(|error| panic!("service and persistence should execute: {error}"));

    let outcomes = storage
        .storage_outcomes()
        .unwrap_or_else(|error| panic!("outcomes should remain ordered: {error}"));
    assert!(matches!(
        outcomes.as_slice(),
        [
            BlockStorageOutcome::Service(BlockServiceCompletion {
                finished_nanos: service_nanos,
                ..
            }),
            BlockStorageOutcome::Persistence(BlockPersistenceMediaOutcome {
                executed_nanos: persistence_nanos,
                ..
            })
        ] if service_nanos == persistence_nanos && *service_nanos == finished
    ));
}
