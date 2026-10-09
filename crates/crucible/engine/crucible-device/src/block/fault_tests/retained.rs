//! Checkpointed read transformations and retained completion release regressions.

use super::*;

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
    directive.retention_timeout_ticks = Some(100);
    directive.retention_recovery_event = Some([7; 32]);
    directive.retention_recovery_after_ticks = Some(0);
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
                event_ticks: 50,
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
    directive.retention_timeout_ticks = Some(100);
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
            directive.execution_ticks = 10;
            directive.persistence_admitted_ticks = 10;
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
    directive.execution_ticks = 20;
    directive.flush_disposition = BlockFaultFlushDisposition::Stall;
    directive.retain_completion = true;
    directive.retention_timeout_response = Some(BlockResponse::error(
        flush.request_id,
        BlockErrorCode::Timeout,
    ));
    directive.retention_timeout_ticks = Some(200);
    directive.retention_recovery_event = Some([7; 32]);
    directive.retention_recovery_after_ticks = Some(20);
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
                event_ticks: 50,
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
        .persist_due(&base, &mut durable, 100_010)
        .unwrap_or_else(|error| panic!("delayed persistence completes: {error}"));
    let released = state
        .resolve_retained_completion(
            &base,
            &mut durable,
            flush.identity(),
            BlockRetainedRelease::Recovery {
                event_ticks: 50,
                event_sequence: 0,
            },
            100_010,
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
