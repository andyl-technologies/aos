//! Directive duplication, transport resets, exact response delays, and frame bounds.

use super::*;

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
    assert_eq!(computed.additional[0].gap_ticks, 11_000);
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
    assert_eq!(computed.additional[0].gap_ticks, 17_000);
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
        data: vec![0; crucible_qemu_shmem::MAX_FRAME_DATA],
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

/// Retired epochs cannot be pruned below the newest epoch the frontend sent.
///
/// A reset that answers a queued request with `RetryPreserveId` does not grant
/// a preserved-retry authorization. The frontend waits out recovery and then
/// resubmits the same pre-reset identity, and a request stamped with the new
/// epoch may cross the ring first. The host still needs the retired epoch's
/// policy to dispose of that resubmission, so a "highest observed epoch" floor
/// is not a sound pruning bound for `retired_transport_epochs`.
#[test]
fn preserved_identity_of_a_retired_epoch_may_follow_a_newer_epoch_request() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::Durable);
    let after_recovery = 1_000_000;

    let first = BlockRequest::read(0, 0, 4);
    let mut opening = ResolvedBlockFaultDirective::fault_free(&first, 32);
    opening.execution_ticks = 0;
    state
        .install(first.identity(), opening)
        .unwrap_or_else(|error| panic!("opening directive installs: {error}"));
    state
        .execute(&base, &mut durable, &first, 0)
        .unwrap_or_else(|error| panic!("opening request executes: {error}"));

    let retried = BlockRequest::read(7, 0, 4);
    state
        .install(
            retried.identity(),
            ResolvedBlockFaultDirective::fault_free(&retried, 32),
        )
        .unwrap_or_else(|error| panic!("queued directive installs: {error}"));
    let responses = state
        .apply_transport_reset(
            BlockTransportReset {
                next_epoch: 1,
                recovery_nanos: 50,
                request_ids: BlockTransportRequestIds::NewEpochFromZero,
                reenumerate_declared: false,
                preserve_duplicate_history: false,
                failure_result: BlockErrorCode::IoError,
                unadmitted: BlockTransportUnadmitted::WaitForRecovery,
                queued: BlockTransportPending::RetryPreserveId,
                executing: BlockTransportPending::Fail,
                resolved: BlockTransportResolved::Complete,
                completed_undelivered: BlockTransportUndelivered::Complete,
                preserve_controller_buffer: true,
                preserve_volatile_cache: true,
            },
            0,
        )
        .unwrap_or_else(|error| panic!("transport reset applies: {error}"));
    let disposition = BlockResponse::decode(&responses[0].payload)
        .unwrap_or_else(|error| panic!("reset disposition decodes: {error}"));
    assert_eq!(disposition.status, BlockStatus::RetryPreserveId);

    // A fresh request in the new epoch crosses the ring before the retry.
    let newer = BlockRequest {
        epoch: 1,
        ..BlockRequest::read(0, 0, 4)
    };
    let mut newer_directive = ResolvedBlockFaultDirective::fault_free(&newer, 32);
    newer_directive.execution_ticks = after_recovery;
    state
        .install(newer.identity(), newer_directive)
        .unwrap_or_else(|error| panic!("newer-epoch directive installs: {error}"));
    state
        .execute(&base, &mut durable, &newer, after_recovery)
        .unwrap_or_else(|error| panic!("newer-epoch request executes: {error}"));

    // The pre-reset identity is disposed of by epoch 0's retained policy.
    let disposed = state
        .dispose_retired_transport_request_if_needed(&retried)
        .unwrap_or_else(|error| panic!("retired epoch policy must remain: {error}"))
        .unwrap_or_else(|| panic!("stale retry must receive a reset disposition"));
    let disposed = BlockResponse::decode(&disposed.payload)
        .unwrap_or_else(|error| panic!("retry disposition decodes: {error}"));
    assert_eq!(disposed.status, BlockStatus::RetryPreserveId);
    assert!(state.retired_transport_epochs.contains_key(&0));

    // That disposition authorized the identity, so its next submission runs.
    let mut resubmitted = ResolvedBlockFaultDirective::fault_free(&retried, 32);
    resubmitted.execution_ticks = after_recovery;
    state
        .install(retried.identity(), resubmitted)
        .unwrap_or_else(|error| panic!("authorized directive installs: {error}"));
    let computed = state
        .execute(&base, &mut durable, &retried, after_recovery)
        .unwrap_or_else(|error| panic!("authorized pre-reset identity executes: {error}"));
    let completed = BlockResponse::decode(
        &computed
            .primary
            .unwrap_or_else(|| panic!("authorized request completes"))
            .payload,
    )
    .unwrap_or_else(|error| panic!("authorized response decodes: {error}"));
    assert_eq!(completed.status, BlockStatus::Ok);
    assert_eq!(completed.identity(), retried.identity());
}
