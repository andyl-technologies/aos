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
