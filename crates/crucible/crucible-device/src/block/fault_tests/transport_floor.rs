//! The frontend's oldest live transport epoch and retired-state pruning ([IO-35]).

use super::*;

const AFTER_RECOVERY: u64 = 1_000_000;

fn new_epoch_reset(next_epoch: u64) -> BlockTransportReset {
    BlockTransportReset {
        next_epoch,
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
    }
}

fn stamped(request: BlockRequest, epoch: u64, oldest_live_epoch: u64) -> BlockRequest {
    let request_id = request.request_id;
    request
        .with_identity(BlockRequestIdentity::new(epoch, request_id))
        .with_oldest_live_epoch(oldest_live_epoch)
}

fn execute_at(
    state: &mut BlockFaultState,
    base: &BaseImage,
    durable: &mut CowOverlay,
    request: &BlockRequest,
    ticks: u64,
) -> Result<ComputedResponse, DeviceError> {
    let mut directive = ResolvedBlockFaultDirective::fault_free(request, 32);
    directive.execution_ticks = ticks;
    state.install(request.identity(), directive)?;
    state.execute(base, durable, request, ticks)
}

fn primary_status(computed: &ComputedResponse) -> BlockStatus {
    let primary = computed
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("request produces a primary response"));
    BlockResponse::decode(&primary.payload)
        .unwrap_or_else(|error| panic!("primary response decodes: {error}"))
        .status
}

/// Builds epoch 1 after one epoch-0 request, with epoch 0 retired.
fn state_after_one_reset(base: &BaseImage, durable: &mut CowOverlay) -> BlockFaultState {
    let mut state = state(BlockCompletionDurability::Durable);
    execute_at(&mut state, base, durable, &BlockRequest::read(0, 0, 4), 0)
        .unwrap_or_else(|error| panic!("opening request executes: {error}"));
    state
        .apply_transport_reset(new_epoch_reset(1), 0)
        .unwrap_or_else(|error| panic!("transport reset applies: {error}"));
    assert!(state.retired_transport_epochs.contains_key(&0));
    state
}

/// Epoch 0 stays retained while the frontend can still resubmit a pre-reset
/// identity, and is dropped once the frontend acknowledges epoch 1 as its
/// oldest live epoch.
#[test]
fn acknowledged_floor_drops_the_retired_epoch_after_its_last_retry() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state_after_one_reset(&base, &mut durable);

    // The frontend still holds (0, 7), so its new-epoch request names floor 0.
    let newer = stamped(BlockRequest::read(0, 0, 4), 1, 0);
    execute_at(&mut state, &base, &mut durable, &newer, AFTER_RECOVERY)
        .unwrap_or_else(|error| panic!("newer-epoch request executes: {error}"));
    assert_eq!(state.oldest_live_transport_epoch(), 0);
    assert!(state.retired_transport_epochs.contains_key(&0));

    // The pre-reset identity is disposed of by epoch 0's policy, then runs.
    let retried = stamped(BlockRequest::read(7, 0, 4), 0, 0);
    let disposed = state
        .dispose_retired_transport_request_if_needed(&retried)
        .unwrap_or_else(|error| panic!("retired epoch policy remains: {error}"))
        .unwrap_or_else(|| panic!("stale retry receives a reset disposition"));
    let disposed = BlockResponse::decode(&disposed.payload)
        .unwrap_or_else(|error| panic!("disposition decodes: {error}"));
    assert_eq!(disposed.status, BlockStatus::RetryPreserveId);
    let computed = execute_at(&mut state, &base, &mut durable, &retried, AFTER_RECOVERY)
        .unwrap_or_else(|error| panic!("authorized retry executes: {error}"));
    assert_eq!(primary_status(&computed), BlockStatus::Ok);

    // With no epoch-0 identity left, the next request acknowledges epoch 1.
    let after = stamped(BlockRequest::read(1, 0, 4), 1, 1);
    execute_at(&mut state, &base, &mut durable, &after, AFTER_RECOVERY)
        .unwrap_or_else(|error| panic!("floor-advancing request executes: {error}"));
    assert_eq!(state.oldest_live_transport_epoch(), 1);
    assert!(state.retired_transport_epochs.is_empty());
    assert!(state.retry_preserve_authorizations.is_empty());

    // A frontend that later names epoch 0 again misreported its live set.
    let before = state.clone();
    let regressed = stamped(BlockRequest::read(8, 0, 4), 0, 0);
    assert_eq!(
        state.dispose_retired_transport_request_if_needed(&regressed),
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "block request oldest live epoch regressed",
        })
    );
    assert_eq!(state, before);
}

#[test]
fn floor_after_the_transport_epoch_or_a_regression_fails_closed() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state_after_one_reset(&base, &mut durable);

    // A request may not claim an epoch the host has not reached as live.
    let future = stamped(BlockRequest::read(0, 0, 4), 2, 2);
    let mut rejected = state.clone();
    assert_eq!(
        rejected.acknowledge_oldest_live_epoch(&future),
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "block request oldest live epoch follows the transport epoch",
        })
    );

    let malformed = BlockRequest {
        oldest_live_epoch: 1,
        ..BlockRequest::read(0, 0, 4)
    };
    assert_eq!(
        rejected.acknowledge_oldest_live_epoch(&malformed),
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "block request oldest live epoch follows its own epoch",
        })
    );

    let advancing = stamped(BlockRequest::read(0, 0, 4), 1, 1);
    execute_at(&mut state, &base, &mut durable, &advancing, AFTER_RECOVERY)
        .unwrap_or_else(|error| panic!("floor-advancing request executes: {error}"));
    let before = state.clone();
    let regressed = stamped(BlockRequest::read(1, 0, 4), 1, 0);
    assert_eq!(
        execute_at(&mut state, &base, &mut durable, &regressed, AFTER_RECOVERY).map(|_| ()),
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "block request oldest live epoch regressed",
        })
    );
    assert_eq!(
        state.oldest_live_transport_epoch(),
        before.oldest_live_transport_epoch()
    );
}

/// An authorization the frontend can no longer use is dropped with its epoch,
/// and the pruned state passes checkpoint validation.
#[test]
fn floor_drops_unusable_preserve_authorizations() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state_after_one_reset(&base, &mut durable);

    let stale = stamped(BlockRequest::read(7, 0, 4), 0, 0);
    state
        .dispose_retired_transport_request_if_needed(&stale)
        .unwrap_or_else(|error| panic!("stale request is disposed of: {error}"));
    assert!(
        state
            .retry_preserve_authorizations
            .contains(&stale.identity())
    );

    // The frontend dropped (0, 7) instead of retrying it.
    let advancing = stamped(BlockRequest::read(0, 0, 4), 1, 1);
    execute_at(&mut state, &base, &mut durable, &advancing, AFTER_RECOVERY)
        .unwrap_or_else(|error| panic!("floor-advancing request executes: {error}"));
    assert!(state.retry_preserve_authorizations.is_empty());
    assert!(state.retired_transport_epochs.is_empty());

    let bytes = state
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("pruned state encodes: {error}"));
    let restored = BlockFaultState::from_canonical_bytes(&bytes, 32)
        .unwrap_or_else(|error| panic!("pruned state restores: {error}"));
    assert_eq!(restored.oldest_live_transport_epoch(), 1);
}

/// Resets beyond the retained-epoch hard limit succeed while the frontend
/// keeps acknowledging its current epoch, because only the live window is
/// retained.
#[test]
fn retired_epochs_stay_bounded_across_more_resets_than_the_hard_limit() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::Durable);
    let resets = u64::try_from(HARD_BLOCK_RETIRED_TRANSPORT_EPOCHS)
        .unwrap_or_else(|error| panic!("hard limit fits u64: {error}"))
        + 1;

    for epoch in 0..resets {
        let request = stamped(BlockRequest::get_length(0), epoch, epoch);
        state
            .execute(&base, &mut durable, &request, AFTER_RECOVERY * epoch)
            .unwrap_or_else(|error| panic!("epoch {epoch} request executes: {error}"));
        state
            .apply_transport_reset(new_epoch_reset(epoch + 1), AFTER_RECOVERY * epoch)
            .unwrap_or_else(|error| panic!("reset after epoch {epoch} applies: {error}"));
        assert!(state.retired_transport_epochs.len() <= 1);
    }

    assert_eq!(state.transport_epoch(), Some(resets));
    assert_eq!(state.oldest_live_transport_epoch(), resets - 1);
}

#[test]
fn restore_rejects_retired_state_inconsistent_with_the_floor() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state_after_one_reset(&base, &mut durable);
    state
        .apply_transport_reset(new_epoch_reset(2), 0)
        .unwrap_or_else(|error| panic!("second reset applies: {error}"));
    state
        .validate_restore(32)
        .unwrap_or_else(|error| panic!("contiguous retired run is valid: {error}"));

    let mut floor_after_epoch = state.clone();
    floor_after_epoch.oldest_live_transport_epoch = 3;
    let mut retained_below_floor = state.clone();
    retained_below_floor.oldest_live_transport_epoch = 1;
    let mut gap = state.clone();
    gap.retired_transport_epochs.remove(&1);
    let mut floor_without_epoch = BlockFaultState::write_through(32);
    floor_without_epoch.oldest_live_transport_epoch = 1;

    for invalid in [
        floor_after_epoch,
        retained_below_floor,
        gap,
        floor_without_epoch,
    ] {
        assert!(matches!(
            invalid.validate_restore(32),
            Err(DeviceError::InvalidBlockFaultDirective { .. })
        ));
    }
}
