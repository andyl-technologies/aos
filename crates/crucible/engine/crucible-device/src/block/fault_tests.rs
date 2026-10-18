//! Tests for block fault state, durability, and recovery behavior.

use super::*;

#[path = "fault_tests/resource_usage.rs"]
mod resource_usage;

#[path = "fault_tests/cache.rs"]
mod cache;
#[path = "fault_tests/media.rs"]
mod media;
#[path = "fault_tests/payload.rs"]
mod payload;
#[path = "fault_tests/pipeline.rs"]
mod pipeline;
#[path = "fault_tests/retained.rs"]
mod retained;
#[path = "fault_tests/transport.rs"]
mod transport;

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
