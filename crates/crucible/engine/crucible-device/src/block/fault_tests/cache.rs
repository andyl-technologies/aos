//! Cache admission, eviction, controller acceptance, and visible-byte regressions.

use super::*;

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
    // Installing and consuming the rejected request are real phase changes,
    // even though the payload/cache rollback returns to the prior state.
    assert!(state.observation_revision > before_state.observation_revision);
    let mut expected = before_state;
    expected.observation_revision = state.observation_revision;
    assert_eq!(state, expected);
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
