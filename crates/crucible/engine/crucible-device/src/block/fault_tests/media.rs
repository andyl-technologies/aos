//! Delayed persistence and exact flash program, discard, and retention regressions.

use super::*;

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
    directive.execution_ticks = 10;
    directive.persistence_admitted_ticks = 10;
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
    flush_directive.execution_ticks = 20;
    state
        .install(flush.identity(), flush_directive)
        .unwrap_or_else(|error| panic!("flush directive: {error}"));
    let computed = state
        .execute(&base, &mut durable, &flush, 20)
        .unwrap_or_else(|error| panic!("delayed flush: {error}"));
    assert_eq!(computed.additional_latency_ticks, 99_990);
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"abcd");
    assert_eq!(state.reported_durable_frontier(), 0);
    assert!(state.media_queue_entries().contains_key(&0));

    state
        .persist_due(&base, &mut durable, 100_009)
        .unwrap_or_else(|error| panic!("pre-deadline service: {error}"));
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"abcd");
    state
        .persist_due(&base, &mut durable, 100_010)
        .unwrap_or_else(|error| panic!("deadline service: {error}"));
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"zzzz");
    assert_eq!(state.reported_durable_frontier(), 1);
    assert!(state.media_queue_entries().is_empty());
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
    storage
        .require_persistence_media_directives(true)
        .unwrap_or_else(|error| panic!("revision admission: {error}"));
    let opportunity = storage
        .next_persistence_opportunity(0)
        .unwrap_or_else(|| panic!("persistence opportunity should be ready"));
    let flash_rule = ResolvedBlockFlashRule {
        contributor: [3; 32],
        choice_key: [4; 32],
        erase_block_bytes: 8,
        program_page_bytes: 4,
        endurance_cycles: 10,
        retention: crate::block::flash::ResolvedBlockFlashRetention {
            minimum_age_nanos: 1,
            wear_age_nanos: 0,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        read_disturb: crate::block::flash::ResolvedBlockFlashReadDisturb {
            read_threshold: 10,
            neighbor_pages: 1,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        program_erase: crate::block::flash::ResolvedBlockFlashProgramErase {
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
    let outcomes = storage
        .drain_persistence_media_outcomes()
        .unwrap_or_else(|error| panic!("revision admission: {error}"));
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
        retention: crate::block::flash::ResolvedBlockFlashRetention {
            minimum_age_nanos: 1,
            wear_age_nanos: 0,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        read_disturb: crate::block::flash::ResolvedBlockFlashReadDisturb {
            read_threshold: 10,
            neighbor_pages: 1,
            bit_probability_millionths: 0,
            maximum_changed_bits: 1,
        },
        program_erase: crate::block::flash::ResolvedBlockFlashProgramErase {
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

    let outcomes = storage
        .drain_persistence_media_outcomes()
        .unwrap_or_else(|error| panic!("revision admission: {error}"));
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
    active.execution_ticks = 1_010;
    active.persistence_media_rules = vec![ResolvedBlockFlashRule {
        contributor: [5; 32],
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
    storage
        .install(read.identity(), active)
        .unwrap_or_else(|error| panic!("active flash read should install: {error}"));
    let changed = storage
        .execute(&base, &mut durable, &read, 1_000)
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
