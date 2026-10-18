//! Phase admission, physical durability, and causal service-evidence regressions.

use super::*;

#[test]
fn staged_execution_does_not_mutate_before_the_exact_decision() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = state(BlockCompletionDurability::Durable);
    storage
        .require_execution_opportunities(true)
        .unwrap_or_else(|error| panic!("revision admission: {error}"));
    let request = BlockRequest::write(61, 4, b"stage".to_vec());
    let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
    admission.request_sequence = 900;
    admission.execution_ticks = 17;
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
    assert_eq!(opportunity.ready_ticks, 17);
    storage
        .validate_restore(32)
        .unwrap_or_else(|error| panic!("pre-decision checkpoint should validate: {error}"));

    let mut execution = ResolvedBlockFaultDirective::fault_free(&request, 32);
    execution.request_sequence = 900;
    execution.execution_ticks = 18;
    assert!(matches!(
        storage.install_execution_directive(ResolvedBlockExecutionDirective {
            opportunity: opportunity.clone(),
            directive: execution.clone(),
        }),
        Err(DeviceError::InvalidBlockFaultDirective { .. })
    ));
    execution.execution_ticks = 17;
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
    persisted.execution_ticks = 17;
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
    assert_eq!(released[0].finished_ticks, 17);
    assert_eq!(durable.read(&base, 4, 5).unwrap_or_default(), b"stage");
    assert!(storage.next_execution_opportunity(u64::MAX).is_none());
}

#[test]
fn durable_delivery_waits_for_the_exact_physical_media_decision() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = state(BlockCompletionDurability::Durable);
    storage
        .require_execution_opportunities(true)
        .unwrap_or_else(|error| panic!("revision admission: {error}"));
    storage
        .require_persistence_media_directives(true)
        .unwrap_or_else(|error| panic!("revision admission: {error}"));
    let request = BlockRequest::write(63, 0, b"sync".to_vec());
    let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
    admission.request_sequence = 902;
    admission.execution_ticks = 17;
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
    persisted.persistence_admitted_ticks = 17;
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
    while let Some(media) = storage.next_persistence_opportunity(100_017) {
        storage
            .install_persistence_media_directive(ResolvedBlockPersistenceMediaDirective {
                opportunity: media,
                flash_rules: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("physical persistence should install: {error}"));
        storage
            .persist_due(&base, &mut durable, 100_017)
            .unwrap_or_else(|error| panic!("physical persistence should execute: {error}"));
        media_count += 1;
    }
    assert_eq!(media_count, 4);

    let delivery = storage
        .next_delivery_opportunity(100_017)
        .unwrap_or_else(|| panic!("delivery should follow actual durability"));
    storage
        .install_delivery_directive(ResolvedBlockDeliveryDirective {
            directive: delivery.resolved.clone(),
            opportunity: delivery,
        })
        .unwrap_or_else(|error| panic!("delivery directive should install: {error}"));
    let released = storage
        .resume_delivery_to(100_017)
        .unwrap_or_else(|error| panic!("durable completion should publish: {error}"));
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].finished_ticks, 100_017);
    assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"sync");
}

#[test]
fn queue_service_release_creates_the_execution_opportunity() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut storage = state(BlockCompletionDurability::Durable);
    storage
        .require_execution_opportunities(true)
        .unwrap_or_else(|error| panic!("revision admission: {error}"));
    let request = BlockRequest::write(62, 0, b"work".to_vec());
    let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
    admission.request_sequence = 901;
    admission.execution_ticks = 10;
    admission.service_rules = vec![ResolvedBlockServiceRule {
        contributor: [7; 32],
        bytes_per_second: 4,
        iops: None,
        queue_depth: 1,
        discipline: crate::block::service::BlockServiceDiscipline::Fifo,
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

    let finished = 1_000_000_000_010;
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
    assert_eq!(opportunity.ready_ticks, finished);
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
    let finished = 1_000_000_000_010;

    let serviced = BlockRequest::read(71, 0, 4);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&serviced, 32);
    directive.execution_ticks = 10;
    directive.service_rules = vec![ResolvedBlockServiceRule {
        contributor: [9; 32],
        bytes_per_second: 4,
        iops: None,
        queue_depth: 1,
        discipline: crate::block::service::BlockServiceDiscipline::Fifo,
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
                finished_ticks: service_ticks,
                ..
            }),
            BlockStorageOutcome::Persistence(BlockPersistenceMediaOutcome {
                executed_ticks: persistence_ticks,
                ..
            })
        ] if service_ticks == persistence_ticks && *service_ticks == finished
    ));
}
