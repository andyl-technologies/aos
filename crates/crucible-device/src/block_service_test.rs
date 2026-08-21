//! Integrated service and cross-device block fault tests.

use super::test_support::*;
use super::*;
use crate::DeviceError;
use crate::subnode::IoCore;
#[test]
fn block_snapshot_codec_round_trips_complete_device_state() {
    let device = device_with_latency(8_192, BlockLatency::new(1, 2, 3, 4, 5));
    let snapshot = device.snapshot();
    let bytes = ok(snapshot.to_canonical_bytes());
    assert_eq!(ok(BlockSnapshot::from_canonical_bytes(&bytes)), snapshot);

    let configured = u64::try_from(bytes.len() - 1)
        .unwrap_or_else(|error| panic!("fixture length is representable: {error}"));
    assert_eq!(
        BlockSnapshot::from_canonical_bytes_with_limit(&bytes, configured),
        Err(BlockSnapshotCodecError::ResourceLimit {
            field: "block snapshot bytes",
            current: 0,
            requested: bytes.len() as u64,
            configured,
            hard: MAX_BLOCK_SNAPSHOT_BYTES,
        })
    );

    let mut prior_version = bytes.clone();
    let version_index = b"crucible.block-snapshot.v".len();
    assert_eq!(prior_version[version_index], b'3');
    prior_version[version_index] = b'2';
    assert_eq!(
        BlockSnapshot::from_canonical_bytes(&prior_version),
        Err(BlockSnapshotCodecError::Version)
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        BlockSnapshot::from_canonical_bytes(&trailing),
        Err(BlockSnapshotCodecError::Noncanonical)
    );
}

fn cached_fault_config(length_bytes: u64) -> BlockDurabilityConfig {
    BlockDurabilityConfig {
        length_bytes,
        atomic_write_bytes: 512,
        maximum_request_bytes: length_bytes,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: length_bytes,
        cache_entries: 64,
        controller_buffer_bytes: 0,
        controller_entries: 0,
        persistence_dependencies: 1024,
        retained_versions: 64,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    }
}

fn fifo_service_rule(contributor: u8) -> ResolvedBlockServiceRule {
    ResolvedBlockServiceRule {
        contributor: [contributor; 32],
        bytes_per_second: 1_000_000_000,
        iops: None,
        queue_depth: 8,
        discipline: BlockServiceDiscipline::Fifo,
        classes: Vec::new(),
        rebuild_shares_service: true,
    }
}

fn priority_service_rule(contributor: u8) -> ResolvedBlockServiceRule {
    ResolvedBlockServiceRule {
        contributor: [contributor; 32],
        bytes_per_second: 1_000_000_000,
        iops: None,
        queue_depth: 8,
        discipline: BlockServiceDiscipline::StrictPriority,
        classes: vec![
            ResolvedBlockServiceClass {
                class: [1; 32],
                operations: vec![BlockOp::Read],
                priority: 0,
                weight: 1,
            },
            ResolvedBlockServiceClass {
                class: [2; 32],
                operations: vec![BlockOp::Write],
                priority: 1,
                weight: 1,
            },
        ],
        rebuild_shares_service: true,
    }
}

#[test]
fn integrated_service_defers_real_mutation_and_survives_restore() {
    let core = ok(IoCore::new(0, crucible_shmem::SLOT_BLK_IO as u32, 16, 16));
    let latency = BlockLatency::new(0, 0, 0, 0, 0);
    let mut original = BlockDevice::new(core, ramp_base(PAGE_SIZE), latency);
    ok(original
        .configure_storage_faults(BlockDurabilityConfig::write_through(PAGE_SIZE as u64), true));
    let request = BlockRequest::write(41, 0, vec![0xa5; 10]);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&request, PAGE_SIZE as u64);
    directive.request_sequence = 700;
    directive.service_rules = vec![fifo_service_rule(1)];
    ok(original.install_storage_fault_directive(request.identity(), directive));
    ok(original.submit(0, &request));

    assert_eq!(original.overlay().page_count(), 0);
    assert_eq!(original.next_exact_local_event(), Some(10));
    let snapshot = original.snapshot();
    let mut restored = ok(BlockDevice::restore(&snapshot, ramp_base(PAGE_SIZE), None));

    assert_eq!(ok(original.advance_to(9)), 0);
    assert_eq!(original.overlay().page_count(), 0);
    assert_eq!(ok(original.advance_to(10)), 1);
    assert_eq!(ok(restored.advance_to(10)), 1);
    assert_eq!(original.snapshot(), restored.snapshot());
    assert_eq!(
        ok(original.next_response())
            .unwrap_or_else(|| panic!("service completion should be delivered"))
            .status,
        BlockStatus::Ok
    );
    assert_eq!(
        ok(original.overlay().read(original.base(), 0, 10)),
        vec![0xa5; 10]
    );
    let outcomes = original.drain_storage_service_outcomes();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].sequence, 700);
    assert_eq!(outcomes[0].finished_nanos, 10);
}

#[test]
fn unresolved_storage_execution_is_a_hard_advance_horizon() {
    let core = ok(IoCore::new(0, crucible_shmem::SLOT_BLK_IO as u32, 16, 16));
    let latency = BlockLatency::new(0, 0, 0, 0, 0);
    let mut device = BlockDevice::new(core, ramp_base(PAGE_SIZE), latency);
    ok(device
        .configure_storage_faults(BlockDurabilityConfig::write_through(PAGE_SIZE as u64), true));
    ok(device.require_storage_execution_opportunities());
    let request = BlockRequest::write(60, 0, vec![0xa5; 4]);
    let mut admission = ResolvedBlockFaultDirective::fault_free(&request, PAGE_SIZE as u64);
    admission.request_sequence = 950;
    ok(device.install_storage_fault_directive(request.identity(), admission));
    ok(device.submit(0, &request));

    assert_eq!(ok(device.advance_to(0)), 0);
    assert_eq!(
        device.advance_to(1),
        Err(DeviceError::UnresolvedBlockFaultOpportunity {
            ready_nanos: 0,
            requested_nanos: 1,
        })
    );
    assert_eq!(device.core().current_icount(), 0);
    let opportunity = device
        .next_storage_execution_opportunity(0)
        .unwrap_or_else(|| panic!("execution opportunity should remain live"));
    let mut execution = ResolvedBlockFaultDirective::fault_free(&request, PAGE_SIZE as u64);
    execution.request_sequence = 950;
    ok(
        device.install_storage_execution_directive(ResolvedBlockExecutionDirective {
            opportunity,
            directive: execution,
        }),
    );
    assert_eq!(ok(device.advance_to(0)), 0);
    let persistence = device
        .next_storage_request_persistence_opportunity(0)
        .unwrap_or_else(|| panic!("persist opportunity should remain live"));
    let mut persisted = persistence.resolved.clone();
    persisted.execution_nanos = 0;
    ok(device.install_storage_request_persistence_directive(
        ResolvedBlockRequestPersistenceDirective {
            opportunity: persistence,
            directive: persisted,
        },
    ));
    assert_eq!(ok(device.advance_to(0)), 0);
    let delivery = device
        .next_storage_delivery_opportunity(0)
        .unwrap_or_else(|| panic!("delivery opportunity should remain live"));
    let delivered = delivery.resolved.clone();
    ok(
        device.install_storage_delivery_directive(ResolvedBlockDeliveryDirective {
            opportunity: delivery,
            directive: delivered,
        }),
    );
    assert_eq!(ok(device.advance_to(1)), 1);
}

#[test]
fn admission_failure_bypasses_integrated_service() {
    let core = ok(IoCore::new(0, crucible_shmem::SLOT_BLK_IO as u32, 16, 16));
    let latency = BlockLatency::new(0, 0, 0, 0, 0);
    let mut device = BlockDevice::new(core, ramp_base(PAGE_SIZE), latency);
    ok(device
        .configure_storage_faults(BlockDurabilityConfig::write_through(PAGE_SIZE as u64), true));
    let request = BlockRequest::write(42, 0, vec![0xa5; 10]);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&request, PAGE_SIZE as u64);
    directive.request_sequence = 701;
    directive.availability = BlockFaultAvailability::Offline;
    directive.service_rules = vec![fifo_service_rule(1)];
    ok(device.install_storage_fault_directive(request.identity(), directive));

    ok(device.submit(0, &request));

    assert_eq!(device.next_exact_local_event(), Some(0));
    assert_eq!(ok(device.advance_to(0)), 1);
    let response = ok(device.next_response())
        .unwrap_or_else(|| panic!("admission failure should be delivered immediately"));
    assert_eq!(response.status, BlockStatus::Error);
    assert_eq!(ok(response.error_code()), BlockErrorCode::Offline);
    assert_eq!(device.overlay().page_count(), 0);
    assert!(device.drain_storage_service_outcomes().is_empty());
    assert_eq!(device.next_exact_local_event(), None);
}

#[test]
fn later_high_priority_admission_cannot_precede_queued_work() {
    let core = ok(IoCore::new(0, crucible_shmem::SLOT_BLK_IO as u32, 16, 16));
    let latency = BlockLatency::new(0, 0, 0, 0, 0);
    let mut device = BlockDevice::new(core, ramp_base(PAGE_SIZE), latency);
    ok(device
        .configure_storage_faults(BlockDurabilityConfig::write_through(PAGE_SIZE as u64), true));
    let requests = [
        (0, BlockRequest::write(50, 0, vec![0xa5; 10]), 800),
        (1, BlockRequest::write(51, 16, vec![0x5a; 10]), 801),
        (100, BlockRequest::read(52, 0, 4), 802),
    ];
    for (request_icount, request, sequence) in &requests {
        let mut directive = ResolvedBlockFaultDirective::fault_free(request, PAGE_SIZE as u64);
        directive.request_sequence = *sequence;
        directive.execution_nanos = *request_icount;
        directive.service_rules = vec![priority_service_rule(2)];
        ok(device.install_storage_fault_directive(request.identity(), directive));
        ok(device.submit(*request_icount, request));
    }

    let outcomes = device.drain_storage_service_outcomes();
    assert_eq!(
        outcomes
            .iter()
            .map(|outcome| (
                outcome.sequence,
                outcome.started_nanos,
                outcome.finished_nanos
            ))
            .collect::<Vec<_>>(),
        vec![(800, 0, 10), (801, 10, 20)]
    );
    assert_eq!(device.overlay().page_count(), 1);
    assert_eq!(ok(device.advance_to(100)), 2);
    assert_eq!(device.next_exact_local_event(), Some(104));
    assert!(device.drain_storage_service_outcomes().is_empty());
}

#[test]
fn full_service_queue_returns_stable_busy_response() {
    let core = ok(IoCore::new(0, crucible_shmem::SLOT_BLK_IO as u32, 16, 16));
    let latency = BlockLatency::new(0, 0, 0, 0, 0);
    let mut device = BlockDevice::new(core, ramp_base(PAGE_SIZE), latency);
    ok(device
        .configure_storage_faults(BlockDurabilityConfig::write_through(PAGE_SIZE as u64), true));
    for (request_icount, request_id, sequence, offset) in [(0, 60, 900, 0), (1, 61, 901, 16)] {
        let request = BlockRequest::write(request_id, offset, vec![0xa5; 10]);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&request, PAGE_SIZE as u64);
        let mut rule = fifo_service_rule(3);
        rule.queue_depth = 1;
        directive.request_sequence = sequence;
        directive.execution_nanos = request_icount;
        directive.service_rules = vec![rule];
        ok(device.install_storage_fault_directive(request.identity(), directive));
        ok(device.submit(request_icount, &request));
    }

    assert_eq!(ok(device.advance_to(1)), 1);
    let response = ok(device.next_response())
        .unwrap_or_else(|| panic!("full service queue should return Busy"));
    assert_eq!(ok(response.error_code()), BlockErrorCode::Busy);
    assert_eq!(device.overlay().page_count(), 0);
    assert!(device.drain_storage_service_outcomes().is_empty());
}

// ---- CoW: read / write / copy-up / base-never-mutated (IO-5,6) ----

#[test]
fn retained_flush_release_rolls_back_when_completion_order_is_exhausted() {
    let mut original = device(PAGE_SIZE);
    ok(original.configure_storage_faults(cached_fault_config(PAGE_SIZE as u64), true));
    let write = BlockRequest::write(1, 0, vec![0x5a; 512]);
    ok(original.install_storage_fault_directive(
        write.identity(),
        ResolvedBlockFaultDirective::fault_free(&write, PAGE_SIZE as u64),
    ));
    ok(original.submit(0, &write));

    let flush = BlockRequest::flush(2);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&flush, PAGE_SIZE as u64);
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
    ok(original.install_storage_fault_directive(flush.identity(), directive));
    ok(original.submit(0, &flush));

    let mut exhausted = original.snapshot();
    exhausted.core.next_seq = u32::MAX;
    let mut restored = ok(BlockDevice::restore(&exhausted, ramp_base(PAGE_SIZE), None));
    let before = restored.snapshot();
    assert!(matches!(
        restored.release_storage_completion(
            flush.identity(),
            BlockRetainedRelease::Recovery {
                event_nanos: 0,
                event_sequence: 1,
            },
        ),
        Err(crate::DeviceError::ResponseSequenceOverflow { .. })
    ));
    assert_eq!(restored.snapshot(), before);
}

#[test]
fn retained_completion_batch_release_is_atomic() {
    let mut block = device(PAGE_SIZE);
    ok(block.configure_storage_faults(cached_fault_config(PAGE_SIZE as u64), true));
    let flush = BlockRequest::flush(2);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&flush, PAGE_SIZE as u64);
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
    ok(block.install_storage_fault_directive(flush.identity(), directive));
    ok(block.submit(0, &flush));

    let before = block.snapshot();
    let absent = BlockRequestIdentity::new(0, 99);
    assert!(matches!(
        block.release_storage_completions(&[
            (
                flush.identity(),
                BlockRetainedRelease::Recovery {
                    event_nanos: 0,
                    event_sequence: 1,
                },
            ),
            (absent, BlockRetainedRelease::Timeout),
        ]),
        Err(crate::DeviceError::InvalidBlockFaultDirective { .. })
    ));
    assert_eq!(block.snapshot(), before);
}

#[test]
fn retained_completion_release_rejects_an_early_timeout() {
    let mut block = device(PAGE_SIZE);
    ok(block.configure_storage_faults(cached_fault_config(PAGE_SIZE as u64), true));
    let flush = BlockRequest::flush(2);
    let mut directive = ResolvedBlockFaultDirective::fault_free(&flush, PAGE_SIZE as u64);
    directive.flush_disposition = BlockFaultFlushDisposition::Stall;
    directive.retain_completion = true;
    directive.retention_timeout_response = Some(BlockResponse::error(
        flush.request_id,
        BlockErrorCode::Timeout,
    ));
    directive.retention_timeout_nanos = Some(100);
    ok(block.install_storage_fault_directive(flush.identity(), directive));
    ok(block.submit(0, &flush));

    let before = block.snapshot();
    assert!(matches!(
        block.release_storage_completion(flush.identity(), BlockRetainedRelease::Timeout),
        Err(crate::DeviceError::InvalidBlockFaultDirective { .. })
    ));
    assert_eq!(block.snapshot(), before);
}

#[test]
fn cross_device_misdirection_commits_both_devices_or_neither() {
    fn stage_persistence(
        source: &mut BlockDevice,
        request: &BlockRequest,
        request_icount: u64,
        now_nanos: u64,
    ) -> BlockRequestPersistenceOpportunity {
        ok(source.require_storage_execution_opportunities());
        let mut admission = ResolvedBlockFaultDirective::fault_free(request, PAGE_SIZE as u64);
        admission.execution_nanos = now_nanos;
        admission.persistence_admitted_nanos = now_nanos;
        ok(source.install_storage_fault_directive(request.identity(), admission));
        ok(source.submit(request_icount, request));
        let opportunity = source
            .next_storage_execution_opportunity(now_nanos)
            .unwrap_or_else(|| panic!("execution opportunity should be available"));
        let mut execution = opportunity.admission.clone();
        execution.execution_nanos = opportunity.ready_nanos;
        execution.persistence_admitted_nanos = opportunity.ready_nanos;
        ok(
            source.install_storage_execution_directive(ResolvedBlockExecutionDirective {
                opportunity,
                directive: execution,
            }),
        );
        ok(source.advance_to(request_icount));
        source
            .next_storage_request_persistence_opportunity(now_nanos)
            .unwrap_or_else(|| panic!("persistence opportunity should be available"))
    }

    let mut source = device(PAGE_SIZE);
    let mut destination = device(PAGE_SIZE);
    ok(source.configure_storage_faults(cached_fault_config(PAGE_SIZE as u64), true));
    let mut destination_config = cached_fault_config(PAGE_SIZE as u64);
    destination_config.completion_durability = BlockCompletionDurability::Durable;
    destination_config.volatile_cache_bytes = 0;
    destination_config.cache_entries = 0;
    ok(destination.configure_storage_faults(destination_config, false));
    ok(destination.require_storage_persistence_media_opportunities());
    let request = BlockRequest::write(10, 0, vec![0x5a; 512]);
    let request_icount = 16;
    let now_nanos = request_icount << 8;
    let opportunity = stage_persistence(&mut source, &request, request_icount, now_nanos);
    let mut directive = opportunity.resolved.clone();
    directive.write_disposition = BlockFaultWriteDisposition::Misdirected {
        destination: BlockFaultMisdirectionDestination::ExternalDevice([7; 32]),
        destination_offset: 512,
    };
    ok(install_cross_device_misdirected_persistence(
        &mut source,
        &mut destination,
        ResolvedBlockRequestPersistenceDirective {
            opportunity,
            directive,
        },
        [7; 32],
    ));
    ok(source.advance_to(request_icount));
    let delivery = source
        .next_storage_delivery_opportunity(now_nanos)
        .unwrap_or_else(|| panic!("source delivery opportunity should be available"));
    let dependency = delivery
        .resolved
        .external_durability_dependencies
        .first()
        .copied()
        .unwrap_or_else(|| panic!("source completion carries destination dependency"));
    assert_eq!(dependency.destination_device, [7; 32]);
    assert_eq!(
        dependency.required_durability,
        BlockCompletionDurability::Durable
    );
    assert!(
        destination.storage_fault_state().actual_durable_frontier() < dependency.required_frontier,
        "destination must not acknowledge durability before media persistence"
    );
    let persistence = destination
        .next_storage_persistence_opportunity(now_nanos)
        .unwrap_or_else(|| panic!("destination persistence opportunity should be available"));
    ok(destination.install_storage_persistence_media_directive(
        ResolvedBlockPersistenceMediaDirective {
            opportunity: persistence,
            flash_rules: Vec::new(),
        },
    ));
    ok(destination.advance_to(request_icount));
    assert!(
        destination.storage_fault_state().actual_durable_frontier() >= dependency.required_frontier,
        "destination must acknowledge the exact required frontier"
    );
    ok(
        source.install_storage_delivery_directive(ResolvedBlockDeliveryDirective {
            directive: delivery.resolved.clone(),
            opportunity: delivery,
        }),
    );
    ok(source.advance_to(request_icount));
    assert_ne!(&source.materialize()[0..512], &[0x5a; 512]);
    assert_eq!(&destination.materialize()[512..1024], &[0x5a; 512]);
    let outcomes = ok(destination.drain_storage_outcomes());
    assert!(outcomes.iter().any(|outcome| matches!(
        outcome,
        BlockStorageOutcome::Persistence(persistence)
            if persistence.executed_nanos == now_nanos
    )));

    let mut failing_source = device(PAGE_SIZE);
    let mut failing_destination = device(PAGE_SIZE);
    ok(failing_source.configure_storage_faults(cached_fault_config(PAGE_SIZE as u64), true));
    let mut too_small = cached_fault_config(PAGE_SIZE as u64);
    too_small.volatile_cache_bytes = 256;
    ok(failing_destination.configure_storage_faults(too_small, false));
    let opportunity = stage_persistence(&mut failing_source, &request, request_icount, now_nanos);
    let before_source = failing_source.snapshot();
    let before_destination = failing_destination.snapshot();
    let mut directive = opportunity.resolved.clone();
    directive.write_disposition = BlockFaultWriteDisposition::Misdirected {
        destination: BlockFaultMisdirectionDestination::ExternalDevice([7; 32]),
        destination_offset: 512,
    };
    assert!(matches!(
        install_cross_device_misdirected_persistence(
            &mut failing_source,
            &mut failing_destination,
            ResolvedBlockRequestPersistenceDirective {
                opportunity,
                directive,
            },
            [7; 32],
        ),
        Err(crate::DeviceError::BlockCacheFull { .. })
    ));
    assert_eq!(failing_source.snapshot(), before_source);
    assert_eq!(failing_destination.snapshot(), before_destination);

    let mut stale_source = device(PAGE_SIZE);
    let mut untouched_destination = device(PAGE_SIZE);
    ok(stale_source.configure_storage_faults(cached_fault_config(PAGE_SIZE as u64), true));
    let mut destination_config = cached_fault_config(PAGE_SIZE as u64);
    destination_config.completion_durability = BlockCompletionDurability::Durable;
    destination_config.volatile_cache_bytes = 0;
    destination_config.cache_entries = 0;
    ok(untouched_destination.configure_storage_faults(destination_config, false));
    let mut opportunity = stage_persistence(&mut stale_source, &request, request_icount, now_nanos);
    let mut directive = opportunity.resolved.clone();
    opportunity.request_sequence = opportunity.request_sequence.saturating_add(1);
    let before_source = stale_source.snapshot();
    let before_destination = untouched_destination.snapshot();
    directive.write_disposition = BlockFaultWriteDisposition::Misdirected {
        destination: BlockFaultMisdirectionDestination::ExternalDevice([7; 32]),
        destination_offset: 512,
    };
    assert!(matches!(
        install_cross_device_misdirected_persistence(
            &mut stale_source,
            &mut untouched_destination,
            ResolvedBlockRequestPersistenceDirective {
                opportunity,
                directive,
            },
            [7; 32],
        ),
        Err(crate::DeviceError::InvalidBlockFaultDirective { .. })
    ));
    assert_eq!(stale_source.snapshot(), before_source);
    assert_eq!(untouched_destination.snapshot(), before_destination);
}
