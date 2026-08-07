//! The block device sub-node: base + CoW overlay, wire ABI, completion model.
//!
//! This module assembles the block I/O sub-node of RFC-0010 §15.2 from three
//! focused submodules and re-exports their public surface:
//!
//! - [`codec`]: the versioned, little-endian, bounds-checked block wire ABI
//!   ([`BlockRequest`] / [`BlockResponse`], [IO-8], [IO-9]).
//! - [`overlay`]: the read-only [`BaseImage`] and its in-memory 4 KiB
//!   copy-on-write [`CowOverlay`] with dirty-page tracking and materialize
//!   ([IO-5], [IO-6], [IO-7], [IO-12]).
//! - [`device`]: the [`BlockDevice`] [`IoSubNode`](crate::subnode::IoSubNode)
//!   implementation, its [`BlockLatency`] completion model, and its
//!   [`BlockSnapshot`] device-half `MaterializedState` ([IO-10], [IO-11],
//!   [IO-22], [IO-23]).
//!
//! The block device composes the uniform [`IoCore`](crate::subnode::IoCore) of
//! the CS-IO-1 foundation for the clock, rings, in-flight queue, and
//! COMPUTE-then-DELIVER lifecycle; this module supplies only the block-specific
//! COMPUTE (serve a request against the overlay/base) and state (overlay, RNG
//! placeholder, base image).

pub mod codec;
pub mod device;
pub mod fault;
pub mod flash;
pub mod media;
pub mod overlay;
pub mod persistence;
pub mod service;

pub use codec::{
    BLOCK_ABI_VERSION, BlockCodecError, BlockErrorCode, BlockOp, BlockRequest,
    BlockRequestIdentity, BlockResponse, BlockStatus, BlockTransportPending,
    BlockTransportRequestIds, BlockTransportReset, BlockTransportResolved,
    BlockTransportUnadmitted, BlockTransportUndelivered, REQUEST_HEADER_LEN, RESPONSE_HEADER_LEN,
};
pub use device::{
    BlockDevice, BlockLatency, BlockSnapshot, install_cross_device_misdirected_persistence,
};
pub use fault::*;
pub use flash::*;
pub use media::*;
pub use overlay::{BaseImage, CowOverlay, OverlayDelta, PAGE_SIZE};
pub use persistence::{
    BlockPersistenceGraph, BlockPersistenceNode, BlockPersistenceOrdering,
    BlockPersistenceReadyKey, BlockPersistenceTransformationEvidence, BlockWriteFragmentId,
    ResolvedBlockPersistenceTransform,
};
pub use service::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceError;
    use crate::subnode::IoCore;
    use crucible_shmem::{FrameEntry, KIND_VM, NodeSlot, RingHeader};

    /// Unwraps a result in tests, panicking with the error on failure.
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
    }

    /// Builds a base image of `len` bytes filled with a deterministic ramp.
    fn ramp_base(len: usize) -> BaseImage {
        let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        BaseImage::new(bytes)
    }

    /// Builds a block device over a ramp base with default latency.
    ///
    /// The source-node id is the reserved `SLOT_BLK_IO` slot index so the
    /// delivery keys match the shmem transport's tie-break order.
    fn device(base_len: usize) -> BlockDevice {
        device_with_latency(base_len, BlockLatency::default())
    }

    /// Builds a block device over a ramp base with an explicit latency model.
    fn device_with_latency(base_len: usize, latency: BlockLatency) -> BlockDevice {
        let src = crucible_shmem::SLOT_BLK_IO as u32;
        let core = ok(IoCore::new(8, src, 16, 16));
        BlockDevice::new(core, ramp_base(base_len), latency)
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
        ok(original.configure_storage_faults(
            BlockDurabilityConfig::write_through(PAGE_SIZE as u64),
            true,
        ));
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
        ok(device.configure_storage_faults(
            BlockDurabilityConfig::write_through(PAGE_SIZE as u64),
            true,
        ));
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
        ok(device.configure_storage_faults(
            BlockDurabilityConfig::write_through(PAGE_SIZE as u64),
            true,
        ));
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
        ok(device.configure_storage_faults(
            BlockDurabilityConfig::write_through(PAGE_SIZE as u64),
            true,
        ));
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
        ok(device.configure_storage_faults(
            BlockDurabilityConfig::write_through(PAGE_SIZE as u64),
            true,
        ));
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
        ) -> BlockRequestPersistenceOpportunity {
            ok(source.require_storage_execution_opportunities());
            let admission = ResolvedBlockFaultDirective::fault_free(request, PAGE_SIZE as u64);
            ok(source.install_storage_fault_directive(request.identity(), admission));
            ok(source.submit(0, request));
            let opportunity = source
                .next_storage_execution_opportunity(0)
                .unwrap_or_else(|| panic!("execution opportunity should be available"));
            ok(
                source.install_storage_execution_directive(ResolvedBlockExecutionDirective {
                    opportunity,
                    directive: ResolvedBlockFaultDirective::fault_free(request, PAGE_SIZE as u64),
                }),
            );
            ok(source.advance_to(0));
            source
                .next_storage_request_persistence_opportunity(0)
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
        let request = BlockRequest::write(10, 0, vec![0x5a; 512]);
        let opportunity = stage_persistence(&mut source, &request);
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
        ok(source.advance_to(0));
        assert_ne!(&source.materialize()[0..512], &[0x5a; 512]);
        assert_eq!(&destination.materialize()[512..1024], &[0x5a; 512]);

        let mut failing_source = device(PAGE_SIZE);
        let mut failing_destination = device(PAGE_SIZE);
        ok(failing_source.configure_storage_faults(cached_fault_config(PAGE_SIZE as u64), true));
        let mut too_small = cached_fault_config(PAGE_SIZE as u64);
        too_small.volatile_cache_bytes = 256;
        ok(failing_destination.configure_storage_faults(too_small, false));
        let opportunity = stage_persistence(&mut failing_source, &request);
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
        let mut opportunity = stage_persistence(&mut stale_source, &request);
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

    #[test]
    fn read_falls_through_to_base_when_overlay_empty() {
        let base = ramp_base(PAGE_SIZE * 3);
        let overlay = CowOverlay::new();
        let got = ok(overlay.read(&base, 100, 50));
        assert_eq!(got, &base.bytes()[100..150]);
        assert_eq!(overlay.page_count(), 0, "a read must not copy up");
    }

    #[test]
    fn write_copies_up_and_read_sees_overlay_over_base() {
        let base = ramp_base(PAGE_SIZE * 3);
        let mut overlay = CowOverlay::new();
        ok(overlay.write(&base, 4090, &[0xAB; 12]));
        // Spans the boundary between page 0 and page 1, so two pages copy up.
        assert_eq!(overlay.page_count(), 2);
        let got = ok(overlay.read(&base, 4088, 16));
        let mut want = base.bytes()[4088..4104].to_vec();
        want[2..14].fill(0xAB);
        assert_eq!(got, want);
    }

    #[test]
    fn base_bytes_never_change_under_writes() {
        let base = ramp_base(PAGE_SIZE * 2);
        let original = base.bytes().to_vec();
        let original_hash = base.hash();
        let mut overlay = CowOverlay::new();
        ok(overlay.write(&base, 0, &[0xFF; PAGE_SIZE]));
        ok(overlay.write(&base, PAGE_SIZE as u64, &[0x01; 10]));
        assert_eq!(base.bytes(), &original[..], "base bytes mutated");
        assert_eq!(base.hash(), original_hash, "base identity changed");
    }

    #[test]
    fn out_of_range_read_and_write_error_not_truncate() {
        let base = ramp_base(PAGE_SIZE);
        let mut overlay = CowOverlay::new();
        assert!(overlay.read(&base, PAGE_SIZE as u64, 1).is_err());
        assert!(overlay.read(&base, PAGE_SIZE as u64 - 1, 2).is_err());
        assert!(overlay.write(&base, PAGE_SIZE as u64 - 1, &[0; 2]).is_err());
        // Exactly at the end with zero length is in range.
        assert!(overlay.read(&base, PAGE_SIZE as u64, 0).is_ok());
    }

    // ---- dirty tracking (IO-7) ----

    #[test]
    fn dirty_set_tracks_written_pages_and_clears_at_boundary() {
        let base = ramp_base(PAGE_SIZE * 4);
        let mut overlay = CowOverlay::new();
        ok(overlay.write(&base, 0, &[1; 10]));
        ok(overlay.write(&base, (PAGE_SIZE * 2) as u64, &[2; 10]));
        let dirty: Vec<u64> = overlay.dirty_pages().iter().copied().collect();
        assert_eq!(dirty, vec![0, (PAGE_SIZE * 2) as u64]);
        assert_eq!(overlay.dirty_delta().pages.len(), 2);

        overlay.clear_dirty();
        assert!(overlay.dirty_pages().is_empty());
        // Pages still present; only dirty bookkeeping reset.
        assert_eq!(overlay.page_count(), 2);

        // Subsequent write produces a disjoint delta.
        ok(overlay.write(&base, (PAGE_SIZE * 3) as u64, &[3; 10]));
        let delta: Vec<u64> = overlay.dirty_delta().pages.keys().copied().collect();
        assert_eq!(delta, vec![(PAGE_SIZE * 3) as u64]);
    }

    // ---- materialize (IO-12) ----

    #[test]
    fn materialize_applies_overlay_over_base_without_mutating_base() {
        let base = ramp_base(PAGE_SIZE * 2 + 100);
        let original = base.bytes().to_vec();
        let mut overlay = CowOverlay::new();
        ok(overlay.write(&base, 5, &[0x55; 20]));
        let image = overlay.materialize(&base);
        assert_eq!(image.len(), base.len() as usize);
        let mut want = original.clone();
        want[5..25].fill(0x55);
        assert_eq!(image, want);
        assert_eq!(base.bytes(), &original[..], "materialize mutated base");
    }

    // ---- wire ABI round-trip + fuzz (IO-8) ----

    #[test]
    fn request_round_trips_for_every_op() {
        let cases = [
            BlockRequest::read(7, 4096, 512),
            BlockRequest::write(8, 100, vec![0xDE; 64]),
            BlockRequest::flush(9),
            BlockRequest::get_length(10),
            BlockRequest::discard(11, 4096, 512),
        ];
        for req in cases {
            let decoded = ok(BlockRequest::decode(&ok(req.encode())));
            assert_eq!(decoded, req);
        }
    }

    #[test]
    fn response_round_trips() {
        let resp = BlockResponse::ok(11, vec![1, 2, 3, 4]);
        assert_eq!(ok(BlockResponse::decode(&ok(resp.encode()))), resp);
        let err = BlockResponse::error(12, BlockErrorCode::NoSpace);
        assert_eq!(ok(BlockResponse::decode(&ok(err.encode()))), err);
    }

    #[test]
    fn every_typed_error_round_trips() {
        let errors = [
            BlockErrorCode::Offline,
            BlockErrorCode::ReadOnly,
            BlockErrorCode::InvalidRange,
            BlockErrorCode::Busy,
            BlockErrorCode::Timeout,
            BlockErrorCode::MediumError,
            BlockErrorCode::IntegrityError,
            BlockErrorCode::IoError,
            BlockErrorCode::NoSpace,
            BlockErrorCode::NotFound,
            BlockErrorCode::Stale,
        ];
        for error in errors {
            let response = BlockResponse::error(12, error);
            let decoded = ok(BlockResponse::decode(&ok(response.encode())));
            assert_eq!(ok(decoded.error_code()), error);
        }
    }

    #[test]
    fn decode_rejects_malformed_typed_error_payloads() {
        for data in [Vec::new(), vec![0], vec![1, 2]] {
            let response = BlockResponse {
                status: BlockStatus::Error,
                epoch: 0,
                request_id: 12,
                data,
            };
            assert!(BlockResponse::decode(&ok(response.encode())).is_err());
        }
    }

    #[test]
    fn decode_rejects_bad_version_and_unknown_op() {
        let mut wire = ok(BlockRequest::read(1, 0, 0).encode());
        wire[1] = 99; // corrupt version byte
        assert!(matches!(
            BlockRequest::decode(&wire),
            Err(BlockCodecError::VersionMismatch { .. })
        ));

        let mut wire = ok(BlockRequest::read(1, 0, 0).encode());
        wire[0] = 200; // unknown op
        assert!(matches!(
            BlockRequest::decode(&wire),
            Err(BlockCodecError::UnknownOp { .. })
        ));
    }

    #[test]
    fn decode_rejects_nonzero_reserved_request_and_response_headers() {
        let mut request = ok(BlockRequest::read(1, 0, 0).encode());
        request[2..4].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            BlockRequest::decode(&request),
            Err(BlockCodecError::NonZeroReserved { reserved: 1 })
        );

        let mut response = ok(BlockResponse::ok(1, Vec::new()).encode());
        response[2..4].copy_from_slice(&0x0201_u16.to_le_bytes());
        assert_eq!(
            BlockResponse::decode(&response),
            Err(BlockCodecError::NonZeroReserved { reserved: 0x0201 })
        );
    }

    #[test]
    fn decode_rejects_write_count_exceeding_payload() {
        // Encode a valid write, then corrupt the on-wire count field (LE u32 at
        // offset 24) to exceed the payload, simulating a hostile frame.
        let mut wire = ok(BlockRequest::write(1, 0, vec![0xAA; 8]).encode());
        wire[24..28].copy_from_slice(&9999u32.to_le_bytes());
        assert!(matches!(
            BlockRequest::decode(&wire),
            Err(BlockCodecError::CountExceedsPayload { .. })
        ));
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        // A deterministic LCG fuzz: feed varied byte strings of varied length and
        // assert decode always returns (Ok or Err), never panics or OOB-reads.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..20_000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 56) as usize % 40;
            let mut bytes = Vec::with_capacity(len);
            let mut s = state;
            for _ in 0..len {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                bytes.push((s >> 33) as u8);
            }
            // Neither call may panic; the result is ignored.
            let _ = BlockRequest::decode(&bytes);
            let _ = BlockResponse::decode(&bytes);
        }
    }

    // ---- end-to-end device serve (IO-5,6 over the lifecycle) ----

    #[test]
    fn device_read_then_write_then_read_through_lifecycle() {
        let mut dev = device(PAGE_SIZE * 2);
        let want0 = ok(dev.overlay().read(&ramp_base(PAGE_SIZE * 2), 0, 8));

        // Read at icount 0.
        ok(dev.submit(0, &BlockRequest::read(1, 0, 8)));
        let next = dev.core().next_exact_local_event();
        assert!(next.is_some());
        let limit = next.unwrap_or(0);
        assert_eq!(ok(dev.advance_to(limit)), 1);
        let r = ok(dev.next_response()).unwrap_or_else(|| panic!("expected response"));
        assert_eq!(r.status, BlockStatus::Ok);
        assert_eq!(r.data, want0);

        // Write, then a later read sees the overlay.
        ok(dev.submit(limit, &BlockRequest::write(2, 0, vec![0x77; 8])));
        let lim2 = dev.core().next_exact_local_event().unwrap_or(limit);
        ok(dev.advance_to(lim2));
        let _ = ok(dev.next_response());

        ok(dev.submit(lim2, &BlockRequest::read(3, 0, 8)));
        let lim3 = dev.core().next_exact_local_event().unwrap_or(lim2);
        ok(dev.advance_to(lim3));
        let r = ok(dev.next_response()).unwrap_or_else(|| panic!("expected response"));
        assert_eq!(r.data, vec![0x77; 8]);
    }

    #[test]
    fn delivered_transport_reset_rewrites_later_completion_without_aliasing_identity() {
        let latency = BlockLatency::new(100, 100, 0, 0, 0);
        let mut dev = device_with_latency(PAGE_SIZE, latency);
        let trigger = BlockRequest::get_length(41).with_identity(BlockRequestIdentity::new(7, 41));
        let victim = BlockRequest::read(42, 0, 8).with_identity(BlockRequestIdentity::new(7, 42));
        let transition = ResolvedBlockControllerTransition {
            failure_result: BlockFaultResult::IoError,
            unadmitted: BlockTransitionUnadmitted::WaitForRecovery,
            queued: BlockTransitionPending::Fail,
            executing: BlockTransitionPending::RetryPreserveId,
            resolved: BlockTransitionResolved::Complete,
            completed_undelivered: BlockTransitionUndelivered::RetryNewId,
            controller_buffer: BlockTransitionState::Preserve,
            volatile_cache: BlockTransitionState::Preserve,
            request_ids: BlockTransportRequestIds::NewEpochFromZero,
            duplicate_history: BlockTransitionState::Lose,
            topology: BlockTransitionTopology::Preserve,
            recovery_nanos: 25,
        };
        let mut directive = ResolvedBlockFaultDirective::fault_free(&trigger, PAGE_SIZE as u64);
        directive.duplicate_completions = vec![ResolvedBlockDuplicateCompletion::Reset {
            gap_nanos: 10,
            transition,
        }];
        ok(dev.install_storage_fault_directive(trigger.identity(), directive));

        ok(dev.submit(0, &trigger));
        ok(dev.submit(0, &victim));
        assert_eq!(ok(dev.advance_to(100)), 3);

        let primary = ok(dev.next_response()).unwrap_or_else(|| panic!("trigger primary"));
        let reset = ok(dev.next_response()).unwrap_or_else(|| panic!("reset event"));
        let retried = ok(dev.next_response()).unwrap_or_else(|| panic!("victim disposition"));
        assert_eq!(primary.identity(), trigger.identity());
        assert_eq!(reset.status, BlockStatus::TransportReset);
        assert_eq!(reset.identity(), trigger.identity());
        assert_eq!(retried.status, BlockStatus::RetryNewId);
        assert_eq!(retried.identity(), victim.identity());
    }

    #[test]
    fn transport_reset_commits_only_after_bounded_shmem_delivery() {
        let latency = BlockLatency::new(100, 100, 0, 0, 0);
        let mut dev = device_with_latency(PAGE_SIZE, latency);
        let trigger = BlockRequest::get_length(41).with_identity(BlockRequestIdentity::new(7, 41));
        let transition = ResolvedBlockControllerTransition {
            failure_result: BlockFaultResult::IoError,
            unadmitted: BlockTransitionUnadmitted::WaitForRecovery,
            queued: BlockTransitionPending::Fail,
            executing: BlockTransitionPending::RetryPreserveId,
            resolved: BlockTransitionResolved::Complete,
            completed_undelivered: BlockTransitionUndelivered::RetryNewId,
            controller_buffer: BlockTransitionState::Preserve,
            volatile_cache: BlockTransitionState::Preserve,
            request_ids: BlockTransportRequestIds::NewEpochFromZero,
            duplicate_history: BlockTransitionState::Lose,
            topology: BlockTransitionTopology::Preserve,
            recovery_nanos: 25,
        };
        let mut directive = ResolvedBlockFaultDirective::fault_free(&trigger, PAGE_SIZE as u64);
        directive.duplicate_completions = vec![ResolvedBlockDuplicateCompletion::Reset {
            gap_nanos: 10,
            transition,
        }];
        ok(dev.install_storage_fault_directive(trigger.identity(), directive));
        ok(dev.submit(0, &trigger));

        let outbox = RingHeader::new();
        let mut entries = vec![FrameEntry::default(); 1];
        let consumer = NodeSlot::new(KIND_VM);
        assert_eq!(
            ok(dev.advance_to_shmem(100, &outbox, &mut entries, &consumer)).delivered,
            1
        );
        assert_eq!(dev.storage_fault_state().transport_epoch(), Some(7));
        assert_eq!(dev.storage_fault_state().recovery_until_nanos(), None);

        let primary = ok(outbox.dequeue(&entries)).unwrap_or_else(|| panic!("primary response"));
        assert_eq!(
            ok(BlockResponse::decode(ok(primary.payload()))).status,
            BlockStatus::Ok
        );
        assert_eq!(
            ok(dev.advance_to_shmem(100, &outbox, &mut entries, &consumer)).delivered,
            1
        );
        assert_eq!(dev.storage_fault_state().transport_epoch(), Some(8));
        assert_eq!(
            dev.storage_fault_state().recovery_until_nanos(),
            Some((100_u64 << 8) + 25)
        );
        let reset = ok(outbox.dequeue(&entries)).unwrap_or_else(|| panic!("reset response"));
        assert_eq!(
            ok(BlockResponse::decode(ok(reset.payload()))).status,
            BlockStatus::TransportReset
        );
    }

    #[test]
    fn queued_old_epoch_frames_receive_every_reset_disposition_after_backpressure() {
        let cases = [
            (BlockTransitionPending::Fail, BlockStatus::Error),
            (BlockTransitionPending::RetryNewId, BlockStatus::RetryNewId),
            (
                BlockTransitionPending::RetryPreserveId,
                BlockStatus::RetryPreserveId,
            ),
        ];

        for (queued, expected_status) in cases {
            let latency = BlockLatency::new(100, 100, 0, 0, 0);
            let mut dev = device_with_latency(PAGE_SIZE, latency);
            let trigger =
                BlockRequest::get_length(41).with_identity(BlockRequestIdentity::new(7, 41));
            let victim =
                BlockRequest::read(42, 0, 8).with_identity(BlockRequestIdentity::new(7, 42));
            let transition = ResolvedBlockControllerTransition {
                failure_result: BlockFaultResult::IoError,
                unadmitted: BlockTransitionUnadmitted::WaitForRecovery,
                queued,
                executing: BlockTransitionPending::Fail,
                resolved: BlockTransitionResolved::Complete,
                completed_undelivered: BlockTransitionUndelivered::Complete,
                controller_buffer: BlockTransitionState::Preserve,
                volatile_cache: BlockTransitionState::Preserve,
                request_ids: BlockTransportRequestIds::NewEpochFromZero,
                duplicate_history: BlockTransitionState::Preserve,
                topology: BlockTransitionTopology::Preserve,
                recovery_nanos: 25,
            };
            let mut directive = ResolvedBlockFaultDirective::fault_free(&trigger, PAGE_SIZE as u64);
            directive.duplicate_completions = vec![ResolvedBlockDuplicateCompletion::Reset {
                gap_nanos: 10,
                transition,
            }];
            ok(dev.install_storage_fault_directive(trigger.identity(), directive));
            ok(dev.submit(0, &trigger));

            let inbox = RingHeader::new();
            let mut inbox_entries = vec![FrameEntry::default(); 2];
            let victim_frame = ok(FrameEntry::new(
                0,
                0,
                victim.request_id,
                &ok(victim.encode()),
            ));
            ok(inbox.enqueue(&mut inbox_entries, &victim_frame));
            let producer = NodeSlot::new(KIND_VM);
            let outbox = RingHeader::new();
            let mut outbox_entries = vec![FrameEntry::default(); 1];
            let consumer = NodeSlot::new(KIND_VM);

            assert_eq!(
                ok(dev.advance_to_shmem(100, &outbox, &mut outbox_entries, &consumer)).delivered,
                1
            );
            assert_eq!(dev.storage_fault_state().transport_epoch(), Some(7));
            assert_eq!(ok(inbox.live_len(&inbox_entries)), 1);
            let primary = ok(outbox.dequeue(&outbox_entries))
                .unwrap_or_else(|| panic!("trigger primary response"));
            assert_eq!(
                ok(BlockResponse::decode(ok(primary.payload()))).status,
                BlockStatus::Ok
            );

            assert_eq!(
                ok(dev.advance_to_shmem(100, &outbox, &mut outbox_entries, &consumer)).delivered,
                1
            );
            assert_eq!(dev.storage_fault_state().transport_epoch(), Some(8));
            assert_eq!(ok(inbox.live_len(&inbox_entries)), 1);
            let reset = ok(outbox.dequeue(&outbox_entries))
                .unwrap_or_else(|| panic!("transport reset response"));
            assert_eq!(
                ok(BlockResponse::decode(ok(reset.payload()))).status,
                BlockStatus::TransportReset
            );

            let victim_directive =
                ResolvedBlockFaultDirective::fault_free(&victim, PAGE_SIZE as u64);
            ok(dev.install_storage_fault_directive(victim.identity(), victim_directive));
            assert_eq!(
                ok(dev.process_one_shmem_request(&inbox, &inbox_entries, &producer)).processed,
                1
            );
            assert_eq!(
                ok(dev.advance_to_shmem(100, &outbox, &mut outbox_entries, &consumer)).delivered,
                1
            );
            let disposition = ok(outbox.dequeue(&outbox_entries))
                .unwrap_or_else(|| panic!("queued request disposition"));
            let disposition = ok(BlockResponse::decode(ok(disposition.payload())));
            assert_eq!(disposition.identity(), victim.identity());
            assert_eq!(disposition.status, expected_status);

            if queued == BlockTransitionPending::RetryPreserveId {
                let retry_frame = ok(FrameEntry::new(
                    101,
                    0,
                    victim.request_id,
                    &ok(victim.encode()),
                ));
                ok(inbox.enqueue(&mut inbox_entries, &retry_frame));
                let retry_directive =
                    ResolvedBlockFaultDirective::fault_free(&victim, PAGE_SIZE as u64);
                ok(dev.install_storage_fault_directive(victim.identity(), retry_directive));
                assert_eq!(
                    ok(dev.process_one_shmem_request(&inbox, &inbox_entries, &producer)).processed,
                    1
                );
                assert_eq!(
                    ok(dev.advance_to_shmem(102, &outbox, &mut outbox_entries, &consumer))
                        .delivered,
                    1
                );
                let completion = ok(outbox.dequeue(&outbox_entries))
                    .unwrap_or_else(|| panic!("preserved retry completion"));
                let completion = ok(BlockResponse::decode(ok(completion.payload())));
                assert_eq!(completion.identity(), victim.identity());
                assert_eq!(completion.status, BlockStatus::Ok);
            }
        }
    }

    #[test]
    fn device_get_length_returns_base_size() {
        let mut dev = device(12345);
        ok(dev.submit(0, &BlockRequest::get_length(1)));
        let lim = dev.core().next_exact_local_event().unwrap_or(0);
        ok(dev.advance_to(lim));
        let r = ok(dev.next_response()).unwrap_or_else(|| panic!("expected response"));
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&r.data[..8]);
        assert_eq!(u64::from_le_bytes(bytes), 12345);
    }

    #[test]
    fn device_out_of_range_read_returns_error_status() {
        let mut dev = device(PAGE_SIZE);
        ok(dev.submit(0, &BlockRequest::read(1, PAGE_SIZE as u64, 1)));
        let lim = dev.core().next_exact_local_event().unwrap_or(0);
        ok(dev.advance_to(lim));
        let r = ok(dev.next_response()).unwrap_or_else(|| panic!("expected response"));
        assert_eq!(r.status, BlockStatus::Error);
    }

    // ---- completion model: host-timing independence (IO-10,22) ----

    #[test]
    fn latency_depends_only_on_op_and_count() {
        let lat = BlockLatency::new(1000, 1500, 500, 100, 2);
        assert_eq!(lat.latency_for(BlockOp::Read, 0), 1000);
        assert_eq!(lat.latency_for(BlockOp::Read, 10), 1020);
        assert_eq!(lat.latency_for(BlockOp::Write, 10), 1520);
        assert_eq!(lat.latency_for(BlockOp::Flush, 999), 500);
        assert_eq!(lat.latency_for(BlockOp::GetLength, 999), 100);
        // Ordinary large count stays exact (no overflow at these magnitudes).
        assert_eq!(
            lat.latency_for(BlockOp::Read, u32::MAX),
            1000 + 2 * u64::from(u32::MAX)
        );
        // Saturating: a hostile per-byte parameter cannot overflow.
        let huge = BlockLatency::new(1000, 1500, 500, 100, u64::MAX);
        assert_eq!(huge.latency_for(BlockOp::Read, u32::MAX), u64::MAX);
    }

    /// Drives a fixed request sequence and returns the (delivery_icount, payload)
    /// of every response. `skew` is artificial host work that must NOT affect the
    /// result ([IO-22]).
    fn run_sequence(skew: usize) -> Vec<(u64, Vec<u8>)> {
        let mut dev = device(PAGE_SIZE * 4);
        let reqs = [
            BlockRequest::read(1, 0, 16),
            BlockRequest::write(2, 100, vec![0x33; 32]),
            BlockRequest::read(3, 100, 32),
            BlockRequest::flush(4),
            BlockRequest::get_length(5),
        ];
        let mut out = Vec::new();
        let mut t = 0u64;
        for req in &reqs {
            // Artificial COMPUTE-time host skew: pure busy work, no clock read.
            let mut sink = 0u64;
            for i in 0..skew {
                sink = sink.wrapping_add(i as u64);
            }
            std::hint::black_box(sink);

            ok(dev.submit(t, req));
            let lim = dev.core().next_exact_local_event().unwrap_or(t);
            ok(dev.advance_to(lim));
            while let Some(pending) = dev.core_mut().pop_response() {
                out.push((pending.delivery_icount(), pending.response.payload));
            }
            t = lim;
        }
        out
    }

    #[test]
    fn completion_is_host_timing_independent() {
        let a = run_sequence(0);
        let b = run_sequence(500_000);
        assert_eq!(a, b, "host COMPUTE skew leaked into delivery/payload");
    }

    // ---- coincident completion ordering (IO-10) ----

    #[test]
    fn coincident_completions_deliver_in_total_order() {
        // Two reads submitted at the same icount with identical latency land on
        // the same delivery_icount; they must deliver in (icount, src, seq) order.
        let mut dev = device(PAGE_SIZE);
        ok(dev.submit(0, &BlockRequest::read(10, 0, 8)));
        ok(dev.submit(0, &BlockRequest::read(11, 8, 8)));
        let lim = dev.core().next_exact_local_event().unwrap_or(0);
        ok(dev.advance_to(lim));
        let first = ok(dev.next_response()).unwrap_or_else(|| panic!("resp"));
        let second = ok(dev.next_response()).unwrap_or_else(|| panic!("resp"));
        // seq increases with submit order, so request_id 10 delivers before 11.
        assert_eq!(first.request_id, 10);
        assert_eq!(second.request_id, 11);
    }

    // ---- snapshot / restore round-trip (IO-11,23) ----

    #[test]
    fn snapshot_excludes_base_and_restore_round_trips() {
        let mut dev = device(PAGE_SIZE * 3);
        ok(dev.submit(0, &BlockRequest::write(1, 50, vec![0x42; 20])));
        let lim = dev.core().next_exact_local_event().unwrap_or(0);
        ok(dev.advance_to(lim));
        let _ = ok(dev.next_response());

        let snap = dev.snapshot();
        assert_eq!(snap.delta_page_count(), 1);
        assert_eq!(snap.base_hash, dev.base_hash());

        // Restore from the self-contained snapshot (no parent chain).
        let base = ramp_base(PAGE_SIZE * 3);
        let restored = ok(BlockDevice::restore(&snap, base, None));
        // Identical subsequent behavior: read the written range back.
        let got = ok(restored.overlay().read(restored.base(), 50, 20));
        assert_eq!(got, vec![0x42; 20]);
        assert_eq!(restored.rng_position(), dev.rng_position());
    }

    #[test]
    fn snapshot_mutate_restore_yields_identical_behavior() {
        let base_len = PAGE_SIZE * 3;
        let mut dev = device(base_len);
        ok(dev.submit(0, &BlockRequest::write(1, 50, vec![0x42; 20])));
        let lim = dev.core().next_exact_local_event().unwrap_or(0);
        ok(dev.advance_to(lim));
        let _ = ok(dev.next_response());

        let snap = dev.snapshot();
        let baseline_image = dev.materialize();

        // Mutate after snapshot.
        ok(dev.submit(lim, &BlockRequest::write(2, 50, vec![0x99; 20])));
        let lim2 = dev.core().next_exact_local_event().unwrap_or(lim);
        ok(dev.advance_to(lim2));
        let _ = ok(dev.next_response());
        assert_ne!(
            dev.materialize(),
            baseline_image,
            "mutation must take effect"
        );

        // Restore: behavior returns to the snapshot point.
        let restored = ok(BlockDevice::restore(&snap, ramp_base(base_len), None));
        assert_eq!(restored.materialize(), baseline_image);
    }

    #[test]
    fn restore_rejects_mismatched_base() {
        let mut dev = device(PAGE_SIZE);
        ok(dev.submit(0, &BlockRequest::write(1, 0, vec![1; 4])));
        let lim = dev.core().next_exact_local_event().unwrap_or(0);
        ok(dev.advance_to(lim));
        let _ = ok(dev.next_response());
        let snap = dev.snapshot();
        // A different base has a different hash.
        let wrong = BaseImage::new(vec![0xFF; PAGE_SIZE]);
        assert!(matches!(
            BlockDevice::restore(&snap, wrong, None),
            Err(crate::error::DeviceError::BaseMismatch { .. })
        ));
    }

    #[test]
    fn snapshot_restore_preserves_inflight_responses() {
        let mut dev = device(PAGE_SIZE);
        // Submit but do not advance: the response stays in flight.
        ok(dev.submit(0, &BlockRequest::read(1, 0, 16)));
        assert_eq!(dev.core().inflight_len(), 1);
        let snap = dev.snapshot();
        assert_eq!(snap.inflight().len(), 1);

        let restored = ok(BlockDevice::restore(&snap, ramp_base(PAGE_SIZE), None));
        assert_eq!(restored.core().inflight_len(), 1);
        assert_eq!(
            restored.core().next_exact_local_event(),
            dev.core().next_exact_local_event()
        );
    }

    // ---- run-twice determinism (IO-22) ----

    #[test]
    fn run_twice_is_byte_identical() {
        let first = run_sequence(0);
        let second = run_sequence(0);
        assert_eq!(first, second);
    }

    #[test]
    fn delta_pages_are_blake3_keyed() {
        let base = ramp_base(PAGE_SIZE * 2);
        let mut overlay = CowOverlay::new();
        ok(overlay.write(&base, 0, &[0xAB; 16]));
        let delta = overlay.dirty_delta();
        let hashes = delta.page_hashes();
        assert_eq!(hashes.len(), 1);
        // Hash is content-derived: same page bytes => same hash.
        let again = delta.page_hashes();
        assert_eq!(hashes, again);
    }

    // ---- regression: MAJOR #1 — snapshot/restore preserves dirty set ----

    #[test]
    fn regression_restore_preserves_mid_epoch_dirty_set() {
        // Write a page WITHOUT crossing a checkpoint boundary: it stays dirty,
        // so a mid-epoch snapshot must capture and a restore must reinstate the
        // dirty bookkeeping ([IO-7], [IO-11]). Before the fix, restore reset the
        // dirty set empty and the next snapshot's delta was incomplete.
        let mut dev = device(PAGE_SIZE * 2);
        ok(dev.submit(0, &BlockRequest::write(1, 0, vec![0xCD; 16])));
        let lim = dev.core().next_exact_local_event().unwrap_or(0);
        ok(dev.advance_to(lim));
        let _ = ok(dev.next_response());

        let snap = dev.snapshot();
        assert_eq!(snap.delta_page_count(), 1, "page dirtied since boundary");

        // Restore (self-contained), then snapshot again: the delta must STILL be
        // 1 — the dirty page survived the round-trip.
        let restored = ok(BlockDevice::restore(&snap, ramp_base(PAGE_SIZE * 2), None));
        let resnap = restored.snapshot();
        assert_eq!(
            resnap.delta_page_count(),
            1,
            "restore must preserve the mid-epoch dirty set"
        );
        assert_eq!(resnap.dirty, snap.dirty);

        // And the parent-chain restore path preserves it too.
        let parent = CowOverlay::new();
        let restored_p = ok(BlockDevice::restore(
            &snap,
            ramp_base(PAGE_SIZE * 2),
            Some(&parent),
        ));
        assert_eq!(restored_p.snapshot().delta_page_count(), 1);
    }

    // ---- regression: MAJOR #2 — restore preserves the latency model ----

    #[test]
    fn regression_restore_preserves_latency_so_delivery_icount_matches() {
        // A device with a non-default latency base must, after plain restore,
        // schedule the next completion at the SAME delivery_icount as the
        // original. Before the fix, restore substituted BlockLatency::default(),
        // changing every post-restore completion icount.
        let latency = BlockLatency::new(9000, 9000, 9000, 9000, 0);
        let mut dev = device_with_latency(PAGE_SIZE, latency);
        // Take a clean snapshot before any request.
        let snap = dev.snapshot();

        // Original: submit a read, observe the next exact local event.
        ok(dev.submit(0, &BlockRequest::read(1, 0, 16)));
        let original_event = dev.core().next_exact_local_event();

        // Restored: same request, must yield the same delivery_icount.
        let mut restored = ok(BlockDevice::restore(&snap, ramp_base(PAGE_SIZE), None));
        ok(restored.submit(0, &BlockRequest::read(1, 0, 16)));
        let restored_event = restored.core().next_exact_local_event();

        assert_eq!(
            original_event, restored_event,
            "restore must not change the completion model"
        );
        // Sanity: with base 9000 at shift 8 the event is ceil(9000/256) = 36, not
        // the default model's value.
        assert_eq!(restored_event, Some(36));
    }

    // ---- regression: MAJOR #3 — oversized read rejected, not un-transportable ----

    #[test]
    fn regression_read_over_frame_cap_returns_error_status() {
        use crate::block::device::MAX_READ_BYTES;
        // A base large enough to satisfy the in-range check at the cap.
        let big = MAX_READ_BYTES + PAGE_SIZE;
        let mut dev = device(big);

        // Exactly at the cap: served OK (payload + header fits one frame).
        ok(dev.submit(0, &BlockRequest::read(1, 0, MAX_READ_BYTES as u32)));
        let lim = dev.core().next_exact_local_event().unwrap_or(0);
        ok(dev.advance_to(lim));
        let r = ok(dev.next_response()).unwrap_or_else(|| panic!("resp"));
        assert_eq!(r.status, BlockStatus::Ok);
        assert_eq!(r.data.len(), MAX_READ_BYTES);
        // The encoded response fits one frame.
        assert!(ok(r.encode()).len() <= crucible_shmem::MAX_FRAME_DATA);

        // One byte over the cap: rejected with an error status, never emitting an
        // un-transportable frame ([IO-8]).
        ok(dev.submit(lim, &BlockRequest::read(2, 0, MAX_READ_BYTES as u32 + 1)));
        let lim2 = dev.core().next_exact_local_event().unwrap_or(lim);
        ok(dev.advance_to(lim2));
        let r2 = ok(dev.next_response()).unwrap_or_else(|| panic!("resp"));
        assert_eq!(r2.status, BlockStatus::Error);
    }

    // ---- uniform I/O fault injection on block (IO-25, IO-26, T-IO-12) ----

    use crate::fault::{IoFaultOutcome, IoFaults, Probability};
    use crate::request::ResponseStatus;

    /// A fixed engine decision-RNG root + device stream id for the block tests
    /// (a stand-in for the engine's name-hash fork of the scenario seed).
    const BLOCK_ROOT: u64 = 0x10c0_5eed_b10c;
    const BLOCK_DOMAIN: &str = "crucible.test.device-stream";
    const BLOCK_NAME: &str = "disk";

    /// Forks the block device's RNG at its captured cursor.
    fn block_rng(dev: &BlockDevice) -> crate::fault::DeviceRng {
        dev.rng(BLOCK_ROOT, BLOCK_DOMAIN, BLOCK_NAME)
    }

    /// Resolves a modeled read completion through the device's active fault table.
    fn resolve_read(
        dev: &mut BlockDevice,
        primary_icount: u64,
        payload: Vec<u8>,
    ) -> IoFaultOutcome {
        let mut rng = block_rng(dev);
        dev.resolve_response(primary_icount, ResponseStatus::Ok, payload, &mut rng)
    }

    #[test]
    fn block_latency_fault_shifts_delivery_icount_later() {
        let mut dev = device(PAGE_SIZE);
        dev.set_faults(IoFaults {
            added_latency_ns: 4096, // 16 icounts at shift 8
            ..IoFaults::none()
        });
        let outcome = resolve_read(&mut dev, 100, vec![0; 4]);
        assert_eq!(outcome.primary.delivery_icount, 116);
        assert!(dev.rng_position() > 0, "fault resolution consumed draws");
    }

    #[test]
    fn block_bandwidth_fault_adds_transfer_delay_proportional_to_count() {
        let mut dev = device(PAGE_SIZE);
        dev.set_faults(IoFaults {
            bandwidth_bytes_per_sec: 1_000_000_000, // 1 ns/byte
            ..IoFaults::none()
        });
        // 256 bytes -> 256 ns -> ceil(256/256) = 1 icount at shift 8.
        let outcome = resolve_read(&mut dev, 0, vec![0; 256]);
        assert_eq!(outcome.primary.delivery_icount, 1);
    }

    #[test]
    fn block_jitter_fault_shifts_within_window() {
        let mut dev = device(PAGE_SIZE);
        dev.set_faults(IoFaults {
            jitter_window_ns: 4096,
            ..IoFaults::none()
        });
        let outcome = resolve_read(&mut dev, 0, vec![0; 4]);
        // Jitter never moves a block completion earlier; bounded by ceil(window).
        assert!(outcome.primary.delivery_icount <= 16);
    }

    #[test]
    fn block_reorder_fault_can_shift_one_completion_past_another() {
        let mut dev = device(PAGE_SIZE);
        dev.set_faults(IoFaults {
            reorder_window_ns: 65_536,
            ..IoFaults::none()
        });
        // Two completions modeled at the same primary icount can land at distinct
        // delivery icounts once reorder shifts them by independent draws.
        let mut rng = block_rng(&dev);
        let a = dev.resolve_response(10, ResponseStatus::Ok, vec![0; 4], &mut rng);
        let b = dev.resolve_response(10, ResponseStatus::Ok, vec![0; 4], &mut rng);
        assert_ne!(
            a.primary.delivery_icount, b.primary.delivery_icount,
            "independent reorder draws move one completion past the other"
        );
    }

    #[test]
    fn block_loss_fault_returns_error_status() {
        let mut dev = device(PAGE_SIZE);
        dev.set_faults(IoFaults {
            loss: Probability::ALWAYS,
            ..IoFaults::none()
        });
        let outcome = resolve_read(&mut dev, 0, vec![1, 2, 3, 4]);
        assert!(outcome.loss_fired);
        assert_eq!(outcome.primary.status, ResponseStatus::Error);
    }

    #[test]
    fn block_duplicate_fault_emits_a_second_completion_later() {
        let mut dev = device(PAGE_SIZE);
        dev.set_faults(IoFaults {
            duplicate: Probability::ALWAYS,
            duplicate_gap_ns: 4096,
            ..IoFaults::none()
        });
        let outcome = resolve_read(&mut dev, 0, vec![9; 8]);
        assert!(outcome.duplicate_fired);
        let dup = outcome
            .duplicate
            .unwrap_or_else(|| panic!("duplicate fault must emit a second completion"));
        assert!(dup.delivery_icount > outcome.primary.delivery_icount);
        assert_eq!(dup.payload, outcome.primary.payload);
    }

    #[test]
    fn block_corrupt_fault_flips_seeded_bits_in_read_payload() {
        let mut dev = device(PAGE_SIZE);
        dev.set_faults(IoFaults {
            corrupt: Probability::ALWAYS,
            corrupt_bit_flips: 3,
            ..IoFaults::none()
        });
        let outcome = resolve_read(&mut dev, 0, vec![0u8; 16]);
        assert!(outcome.corrupt_fired);
        assert_ne!(outcome.primary.payload, vec![0u8; 16]);
    }

    #[test]
    fn block_fault_resolution_is_reproducible_and_snapshots_rng_and_faults() {
        let faults = IoFaults {
            jitter_window_ns: 1024,
            loss: Probability::new(1, 3),
            duplicate: Probability::new(1, 2),
            duplicate_gap_ns: 512,
            corrupt: Probability::new(1, 2),
            corrupt_bit_flips: 2,
            ..IoFaults::none()
        };
        let mut a = device(PAGE_SIZE);
        a.set_faults(faults.clone());
        let mut b = device(PAGE_SIZE);
        b.set_faults(faults.clone());
        let oa = resolve_read(&mut a, 5, vec![7; 8]);
        let ob = resolve_read(&mut b, 5, vec![7; 8]);
        assert_eq!(oa, ob, "same seed + same inputs => identical outcome");
        assert_eq!(a.rng_position(), b.rng_position());

        // The active faults AND the RNG cursor round-trip through snapshot/restore.
        let snap = a.snapshot();
        assert_eq!(snap.faults, faults);
        assert_eq!(snap.rng_position, a.rng_position());
        let restored = ok(BlockDevice::restore(&snap, ramp_base(PAGE_SIZE), None));
        assert_eq!(restored.faults(), &faults);
        assert_eq!(restored.rng_position(), a.rng_position());

        // A restored device resumes the draw stream byte-identically: its next
        // fault resolution matches the uninterrupted run's continuation.
        let mut restored = restored;
        let mut continue_a = a;
        let resumed = resolve_read(&mut restored, 9, vec![3; 8]);
        let uninterrupted = resolve_read(&mut continue_a, 9, vec![3; 8]);
        assert_eq!(resumed, uninterrupted);
    }
}
