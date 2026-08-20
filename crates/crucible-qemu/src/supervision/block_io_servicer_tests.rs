//! Unit tests for the production host-I/O checkpoint boundary.

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use crucible_shmem::{RegionAllocation, RegionConfig, authorize_advance_ceiling};

use super::*;

#[cfg(unix)]
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
fn checkpoint_fixture() -> (fs::File, u64, QemuLiveBlockIoServicer) {
    checkpoint_fixture_with_latency(BlockLatency::default())
}

#[cfg(unix)]
fn checkpoint_fixture_with_latency(
    latency: BlockLatency,
) -> (fs::File, u64, QemuLiveBlockIoServicer) {
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))
        .unwrap_or_else(|error| panic!("allocate test region: {error}"));
    let slot = allocation
        .node_slot(0)
        .unwrap_or_else(|| panic!("test region must contain slot zero"));
    let ceiling = authorize_advance_ceiling(0, 0, None)
        .unwrap_or_else(|error| panic!("authorize test boundary: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("publish test ceiling: {error}"));
    slot.publish_reached_icount(0, 0)
        .unwrap_or_else(|error| panic!("publish test boundary: {error}"));
    allocation
        .header()
        .request_pause([slot])
        .unwrap_or_else(|error| panic!("request test checkpoint pause: {error}"));
    slot.publish_pause_quiesced(0, 0, 0)
        .unwrap_or_else(|error| panic!("publish test checkpoint pause: {error}"));
    let layout = allocation.layout();
    let bytes = allocation
        .setup_region_bytes()
        .unwrap_or_else(|error| panic!("serialize test region: {error}"));
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crucible-block-servicer-checkpoint-{}-{}",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|error| panic!("create test region: {error}"));
    fs::remove_file(&path).unwrap_or_else(|error| panic!("unlink test region: {error}"));
    file.set_len(layout.region_size)
        .unwrap_or_else(|error| panic!("size test region: {error}"));
    file.write_all(&bytes)
        .unwrap_or_else(|error| panic!("write test region: {error}"));
    let servicer = QemuLiveBlockIoServicer::from_shmem_fd_with_base_and_latency(
        file.as_fd(),
        layout.region_size,
        0,
        0,
        BaseImage::new(deterministic_base_image(4096)),
        latency,
    )
    .unwrap_or_else(|error| panic!("map test servicer: {error}"));
    (file, layout.region_size, servicer)
}

#[cfg(unix)]
fn unlinked_wake_file() -> fs::File {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crucible-block-servicer-wake-{}-{}",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|error| panic!("create test wake: {error}"));
    fs::remove_file(&path).unwrap_or_else(|error| panic!("unlink test wake: {error}"));
    file
}

#[test]
fn deterministic_base_image_is_reproducible_and_sized() {
    let first = deterministic_base_image(512);
    let second = deterministic_base_image(512);
    assert_eq!(first.len(), 512);
    assert_eq!(first, second);
    assert_eq!(first[0], 0);
    assert_eq!(first[251], 0);
    assert_eq!(first[250], 250);
}

#[cfg(unix)]
#[test]
fn explicit_latency_is_retained_in_exact_checkpoint_state() {
    let latency = BlockLatency::new(50_000_000, 60_000_000, 700, 300, 4);
    let (_file, _region_len, mut servicer) = checkpoint_fixture_with_latency(latency);
    let checkpoint = servicer
        .checkpoint(ContentHash::from_bytes(b"explicit-block-latency"))
        .unwrap_or_else(|error| panic!("capture timed block checkpoint: {error}"));

    assert_eq!(checkpoint.device.latency, latency);
}

#[cfg(unix)]
#[test]
fn latency_replacement_is_retained_in_exact_checkpoint_state() {
    let replacement = BlockLatency::new(70_000_000, 80_000_000, 900, 400, 8);
    let (_file, _region_len, mut servicer) = checkpoint_fixture();
    servicer
        .set_latency_model(replacement)
        .unwrap_or_else(|error| panic!("replace latency model: {error}"));
    let checkpoint = servicer
        .checkpoint(ContentHash::from_bytes(b"replacement-block-latency"))
        .unwrap_or_else(|error| panic!("capture replacement block checkpoint: {error}"));

    assert_eq!(checkpoint.device.latency, replacement);
}

#[test]
fn deterministic_diagnostics_ignore_host_poll_cadence() {
    let first = BlockIoDiagnosticsSnapshot {
        frames_processed: 1,
        write_frames_processed: 1,
        frames_delivered: 1,
        service_calls: 17,
        first_request_icount: Some(0),
        first_completion_horizon: Some(1512),
        last_current_icount: 12_000_000,
        max_current_icount: 12_000_000,
        last_device_io_active: false,
        last_idle_wake_icount: 1,
    };
    let second = BlockIoDiagnosticsSnapshot {
        service_calls: 29,
        ..first
    };

    assert_ne!(first, second);
    assert!(first.deterministic_observation_eq(&second));
}

#[test]
fn terminal_slot_observation_replaces_pre_consumption_device_state() {
    let diagnostics = BlockIoDiagnostics::default();
    diagnostics.record(
        10,
        true,
        20,
        &QemuLiveBlockIoServiceStep {
            processed: 1,
            write_frames_processed: 1,
            delivered: 1,
            first_request_icount: Some(10),
            computed_completion_icount: Some(20),
            next_completion_icount: None,
        },
    );

    diagnostics.observe_slot(30, false, 30);

    let snapshot = diagnostics.snapshot();
    assert_eq!(snapshot.service_calls, 1);
    assert_eq!(snapshot.last_current_icount, 30);
    assert_eq!(snapshot.max_current_icount, 30);
    assert!(!snapshot.last_device_io_active);
    assert_eq!(snapshot.last_idle_wake_icount, 30);
}

#[cfg(unix)]
#[test]
fn in_place_checkpoint_restore_reinstates_exact_device_and_ring_state() {
    let (_file, _region_len, mut servicer) = checkpoint_fixture();
    let binding = ContentHash::from_bytes(b"execution-checkpoint-a");
    let mut cached = BlockDurabilityConfig::write_through(4096);
    cached.atomic_write_bytes = 512;
    cached.volatile_cache_bytes = 4096;
    cached.cache_entries = 16;
    cached.retained_versions = 16;
    cached.completion_durability =
        crucible_device::block::BlockCompletionDurability::VolatileCacheAccepted;
    servicer
        .configure_storage_faults(cached, true)
        .unwrap_or_else(|error| panic!("configure storage: {error}"));
    servicer.frames_processed = 7;
    servicer.frames_delivered = 5;
    let checkpoint = servicer
        .checkpoint(binding)
        .unwrap_or_else(|error| panic!("capture block checkpoint: {error}"));

    servicer
        .configure_storage_faults(BlockDurabilityConfig::write_through(4096), false)
        .unwrap_or_else(|error| panic!("mutate storage configuration: {error}"));
    servicer.frames_processed = 99;
    servicer.frames_delivered = 88;
    servicer
        .restore_checkpoint(binding, &checkpoint)
        .unwrap_or_else(|error| panic!("restore block checkpoint: {error}"));

    let restored = servicer
        .checkpoint(binding)
        .unwrap_or_else(|error| panic!("recapture restored checkpoint: {error}"));
    assert_eq!(restored, checkpoint);
}

#[cfg(unix)]
#[test]
fn rejected_in_place_restore_preserves_exact_live_continuation() {
    let (_file, _region_len, mut servicer) = checkpoint_fixture();
    let binding = ContentHash::from_bytes(b"execution-checkpoint-a");
    let checkpoint = servicer
        .checkpoint(binding)
        .unwrap_or_else(|error| panic!("capture block checkpoint: {error}"));
    let before = checkpoint.clone();

    let error = match servicer.restore_checkpoint(
        ContentHash::from_bytes(b"execution-checkpoint-b"),
        &checkpoint,
    ) {
        Ok(()) => panic!("a mismatched checkpoint binding must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        QemuLiveBlockIoServicerError::CheckpointBindingMismatch
    ));
    let after = servicer
        .checkpoint(binding)
        .unwrap_or_else(|error| panic!("capture state after rejected restore: {error}"));
    assert_eq!(after, before);
}

#[cfg(unix)]
#[test]
fn remote_write_publishes_destination_deadline_and_wake() {
    fn cached_config() -> BlockDurabilityConfig {
        let mut config = BlockDurabilityConfig::write_through(4096);
        config.atomic_write_bytes = 512;
        config.volatile_cache_bytes = 4096;
        config.cache_entries = 16;
        config.retained_versions = 16;
        config.completion_durability =
            crucible_device::block::BlockCompletionDurability::VolatileCacheAccepted;
        config
    }

    fn staged_persistence(
        source: &QemuSharedBlockDevice,
        now_nanos: u64,
    ) -> ResolvedBlockRequestPersistenceDirective {
        let request = BlockRequest::write(31, 0, vec![0xa5; 512]);
        let mut device = source
            .lock()
            .unwrap_or_else(|error| panic!("lock source: {error}"));
        device
            .configure_storage_faults(cached_config(), true)
            .unwrap_or_else(|error| panic!("configure source: {error}"));
        device
            .require_storage_execution_opportunities()
            .unwrap_or_else(|error| panic!("require source opportunities: {error}"));
        let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 4096);
        admission.execution_nanos = now_nanos;
        admission.persistence_admitted_nanos = now_nanos;
        device
            .install_storage_fault_directive(request.identity(), admission)
            .unwrap_or_else(|error| panic!("install admission: {error}"));
        device
            .submit(now_nanos, &request)
            .unwrap_or_else(|error| panic!("submit source write: {error}"));
        let opportunity = device
            .next_storage_execution_opportunity(now_nanos)
            .unwrap_or_else(|| panic!("execution opportunity is present"));
        let mut execution = opportunity.admission.clone();
        execution.execution_nanos = opportunity.ready_nanos;
        execution.persistence_admitted_nanos = opportunity.ready_nanos;
        device
            .install_storage_execution_directive(ResolvedBlockExecutionDirective {
                opportunity,
                directive: execution,
            })
            .unwrap_or_else(|error| panic!("install execution: {error}"));
        device
            .advance_to(now_nanos)
            .unwrap_or_else(|error| panic!("advance source: {error}"));
        let opportunity = device
            .next_storage_request_persistence_opportunity(now_nanos)
            .unwrap_or_else(|| panic!("persistence opportunity is present"));
        let mut directive = opportunity.resolved.clone();
        directive.write_disposition =
            crucible_device::block::BlockFaultWriteDisposition::Misdirected {
                destination:
                    crucible_device::block::BlockFaultMisdirectionDestination::ExternalDevice(
                        [2; 32],
                    ),
                destination_offset: 512,
            };
        ResolvedBlockRequestPersistenceDirective {
            opportunity,
            directive,
        }
    }

    let (_source_file, _source_region_len, source_servicer) = checkpoint_fixture();
    let (_destination_file, _destination_region_len, destination_servicer) = checkpoint_fixture();
    let source = source_servicer.shared_device();
    let destination = destination_servicer.shared_device();
    {
        let mut destination_device = destination
            .lock()
            .unwrap_or_else(|error| panic!("lock destination: {error}"));
        let mut destination_config = BlockDurabilityConfig::write_through(4096);
        destination_config.atomic_write_bytes = 512;
        destination_config.retained_versions = 16;
        destination_device
            .configure_storage_faults(destination_config, false)
            .unwrap_or_else(|error| panic!("configure destination: {error}"));
        destination_device
            .require_storage_persistence_media_opportunities()
            .unwrap_or_else(|error| panic!("require destination persistence: {error}"));
    }
    let wake = Arc::new(unlinked_wake_file());
    destination
        .attach_notification_wake(Arc::clone(&wake))
        .unwrap_or_else(|error| panic!("attach destination wake: {error}"));
    let now_nanos = 64;
    let directive = staged_persistence(&source, now_nanos);

    let dependency = source
        .install_cross_device_misdirected_persistence(
            ContentHash { bytes: [1; 32] },
            &destination,
            ContentHash { bytes: [2; 32] },
            directive,
        )
        .unwrap_or_else(|error| panic!("commit remote write: {error}"));

    assert!(
        !destination
            .satisfies_external_durability(dependency)
            .unwrap_or_else(|error| panic!("inspect early durability: {error}")),
        "source completion must remain gated before destination persistence"
    );

    assert_eq!(
        destination_servicer
            .region
            .node_slot(0)
            .unwrap_or_else(|error| panic!("read destination slot: {error}"))
            .device_completion_deadline_icount(),
        now_nanos
    );
    assert_eq!(
        wake.metadata()
            .unwrap_or_else(|error| panic!("inspect wake write: {error}"))
            .len(),
        8
    );
    assert_eq!(
        destination
            .inspect_storage_visible(512, 512)
            .unwrap_or_else(|error| panic!("inspect destination bytes: {error}")),
        vec![0xa5; 512]
    );
    {
        let mut destination_device = destination
            .lock()
            .unwrap_or_else(|error| panic!("lock destination persistence: {error}"));
        let opportunity = destination_device
            .next_storage_persistence_opportunity(now_nanos)
            .unwrap_or_else(|| panic!("destination persistence opportunity is present"));
        destination_device
            .install_storage_persistence_media_directive(ResolvedBlockPersistenceMediaDirective {
                opportunity,
                flash_rules: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("install destination persistence: {error}"));
        destination_device
            .advance_to(now_nanos)
            .unwrap_or_else(|error| panic!("advance destination persistence: {error}"));
    }
    assert!(
        destination
            .satisfies_external_durability(dependency)
            .unwrap_or_else(|error| panic!("inspect acknowledged durability: {error}")),
        "source completion may proceed only after the exact frontier is durable"
    );
}

#[cfg(unix)]
#[test]
fn multi_device_write_commits_every_member_and_orders_dependencies() {
    fn staged_persistence(
        source: &QemuSharedBlockDevice,
        now_nanos: u64,
    ) -> ResolvedBlockRequestPersistenceDirective {
        let request = BlockRequest::write(31, 0, vec![0xa5; 512]);
        let mut device = source
            .lock()
            .unwrap_or_else(|error| panic!("lock source: {error}"));
        let mut config = BlockDurabilityConfig::write_through(4096);
        config.atomic_write_bytes = 512;
        config.volatile_cache_bytes = 4096;
        config.cache_entries = 16;
        config.retained_versions = 16;
        config.completion_durability =
            crucible_device::block::BlockCompletionDurability::VolatileCacheAccepted;
        device
            .configure_storage_faults(config, true)
            .unwrap_or_else(|error| panic!("configure source: {error}"));
        device
            .require_storage_execution_opportunities()
            .unwrap_or_else(|error| panic!("require source opportunities: {error}"));
        let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 4096);
        admission.execution_nanos = now_nanos;
        admission.persistence_admitted_nanos = now_nanos;
        device
            .install_storage_fault_directive(request.identity(), admission)
            .unwrap_or_else(|error| panic!("install admission: {error}"));
        device
            .submit(now_nanos, &request)
            .unwrap_or_else(|error| panic!("submit source write: {error}"));
        let opportunity = device
            .next_storage_execution_opportunity(now_nanos)
            .unwrap_or_else(|| panic!("execution opportunity is present"));
        let mut execution = opportunity.admission.clone();
        execution.execution_nanos = opportunity.ready_nanos;
        execution.persistence_admitted_nanos = opportunity.ready_nanos;
        device
            .install_storage_execution_directive(ResolvedBlockExecutionDirective {
                opportunity,
                directive: execution,
            })
            .unwrap_or_else(|error| panic!("install execution: {error}"));
        device
            .advance_to(now_nanos)
            .unwrap_or_else(|error| panic!("advance source: {error}"));
        let opportunity = device
            .next_storage_request_persistence_opportunity(now_nanos)
            .unwrap_or_else(|| panic!("persistence opportunity is present"));
        let mut directive = opportunity.resolved.clone();
        directive.write_disposition = BlockFaultWriteDisposition::Apply;
        ResolvedBlockRequestPersistenceDirective {
            opportunity,
            directive,
        }
    }

    let (_source_file, _source_region_len, source_servicer) = checkpoint_fixture();
    let (_first_file, _first_region_len, first_servicer) = checkpoint_fixture();
    let (_second_file, _second_region_len, second_servicer) = checkpoint_fixture();
    let source = source_servicer.shared_device();
    let first = first_servicer.shared_device();
    let second = second_servicer.shared_device();
    for destination in [&first, &second] {
        let mut device = destination
            .lock()
            .unwrap_or_else(|error| panic!("lock destination: {error}"));
        let mut config = BlockDurabilityConfig::write_through(4096);
        config.atomic_write_bytes = 512;
        config.retained_versions = 16;
        device
            .configure_storage_faults(config, false)
            .unwrap_or_else(|error| panic!("configure destination: {error}"));
    }
    first
        .attach_notification_wake(Arc::new(unlinked_wake_file()))
        .unwrap_or_else(|error| panic!("attach first wake: {error}"));
    second
        .attach_notification_wake(Arc::new(unlinked_wake_file()))
        .unwrap_or_else(|error| panic!("attach second wake: {error}"));
    let now_nanos = 64;
    let mut directive = staged_persistence(&source, now_nanos);
    directive.directive.write_disposition = BlockFaultWriteDisposition::Apply;
    let dependencies = source
        .install_multi_device_mutation(
            ContentHash { bytes: [1; 32] },
            &[
                (
                    ContentHash { bytes: [2; 32] },
                    first.clone(),
                    vec![BlockRequest::write(31, 0, vec![0xa5; 512])],
                ),
                (
                    ContentHash { bytes: [3; 32] },
                    second.clone(),
                    vec![BlockRequest::write(31, 512, vec![0x5a; 512])],
                ),
            ],
            &[],
            directive,
        )
        .unwrap_or_else(|error| panic!("commit multi-device write: {error}"));
    assert_eq!(
        dependencies
            .iter()
            .map(|dependency| dependency.destination_device)
            .collect::<Vec<_>>(),
        vec![[2; 32], [3; 32]]
    );
    assert_eq!(
        first
            .inspect_storage_visible(0, 512)
            .unwrap_or_else(|error| panic!("inspect first member: {error}")),
        vec![0xa5; 512]
    );
    assert_eq!(
        second
            .inspect_storage_visible(512, 512)
            .unwrap_or_else(|error| panic!("inspect second member: {error}")),
        vec![0x5a; 512]
    );
}
