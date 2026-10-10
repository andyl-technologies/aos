//! Real mapped command, result, capture and sample receiver regressions.
//!
//! The receiver models fault application; it is not a native VM or a deployed
//! fault witness. Node and host-I/O transport/publication code remain actual.

use super::*;
use crucible::{SchedulerError, SchedulerSendAuthorization, SchedulerSendAuthorizer};
use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_shmem::{
    DequeuedFaultCommand, MappedSetupRegion, dequeue_fault_command, enqueue_fault_result,
};
use std::io::Read;
use std::os::unix::net::UnixStream;

struct FixtureNetworkAuthorizer;

impl SchedulerSendAuthorizer for FixtureNetworkAuthorizer {
    fn authorize_cross_node_send(
        &self,
        producer: &crucible::SchedulerNodeId,
        consumer: &crucible::SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}

struct Fixture {
    node: QemuNode,
    receiver: MappedSetupRegion,
    notifications: UnixStream,
    supervisor: HostOperationSupervisor,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4))?;
        let layout = allocation.layout();
        let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
        shmem.write_all(&allocation.setup_region_bytes()?)?;
        let (notifications, wake) = UnixStream::pair()?;
        notifications.set_read_timeout(Some(Duration::from_secs(2)))?;
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )?;
        let runtime = crate::supervision::QemuLiveHostIoRuntime::from_shmem_fd(
            shmem.as_fd(),
            wake.as_fd(),
            layout.region_size,
            0,
        )?
        .with_host_operation_supervisor(supervisor.clone());
        let mut node = host_io_runtime::scripted_node_with_live_host_runtime(runtime)?;
        node.channels.shmem_hot_path = Box::new(crate::QemuMappedQuantumShmemHotPath::new(
            crate::QemuQuantumShmemConfig::new(node_id("vm-a"), 0),
            mmap_setup_region(shmem.as_fd(), layout.region_size)?,
            FixtureNetworkAuthorizer,
        )?);
        node = node.with_fault_capabilities(vec![FaultCapabilityRowV1 {
            command_kind: FaultCommandKind::MemoryMutation,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            scope: FaultCapabilityScope::All,
            phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
            maximum_payload_bytes: 64,
            maximum_pending_commands: 1,
            required_feature_bits: 0,
            capability_hash: [7; 32],
        }]);
        let receiver = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        receiver
            .node_slot(0)?
            .arm_external_state_restore_ceiling(11)?;
        receiver.node_slot(0)?.publish_reached_icount(11)?;
        receiver
            .fingerprint_sample(0)?
            .publish(&baseline_sample())?;
        Ok(Self {
            node,
            receiver,
            notifications,
            supervisor,
        })
    }
}

fn baseline_sample() -> QemuFingerprintSample {
    let mut sample = QemuFingerprintSample {
        sample_icount: 11,
        vcpu_count: 1,
        rr_switch_quantum: 4096,
        ram_bytes: 4096,
        ram_digest: [1; 32],
        device_state_bytes: 64,
        device_state_sections: 1,
        device_state_digest: [2; 32],
        device_state_schema_digest: [3; 32],
        ..Default::default()
    };
    sample.vcpus[0].register_file_bytes = 8;
    sample.vcpus[0].register_digest = [4; 32];
    sample
}

fn command() -> FaultCommandHeaderV1 {
    FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation,
        command_flags: 0,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 7,
        target_node_hash: [1; 32],
        target_icount: 11,
        authorization_ceiling_icount: 11,
        binding_hash: [2; 32],
        opportunity_hash: [3; 32],
        expected_precondition_hash: [4; 32],
        payload_hash: [0; 32],
        payload_offset: 0,
        payload_length: 0,
    }
}

fn publish_applied(receiver: &mut MappedSetupRegion) -> Result<(), Box<dyn Error>> {
    let transport = receiver.fault_command_transport_mut(0)?;
    let decoded = dequeue_fault_command(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )?
    .ok_or("command was not published")?;
    let DequeuedFaultCommand::Valid { header, payload } = decoded else {
        return Err("command failed transport authentication".into());
    };
    assert_eq!(header.command_sequence, 7);
    assert_eq!(payload, b"receiver mutation");
    let transport = receiver.fault_result_transport_mut(0)?;
    enqueue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
        FaultResultHeaderV2 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: header.command_kind as u16,
            status: FaultResultStatus::Applied,
            semantic_version: header.semantic_version,
            command_sequence: header.command_sequence,
            observed_icount: 11,
            applied_icount: 11,
            emitted_tick: 11,
            capability_version: 1,
            phase: header.phase,
            before_hash: [4; 32],
            after_hash: [5; 32],
            evidence_hash: [6; 32],
            result_payload_hash: [0; 32],
            result_offset: 0,
            result_length: 0,
        },
        &[],
    )?;
    receiver.node_slot(0)?.publish_control_boundary(11, 0)?;
    receiver.node_slot(0)?.acknowledge_control_boundary();
    Ok(())
}

#[test]
fn fault_fingerprint_applied_controller_and_ram_changes_refresh_same_icount()
-> Result<(), Box<dyn Error>> {
    for (controller_only, raw_sample_first) in [(true, false), (false, true)] {
        let mut fixture = Fixture::new()?;
        let before = fixture.node.execution_fingerprint()?;
        let mut fresh = baseline_sample();
        let digest = *blake3::hash(b"receiver mutation").as_bytes();
        if controller_only {
            fresh.device_state_digest = digest;
        } else {
            fresh.ram_digest = digest;
        }
        let expected =
            crate::mapped_quantum::black_box_execution_fingerprint(&node_id("vm-a"), &fresh)?;
        assert_ne!(before, expected);

        let mut node = fixture.node;
        let host = std::thread::spawn(move || -> Result<(), QemuNodeError> {
            node.apply_fault_command_at_current_boundary_with_limits(
                command(),
                b"receiver mutation",
                Vec::new(),
                crucible_shmem::HARD_FAULT_EVENT_CAPACITY as usize,
            )?;
            assert_eq!(node.current_icount()?.retired, 11);
            if raw_sample_first {
                assert_eq!(node.fingerprint_sample()?, fresh);
            }
            assert_eq!(node.execution_fingerprint()?, expected);
            assert_eq!(node.execution_fingerprint()?, expected);
            node.shutdown_child()?;
            Ok(())
        });
        let observation = (|| -> Result<(), Box<dyn Error>> {
            let mut bytes = [0; 8];
            fixture.notifications.read_exact(&mut bytes)?;
            publish_applied(&mut fixture.receiver)?;
            let request = loop {
                fixture.notifications.read_exact(&mut bytes)?;
                // The result poller may publish another token before observing
                // the result. Model every control pump, not only the first wake.
                fixture
                    .receiver
                    .node_slot(0)?
                    .publish_control_boundary(11, 0)?;
                fixture
                    .receiver
                    .node_slot(0)?
                    .acknowledge_control_boundary();
                if let Some(request) = fixture
                    .receiver
                    .fingerprint_sample(0)?
                    .pending_capture_request_v1()
                {
                    break request;
                }
            };
            assert_eq!(request, 1);
            assert_eq!(fixture.receiver.node_slot(0)?.snapshot().current_icount, 11);
            fixture.receiver.fingerprint_sample(0)?.publish(&fresh)?;
            assert!(
                fixture
                    .receiver
                    .fingerprint_sample(0)?
                    .acknowledge_capture_v1(request)
            );
            fixture
                .receiver
                .node_slot(0)?
                .publish_control_boundary(11, 0)?;
            fixture
                .receiver
                .node_slot(0)?
                .acknowledge_control_boundary();
            Ok(())
        })();
        let outcome = host.join().map_err(|_| "host fixture panicked")?;
        outcome?;
        observation?;
        assert_eq!(
            fixture
                .receiver
                .fingerprint_sample(0)?
                .capture_request_generation(),
            2
        );
    }
    Ok(())
}

#[test]
fn fault_fingerprint_prepublication_denial_preserves_cached_sample() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new()?;
    let before = fixture.node.execution_fingerprint()?;
    let mut past = command();
    past.target_icount = 10;
    assert!(
        fixture
            .node
            .apply_fault_command_at_current_boundary_with_limits(past, &[], Vec::new(), 0,)
            .is_err()
    );
    let mut invalid = command();
    invalid.abi_major = 0;
    assert!(fixture.node.enqueue_fault_command(invalid, &[]).is_err());
    assert!(!fixture.node.fault_fingerprint_invalidated);
    assert_eq!(fixture.node.execution_fingerprint()?, before);
    assert_eq!(
        fixture
            .receiver
            .fingerprint_sample(0)?
            .capture_request_generation(),
        0
    );
    fixture.notifications.set_nonblocking(true)?;
    assert_eq!(
        fixture.notifications.read(&mut [0; 8]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.node.shutdown_child()?;
    Ok(())
}

#[test]
fn fault_fingerprint_old_pending_capture_cannot_reopen_invalid_cache() -> Result<(), Box<dyn Error>>
{
    let mut fixture = Fixture::new()?;
    fixture.node.enqueue_fault_command(command(), &[])?;
    let request = fixture.receiver.fingerprint_sample(0)?.request_capture_v1();
    for raw_sample in [false, true] {
        let error = if raw_sample {
            fixture.node.fingerprint_sample().map(|_| ())
        } else {
            fixture.node.execution_fingerprint().map(|_| ())
        }
        .expect_err("an old pending capture cannot satisfy fault freshness");
        assert!(error.to_string().contains("already pending"));
        assert!(fixture.node.fault_fingerprint_invalidated);
    }
    assert_eq!(
        fixture
            .receiver
            .fingerprint_sample(0)?
            .capture_request_generation(),
        request
    );
    fixture.notifications.set_nonblocking(true)?;
    assert_eq!(
        fixture.notifications.read(&mut [0; 8]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.node.shutdown_child()?;
    Ok(())
}

#[test]
fn fault_fingerprint_cancelled_owner_refuses_before_capture() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new()?;
    fixture.node.enqueue_fault_command(command(), &[])?;
    fixture.supervisor.cancel()?;

    assert!(fixture.node.execution_fingerprint().is_err());
    assert!(fixture.node.fingerprint_sample().is_err());
    assert!(fixture.node.fault_fingerprint_invalidated);
    assert_eq!(
        fixture
            .receiver
            .fingerprint_sample(0)?
            .capture_request_generation(),
        0
    );
    fixture.notifications.set_nonblocking(true)?;
    assert_eq!(
        fixture.notifications.read(&mut [0; 8]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    Ok(())
}

#[test]
fn fault_fingerprint_invalid_fresh_sample_stays_invalid_without_second_capture()
-> Result<(), Box<dyn Error>> {
    for bad_coordinate in [false, true] {
        let fixture = Fixture::new()?;
        let mut node = fixture.node;
        node.enqueue_fault_command(command(), b"receiver mutation")?;
        let host = std::thread::spawn(move || -> Result<(), QemuNodeError> {
            let error = node
                .fingerprint_sample()
                .expect_err("fresh sample is invalid");
            let expected = if bad_coordinate {
                "differs from current boundary"
            } else {
                "component failure mask"
            };
            assert!(error.to_string().contains(expected));
            assert!(node.fault_fingerprint_invalidated);
            node.shutdown_child()?;
            Ok(())
        });

        let mut receiver = fixture.receiver;
        let mut notifications = fixture.notifications;
        let observation = (|| -> Result<(), Box<dyn Error>> {
            notifications.read_exact(&mut [0; 8])?;
            let request = receiver
                .fingerprint_sample(0)?
                .pending_capture_request_v1()
                .ok_or("fresh capture was not requested")?;
            publish_applied(&mut receiver)?;
            let mut invalid = baseline_sample();
            if bad_coordinate {
                invalid.sample_icount = 12;
            } else {
                invalid.component_failures = 1;
            }
            receiver.fingerprint_sample(0)?.publish(&invalid)?;
            assert!(
                receiver
                    .fingerprint_sample(0)?
                    .acknowledge_capture_v1(request)
            );
            receiver.node_slot(0)?.publish_control_boundary(11, 0)?;
            receiver.node_slot(0)?.acknowledge_control_boundary();
            Ok(())
        })();
        let outcome = host.join().map_err(|_| "host fixture panicked")?;
        observation?;
        outcome?;
        assert_eq!(
            receiver.fingerprint_sample(0)?.capture_request_generation(),
            2
        );
    }
    Ok(())
}
