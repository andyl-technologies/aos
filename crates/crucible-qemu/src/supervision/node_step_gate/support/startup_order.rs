//! Exercises the descriptor/setup and mapped-barrier prerequisites of RAM admission.
//!
//! This component peer uses the real SIM descriptor protocol and RAM control
//! authentication. It proves startup ordering, not native paging qualification.

#![cfg(test)]

use super::*;
use crate::QemuPluginIpcControlChannel;
use crate::host_setup::tests::plugin_peer_complete_setup_after_ack;
use crate::spawn::create_test_spawn_resource_pair;
use crucible_linux_resource::host_supervision::{HostOperationBudget, HostOperationBudgets};
use crucible_linux_resource::ram_policy::HostRamTarget;
use crucible_protocol::ram_control::{
    RamControlConvergence, RamControlDisposition, RamControlFrame, RamControlMessage,
    RamControlReply, RamControlRequest, ram_control_request_digest, read_ram_control,
    write_ram_control,
};
use crucible_shmem::{RegionConfig, RegionLayout};
use std::error::Error;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;

#[test]
fn ram_authentication_progresses_after_descriptor_setup_and_mapped_prime()
-> Result<(), Box<dyn Error>> {
    let config = RegionConfig::new(1, 4);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let (host_ram, mut peer_ram) = UnixStream::pair()?;
    let (waiting_for_setup, setup_wait) = mpsc::channel();
    let (waiting_for_prime, prime_wait) = mpsc::channel();
    let (prime_published, prime_release) = mpsc::channel();
    let (authenticated, authentication_result) = mpsc::channel();
    let timeout = Duration::from_secs(5);

    let plugin_peer = thread::spawn(move || {
        waiting_for_setup
            .send(())
            .map_err(|error| error.to_string())?;
        let requirement = crate::QemuFaultCapabilityRequirement::abi_boundary_v1();
        plugin_peer_complete_setup_after_ack(plugin_socket, requirement.rows(), |mapped| {
            // The real SetupAck has arrived, but machine creation's inventory
            // cannot yet run: the installation barrier still has no ceiling.
            let slot = mapped
                .node_slot(GATE_SLOT)
                .map_err(|error| error.to_string())?;
            assert_eq!(slot.snapshot().max_advance_icount, 0);
            peer_ram
                .set_read_timeout(Some(timeout))
                .map_err(|error| error.to_string())?;
            let hello = read_ram_control(&mut peer_ram)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| String::from("RAM peer closed before Hello"))?;
            assert_eq!(
                hello.message,
                RamControlMessage::Request(RamControlRequest::Hello)
            );
            waiting_for_prime
                .send(())
                .map_err(|error| error.to_string())?;
            prime_release
                .recv_timeout(timeout)
                .map_err(|error| error.to_string())?;

            let snapshot = slot.snapshot();
            assert_eq!(snapshot.max_advance_icount, PRIME_CEILING_ICOUNT);
            assert_eq!(snapshot.current_icount, 0);
            let reply = RamControlFrame {
                message: RamControlMessage::Reply {
                    request_digest: ram_control_request_digest(&hello)
                        .map_err(|error| error.to_string())?,
                    state: ready_reply(),
                },
                ..hello
            };
            write_ram_control(&mut peer_ram, &reply).map_err(|error| error.to_string())
        })
    });
    let target = HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    };
    let budgets = HostOperationBudgets {
        classes: [HostOperationBudget::finite(timeout); 14],
    };
    let supervisor = HostOperationSupervisor::new(budgets, Some(timeout))?;
    let original_cap = supervisor.cap_id();
    let authentication_supervisor = supervisor.clone();
    let controller_peer = thread::spawn(move || {
        let result = crate::ram_control::RamControlClient::connect_supervised(
            host_ram,
            [4; 32],
            target,
            authentication_supervisor,
        );
        authenticated
            .send(result)
            .map_err(|error| error.to_string())
    });

    setup_wait.recv_timeout(timeout)?;
    assert!(matches!(
        authentication_result.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    // Waiting for RAM here recreates the first cycle: the peer cannot install
    // its controller until the host sends these real SCM_RIGHTS descriptors.
    let mut setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        GATE_SLOT,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
    prime_wait.recv_timeout(timeout)?;
    assert!(matches!(
        authentication_result.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    // Waiting after SetupAck alone recreates the second cycle. Publish through
    // the production priming path; there is still no QMP cont or retired tick.
    let priming = prepare_guest_prime(
        &setup,
        QemuLiveNodeIdentity::new("vm", "router", "crash"),
        QemuLaunchPluginSwitch::Off,
        None,
    )?;
    prime_published.send(())?;
    let controller = authentication_result.recv_timeout(timeout)??;
    assert_eq!(supervisor.cap_id(), original_cap);
    let mapped = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)?;
    assert_eq!(mapped.node_slot(GATE_SLOT)?.snapshot().current_icount, 0);

    QemuPluginIpcControlChannel::send_quit(&mut setup)?;
    plugin_peer.join().map_err(|_| "plugin peer panicked")??;
    controller_peer
        .join()
        .map_err(|_| "controller peer panicked")??;
    drop(controller);
    drop(priming);
    Ok(())
}

fn ready_reply() -> RamControlReply {
    RamControlReply {
        disposition: RamControlDisposition::Accepted,
        requested_policy_revision: 1,
        applied_policy_revision: 1,
        reservation_revision: 1,
        observation_sequence: 1,
        logical_ram_bytes: 8192,
        effective_resident_target_bytes: 8192,
        effective_floor_bytes: 8192,
        private_resident_bytes: 8192,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 0,
        private_dirty_bytes: 0,
        writeback_pending_bytes: 0,
        limitation_reasons: 0,
        measurements_available: true,
        convergence: RamControlConvergence::Stable,
        inventory: None,
        inventory_region: None,
        activity: None,
        kernel_probe: None,
        placement_receipt: None,
        fault_actor: None,
        operation_failure: None,
    }
}
