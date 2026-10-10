//! Original-operation refusal before any fingerprint request or doorbell.

#![cfg(test)]

use super::*;
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

#[test]
fn closed_original_refuses_capture_without_using_live_ambient_owner()
-> Result<(), Box<dyn std::error::Error>> {
    for cancelled in [false, true] {
        let allocation =
            crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
        let layout = allocation.layout();
        let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
        shmem.write_all(&allocation.setup_region_bytes()?)?;
        let (mut notifications, wake) = UnixStream::pair()?;
        notifications.set_nonblocking(true)?;
        let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let ambient = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )?;
        let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
            shmem.as_fd(),
            wake.as_fd(),
            layout.region_size,
            0,
        )?
        .with_host_operation_supervisor(ambient);
        let original_owner = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )?;
        let original = original_owner.begin(HostOperationClass::Preparation)?;
        if cancelled {
            original_owner.cancel()?;
        } else {
            original.complete()?;
        }
        let initial_ack = plugin.node_slot(0)?.snapshot().control_boundary_ack;
        let expected = original.wait_slice().expect_err("original is closed");

        let error = runtime
            .publish_current_execution_fingerprint_under_original(&original)
            .expect_err("ambient owner cannot replace original");

        assert_eq!(error.operational_supervision_source(), Some(expected));
        assert_eq!(
            plugin.fingerprint_sample(0)?.capture_request_generation(),
            0
        );
        assert_eq!(
            plugin.node_slot(0)?.snapshot().control_boundary_ack,
            initial_ack
        );
        assert_eq!(
            notifications.read(&mut [0_u8; 8]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    Ok(())
}

#[test]
fn old_pending_capture_refuses_fresh_original_request_before_any_wake()
-> Result<(), Box<dyn std::error::Error>> {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
    let layout = allocation.layout();
    let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_nonblocking(true)?;
    let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let mut runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(shmem.as_fd(), wake.as_fd(), layout.region_size, 0)?;
    let original_owner = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = original_owner.begin(HostOperationClass::Preparation)?;
    let old_request = plugin.fingerprint_sample(0)?.request_capture_v1();
    let initial_ack = plugin.node_slot(0)?.snapshot().control_boundary_ack;

    let error = runtime
        .publish_current_execution_fingerprint_under_original(&original)
        .expect_err("fresh request cannot adopt an old in-flight capture");

    assert!(error.message.contains("already pending"));
    assert_eq!(
        plugin.fingerprint_sample(0)?.capture_request_generation(),
        old_request
    );
    assert_eq!(
        plugin.node_slot(0)?.snapshot().control_boundary_ack,
        initial_ack
    );
    assert_eq!(
        notifications.read(&mut [0_u8; 8]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(original.wait_slice().is_ok());
    Ok(())
}

// The account below funds only actual guard subscriptions in these mapped host
// fixtures. It is not an actor/family issuer or a native park entitlement.
#[cfg(feature = "private-measurement-domain")]
pub(super) struct CapturePair {
    pub(super) actor: crucible_linux_resource::host_supervision::HostOperationGuard,
    pub(super) family: crucible_linux_resource::host_supervision::HostOperationGuard,
    actor_event: std::os::fd::OwnedFd,
    family_event: std::os::fd::OwnedFd,
    _actor_owner: HostOperationSupervisor,
    _family_owner: HostOperationSupervisor,
    _account: crucible_linux_resource::host_services::HostServiceAllocator,
}

#[cfg(feature = "private-measurement-domain")]
impl CapturePair {
    pub(super) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        use crucible_linux_resource::host_services::HostServiceAllocator;
        use crucible_linux_resource::host_supervision::HostOperationGuard;

        let actor_owner = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )?;
        let family_owner = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )?;
        let actor = actor_owner.begin(HostOperationClass::Quiescence)?;
        let family = family_owner.begin(HostOperationClass::Quiescence)?;
        let account = HostServiceAllocator::new(1, 2, 8192)?;
        let subscribe = |guard: &HostOperationGuard| -> Result<_, Box<dyn std::error::Error>> {
            let event = rustix::event::eventfd(
                0,
                rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
            )?;
            let credit = account.reserve_resources(
                0,
                1,
                HostOperationGuard::original_quiescence_cancellation_bytes(),
            )?;
            guard.retain_original_quiescence_cancellation(
                rustix::io::fcntl_dupfd_cloexec(&event, 3)?,
                credit,
            )?;
            Ok(event)
        };
        let actor_event = subscribe(&actor)?;
        let family_event = subscribe(&family)?;
        Ok(Self {
            actor,
            family,
            actor_event,
            family_event,
            _actor_owner: actor_owner,
            _family_owner: family_owner,
            _account: account,
        })
    }
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn paired_fingerprint_revoked_owner_refuses_before_request_or_wake()
-> Result<(), Box<dyn std::error::Error>> {
    for revoke_actor in [false, true] {
        let allocation =
            crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
        let layout = allocation.layout();
        let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
        shmem.write_all(&allocation.setup_region_bytes()?)?;
        let (mut notifications, wake) = UnixStream::pair()?;
        notifications.set_nonblocking(true)?;
        let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
            shmem.as_fd(),
            wake.as_fd(),
            layout.region_size,
            0,
        )?;
        let pair = CapturePair::new()?;
        let (revoked, event) = if revoke_actor {
            (&pair.actor, &pair.actor_event)
        } else {
            (&pair.family, &pair.family_event)
        };
        let before = plugin.node_slot(0)?.snapshot();
        rustix::io::write(event, &1_u64.to_ne_bytes())?;
        let expected = revoked
            .check_original_quiescence_cancellation()
            .unwrap_err();

        let error = runtime
            .publish_current_execution_fingerprint_under_originals(&pair.actor, &pair.family)
            .expect_err("neither original may be replaced by the other live owner");

        assert_eq!(error.operational_supervision_source(), Some(expected));
        assert_eq!(
            plugin.fingerprint_sample(0)?.capture_request_generation(),
            0
        );
        assert_eq!(plugin.node_slot(0)?.snapshot(), before);
        assert_eq!(
            notifications.read(&mut [0; 8]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            revoked
                .check_original_quiescence_cancellation()
                .unwrap_err(),
            expected
        );
    }
    Ok(())
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn paired_fingerprint_old_pending_request_refuses_before_wake()
-> Result<(), Box<dyn std::error::Error>> {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
    let layout = allocation.layout();
    let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_nonblocking(true)?;
    let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let mut runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(shmem.as_fd(), wake.as_fd(), layout.region_size, 0)?;
    let pair = CapturePair::new()?;
    let request = plugin.fingerprint_sample(0)?.request_capture_v1();
    let before = plugin.node_slot(0)?.snapshot();

    let error = runtime
        .publish_current_execution_fingerprint_under_originals(&pair.actor, &pair.family)
        .expect_err("a paired fresh capture cannot coalesce an older request");

    assert!(error.message.contains("already pending"));
    assert_eq!(
        plugin.fingerprint_sample(0)?.capture_request_generation(),
        request
    );
    assert_eq!(plugin.node_slot(0)?.snapshot(), before);
    assert_eq!(
        notifications.read(&mut [0; 8]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    pair.actor.check_original_quiescence_cancellation()?;
    pair.family.check_original_quiescence_cancellation()?;
    Ok(())
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn paired_fingerprint_revocation_after_publication_retains_pending_without_doorbell()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::supervision::host_io_runtime::operational_wait::OperationPollBudget;

    for revoke_actor in [false, true] {
        let allocation =
            crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
        let layout = allocation.layout();
        let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
        shmem.write_all(&allocation.setup_region_bytes()?)?;
        let (mut notifications, wake) = UnixStream::pair()?;
        notifications.set_nonblocking(true)?;
        let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
            shmem.as_fd(),
            wake.as_fd(),
            layout.region_size,
            0,
        )?;
        let pair = CapturePair::new()?;
        let deadline = OperationPollBudget::borrow_quiescence_pair(
            &pair.actor,
            &pair.family,
            "paired publication fixture",
        )?;
        let capture = plugin.fingerprint_sample(0)?.request_fresh_capture_v1()?;
        let before = plugin.node_slot(0)?.snapshot();
        let pending = runtime.publish_paired_fingerprint_control(&deadline, capture)?;
        let published = plugin.node_slot(0)?.snapshot();
        assert_eq!(
            plugin.node_slot(0)?.control_boundary_capture_request(),
            Some(capture)
        );
        assert!(plugin.node_slot(0)?.control_boundary_is_requested());
        assert_eq!(published.control_boundary_ack, pending.generation);
        assert_eq!(
            pending.generation,
            before.control_boundary_ack.wrapping_add(1)
        );
        assert_eq!(pending.generation & 1, 0);
        let (revoked, event) = if revoke_actor {
            (&pair.actor, &pair.actor_event)
        } else {
            (&pair.family, &pair.family_event)
        };
        rustix::io::write(event, &1_u64.to_ne_bytes())?;
        let expected = revoked
            .check_original_quiescence_cancellation()
            .unwrap_err();

        let failure = runtime
            .wake_paired_fingerprint_control(&deadline, pending)
            .expect_err("published control does not authorize a wake after original refusal");

        assert_eq!(failure.operational_supervision_source(), Some(expected));
        assert_eq!(plugin.node_slot(0)?.snapshot(), published);
        assert_eq!(
            plugin.fingerprint_sample(0)?.capture_request_generation(),
            capture
        );
        assert!(plugin.node_slot(0)?.control_boundary_is_requested());
        assert_eq!(
            notifications.read(&mut [0; 8]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    Ok(())
}
