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
