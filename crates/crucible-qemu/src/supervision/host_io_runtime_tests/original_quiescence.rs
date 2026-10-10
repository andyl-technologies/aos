//! Original-bound pause publication and fresh capture at the same idle coordinate.

#![cfg(test)]

use super::*;
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

#[test]
fn cancelled_original_refuses_pause_before_header_or_doorbell()
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
    let owner = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = owner.begin(HostOperationClass::Preparation)?;
    let before = plugin.node_slot(0)?.snapshot();
    owner.cancel()?;
    let expected = original.wait_slice().expect_err("original is cancelled");

    let failure = runtime
        .quiesce_for_checkpoint_under_original(&original)
        .expect_err("cancelled original cannot publish pause");

    assert_eq!(failure.operational_supervision_source(), Some(expected));
    assert!(!plugin.header().pause_requested());
    assert_eq!(plugin.node_slot(0)?.snapshot(), before);
    assert_eq!(
        notifications.read(&mut [0; 8]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    Ok(())
}

#[test]
fn original_idle_handoff_publishes_pause_before_fresh_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
    let layout = allocation.layout();
    let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    // This authored host-fixture bound only contains a broken publication
    // handshake; it neither replaces nor renews the original operation.
    notifications.set_read_timeout(Some(Duration::from_secs(2)))?;
    let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    plugin
        .node_slot(0)?
        .publish_pause_quiesced(73, 73 / crucible_shmem::TICKS_PER_INSTRUCTION)?;
    // Model the completed initial idle callback before requesting another one.
    plugin.node_slot(0)?.acknowledge_control_boundary();
    let stale = crucible_shmem::FingerprintSample {
        ram_digest: [0x11; 32],
        sample_icount: 73,
        ..Default::default()
    };
    plugin.fingerprint_sample(0)?.publish(&stale)?;
    let mut runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(shmem.as_fd(), wake.as_fd(), layout.region_size, 0)?;
    let owner = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = Arc::new(owner.begin(HostOperationClass::Preparation)?);
    // The scope joins the actual fixture worker even when an observation or
    // assertion fails; the same original deadline bounds its cleanup wait.
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let captured_original = Arc::clone(&original);
        let host = scope.spawn(move || -> Result<_, QemuAsyncDriverRuntimeError> {
            runtime.quiesce_for_checkpoint_under_original(&captured_original)?;
            runtime.publish_current_execution_fingerprint_under_original(&captured_original)?;
            captured_original.status().map_err(|source| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "original after pause and fresh capture",
                    source,
                )
            })
        });
        let mut notification = [0; 8];
        while !plugin.header().pause_requested()
            || plugin.node_slot(0)?.snapshot().max_advance_icount != 73
        {
            original.wait_slice()?;
            std::thread::yield_now();
        }
        // The idle-at-current handoff emits no pre-pause device probe. Observe
        // actual shared Pause before publishing the modeled plugin acknowledgement.
        assert!(plugin.header().pause_requested());
        assert_eq!(plugin.node_slot(0)?.snapshot().max_advance_icount, 73);
        assert_eq!(
            plugin.fingerprint_sample(0)?.capture_request_generation(),
            0
        );
        plugin
            .node_slot(0)?
            .publish_pause_quiesced(73, 73 / crucible_shmem::TICKS_PER_INSTRUCTION)?;
        notifications.read_exact(&mut notification)?;
        // The completed pause wakes the main loop, then the fresh capture publishes
        // its own token. Observe that token before acknowledging it.
        while plugin
            .fingerprint_sample(0)?
            .pending_capture_request_v1()
            .is_none()
        {
            notifications.read_exact(&mut notification)?;
        }
        let request = plugin
            .fingerprint_sample(0)?
            .pending_capture_request_v1()
            .ok_or("fresh capture was not published")?;
        // The fingerprint request becomes visible before its control token.
        // Acknowledge only the actual paired publication, never an earlier wake.
        while plugin.node_slot(0)?.control_boundary_capture_request() != Some(request)
            || !plugin.node_slot(0)?.control_boundary_is_requested()
        {
            original.wait_slice()?;
            std::thread::yield_now();
        }
        assert!(plugin.header().pause_requested());
        let fresh = crucible_shmem::FingerprintSample {
            ram_digest: [0x22; 32],
            ..stale
        };
        plugin.fingerprint_sample(0)?.publish(&fresh)?;
        assert!(
            plugin
                .fingerprint_sample(0)?
                .acknowledge_capture_v1(request)
        );
        plugin
            .node_slot(0)?
            .publish_control_boundary(73, 73 / crucible_shmem::TICKS_PER_INSTRUCTION)?;
        plugin.node_slot(0)?.acknowledge_control_boundary();
        let status = host.join().map_err(|_| "pause host panicked")??;
        assert_eq!(status.completed_work_units, 0);
        assert!(original.wait_slice().is_ok());
        assert_eq!(plugin.fingerprint_sample(0)?.snapshot(), Some(fresh));
        assert!(plugin.header().pause_requested());
        Ok(())
    })
}

#[test]
fn original_pause_rollback_retains_cancelled_first_cause_when_wake_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
    let layout = allocation.layout();
    let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let (notifications, wake) = UnixStream::pair()?;
    let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let mut runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(shmem.as_fd(), wake.as_fd(), layout.region_size, 0)?;
    plugin.header().request_pause([plugin.node_slot(0)?])?;
    let owner = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = owner.begin(HostOperationClass::Preparation)?;
    owner.cancel()?;
    let cancelled = original.wait_slice().expect_err("original is cancelled");
    // Closing the actual peer makes rollback's eventfd-style write refuse.
    drop(notifications);
    let primary = QemuAsyncDriverRuntimeError::operational_supervision(
        "original checkpoint pause",
        cancelled,
    );

    let failure = runtime
        .fail_checkpoint_pause(primary)
        .expect_err("rollback preserves the initiating refusal");

    assert_eq!(failure.operational_supervision_source(), Some(cancelled));
    assert!(std::error::Error::source(&failure).is_some());
    assert_eq!(failure.operation, "rollback failed checkpoint pause");
    assert!(
        failure
            .message
            .contains("pause release failure: signal plugin wake")
    );
    assert!(!plugin.header().pause_requested());
    Ok(())
}
