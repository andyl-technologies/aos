//! Block coordinator startup and hot-fork ownership tests.

use super::*;

struct TestBlockCoordinator;

impl QemuBlockFaultCoordinator for TestBlockCoordinator {
    fn apply_boundary_actions(
        &mut self,
        _servicer: &mut QemuLiveBlockIoServicer,
        _coordinate: crucible::model::FaultCoordinate,
        _evaluation_sequence: u64,
        _actions: &[crucible::model::ResolvedBindingAction],
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    fn service_block_io(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
    ) -> Result<crate::QemuLiveBlockIoServiceStep, QemuAsyncDriverRuntimeError> {
        servicer.service(guest_icount).map_err(|source| {
            QemuAsyncDriverRuntimeError::new("test block coordinator", source.to_string())
        })
    }
}

#[cfg(target_os = "linux")]
#[test]
fn empty_block_poll_does_not_block_late_fault_coordinator_installation()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsFd;

    let (region, _unused_region, region_len) = private_region_pair()?;
    let wake = tempfile::tempfile()?;
    let block =
        QemuLiveBlockIoServicer::from_shmem_fd(region.as_fd(), region_len, 0, 0, 16 * 1024)?;
    let mut runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(region.as_fd(), wake.as_fd(), region_len, 0)?
            .with_block_servicer(block, BlockIoDiagnostics::shared())?;
    let snapshot = runtime.region.node_slot(0)?.snapshot();

    assert!(!runtime.service_block_io(&snapshot)?);
    assert!(
        !runtime
            .block
            .as_ref()
            .ok_or("block servicer should be present")?
            .worker
            .work_in_flight()
    );
    runtime.install_block_fault_coordinator(Box::new(TestBlockCoordinator))?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn hot_fork_clone_requires_fresh_branch_local_fault_coordinator()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsFd;

    let (source_region, child_region, region_len) = private_region_pair()?;
    let source_wake = tempfile::tempfile()?;
    let child_wake = tempfile::tempfile()?;
    let block =
        QemuLiveBlockIoServicer::from_shmem_fd(source_region.as_fd(), region_len, 0, 0, 16 * 1024)?;
    let mut source = QemuLiveHostIoRuntime::from_shmem_fd(
        source_region.as_fd(),
        source_wake.as_fd(),
        region_len,
        0,
    )?
    .with_block_servicer(block, BlockIoDiagnostics::shared())?;
    source.install_block_fault_coordinator(Box::new(TestBlockCoordinator))?;
    let binding = ContentHash::from_bytes(b"coordinator-isolation");
    let mut child = source.clone_hot_fork_host_io_continuation(
        binding,
        child_region.as_fd(),
        child_wake.as_fd(),
        region_len,
        None,
    )?;
    let coordinate = crucible::model::FaultCoordinate {
        virtual_nanos: 0,
        retired_instructions: Some(0),
    };

    assert!(
        child
            .apply_block_boundary_actions(coordinate, 0, &[])
            .is_err()
    );
    child.install_block_fault_coordinator(Box::new(TestBlockCoordinator))?;
    child.apply_block_boundary_actions(coordinate, 0, &[])?;
    Ok(())
}
