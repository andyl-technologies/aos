//! Actual child, descriptor and map-mutation controls for whole-set return.

use super::*;
use crate::node::test_support::hot_fork::{QemuTestHotForkOutcome, scripted_hot_fork_source_for_test};
use std::error::Error;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn binding() -> ContentHash {
    ContentHash::from_bytes(b"component generation binding")
}

fn actual_node() -> Result<(NodeId, QemuNode), Box<dyn Error>> {
    Ok((
        NodeId {
            name: String::from("component"),
        },
        crate::node::tests::node_set_source_with_retained_file(tempfile::tempfile()?)?,
    ))
}

#[test]
fn empty_shutdown_cannot_mint_a_leased_node_return() -> Result<(), Box<dyn Error>> {
    let mut nodes = QemuNodeSet::new();
    let node = NodeId {
        name: String::from("missing"),
    };
    assert!(nodes.prepare_whole_shutdown(binding(), [&node]).is_err());
    SimulationBackend::shutdown(&mut nodes)?;
    assert!(nodes.verify_whole_shutdown_return(binding()).is_err());
    assert!(nodes.prepare_whole_shutdown(binding(), [&node]).is_err());
    Ok(())
}

#[test]
fn return_is_visible_only_after_actual_node_owned_file_closes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("unlinked-attempt");
    let file = std::fs::File::create(&path)?;
    let descriptor = format!("/proc/self/fd/{}", file.as_raw_fd());
    std::fs::remove_file(path)?;
    let identity = std::fs::read_link(&descriptor)?;
    let node = NodeId {
        name: String::from("component"),
    };
    let mut nodes = QemuNodeSet::new();
    nodes.insert(
        node.clone(),
        crate::node::tests::node_set_source_with_retained_file(file)?,
    );
    nodes.prepare_whole_shutdown(binding(), [&node])?;
    assert!(nodes.verify_whole_shutdown_return(binding()).is_err());
    assert_eq!(std::fs::read_link(&descriptor)?, identity);

    SimulationBackend::shutdown(&mut nodes)?;
    nodes.verify_whole_shutdown_return(binding())?;
    assert!(nodes.is_empty());
    assert_ne!(std::fs::read_link(&descriptor).ok(), Some(identity));
    // Reentry observes the same physical return without another node to signal.
    SimulationBackend::shutdown(&mut nodes)?;
    nodes.verify_whole_shutdown_return(binding())?;
    assert!(
        nodes
            .verify_whole_shutdown_return(ContentHash::from_bytes(b"foreign"))
            .is_err()
    );
    Ok(())
}

#[test]
fn insert_and_take_cannot_reuse_an_armed_or_returned_phase() -> Result<(), Box<dyn Error>> {
    let (node, backend) = actual_node()?;
    let mut nodes = QemuNodeSet::new();
    nodes.insert(node.clone(), backend);
    nodes.prepare_whole_shutdown(binding(), [&node])?;
    let mut backend = nodes.take(&node).ok_or("actual owner absent")?;
    assert!(backend.shutdown_child()?.reaped);
    nodes.insert(node.clone(), backend);
    SimulationBackend::shutdown(&mut nodes)?;
    assert!(nodes.verify_whole_shutdown_return(binding()).is_err());
    assert!(nodes.prepare_whole_shutdown(binding(), [&node]).is_err());

    let (node, backend) = actual_node()?;
    let mut nodes = QemuNodeSet::new();
    nodes.insert(node.clone(), backend);
    nodes.prepare_whole_shutdown(binding(), [&node])?;
    SimulationBackend::shutdown(&mut nodes)?;
    nodes.verify_whole_shutdown_return(binding())?;
    let (node, mut backend) = actual_node()?;
    assert!(backend.shutdown_child()?.reaped);
    nodes.insert(node.clone(), backend);
    SimulationBackend::shutdown(&mut nodes)?;
    assert!(nodes.verify_whole_shutdown_return(binding()).is_err());
    assert!(nodes.prepare_whole_shutdown(binding(), [&node]).is_err());
    Ok(())
}

#[test]
fn selected_replacement_invalidates_whole_return_without_weakening_its_checks()
-> Result<(), Box<dyn Error>> {
    let (node, mut backend) = actual_node()?;
    assert!(backend.shutdown_child()?.reaped);
    let mut nodes = QemuNodeSet::new();
    nodes.insert(node.clone(), backend);
    nodes.prepare_whole_shutdown(binding(), [&node])?;
    let plan = nodes.prepare_terminal_replacements(vec![node.clone()])?;
    let retired = nodes.commit_terminal_replacements(plan, &mut vec![None])?;
    assert_eq!(retired.len(), 1);
    assert!(retired[0].1.cleanup_physically_returned());
    drop(retired);
    SimulationBackend::shutdown(&mut nodes)?;
    assert!(nodes.verify_whole_shutdown_return(binding()).is_err());
    assert!(nodes.prepare_whole_shutdown(binding(), [&node]).is_err());
    assert!(nodes.settle_terminal_exits_for_return(&[node]).is_err());
    Ok(())
}

struct PanickingObserver {
    drops: Arc<AtomicUsize>,
}

impl Drop for PanickingObserver {
    fn drop(&mut self) {
        let previous = self.drops.fetch_add(1, Ordering::SeqCst);
        assert_eq!(previous, 0, "the actual observer must be destroyed once");
        panic!("component observer destruction interrupted");
    }
}

impl crate::QemuTestBlockCompletionObserver for PanickingObserver {
    fn before_completion(
        &self,
        _: &crucible_engine::model::ResolvedFaultTarget,
        _: crucible_device::block::BlockRequestIdentity,
        _: u64,
    ) -> Result<(), crate::QemuAsyncDriverRuntimeError> {
        Err(crate::QemuAsyncDriverRuntimeError::new(
            "component observer",
            "no block completion authority",
        ))
    }

    fn observation_guard(
        &self,
    ) -> Option<Arc<crucible_host_resources::host_supervision::HostOperationGuard>> {
        None
    }

    fn observe_native(
        &self,
        _: &crate::QmpHotForkBlockBarrierState,
    ) -> Result<(), crate::QemuNodeChannelError> {
        Err(crate::QemuNodeChannelError::new(
            "component observer",
            "no native observation authority",
        ))
    }
}

#[test]
fn actual_field_drop_unwind_permanently_refuses_empty_shutdown() -> Result<(), Box<dyn Error>> {
    let node = NodeId {
        name: String::from("component"),
    };
    let backend = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked)?;
    let drops = Arc::new(AtomicUsize::new(0));
    let mut nodes = QemuNodeSet::new();
    nodes.insert(node.clone(), backend);
    nodes.install_block_completion_observer_for_test(
        &node,
        Arc::new(PanickingObserver {
            drops: Arc::clone(&drops),
        }),
    )?;
    nodes.prepare_whole_shutdown(binding(), [&node])?;

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        SimulationBackend::shutdown(&mut nodes)
    }));
    let payload = unwound.expect_err("the actual node field must unwind during destruction");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"component observer destruction interrupted")
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(nodes.is_empty());

    assert!(nodes.verify_whole_shutdown_return(binding()).is_err());
    assert!(nodes.prepare_whole_shutdown(binding(), [&node]).is_err());
    assert!(SimulationBackend::shutdown(&mut nodes).is_err());
    assert!(nodes.release_reaped_nodes().is_err());
    assert!(nodes.verify_whole_shutdown_return(binding()).is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    Ok(())
}
