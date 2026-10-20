//! Actual node-return and retained-lease controls without Source admission.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn retain_lease(lifecycle: &mut ProductionVmLifecycleLoop, node: &NodeId) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    lifecycle.node_generations.insert(node.clone(), 3);
    lifecycle.node_leases.insert(
        node.clone(),
        Box::new(RecordingNodeLease {
            identity: ProductionVmNodeGeneration::new(node.clone(), 3).unwrap(),
            finish_calls: Arc::clone(&calls),
            finish_order: None,
            fail: false,
        }),
    );
    calls
}

#[test]
fn empty_backend_never_returns_an_unmatched_existing_lease() {
    let mut lifecycle = production_loop_without_backends(&initially_violated_scenario());
    let node = node();
    let calls = retain_lease(&mut lifecycle, &node);

    assert!(lifecycle.prepare_whole_node_shutdown().is_err());
    crucible_engine::SimulationBackend::shutdown(lifecycle.inner.backend_mut()).unwrap();
    assert!(lifecycle.prepare_whole_node_shutdown().is_err());

    assert!(lifecycle.node_leases.contains_key(&node));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn semantic_shutdown_error_keeps_actual_clear_for_same_lease_return() {
    let source = initially_violated_scenario();
    let node = source.world().vm_nodes().iter().next().unwrap().id.clone();
    let mut lifecycle = production_loop_without_backends(&source);
    let calls = retain_lease(&mut lifecycle, &node);
    let backend = crucible_qemu_host::scripted_hot_fork_source_with_observations_for_test(
        crucible_qemu_host::QemuTestHotForkOutcome::Forked,
        vec![crucible_engine::ObservableEvent::console_output(
            VirtualTime { ticks: 1 },
            node.clone(),
            b"uncommitted future output".to_vec(),
        )],
    )
    .unwrap();
    assert!(
        lifecycle
            .inner
            .backend_mut()
            .insert(node.clone(), backend)
            .is_none()
    );
    let binding = lifecycle.prepare_whole_node_shutdown().unwrap();

    let semantic = lifecycle.inner.shutdown().unwrap_err();
    assert!(semantic.to_string().contains("uncommitted"));
    assert!(lifecycle.inner.backend().is_empty());
    lifecycle.finish_whole_node_leases(binding).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(lifecycle.node_leases.is_empty());
}

struct RefuseOnceLease {
    identity: ProductionVmNodeGeneration,
    calls: Arc<AtomicUsize>,
}

impl ProductionVmNodeLease for RefuseOnceLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError> {
        Err(loop_factory_error(
            "component lease supplies no checkpoint grant",
        ))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(loop_factory_error("actual component lease return refusal"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn failed_lease_reuses_actual_return_without_another_child_or_original() {
    let mut lifecycle = production_loop_without_backends(&initially_violated_scenario());
    let node = node();
    let calls = Arc::new(AtomicUsize::new(0));
    lifecycle.node_generations.insert(node.clone(), 3);
    lifecycle.node_leases.insert(
        node.clone(),
        Box::new(RefuseOnceLease {
            identity: ProductionVmNodeGeneration::new(node.clone(), 3).unwrap(),
            calls: Arc::clone(&calls),
        }),
    );
    let backend = crucible_qemu_host::scripted_hot_fork_source_for_test(
        crucible_qemu_host::QemuTestHotForkOutcome::Forked,
    )
    .unwrap();
    let supervisor = backend.host_operation_supervisor().unwrap().clone();
    lifecycle.inner.backend_mut().insert(node.clone(), backend);
    let binding = lifecycle.prepare_whole_node_shutdown().unwrap();
    crucible_engine::SimulationBackend::shutdown(lifecycle.inner.backend_mut()).unwrap();
    let completed = supervisor.operation_statuses().unwrap();

    assert!(lifecycle.finish_whole_node_leases(binding).is_err());
    assert!(lifecycle.node_leases.contains_key(&node));
    lifecycle.node_generations.remove(&node);
    assert!(lifecycle.prepare_whole_node_shutdown().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    lifecycle.node_generations.insert(node.clone(), 4);
    assert!(lifecycle.prepare_whole_node_shutdown().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    lifecycle.node_generations.insert(node.clone(), 3);
    assert_eq!(lifecycle.prepare_whole_node_shutdown().unwrap(), binding);
    lifecycle.finish_whole_node_leases(binding).unwrap();

    assert!(lifecycle.inner.backend().is_empty());
    assert!(lifecycle.node_leases.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(supervisor.operation_statuses().unwrap(), completed);
    assert!(lifecycle.node_lease_cleanup_failed);
}
