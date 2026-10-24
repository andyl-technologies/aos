//! Tests configuration rebinding for attempt-launched retained sources.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;

/// Records whether attempt bindings were released, optionally refusing.
struct BindingLauncher {
    released: Arc<AtomicBool>,
    refuse: bool,
}

impl ProductionVmNodeLauncher for BindingLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _executable: &Path,
        _root_image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error("test launcher does not spawn"))
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _exact: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error("test launcher does not spawn"))
    }

    fn release_execution_bindings(&mut self) -> Result<(), LifecycleApiError> {
        if self.refuse {
            return Err(loop_factory_error("test launcher keeps its bindings"));
        }
        self.released.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(loop_factory_error("test launcher does not admit replay"))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}

fn lifecycle_with_launcher(refuse: bool) -> (ProductionVmLifecycleLoop, Arc<AtomicBool>) {
    let (_source, mut lifecycle) = production_permanently_failed_loop_for_test()
        .unwrap_or_else(|error| panic!("process-free lifecycle should build: {error}"));
    let released = Arc::new(AtomicBool::new(false));
    lifecycle.node_launcher = Box::new(BindingLauncher {
        released: Arc::clone(&released),
        refuse,
    });
    (lifecycle, released)
}

fn recovered(
    failure: ProductionVmHotForkSourceWorldPreparationFailure,
) -> ProductionVmLifecycleLoop {
    failure
        .into_recovered_lifecycle()
        .unwrap_or_else(|failure| panic!("rejection should return the lifecycle: {failure}"))
}

#[test]
fn resume_configuration_replaces_replay_inputs_after_releasing_bindings() {
    let (lifecycle, released) = lifecycle_with_launcher(false);
    let timeout = lifecycle.config.completion_timeout() + Duration::from_secs(1);
    let config = lifecycle
        .config
        .clone()
        .with_completion_timeout(timeout)
        .with_unbounded_advance_completion();

    let source = lifecycle
        .prepare_hot_fork_source_world_with_config(config)
        .unwrap_or_else(|error| panic!("matching launch basis should prepare: {error}"));

    assert!(released.load(Ordering::SeqCst));
    let inherited = &source.continuation().config;
    assert_eq!(inherited.completion_timeout(), timeout);
    assert!(inherited.unbounded_advance_completion());
}

#[test]
fn resume_configuration_cannot_change_the_launch_basis() {
    let (lifecycle, released) = lifecycle_with_launcher(false);
    let budget = lifecycle.config.quantum_budget();
    let config = lifecycle.config.clone().with_quantum_budget(budget + 1);

    let failure = lifecycle
        .prepare_hot_fork_source_world_with_config(config)
        .err()
        .unwrap_or_else(|| panic!("a changed quantum budget must be rejected"));

    assert!(
        failure
            .to_string()
            .ends_with("launch basis: quantum_budget"),
        "the refusal names the changed field: {failure}"
    );
    assert!(!released.load(Ordering::SeqCst));
    assert_eq!(recovered(failure).config.quantum_budget(), budget);
}

#[test]
fn resume_configuration_keeps_the_attempt_trace_segment_store() {
    let (mut lifecycle, _released) = lifecycle_with_launcher(false);
    let segments: Arc<dyn SegmentSink> =
        Arc::new(crucible::segment_store::SharedSegmentStore::new());
    let trusted = lifecycle.config.clone();
    lifecycle.config = trusted
        .clone()
        .with_fault_trace_segments(Arc::clone(&segments));

    // A resume configuration derived from the trusted base names no store;
    // the retained world keeps sealing into the one it launched with.
    let source = lifecycle
        .prepare_hot_fork_source_world_with_config(trusted)
        .unwrap_or_else(|error| panic!("an unset store should adopt the launched one: {error}"));

    let inherited = source.continuation().config.fault_trace_segments.as_ref();
    assert!(inherited.is_some_and(|inherited| Arc::ptr_eq(inherited, &segments)));
}

#[test]
fn resume_configuration_cannot_replace_the_trace_segment_store() {
    let (mut lifecycle, released) = lifecycle_with_launcher(false);
    let launched: Arc<dyn SegmentSink> =
        Arc::new(crucible::segment_store::SharedSegmentStore::new());
    let replacement: Arc<dyn SegmentSink> =
        Arc::new(crucible::segment_store::SharedSegmentStore::new());
    let trusted = lifecycle.config.clone();
    lifecycle.config = trusted.clone().with_fault_trace_segments(launched);

    let failure = lifecycle
        .prepare_hot_fork_source_world_with_config(trusted.with_fault_trace_segments(replacement))
        .err()
        .unwrap_or_else(|| panic!("a different trace store must be rejected"));

    assert!(
        failure
            .to_string()
            .ends_with("launch basis: fault_trace_segments"),
        "the refusal names the store: {failure}"
    );
    assert!(!released.load(Ordering::SeqCst));
}

#[test]
fn resume_configuration_cannot_schedule_a_branch_boundary() {
    let (lifecycle, released) = lifecycle_with_launcher(false);
    let base = lifecycle.inner.loop_impl().configuration().clone();
    let config = lifecycle
        .config
        .clone()
        .with_branch_boundary(base, VirtualTime { ticks: 1 });

    let failure = lifecycle
        .prepare_hot_fork_source_world_with_config(config)
        .err()
        .unwrap_or_else(|| panic!("a branch boundary must be rejected"));

    assert!(!released.load(Ordering::SeqCst));
    assert!(!recovered(failure).config.has_pending_branch_boundary());
}

#[test]
fn refused_binding_release_keeps_the_attempt_configuration() {
    let (lifecycle, _released) = lifecycle_with_launcher(true);
    let original = lifecycle.config.completion_timeout();
    let config = lifecycle
        .config
        .clone()
        .with_completion_timeout(original + Duration::from_secs(1));

    let failure = lifecycle
        .prepare_hot_fork_source_world_with_config(config)
        .err()
        .unwrap_or_else(|| panic!("a refused release must fail preparation"));

    assert_eq!(recovered(failure).config.completion_timeout(), original);
}
