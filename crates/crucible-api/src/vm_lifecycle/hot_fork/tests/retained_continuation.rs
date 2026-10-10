//! Checks complete continuation custody under the launcher's negative phase gate.
//!
//! The launcher below models exclusion only; it issues no native park authority.

use super::*;

struct HeldLauncher;

impl ProductionVmNodeLauncher for HeldLauncher {
    fn parent_park_drain_is_owned(&self) -> bool {
        true
    }

    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        panic!("held Drop cannot begin guest execution")
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        panic!("held Drop cannot enter an ordinary boundary")
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _executable: &Path,
        _root_image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        panic!("held Drop cannot launch a node")
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        panic!("held Drop cannot restore a node")
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        panic!("held Drop cannot mint replay authority")
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        panic!("held Drop cannot release the containing owner")
    }
}

#[test]
fn held_drop_retains_complete_continuation_while_ordinary_drop_releases_it() {
    for held in [false, true] {
        let (_, lifecycle) = permanently_failed_loop();
        let mut world = lifecycle.prepare_hot_fork_source_world().unwrap();
        let continuation = world.continuation().unwrap();
        let scheduler = Arc::downgrade(&continuation.scheduler);
        let event_objects = Arc::downgrade(&continuation.event_log_objects);
        let signal_objects = Arc::downgrade(&continuation.signal_artifact_objects);

        if held {
            let lifecycle = world.lifecycle.as_mut().unwrap();
            lifecycle.node_launcher = Box::new(HeldLauncher);
        }
        drop(world);

        assert_eq!(scheduler.upgrade().is_some(), held);
        assert_eq!(event_objects.upgrade().is_some(), held);
        assert_eq!(signal_objects.upgrade().is_some(), held);
    }
}

#[test]
fn unavailable_continuation_refuses_access_and_fork_without_a_default_identity() {
    let (_, lifecycle) = permanently_failed_loop();
    let mut world = lifecycle.prepare_hot_fork_source_world().unwrap();
    let retained = world.continuation.take().unwrap();

    assert!(matches!(
        world.continuation(),
        Err(ProductionVmHotForkContinuationUnavailable)
    ));
    assert!(world.fork_continuation().is_err());
    assert!(world.mark_reuse_boundary_advanced_for_test().is_err());

    world.continuation = Some(retained);
    assert!(world.continuation().is_ok());
    assert!(world.recover().is_ok());
}
