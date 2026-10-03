//! Lease observation preserves original runtime and resource-guard precedence.

// crucible-lint: allow panic-shortcut -- Lease fixtures intentionally panic to localize invalid test setup and poisoned diagnostic mutexes.
#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::SchedulerOperationalFailureClass;

use super::*;

struct DefaultLease {
    identity: ProductionVmNodeGeneration,
    finishes: Arc<AtomicUsize>,
}

impl ProductionVmNodeLease for DefaultLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError> {
        Err(loop_factory_error(
            "test lease has no physical root overlay",
        ))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        self.finishes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct ObservedLease {
    inner: DefaultLease,
    observations: Arc<AtomicUsize>,
    diagnostic_error: Arc<std::sync::Mutex<Option<&'static str>>>,
}

impl ProductionVmNodeLease for ObservedLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        self.inner.identity()
    }

    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError> {
        self.inner.open_checkpoint_root_overlay()
    }

    fn observe_operational_diagnostics(&mut self) {
        self.observations.fetch_add(1, Ordering::Relaxed);
        *self.diagnostic_error.lock().expect("test diagnostic mutex") =
            Some("diagnostic capture loss");
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        self.inner.finish()
    }
}

fn identity() -> ProductionVmNodeGeneration {
    ProductionVmNodeGeneration::new(
        NodeId {
            name: "single".into(),
        },
        2,
    )
    .expect("valid test generation")
}

#[test]
fn default_lease_observer_does_not_release_or_change_generation_identity() {
    let finishes = Arc::new(AtomicUsize::new(0));
    let original = identity();
    let mut lease = DefaultLease {
        identity: original.clone(),
        finishes: Arc::clone(&finishes),
    };

    lease.observe_operational_diagnostics();
    assert_eq!(lease.identity(), &original);
    assert_eq!(finishes.load(Ordering::Relaxed), 0);
    lease.finish().expect("test lease release");
    assert_eq!(finishes.load(Ordering::Relaxed), 1);
}

fn operation(failed: bool) -> Result<u64, SchedulerError> {
    if failed {
        Err(SchedulerError::BoundaryViolation {
            message: "original quantum failed".into(),
        })
    } else {
        Ok(17)
    }
}

fn boundary(failed: bool) -> Result<(), LifecycleApiError> {
    if failed {
        Err(LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Canceled,
            message: "original guard canceled".into(),
        })
    } else {
        Ok(())
    }
}

#[test]
fn owned_observer_keeps_original_success_operation_error_and_guard_error() {
    for operation_failed in [false, true] {
        for boundary_failed in [false, true] {
            let finishes = Arc::new(AtomicUsize::new(0));
            let observations = Arc::new(AtomicUsize::new(0));
            let diagnostic_error = Arc::new(std::sync::Mutex::new(None));
            let original = identity();
            let lease = ObservedLease {
                inner: DefaultLease {
                    identity: original.clone(),
                    finishes: Arc::clone(&finishes),
                },
                observations: Arc::clone(&observations),
                diagnostic_error: Arc::clone(&diagnostic_error),
            };
            let mut leases: BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>> =
                BTreeMap::from([(original.node().clone(), Box::new(lease) as _)]);
            let expected = combine_attempt_quantum_boundary(
                operation(operation_failed),
                boundary(boundary_failed),
            );

            let operation = operation(operation_failed);
            let boundary = boundary(boundary_failed);
            observe_owned_node_diagnostics(&mut leases);
            let actual = combine_attempt_quantum_boundary(operation, boundary);

            assert_eq!(
                actual.map_err(|error| error.to_string()),
                expected.map_err(|error| error.to_string())
            );
            assert_eq!(observations.load(Ordering::Relaxed), 1);
            assert_eq!(
                *diagnostic_error.lock().expect("test diagnostic mutex"),
                Some("diagnostic capture loss")
            );
            assert_eq!(finishes.load(Ordering::Relaxed), 0);
            assert_eq!(
                leases.values().next().expect("owned test lease").identity(),
                &original
            );
        }
    }
}
