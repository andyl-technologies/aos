//! Exercises exact local generation return without lending native authority.

// crucible-lint: allow panic-shortcut -- registry controls use deliberate fixture assertions.
#![allow(clippy::expect_used)]

use super::*;

struct RegistryGuard {
    cancellation: ExecutionCancellation,
}

impl crate::QemuAttemptOperationalBoundary for RegistryGuard {
    fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
        crucible_campaign::AttemptResourceLimits::new(1, 64 * 1024 * 1024, 128 * 1024 * 1024, 8)
            .expect("component resource limits")
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("registry controls cannot execute a guest")
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("registry controls cannot execute a guest")
    }
}

impl QemuAttemptResourceGuard for RegistryGuard {
    fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        Ok(())
    }

    fn quarantine(&mut self) {
        panic!("an owned no-process lease must not be abandoned")
    }
}

fn owner() -> QemuAttemptGenerationResourceOwner<RegistryGuard> {
    let node = NodeId {
        name: String::from("vm-a"),
    };
    let storage = QemuAttemptGenerationStorage::prepare(std::iter::once(&node))
        .expect("actual selected registry");
    QemuAttemptGenerationResourceOwner::new(
        RegistryGuard {
            cancellation: ExecutionCancellation::default(),
        },
        storage,
    )
}

fn generation(value: u64) -> ProductionVmNodeGeneration {
    ProductionVmNodeGeneration::new(
        NodeId {
            name: String::from("vm-a"),
        },
        value,
    )
    .expect("positive generation")
}

#[test]
fn contention_retains_the_same_no_process_lease_for_exact_retry() {
    let mut owner = owner();
    let mut pending = owner
        .register_generation(generation(1))
        .expect("register actual lease");
    let identity = pending.identity().clone();
    let registry = Arc::clone(&pending.generations);
    let locked = registry.lock().expect("hold actual registry");

    assert!(pending.abort_without_process().is_err());
    assert!(!pending.finished);
    assert_eq!(pending.identity(), &identity);
    assert!(!locked.abandoned);
    assert_eq!(locked.nodes[0].active[0], Some(1));
    drop(locked);

    pending
        .abort_without_process()
        .expect("same lease return after contention");
    assert!(pending.abort_without_process().is_err(), "no second return");
    let mut retry = owner
        .register_generation(identity)
        .expect("exact generation reusable");
    retry.abort_without_process().expect("return exact retry");
    owner.finish().expect("no abandoned local generation");
}

#[test]
fn nonlatest_no_process_refusal_preserves_both_issued_leases() {
    let mut owner = owner();
    let mut first = owner
        .register_generation(generation(1))
        .expect("first actual lease");
    let mut next = owner
        .register_generation(generation(2))
        .expect("second actual lease");

    assert!(first.abort_without_process().is_err());
    assert!(!first.finished);
    assert!(!next.finished);
    assert!(
        !owner
            .generations
            .lock()
            .expect("registry observation")
            .abandoned
    );

    next.abort_without_process()
        .expect("restore actual previous fence");
    first
        .abort_without_process()
        .expect("return same first lease");
    owner.finish().expect("both exact leases physically absent");
}

#[test]
fn monotone_generation_return_never_reopens_the_entered_generation() {
    let mut owner = owner();
    let mut entered = owner
        .register_generation(generation(1))
        .expect("actual local generation");

    entered
        .finish()
        .expect("monotone local return after caller-proved physical cleanup");
    assert!(entered.finished);
    assert!(owner.register_generation(generation(1)).is_err());
    let mut successor = owner
        .register_generation(generation(2))
        .expect("next generation advances");
    successor
        .abort_without_process()
        .expect("return unentered successor");
    assert!(owner.register_generation(generation(1)).is_err());
    owner.finish().expect("no active local generation");
}
