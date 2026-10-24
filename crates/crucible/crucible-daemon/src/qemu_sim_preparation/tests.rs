//! Clock data and original preparation custody, never native execution authority.
//!
//! Reference metadata is an inert builder fixture, not installed source/class
//! evidence. Two cleanup controls use a real owned sleep child with scripted
//! QEMU channels; they do not execute QEMU, grant a common operation, or qualify
//! the legacy protocol as full-phase native evidence.

// crucible-lint: allow panic-shortcut -- Assertions and fixture setup panics are the test oracle.
#![allow(clippy::unwrap_used)]

use super::*;
use std::cell::Cell;

#[cfg(feature = "test-support")]
use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_campaign::AttemptResourceLimits;
#[cfg(feature = "test-support")]
use crucible_engine::node_contract::{
    ProviderPreparationPlan, ProviderRegistryLimits, ProviderWorldPreparation, RuntimeCustodyQueue,
    RuntimeCustodySupervisor, RuntimeLimits,
};
use crucible_node_format::{Extensions, LiveAuthority, Phase, Position, canonical};
use crucible_node_transport::reference_service::ReferenceProfile;
use crucible_qemu_host::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuLogicalTimeCalibration,
    QemuNodeChild, QemuPreparedRunDirectory, QemuVmRealizationError,
};

use crate::{ExecutionCancellation, QemuAttemptOperationalBoundary, QemuAttemptResourceGuard};

fn boundary(ticks: u64) -> Position {
    Position::new(ticks.into(), 0.into(), Phase::BoundaryControl)
}

#[test]
fn reported_idle_bias_is_preserved_without_reinterpreting_logical_ceiling_as_raw() {
    let reported = QemuLogicalTimeCalibration {
        logical_icount: 1_250,
        raw_icount: 20,
    };
    let clock = QemuSimClockLattice::from_calibration(reported).unwrap();

    assert_eq!(clock.reported(), reported);
    assert_eq!(clock.logical_time(20).unwrap().ticks, 1_250);
    assert_eq!(clock.logical_time(31).unwrap().ticks, 1_800);
    assert_eq!(
        clock.legacy_ceiling(boundary(1_800)).unwrap().retired,
        1_800
    );
    assert_eq!(crucible_engine::SIM_TICKS_PER_INSTRUCTION, 50);
}

#[test]
fn calibration_and_boundary_refuse_overflow_rounding_and_partial_superdense_positions() {
    assert!(
        QemuSimClockLattice::from_calibration(QemuLogicalTimeCalibration {
            logical_icount: 49,
            raw_icount: 1,
        })
        .is_err()
    );
    assert!(
        QemuSimClockLattice::from_calibration(QemuLogicalTimeCalibration {
            logical_icount: u64::MAX,
            raw_icount: u64::MAX,
        })
        .is_err()
    );
    let clock = QemuSimClockLattice::from_calibration(QemuLogicalTimeCalibration {
        logical_icount: 1_251,
        raw_icount: 20,
    })
    .unwrap();

    assert!(clock.logical_time(u64::MAX).is_err());
    assert!(clock.legacy_ceiling(boundary(1_250)).is_err());
    assert!(clock.legacy_ceiling(boundary(1_300)).is_err());
    assert_eq!(
        clock.legacy_ceiling(boundary(1_301)).unwrap().retired,
        1_301
    );
    assert!(
        clock
            .legacy_ceiling(Position::new(
                1_301.into(),
                1.into(),
                Phase::BoundaryControl
            ))
            .is_err()
    );
    for phase in [Phase::Publication, Phase::Delivery, Phase::Reaction] {
        assert!(
            clock
                .legacy_ceiling(Position::new(1_301.into(), 0.into(), phase))
                .is_err()
        );
    }
}

#[derive(Default)]
struct Counts {
    checks: Cell<usize>,
    finishes: Cell<usize>,
    quarantines: Cell<usize>,
    drops: Cell<usize>,
}

struct ModelGuard {
    counts: Rc<Counts>,
    cancellation: ExecutionCancellation,
}

impl Drop for ModelGuard {
    fn drop(&mut self) {
        self.counts.drops.set(self.counts.drops.get() + 1);
    }
}

impl QemuAttemptOperationalBoundary for ModelGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1).unwrap()
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.counts.checks.set(self.counts.checks.get() + 1);
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("preparation must never charge or execute a quantum")
    }
}

impl QemuAttemptResourceGuard for ModelGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.counts.finishes.set(self.counts.finishes.get() + 1);
        Ok(())
    }

    fn quarantine(&mut self) {
        self.counts
            .quarantines
            .set(self.counts.quarantines.get() + 1);
    }
}

impl QemuAttemptProcessResourceGuard for ModelGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "model original guard association",
            message: "model guard has no genuine child process contract".into(),
        })
    }

    fn prepare_generation_run_directory(
        &mut self,
        _: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        panic!("preparation custody test must not launch a generation")
    }

    fn retain_failed_launch_child(&mut self, _: QemuNodeChild) {
        panic!("preparation custody test must not extract the original child")
    }
}

fn id(text: &str) -> Id {
    Id::new(text).unwrap()
}

fn fixture() -> (
    Box<PreparedQemuSimNode<ModelGuard>>,
    QemuSimPreparationSupervisor<ModelGuard>,
    Rc<Counts>,
    ActivationRecord,
) {
    let artifact = canonical::content_ref(b"inert preparation metadata", "text/plain").unwrap();
    let profile = ReferenceProfile::build(
        id("node"),
        id("owner"),
        artifact.clone(),
        artifact.clone(),
        1_000.into(),
        1_000_000.into(),
    )
    .unwrap();
    let (binding, _) = profile
        .bind(LiveAuthority {
            schema_version: 1,
            session_id: id("session"),
            incarnation_id: id("incarnation"),
            realization_id: id("realization"),
            activation_id: None,
            world_generation: 0.into(),
            owner_generation: 1.into(),
            input_epoch: id("epoch"),
            host_receipt: artifact,
            extensions: Extensions::new(),
        })
        .unwrap();
    let owner = OwnerIdentity {
        owner: id("owner"),
        incarnation: id("incarnation"),
        generation: 1.into(),
    };
    let route = NodeRoute {
        node: id("node"),
        owners: vec![owner.clone()],
    };
    let activation = ActivationRecord {
        generation: 1.into(),
        activation_id: id("activation"),
        world_binding_hash: canonical::hash("cnp.world-binding.v1", b"inert preparation world")
            .unwrap(),
        owners: vec![owner],
        boundary: boundary(0),
    };
    let counts = Rc::new(Counts::default());
    let (node, supervisor) = PreparedQemuSimNode::reserve_storage(
        profile.descriptor,
        binding,
        route,
        ModelGuard {
            counts: Rc::clone(&counts),
            cancellation: ExecutionCancellation::default(),
        },
        None,
    );

    (node, supervisor, counts, activation)
}

#[test]
fn original_identity_and_conflicting_loans_refuse_before_callbacks_or_renewal() {
    let (mut node, mut supervisor, counts, activation) = fixture();
    assert!(Rc::ptr_eq(&node.original, &supervisor.original));
    assert!(node.facets().is_empty());
    assert!(node.arm(&activation).is_err());
    assert!(node.facet(FacetKind::ExactExecution).is_err());

    let original = Rc::clone(&supervisor.original);
    let loan = original.resources.borrow_mut();
    assert!(
        supervisor
            .install_original(&mut None)
            .unwrap_err()
            .reason
            .contains("borrowed")
    );
    assert_eq!(counts.checks.get(), 0);
    drop(loan);

    assert!(supervisor.install_original(&mut None).is_err());
    assert!(
        supervisor
            .install_original(&mut None)
            .unwrap_err()
            .reason
            .contains("renewed")
    );
    assert_eq!(counts.checks.get(), 0);
    supervisor.reclaim_preparation().unwrap();
    assert_eq!(counts.finishes.get(), 1);
    assert!(supervisor.clock().is_err());
    drop(original);
    drop(supervisor);
    drop(node);
    assert_eq!(counts.drops.get(), 1);
}

#[test]
fn raw_creator_check_precedes_contested_storage_and_guard_access() {
    let (node, mut supervisor, counts, _) = fixture();
    drop(node);
    let original = Rc::get_mut(&mut supervisor.original).unwrap();
    let real = original.creator_pid;
    original.creator_pid = real.checked_add(1).unwrap();
    let loan = original.resources.borrow_mut();

    assert!(
        original
            .loan()
            .err()
            .unwrap()
            .reason
            .contains("creator process")
    );
    assert_eq!(counts.checks.get(), 0);
    drop(loan);
    original.creator_pid = real;
    supervisor.reclaim_preparation().unwrap();
    drop(supervisor);
    assert_eq!(counts.drops.get(), 1);
}

#[cfg(feature = "test-support")]
fn enrolled_original(refuse_route: bool, unwind: bool) {
    use crucible_qemu_host::{QemuTestHotForkOutcome, scripted_hot_fork_source_for_test};

    let (mut node, mut supervisor, counts, activation) = fixture();
    let plan = ProviderPreparationPlan {
        descriptors: vec![node.descriptor.clone()],
        bindings: vec![node.binding.compatibility.clone()],
    };
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let limits = RuntimeLimits::default();
    let slot = queue.reserve_world(&activation, limits).unwrap();
    let mut world = match ProviderWorldPreparation::for_world(
        &plan,
        &activation,
        limits,
        ProviderRegistryLimits::default(),
        slot,
    ) {
        Ok(world) => world,
        Err(failure) => panic!("inert world reservation: {}", failure.reason),
    };
    let mut incoming =
        Some(scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).unwrap());
    let original_pid = incoming.as_ref().unwrap().process_id();

    // The model guard deliberately has no genuine process contract. Refusal
    // follows the real child move and operational check, before native clock
    // observation. Nothing about this scripted process can establish QEMU Ready.
    assert!(supervisor.install_original(&mut incoming).is_err());
    assert!(incoming.is_none());
    assert_eq!(
        supervisor
            .original
            .loan()
            .unwrap()
            .as_ref()
            .unwrap()
            .node
            .as_ref()
            .unwrap()
            .process_id(),
        original_pid
    );
    if refuse_route {
        node.route.node = id("foreign-node");
    }
    let mut participant = Some(node.into_participant());
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let result = world.append_original(0, &mut participant);
        if unwind {
            assert!(result.is_ok());
            panic!("modeled contributor unwinds after original adoption");
        }
        assert!(result.is_err());
    }));

    assert_eq!(outcome.is_err(), unwind);
    assert!(participant.is_none());
    assert_eq!(counts.finishes.get(), 0);
    drop(world);
    assert_eq!(queue.retained_worlds(), 1);
    assert_eq!(counts.drops.get(), 0);
    assert_eq!(
        supervisor
            .original
            .loan()
            .unwrap()
            .as_ref()
            .unwrap()
            .node
            .as_ref()
            .unwrap()
            .process_id(),
        original_pid
    );

    assert!(supervisor.reclaim_preparation().is_err());
    let loan = supervisor.original.loan().unwrap();
    assert!(loan.as_ref().unwrap().node.as_ref().unwrap().child_reaped());
    assert!(!loan.as_ref().unwrap().released);
    assert_eq!(counts.finishes.get(), 0);
    assert_eq!(counts.quarantines.get(), 1);
}

#[cfg(feature = "test-support")]
#[test]
fn refused_enrollment_reaps_same_original_and_keeps_unmatched_guard_quarantined() {
    enrolled_original(true, false);
}

#[cfg(feature = "test-support")]
#[test]
fn contributor_unwind_retains_the_same_original_under_the_global_slot() {
    enrolled_original(false, true);
}
