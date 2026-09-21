//! Aggregate resource ownership and failure-recovery regressions.

use std::fs::File;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::NodeId;
use tempfile::TempDir;

use super::*;
use crate::QemuExecutionQuantumCounter;

#[derive(Debug)]
struct FakeGuard {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    counter: QemuExecutionQuantumCounter,
    process_contract: QemuChildProcessContract,
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    active_capacity: Option<Arc<AtomicUsize>>,
    run_root: TempDir,
    next_generation: usize,
    terminal: bool,
}

impl QemuAttemptOperationalBoundary for FakeGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.cancellation.is_canceled() {
            Err(QemuVmRealizationError::Canceled {
                operation: "check fake world resources",
            })
        } else {
            Ok(())
        }
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.check_operational_boundary()?;
        self.counter.charge()
    }
}

impl QemuAttemptResourceGuard for FakeGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.terminal {
            return Ok(());
        }
        self.finishes.fetch_add(1, Ordering::AcqRel);
        if let Some(active) = &self.active_capacity {
            active.fetch_sub(1, Ordering::AcqRel);
        }
        self.terminal = true;
        Ok(())
    }

    fn quarantine(&mut self) {
        if self.terminal {
            return;
        }
        self.quarantines.fetch_add(1, Ordering::AcqRel);
        if let Some(active) = &self.active_capacity {
            active.fetch_sub(1, Ordering::AcqRel);
        }
        self.terminal = true;
    }
}

impl QemuAttemptProcessResourceGuard for FakeGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Ok(&self.process_contract)
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let generation = self
            .run_root
            .path()
            .join(format!("generation-{:03}", self.next_generation));
        self.next_generation += 1;
        std::fs::create_dir(&generation)
            .map_err(|error| world_resource_error(error.to_string()))?;
        File::create(generation.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME))
            .map_err(|error| world_resource_error(error.to_string()))?;
        if requirements.has_root_overlay() {
            File::create(generation.join(crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME))
                .map_err(|error| world_resource_error(error.to_string()))?;
        }
        QemuPreparedRunDirectory::open_for_test_requirements(
            requirements,
            generation,
            &self.process_contract,
        )
        .map_err(|error| world_resource_error(error.to_string()))
    }

    fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {}
}

fn resources() -> Result<AttemptResourceLimits, QemuVmRealizationError> {
    AttemptResourceLimits::new(1, 1024 * 1024, 1024 * 1024 * 1024, 2)
        .map_err(|error| world_resource_error(error.to_string()))
}

fn identity(
    name: &str,
    generation: u64,
) -> Result<ProductionVmNodeGeneration, QemuVmRealizationError> {
    ProductionVmNodeGeneration::new(
        NodeId {
            name: name.to_owned(),
        },
        generation,
    )
    .map_err(|error| world_resource_error(error.to_string()))
}

fn guard(
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
) -> Result<FakeGuard, QemuVmRealizationError> {
    let resources = resources()?;
    let (cgroup_procs, _cgroup_peer) =
        UnixStream::pair().map_err(|error| world_resource_error(error.to_string()))?;
    let (cancellation_event, _cancellation_peer) =
        UnixStream::pair().map_err(|error| world_resource_error(error.to_string()))?;
    Ok(FakeGuard {
        resources,
        cancellation: ExecutionCancellation::default(),
        counter: QemuExecutionQuantumCounter::new(resources),
        process_contract: QemuChildProcessContract::from_unvalidated_test_descriptors(
            cgroup_procs.into(),
            cancellation_event.into(),
            resources.maximum_vcpus(),
            resources.maximum_resident_bytes(),
            resources.maximum_disk_bytes(),
        ),
        finishes,
        quarantines,
        active_capacity: None,
        run_root: TempDir::new().map_err(|error| world_resource_error(error.to_string()))?,
        next_generation: 0,
        terminal: false,
    })
}

struct OneCapacityGuardFactory {
    active: Arc<AtomicUsize>,
    begins: Arc<AtomicUsize>,
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
}

impl QemuAttemptResourceGuardFactory for OneCapacityGuardFactory {
    type Guard = FakeGuard;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        _selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
        if self
            .active
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(world_resource_error("one-capacity resource factory is occupied").into());
        }
        self.begins.fetch_add(1, Ordering::AcqRel);
        let mut admitted = guard(Arc::clone(&self.finishes), Arc::clone(&self.quarantines))?;
        admitted.resources = resources;
        admitted.cancellation = cancellation;
        admitted.counter = QemuExecutionQuantumCounter::new(resources);
        admitted.active_capacity = Some(Arc::clone(&self.active));
        Ok(admitted)
    }
}

fn finish_primary_lifecycle(
    owner: &mut QemuHotForkWorldResourceOwner<FakeGuard>,
    node: &str,
) -> Result<(), QemuVmRealizationError> {
    let mut target = owner.reserve_node(identity(node, 1)?)?;
    QemuAttemptResourceGuard::finish(&mut target)?;
    let mut lifecycle = owner.lifecycle_guard()?;
    QemuAttemptResourceGuard::finish(&mut lifecycle)
}

type TestAuxiliaryResourceFactory =
    QemuHotForkWorldAuxiliaryResourceFactory<OneCapacityGuardFactory>;
type TestAuxiliaryResourceGuard = QemuHotForkWorldAuxiliaryResourceGuard<FakeGuard>;

fn bound_auxiliary_resources(
    owner: &QemuHotForkWorldResourceOwner<FakeGuard>,
) -> Result<
    (
        QemuHotForkWorldAuxiliaryResourceBinding<FakeGuard>,
        TestAuxiliaryResourceFactory,
    ),
    QemuVmRealizationError,
> {
    let broker = QemuHotForkWorldAuxiliaryResourceBroker::new();
    let binding = broker.bind(owner)?;
    let factory = OneCapacityGuardFactory {
        active: Arc::new(AtomicUsize::new(0)),
        begins: Arc::new(AtomicUsize::new(0)),
        finishes: Arc::new(AtomicUsize::new(0)),
        quarantines: Arc::new(AtomicUsize::new(0)),
    };
    Ok((
        binding,
        QemuHotForkWorldAuxiliaryResourceFactory::new(broker, factory),
    ))
}

fn begin_auxiliary_resources(
    factory: &mut TestAuxiliaryResourceFactory,
    owner: &QemuHotForkWorldResourceOwner<FakeGuard>,
) -> Result<TestAuxiliaryResourceGuard, QemuVmRealizationError> {
    factory
        .begin(owner.resources, owner.cancellation.clone(), None)
        .map_err(|failure| failure.into_parts().0)
}

#[test]
fn aggregate_release_waits_for_every_exact_node_target() -> Result<(), QemuVmRealizationError> {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        2,
    )?;
    let mut first = owner.reserve_node(identity("first", 4)?)?;
    let mut second = owner.reserve_node(identity("second", 9)?)?;

    first.charge_execution_quantum()?;
    second.charge_execution_quantum()?;
    assert!(second.charge_execution_quantum().is_err());
    QemuAttemptResourceGuard::finish(&mut first)?;
    QemuAttemptResourceGuard::finish(&mut second)?;
    owner.finish()?;

    assert_eq!(finishes.load(Ordering::Acquire), 1);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn unfinished_or_duplicate_node_fails_closed() -> Result<(), QemuVmRealizationError> {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        1,
    )?;
    let target = owner.reserve_node(identity("node", 3)?)?;
    assert!(owner.reserve_node(identity("node", 4)?).is_err());
    assert!(owner.finish().is_err());
    drop(target);

    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn explicit_no_child_rollback_reopens_the_exact_slot() -> Result<(), QemuVmRealizationError> {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        1,
    )?;
    owner
        .reserve_node(identity("node", 3)?)?
        .abort_without_child()?;
    let mut retried = owner.reserve_node(identity("node", 3)?)?;
    QemuAttemptResourceGuard::finish(&mut retried)?;
    owner.finish()?;

    assert_eq!(finishes.load(Ordering::Acquire), 1);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn partial_world_rejection_rolls_back_only_the_unforked_node() -> Result<(), QemuVmRealizationError>
{
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        2,
    )?;
    let mut first = owner.reserve_node(identity("first", 4)?)?;
    owner
        .reserve_node(identity("second", 9)?)?
        .abort_without_child()?;

    let mut retried = owner.reserve_node(identity("second", 9)?)?;
    QemuAttemptResourceGuard::finish(&mut first)?;
    QemuAttemptResourceGuard::finish(&mut retried)?;
    owner.finish()?;

    assert_eq!(finishes.load(Ordering::Acquire), 1);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn partial_world_ambiguous_failure_quarantines_the_aggregate() -> Result<(), QemuVmRealizationError>
{
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        2,
    )?;
    let mut first = owner.reserve_node(identity("first", 4)?)?;
    let ambiguous = owner.reserve_node(identity("second", 9)?)?;
    QemuAttemptResourceGuard::finish(&mut first)?;

    drop(ambiguous);
    assert!(owner.finish().is_err());
    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn auxiliary_lifecycle_requires_complete_primary_cleanup() -> Result<(), QemuVmRealizationError> {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        1,
    )?;
    let (_binding, mut auxiliary_resources) = bound_auxiliary_resources(&owner)?;
    assert!(begin_auxiliary_resources(&mut auxiliary_resources, &owner).is_err());

    let mut target = owner.reserve_node(identity("node", 1)?)?;
    let mut lifecycle = owner.lifecycle_guard()?;
    QemuAttemptResourceGuard::finish(&mut lifecycle)?;
    assert!(begin_auxiliary_resources(&mut auxiliary_resources, &owner).is_err());

    QemuAttemptResourceGuard::finish(&mut target)?;
    let mut auxiliary = begin_auxiliary_resources(&mut auxiliary_resources, &owner)?;
    QemuAttemptResourceGuard::finish(&mut auxiliary)?;
    owner.finish()?;

    assert_eq!(finishes.load(Ordering::Acquire), 1);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn auxiliary_lifecycle_is_a_single_reusable_sequential_lease() -> Result<(), QemuVmRealizationError>
{
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        1,
    )?;
    finish_primary_lifecycle(&mut owner, "node")?;
    let (_binding, mut auxiliary_resources) = bound_auxiliary_resources(&owner)?;

    let mut first = begin_auxiliary_resources(&mut auxiliary_resources, &owner)?;
    assert!(begin_auxiliary_resources(&mut auxiliary_resources, &owner).is_err());
    QemuAttemptResourceGuard::finish(&mut first)?;

    let mut second = begin_auxiliary_resources(&mut auxiliary_resources, &owner)?;
    QemuAttemptResourceGuard::finish(&mut second)?;
    owner.finish()?;
    owner.finish()?;

    assert_eq!(finishes.load(Ordering::Acquire), 1);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn auxiliary_lifecycle_shares_one_capacity_quantum_and_cancellation()
-> Result<(), QemuVmRealizationError> {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        1,
    )?;
    let mut target = owner.reserve_node(identity("node", 1)?)?;
    target.charge_execution_quantum()?;
    QemuAttemptResourceGuard::finish(&mut target)?;
    let mut lifecycle = owner.lifecycle_guard()?;
    QemuAttemptResourceGuard::finish(&mut lifecycle)?;
    let (_binding, mut auxiliary_resources) = bound_auxiliary_resources(&owner)?;

    let mut auxiliary = begin_auxiliary_resources(&mut auxiliary_resources, &owner)?;
    assert_eq!(auxiliary.resource_limits(), owner.resources);
    assert!(
        auxiliary
            .cancellation()
            .same_incarnation(&owner.cancellation)
    );
    auxiliary.charge_execution_quantum()?;
    assert!(auxiliary.charge_execution_quantum().is_err());

    owner.cancellation.cancel_for_test();
    assert!(auxiliary.check_operational_boundary().is_err());
    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    QemuAttemptResourceGuard::finish(&mut auxiliary)?;
    owner.finish()?;

    assert_eq!(finishes.load(Ordering::Acquire), 1);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn bound_replay_factory_reuses_one_capacity_with_fresh_private_directories()
-> Result<(), QemuVmRealizationError> {
    let active = Arc::new(AtomicUsize::new(0));
    let begins = Arc::new(AtomicUsize::new(0));
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut one_capacity = OneCapacityGuardFactory {
        active: Arc::clone(&active),
        begins: Arc::clone(&begins),
        finishes: Arc::clone(&finishes),
        quarantines: Arc::clone(&quarantines),
    };
    let cancellation = ExecutionCancellation::default();
    let primary = one_capacity
        .begin(resources()?, cancellation.clone(), None)
        .map_err(|failure| failure.into_parts().0)?;
    let mut owner = QemuHotForkWorldResourceOwner::new(primary, 1)?;
    finish_primary_lifecycle(&mut owner, "primary")?;

    let broker = QemuHotForkWorldAuxiliaryResourceBroker::new();
    let binding = broker.bind(&owner)?;
    let mut replay_resources = QemuHotForkWorldAuxiliaryResourceFactory::new(broker, one_capacity);
    let requirements = QemuLaunchResourceRequirements::from_vm_shape(1, 1, false);

    let mut first = replay_resources
        .begin(resources()?, cancellation.clone(), None)
        .map_err(|failure| failure.into_parts().0)?;
    assert!(matches!(
        first,
        QemuHotForkWorldAuxiliaryResourceGuard::Retained(_)
    ));
    let first_path = first
        .prepare_generation_run_directory(requirements)?
        .path()
        .to_path_buf();
    assert!(
        replay_resources
            .begin(resources()?, cancellation.clone(), None)
            .is_err()
    );
    first.finish()?;

    let mut second = replay_resources
        .begin(resources()?, cancellation.clone(), None)
        .map_err(|failure| failure.into_parts().0)?;
    let second_path = second
        .prepare_generation_run_directory(requirements)?
        .path()
        .to_path_buf();
    assert_ne!(first_path, second_path);
    assert_eq!(begins.load(Ordering::Acquire), 1);
    assert_eq!(active.load(Ordering::Acquire), 1);
    second.finish()?;

    drop(binding);
    assert!(
        replay_resources
            .begin(resources()?, cancellation.clone(), None)
            .is_err()
    );
    owner.finish()?;
    assert_eq!(active.load(Ordering::Acquire), 0);

    let mut independent = replay_resources
        .begin(resources()?, cancellation, None)
        .map_err(|failure| failure.into_parts().0)?;
    assert!(matches!(
        independent,
        QemuHotForkWorldAuxiliaryResourceGuard::Fresh(_)
    ));
    let independent_path = independent
        .prepare_generation_run_directory(requirements)?
        .path()
        .to_path_buf();
    assert_ne!(first_path, independent_path);
    assert_ne!(second_path, independent_path);
    independent.finish()?;

    assert_eq!(begins.load(Ordering::Acquire), 2);
    assert_eq!(finishes.load(Ordering::Acquire), 2);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn auxiliary_cleanup_failure_quarantines_and_poisons_the_aggregate()
-> Result<(), QemuVmRealizationError> {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        1,
    )?;
    finish_primary_lifecycle(&mut owner, "node")?;
    let (_binding, mut auxiliary_resources) = bound_auxiliary_resources(&owner)?;
    let mut auxiliary = begin_auxiliary_resources(&mut auxiliary_resources, &owner)?;

    auxiliary.quarantine();
    assert!(begin_auxiliary_resources(&mut auxiliary_resources, &owner).is_err());
    assert!(owner.finish().is_err());

    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn aggregate_finish_refuses_an_active_auxiliary_lifecycle() -> Result<(), QemuVmRealizationError> {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkWorldResourceOwner::new(
        guard(Arc::clone(&finishes), Arc::clone(&quarantines))?,
        1,
    )?;
    finish_primary_lifecycle(&mut owner, "node")?;
    let (_binding, mut auxiliary_resources) = bound_auxiliary_resources(&owner)?;
    let auxiliary = begin_auxiliary_resources(&mut auxiliary_resources, &owner)?;

    assert!(owner.finish().is_err());
    drop(auxiliary);

    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 1);
    Ok(())
}
