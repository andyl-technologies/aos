//! Scripted production whole-world composition regressions.

// crucible-lint: allow panic-shortcut -- fixture construction and assertions use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crucible::{Configuration, ContentHash};
use crucible_api::vm_lifecycle::{
    hot_fork_adoption_count_for_test, prepared_multi_node_hot_fork_source_world_for_test,
    reset_hot_fork_adoption_count_for_test,
};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignHash, CampaignLineage,
    ConfigurationArtifact, ConfigurationId, ExecutionId, ExecutionRetentionIntent,
    ScenarioArtifact, ScenarioDefId, StopCondition,
};
use crucible_qemu::{
    LinuxQemuHotForkChildProcessAuthority, QemuChildProcessContract, QemuHotForkChildProcessBasis,
    QemuHotForkChildProcessOwner, QemuLaunchResourceRequirements, QemuNodeChannelError,
    QemuPreparedRunDirectory, QemuTestHotForkOutcome, QemuVmRealizationError,
    linux_process_identity, scripted_hot_fork_source_for_test,
};
use rustix::process::{Pid, PidfdFlags, pidfd_open};

use super::*;
use crate::{
    AttemptExecutionKey, AttemptExecutionRuntimeBasis, ExecutionCancellation,
    ExecutionCheckpointRequest, QemuAttemptOperationalBoundary, QemuAttemptResourceGuard,
};

struct ScriptedWorldGuard {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    process_contract: QemuChildProcessContract,
    run_root: tempfile::TempDir,
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    retained_child_processes: Arc<Mutex<Vec<u32>>>,
    _liveness: Arc<()>,
    terminal: bool,
}

impl QemuAttemptOperationalBoundary for ScriptedWorldGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }
}

impl QemuAttemptResourceGuard for ScriptedWorldGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if !self.terminal {
            self.finishes.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.terminal {
            self.quarantines.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
    }
}

impl QemuAttemptProcessResourceGuard for ScriptedWorldGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Ok(&self.process_contract)
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let index = self
            .run_root
            .path()
            .read_dir()
            .map_err(test_realization_error)?
            .count();
        let generation = self.run_root.path().join(format!("generation-{index:03}"));
        std::fs::create_dir(&generation).map_err(test_realization_error)?;
        File::create(generation.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME))
            .map_err(test_realization_error)?;
        if requirements.has_root_overlay() {
            File::create(generation.join(crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME))
                .map_err(test_realization_error)?;
        }
        QemuPreparedRunDirectory::open_for_test_requirements(
            requirements,
            generation,
            &self.process_contract,
        )
        .map_err(test_realization_error)
    }

    fn retain_failed_launch_child(&mut self, _child: crucible_qemu::QemuNodeChild) {}
}

impl QemuHotForkChildProcessOwner for ScriptedWorldGuard {
    type Authority = LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        let process_id =
            Pid::from_raw(i32::try_from(basis.child_process_id()).map_err(|error| {
                QemuNodeChannelError::new("retain scripted child", error.to_string())
            })?)
            .ok_or_else(|| {
                QemuNodeChannelError::new("retain scripted child", "child PID must be positive")
            })?;
        let descriptor = pidfd_open(process_id, PidfdFlags::empty()).map_err(|error| {
            QemuNodeChannelError::new("open scripted child pidfd", error.to_string())
        })?;
        let identity = linux_process_identity(basis.child_process_id())
            .map_err(|error| {
                QemuNodeChannelError::new("authenticate scripted child", error.to_string())
            })?
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "authenticate scripted child",
                    "scripted child process is absent",
                )
            })?;
        self.retained_child_processes
            .lock()
            .map_err(|_error| {
                QemuNodeChannelError::new(
                    "record scripted child",
                    "scripted child registry is poisoned",
                )
            })?
            .push(basis.child_process_id());
        Ok(
            LinuxQemuHotForkChildProcessAuthority::from_unvalidated_test_parts(
                basis, identity, descriptor,
            ),
        )
    }
}

struct ScriptedWorldGuardFactory {
    observations: ScriptedWorldObservations,
}

#[derive(Clone)]
struct ScriptedWorldObservations {
    finishes: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    retained_child_processes: Arc<Mutex<Vec<u32>>>,
    guard_liveness: Arc<Mutex<Option<Weak<()>>>>,
}

impl ScriptedWorldObservations {
    fn new() -> Self {
        Self {
            finishes: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
            retained_child_processes: Arc::new(Mutex::new(Vec::new())),
            guard_liveness: Arc::new(Mutex::new(None)),
        }
    }
}

impl QemuAttemptResourceGuardFactory for ScriptedWorldGuardFactory {
    type Guard = ScriptedWorldGuard;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        let cgroup = tempfile::tempdir().map_err(test_realization_error)?;
        let cgroup_directory: OwnedFd = File::open(cgroup.path())
            .map_err(test_realization_error)?
            .into();
        let cgroup_procs: OwnedFd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(cgroup.path().join("cgroup.procs"))
            .map_err(test_realization_error)?
            .into();
        let cancellation_event = rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .map_err(test_realization_error)?;
        let process_contract = QemuChildProcessContract::from_unvalidated_hot_fork_test_descriptors(
            cgroup_directory,
            cgroup_procs,
            cancellation_event,
            resources.maximum_vcpus(),
            resources.maximum_resident_bytes(),
            resources.maximum_disk_bytes(),
        );
        let liveness = Arc::new(());
        *self
            .observations
            .guard_liveness
            .lock()
            .map_err(|_error| test_realization_error("guard liveness registry is poisoned"))? =
            Some(Arc::downgrade(&liveness));
        Ok(ScriptedWorldGuard {
            resources,
            cancellation,
            process_contract,
            run_root: tempfile::tempdir().map_err(test_realization_error)?,
            finishes: Arc::clone(&self.observations.finishes),
            quarantines: Arc::clone(&self.observations.quarantines),
            retained_child_processes: Arc::clone(&self.observations.retained_child_processes),
            _liveness: liveness,
            terminal: false,
        })
    }
}

fn test_realization_error(error: impl std::fmt::Display) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "construct scripted whole-world fixture",
        message: error.to_string(),
    }
}

fn execution_input() -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let definition = scenario.scenario_def();
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(definition.id().bytes));
    let scenario_artifact =
        ScenarioArtifact::new(scenario_id, 1, b"scenario".to_vec()).expect("scenario artifact");
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    let configuration = Configuration::genesis(definition);
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let configuration_artifact = ConfigurationArtifact::new(
        scenario_id,
        scenario_content,
        configuration_id,
        1,
        b"configuration".to_vec(),
    )
    .expect("configuration artifact");
    let configuration_content = configuration_artifact
        .id()
        .expect("configuration artifact id");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_content,
        configuration_id,
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("campaign lineage");
    let path = BranchPath::new(Vec::new()).expect("genesis path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("path id"),
        StopCondition::Terminal,
    )
    .expect("attempt");
    CrucibleAttemptExecution::from_test_parts(
        lineage,
        scenario,
        attempt,
        path,
        crate::CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn execution_basis(
    input: &CrucibleAttemptExecution,
    execution_byte: u8,
) -> AttemptExecutionRuntimeBasis {
    AttemptExecutionRuntimeBasis::new(
        AttemptExecutionKey::new(
            input.lineage().id().expect("lineage id"),
            input.attempt().id().expect("attempt id"),
        ),
        ExecutionId::from_bytes([execution_byte; 16]).expect("execution"),
    )
}

fn execution_context(
    input: &CrucibleAttemptExecution,
    execution_byte: u8,
) -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 64).expect("resources"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
    )
    .with_runtime_basis(execution_basis(input, execution_byte))
}

fn factory(
    source_world: ProductionVmHotForkSourceWorld,
    run_state_root: PathBuf,
    observations: ScriptedWorldObservations,
) -> QemuProductionHotForkWorldLifecycleFactory<
    QemuSingleHotForkSourceWorldProvider,
    ScriptedWorldGuardFactory,
> {
    QemuProductionHotForkWorldLifecycleFactory::new(
        QemuSingleHotForkSourceWorldProvider::new(source_world),
        ScriptedWorldGuardFactory { observations },
        run_state_root,
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    )
}

fn reconcile_canceled_world(
    lifecycle: &mut QemuProductionHotForkWorldLifecycle<ScriptedWorldGuard>,
) {
    let mut reconciled = false;
    for _ in 0..64 {
        if lifecycle
            .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
            .expect("reconcile world")
            == AttemptExecutionReconciliationStep::Complete
        {
            reconciled = true;
            break;
        }
    }
    assert!(reconciled);
}

#[test]
fn two_running_nodes_install_shutdown_reconcile_and_reuse_one_source_world() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (nodes, source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first, second])
            .expect("prepared source world");
    assert_eq!(nodes.len(), 2);

    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    let mut lifecycle = match factory.try_start(&input, &context).expect("start world") {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("exact source world declined"),
    };
    assert!(!factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    assert!(lifecycle.start_materialization().is_ok());
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown adopted world");
    assert!(!factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    reconcile_canceled_world(&mut lifecycle);

    let competing_source_owner = lifecycle.source_world_owner_for_test();
    let lifecycle = factory
        .recover(lifecycle)
        .expect_err("a competing source owner must defer recovery");
    drop(competing_source_owner);
    assert!(factory.recover(lifecycle).is_ok());

    assert!(factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);

    let second_context = execution_context(&input, 0x7a);
    let mut second_lifecycle = match factory
        .try_start(&input, &second_context)
        .expect("reuse source world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("reprepared source world declined"),
    };
    assert!(second_lifecycle.start_materialization().is_ok());
    QemuFreshAttemptLifecycleOwner::shutdown(&mut second_lifecycle)
        .expect("shutdown second adopted world");
    reconcile_canceled_world(&mut second_lifecycle);
    assert!(factory.recover(second_lifecycle).is_ok());

    assert!(factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 2);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn second_child_indeterminate_failure_quarantines_first_child_and_complete_world() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let first_source_process = first.process_id();
    let second = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Indeterminate)
        .expect("second source");
    let second_source_process = second.process_id();
    let (_nodes, source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first, second])
            .expect("prepared source world");
    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
        ))
    ));
    assert!(!factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
    assert!(linux_process_identity(first_source_process).is_ok_and(|identity| identity.is_some()));
    assert!(linux_process_identity(second_source_process).is_ok_and(|identity| identity.is_some()));
    let retained_children = observations
        .retained_child_processes
        .lock()
        .expect("retained child registry");
    assert_eq!(retained_children.len(), 1);
    assert!(
        PathBuf::from("/proc")
            .join(retained_children[0].to_string())
            .exists()
    );
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_some());
}

#[test]
fn second_adoption_failure_retains_first_adoption_and_complete_world() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let first_source_process = first.process_id();
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let second_source_process = second.process_id();
    let (nodes, mut source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first, second])
            .expect("prepared source world");
    source_world
        .replace_immutable_root_for_test(&nodes[1].0, ContentHash::from_bytes(b"mismatched-root"))
        .expect("replace second immutable root");
    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    reset_hot_fork_adoption_count_for_test();
    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(_)
        ))
    ));
    assert_eq!(hot_fork_adoption_count_for_test(), 1);
    assert!(!factory.sources().available());
    assert!(linux_process_identity(first_source_process).is_ok_and(|identity| identity.is_some()));
    assert!(linux_process_identity(second_source_process).is_ok_and(|identity| identity.is_some()));
    let retained_children = observations
        .retained_child_processes
        .lock()
        .expect("retained child registry");
    assert_eq!(retained_children.len(), 2);
    assert!(
        retained_children
            .iter()
            .all(|process| PathBuf::from("/proc").join(process.to_string()).exists())
    );
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_some());
}

#[test]
fn poisoned_source_owner_cannot_be_recovered_on_retry() {
    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source");
    let (_nodes, source_world) = prepared_multi_node_hot_fork_source_world_for_test(vec![source])
        .expect("prepared source world");
    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(source_world, run_state.path().to_path_buf(), observations);
    let mut lifecycle = match factory.try_start(&input, &context).expect("start world") {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("exact source world declined"),
    };
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown adopted world");
    reconcile_canceled_world(&mut lifecycle);

    let source_owner = lifecycle.source_world_owner_for_test();
    let poisoner = std::thread::spawn(move || {
        let _source = source_owner.lock().expect("lock source owner");
        panic!("poison source owner");
    });
    assert!(poisoner.join().is_err());

    let lifecycle = factory
        .recover(lifecycle)
        .expect_err("poisoned source owner must fail recovery");
    let lifecycle = factory
        .recover(lifecycle)
        .expect_err("recovery retry must preserve source poison");
    assert!(!factory.sources().available());
    factory.quarantine(lifecycle);
}
