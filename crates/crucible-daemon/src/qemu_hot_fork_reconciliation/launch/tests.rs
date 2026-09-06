//! Production source-world launch regressions through scripted QMP.

// crucible-lint: allow panic-shortcut -- fixture-only unreachable process retention and assertions use panic shortcuts.
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::Configuration;
use crucible_api::vm_lifecycle::prepared_hot_fork_source_world_for_test;
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignHash, CampaignLineage,
    ConfigurationArtifact, ConfigurationId, ExecutionId, ScenarioArtifact, ScenarioDefId,
    StopCondition,
};
use crucible_qemu::{
    QemuChildProcessContract, QemuHotForkChildProcessBasis, QemuHotForkChildProcessOwner,
    QemuLaunchResourceRequirements, QemuNodeChannelError, QemuPreparedRunDirectory,
    QemuTestHotForkOutcome, QemuVmRealizationError, scripted_hot_fork_source_for_test,
};

use super::*;
use crate::{
    AttemptExecutionKey, AttemptExecutionRuntimeBasis, ExecutionCancellation,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
};

struct ScriptedLaunchGuard {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    process_contract: QemuChildProcessContract,
    run_root: tempfile::TempDir,
    preparations: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    terminal: bool,
}

impl QemuAttemptOperationalBoundary for ScriptedLaunchGuard {
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

impl QemuAttemptResourceGuard for ScriptedLaunchGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.terminal = true;
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.terminal {
            self.quarantines.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
    }
}

impl QemuAttemptProcessResourceGuard for ScriptedLaunchGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Ok(&self.process_contract)
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        requirements
            .validate_ceiling(
                self.resources.maximum_vcpus(),
                self.resources.maximum_resident_bytes(),
                self.resources.maximum_disk_bytes(),
            )
            .map_err(|source| launch_test_error(source.to_string()))?;

        let generation = self.run_root.path().join(format!(
            "generation-{}",
            self.preparations.load(Ordering::SeqCst)
        ));
        std::fs::create_dir(&generation).map_err(|source| launch_test_error(source.to_string()))?;
        File::create(generation.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME))
            .map_err(|source| launch_test_error(source.to_string()))?;
        if requirements.has_root_overlay() {
            File::create(generation.join(crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME))
                .map_err(|source| launch_test_error(source.to_string()))?;
        }
        QemuPreparedRunDirectory::open_for_test_requirements(
            requirements,
            &generation,
            &self.process_contract,
        )
        .map_err(|source| launch_test_error(source.to_string()))
    }

    fn retain_failed_launch_child(&mut self, _child: crucible_qemu::QemuNodeChild) {}
}

impl QemuHotForkChildProcessOwner for ScriptedLaunchGuard {
    type Authority = crucible_qemu::LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        _basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        panic!("indeterminate fixture must fail before child-process retention")
    }
}

fn scripted_guard(
    resources: AttemptResourceLimits,
    preparations: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
) -> Result<ScriptedLaunchGuard, Box<dyn Error>> {
    let cgroup = tempfile::tempdir()?;
    let cgroup_directory: OwnedFd = File::open(cgroup.path())?.into();
    let cgroup_procs: OwnedFd = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(cgroup.path().join("cgroup.procs"))?
        .into();
    let cancellation = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )?;
    let process_contract = QemuChildProcessContract::from_unvalidated_hot_fork_test_descriptors(
        cgroup_directory,
        cgroup_procs,
        cancellation,
        resources.maximum_vcpus(),
        resources.maximum_resident_bytes(),
        resources.maximum_disk_bytes(),
    );

    Ok(ScriptedLaunchGuard {
        resources,
        cancellation: ExecutionCancellation::default(),
        process_contract,
        run_root: tempfile::tempdir()?,
        preparations,
        quarantines,
        terminal: false,
    })
}

fn launch_test_error(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "build scripted hot-fork launch target",
        message: message.into(),
    }
}

#[test]
fn indeterminate_qmp_launch_retains_source_world_and_prepared_directory()
-> Result<(), Box<dyn Error>> {
    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Indeterminate)?;
    let (node, generation, source_world) = prepared_hot_fork_source_world_for_test(source)?;
    let source_world = Arc::new(Mutex::new(source_world));
    let retained_source = Arc::clone(&source_world);
    let weak_source = Arc::downgrade(&source_world);
    let continuation = source_world
        .lock()
        .map_err(|_| std::io::Error::other("source-world lock poisoned"))?
        .fork_continuation()?;
    let assembly = crate::QemuHotForkWorldAssembly::<
        QemuHotForkAttemptReconciliation<
            LinuxQemuHotForkReconciliationBackend<
                crate::QemuHotForkWorldNodeTarget<ScriptedLaunchGuard>,
            >,
        >,
    >::new(continuation);
    let preparations = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let resources = AttemptResourceLimits::new(2, 1024 * 1024 * 1024, 1024 * 1024 * 1024, 8)?;
    let guard = scripted_guard(
        resources,
        Arc::clone(&preparations),
        Arc::clone(&quarantines),
    )?;
    let mut target = QemuHotForkWorldResourceOwner::new(guard, 1)?;
    let input = execution_input();

    let error = QemuHotForkAttemptReconciliation::launch_from_source_world(
        execution_basis(&input),
        &input,
        source_world,
        node,
        &mut target,
        generation,
        assembly.child_launch_token(),
    )
    .err()
    .ok_or_else(|| std::io::Error::other("indeterminate fork unexpectedly succeeded"))?;
    let (failure, returned_owner) = error.into_parts();

    assert!(matches!(
        failure,
        LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(
            QemuHotForkLaunchError::Indeterminate { .. }
        )
    ));
    assert!(
        returned_owner
            .source_world()
            .is_some_and(|returned_source| Arc::ptr_eq(&retained_source, returned_source))
    );
    assert!(returned_owner.has_run_directory());
    assert!(!returned_owner.has_stranded_launch());
    let returned_owner = returned_owner
        .into_recoverable_parts()
        .err()
        .ok_or_else(|| std::io::Error::other("indeterminate child authority was recoverable"))?;
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert!(target.finish().is_err());
    assert_eq!(quarantines.load(Ordering::SeqCst), 1);
    drop(retained_source);
    drop(returned_owner);
    assert!(weak_source.upgrade().is_some());
    Ok(())
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

fn execution_basis(input: &CrucibleAttemptExecution) -> AttemptExecutionRuntimeBasis {
    AttemptExecutionRuntimeBasis::new(
        AttemptExecutionKey::new(
            input.lineage().id().expect("lineage id"),
            input.attempt().id().expect("attempt id"),
        ),
        ExecutionId::from_bytes([0x71; 16]).expect("execution"),
    )
}
