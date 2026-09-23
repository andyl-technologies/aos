//! Real-QEMU rejection of missing or aliased branch-private child files.

// crucible-lint: allow panic-shortcut -- native gate assertions use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum ChildFileFault {
    Missing,
    Aliased,
}

impl ChildFileFault {
    fn label(self) -> &'static str {
        match self {
            Self::Missing => "omission",
            Self::Aliased => "alias",
        }
    }
}

struct InvalidChildFileFactory<R> {
    inner: R,
    fault: ChildFileFault,
    injected_files: Arc<AtomicUsize>,
}

struct InvalidChildFileGuard<G> {
    inner: G,
    fault: ChildFileFault,
    prepared_files: Vec<PathBuf>,
    injected_files: Arc<AtomicUsize>,
}

impl<R: QemuAttemptResourceGuardFactory> QemuAttemptResourceGuardFactory
    for InvalidChildFileFactory<R>
{
    type Guard = InvalidChildFileGuard<R::Guard>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
        Ok(InvalidChildFileGuard {
            inner: self
                .inner
                .begin(resources, cancellation, selected_checkpoint)?,
            fault: self.fault,
            prepared_files: Vec::new(),
            injected_files: Arc::clone(&self.injected_files),
        })
    }
}

impl<G: QemuAttemptOperationalBoundary> QemuAttemptOperationalBoundary
    for InvalidChildFileGuard<G>
{
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.inner.resource_limits()
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        self.inner.cancellation()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.inner.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.inner.charge_execution_quantum()
    }
}

impl<G: QemuAttemptResourceGuard> QemuAttemptResourceGuard for InvalidChildFileGuard<G> {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.inner.finish()
    }

    fn quarantine(&mut self) {
        self.inner.quarantine();
    }
}

impl<G: QemuAttemptProcessResourceGuard> QemuAttemptProcessResourceGuard
    for InvalidChildFileGuard<G>
{
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.inner.child_process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let directory = self.inner.prepare_generation_run_directory(requirements)?;

        let named_file = directory
            .path()
            .join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
        match self.fault {
            ChildFileFault::Missing => {
                // The descriptor remains pinned while its required name is gone.
                fs::remove_file(&named_file).expect("remove named child VMState destination");
                self.injected_files.fetch_add(1, Ordering::SeqCst);
            }
            ChildFileFault::Aliased => {
                self.prepared_files.push(named_file);
                if self.prepared_files.len() == 2 {
                    let anchor = directory.path().join("aliased-child-vmstate");
                    fs::File::create(&anchor).expect("create distinct alias target");
                    for path in &self.prepared_files {
                        // Both destinations now name one new inode, distinct
                        // from each child file retained by the resource guard.
                        fs::remove_file(path).expect("remove original child destination");
                        fs::hard_link(&anchor, path).expect("alias child destinations");
                        self.injected_files.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        Ok(directory)
    }

    fn retain_failed_launch_child(&mut self, child: crucible_qemu::QemuNodeChild) {
        self.inner.retain_failed_launch_child(child);
    }
}

impl<G: crucible_qemu::QemuHotForkChildProcessOwner> crucible_qemu::QemuHotForkChildProcessOwner
    for InvalidChildFileGuard<G>
{
    type Authority = G::Authority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        self.inner.retain_hot_fork_child(basis)
    }
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_rejects_missing_child_file_with_live_qemu_source() {
    reject_invalid_child_file_with_live_qemu_source(ChildFileFault::Missing);
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_rejects_aliased_child_files_with_live_qemu_source() {
    reject_invalid_child_file_with_live_qemu_source(ChildFileFault::Aliased);
}

fn reject_invalid_child_file_with_live_qemu_source(fault: ChildFileFault) {
    let paths = NativeGatePaths::from_environment();
    let lane = format!("isolation-{}", fault.label());
    let prepared = prepare_native_source(&paths, &lane, 0xb1, 12_000);
    let source_processes = prepared
        .world
        .continuation()
        .nodes()
        .iter()
        .filter_map(|node| node.process())
        .map(|process| {
            let current = linux_process_identity(process.process_id)
                .expect("inspect source QEMU process")
                .expect("source QEMU process exists");
            assert_eq!(&current, process);
            current
        })
        .collect::<Vec<_>>();
    assert_eq!(source_processes.len(), 2);

    let input = execution_input_for_scenario_configuration(prepared.source, prepared.configuration);
    let context = execution_context(&input, 0xb2);
    let key =
        QemuHotForkSourceWorldKey::for_execution(&input, &context, execution_basis(&input, 0xb2))
            .expect("derive exact source key");
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, prepared.world);
    let target_lane = format!("{lane}-target");
    let target = open_host(&paths, &target_lane, 12_100);
    let injected_files = Arc::new(AtomicUsize::new(0));
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        InvalidChildFileFactory {
            inner: ComposedQemuAttemptResourceGuardFactory::new(target),
            fault,
            injected_files: Arc::clone(&injected_files),
        },
        paths.run_state_root.join(&lane).join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );

    reset_hot_fork_adoption_count_for_test();
    let failure = match factory.try_start(&input, &context) {
        Err(failure) => failure,
        Ok(_) => panic!("{} child VMState fault exposed a world", fault.label()),
    };
    let AttemptWorkerFailure::Retryable(QemuProductionHotForkWorldLifecycleFactoryError::Assembly(
        message,
    )) = failure
    else {
        panic!(
            "{} child VMState fault produced the wrong failure class",
            fault.label()
        );
    };
    let expected_rejection = match fault {
        ChildFileFault::Missing => "requires pre-provisioned device-state container",
        ChildFileFault::Aliased => "prepared device-state identity changed",
    };
    assert!(
        message.contains(expected_rejection),
        "wrong rejection: {message}"
    );
    assert_eq!(injected_files.load(Ordering::SeqCst), 2);
    assert_eq!(hot_fork_adoption_count_for_test(), 0);
    // The provider only restores a rejected source after exact reauthentication.
    assert!(factory.sources.available());
    assert!(cgroup_processes(&paths.cgroup_root.join(&target_lane)).is_empty());
    for process in source_processes {
        assert_eq!(
            linux_process_identity(process.process_id)
                .expect("inspect source after rejection")
                .expect("source QEMU survives rejection"),
            process,
        );
    }

    println!(
        "\nnative_real_resource_{}=child-vmstate-destination",
        fault.label()
    );
    println!("native_real_resource_{}_nodes=2", fault.label());
    println!(
        "native_real_resource_{}_rejected_before=child-readiness,world-publication",
        fault.label()
    );
    println!(
        "native_real_resource_{}_source_unchanged=true",
        fault.label()
    );
}
