//! Fail-closed native child-fork and adoption acceptance cases.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crucible::ContentHash;
use crucible_api::vm_lifecycle::{
    hot_fork_adoption_count_for_test, reset_hot_fork_adoption_count_for_test,
};
use rustix::process::{Pid, Signal, kill_process};

use super::*;

struct FinishFailingFactory<R> {
    inner: R,
    failures: Arc<AtomicUsize>,
}

struct FinishFailingGuard<G> {
    inner: G,
    failures: Arc<AtomicUsize>,
}

impl<R> QemuAttemptResourceGuardFactory for FinishFailingFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
{
    type Guard = FinishFailingGuard<R::Guard>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        Ok(FinishFailingGuard {
            inner: self.inner.begin(resources, cancellation)?,
            failures: Arc::clone(&self.failures),
        })
    }
}

impl<G> QemuAttemptOperationalBoundary for FinishFailingGuard<G>
where
    G: QemuAttemptOperationalBoundary,
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

impl<G> QemuAttemptResourceGuard for FinishFailingGuard<G>
where
    G: QemuAttemptResourceGuard,
{
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(QemuVmRealizationError::Executor {
                operation: "publish native atomic-world disposition",
                message: String::from("injected target guard finish failure"),
            });
        }
        self.inner.finish()
    }

    fn quarantine(&mut self) {
        self.inner.quarantine();
    }
}

impl<G> QemuAttemptProcessResourceGuard for FinishFailingGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn child_process_contract(
        &self,
    ) -> Result<&crucible_qemu::QemuChildProcessContract, QemuVmRealizationError> {
        self.inner.child_process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: crucible_qemu::QemuLaunchResourceRequirements,
    ) -> Result<crucible_qemu::QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.inner.prepare_generation_run_directory(requirements)
    }

    fn retain_failed_launch_child(&mut self, child: crucible_qemu::QemuNodeChild) {
        self.inner.retain_failed_launch_child(child);
    }
}

impl<G> crucible_qemu::QemuHotForkChildProcessOwner for FinishFailingGuard<G>
where
    G: crucible_qemu::QemuHotForkChildProcessOwner,
{
    type Authority = G::Authority;

    fn retain_hot_fork_child(
        &mut self,
        basis: crucible_qemu::QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, crucible_qemu::QemuNodeChannelError> {
        self.inner.retain_hot_fork_child(basis)
    }
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_exposes_no_world_when_second_real_fork_fails() {
    let paths = NativeGatePaths::from_environment();
    let prepared = prepare_native_source(&paths, "fork-failure", 0x72);
    let failed_pid = prepared
        .world
        .continuation()
        .nodes()
        .iter()
        .find(|node| node.node().name == "nginx")
        .and_then(|node| node.process())
        .map(|identity| identity.process_id)
        .expect("nginx source process");
    let pid = Pid::from_raw(i32::try_from(failed_pid).expect("QEMU PID fits i32"))
        .expect("positive QEMU PID");
    kill_process(pid, Signal::KILL).expect("kill second running source process");
    std::thread::sleep(Duration::from_millis(50));

    let input = execution_input_for_scenario_configuration(prepared.source, prepared.configuration);
    let context = execution_context(&input, 0x73);
    let key = QemuHotForkSourceWorldKey::for_execution(&input, execution_basis(&input, 0x73))
        .expect("derive exact source key");
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, prepared.world);
    let target = open_host(&paths, "fork-failure-target", 2);
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ComposedQemuAttemptResourceGuardFactory::new(target),
        paths.run_state_root.join("fork-failure").join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );

    reset_hot_fork_adoption_count_for_test();
    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
        ))
    ));
    assert_eq!(hot_fork_adoption_count_for_test(), 0);
    assert!(!factory.sources().available());
    eprintln!(
        "atomic-world phase=fork-failure-complete failed_source_pid={failed_pid} public_world=false"
    );
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_exposes_no_world_when_second_real_adoption_fails() {
    let paths = NativeGatePaths::from_environment();
    let mut prepared = prepare_native_source(&paths, "adoption-failure", 0x74);
    prepared
        .world
        .replace_immutable_root_for_test(
            &NodeId {
                name: String::from("nginx"),
            },
            ContentHash::from_bytes(b"native-adoption-mismatch"),
        )
        .expect("inject second-child immutable-root mismatch");

    let input = execution_input_for_scenario_configuration(prepared.source, prepared.configuration);
    let context = execution_context(&input, 0x75);
    let key = QemuHotForkSourceWorldKey::for_execution(&input, execution_basis(&input, 0x75))
        .expect("derive exact source key");
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, prepared.world);
    let target = open_host(&paths, "adoption-failure-target", 2);
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ComposedQemuAttemptResourceGuardFactory::new(target),
        paths.run_state_root.join("adoption-failure").join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
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
    eprintln!(
        "atomic-world phase=adoption-failure-complete adopted_before_failure=1 public_world=false"
    );
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_keeps_source_private_until_publication_cleanup_retries() {
    let paths = NativeGatePaths::from_environment();
    let prepared = prepare_native_source(&paths, "publication-failure", 0x76);
    let input = execution_input_for_scenario_configuration(prepared.source, prepared.configuration);
    let context = execution_context(&input, 0x77);
    let key = QemuHotForkSourceWorldKey::for_execution(&input, execution_basis(&input, 0x77))
        .expect("derive exact source key");
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, prepared.world);
    let target = open_host(&paths, "publication-failure-target", 2);
    let failures = Arc::new(AtomicUsize::new(1));
    let resources = FinishFailingFactory {
        inner: ComposedQemuAttemptResourceGuardFactory::new(target),
        failures: Arc::clone(&failures),
    };
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        resources,
        paths
            .run_state_root
            .join("publication-failure")
            .join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );
    let mut lifecycle = match factory
        .try_start(&input, &context)
        .expect("assemble complete child world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("prepared source was declined"),
    };
    assert!(!factory.sources().available());
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown child world");

    let mut observed_failure = false;
    for _ in 0..64 {
        match lifecycle.reconcile_execution_disposition(AttemptExecutionDisposition::Canceled) {
            Ok(AttemptExecutionReconciliationStep::Progressed) => {}
            Ok(AttemptExecutionReconciliationStep::Complete) => {
                panic!("publication cleanup completed before the injected failure")
            }
            Err(_) => {
                observed_failure = true;
                break;
            }
        }
    }
    assert!(observed_failure);
    assert_eq!(failures.load(Ordering::SeqCst), 0);
    assert!(!factory.sources().available());
    eprintln!("atomic-world phase=publication-failure source_reusable=false retry_authority=true");

    reconcile_native_world(&mut lifecycle);
    assert!(factory.recover(lifecycle).is_ok());
    assert!(factory.sources().available());
    eprintln!(
        "atomic-world phase=publication-retry-complete source_reusable=true public_boundary=complete"
    );
}
