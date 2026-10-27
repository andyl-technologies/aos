//! Accepted-worker admission requirements for the native plugin assertion driver.
//!
//! The positive driver remains required, but its independent factory does not
//! yet receive Main's authentic normal pool and cleanup owner. Entry refuses
//! until that real composition is supplied; no callback fabricates Source
//! custody. The retained node path charges both execution and physical guards.

use super::super::super::*;
use crate::qemu_campaign_lifecycle::config_for_assignment_host_watchdog;
use crate::{
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory,
};
use crucible_engine::{
    BackendEffect, BackendError, BackendSnapshot, FingerprintSample, SimulationBackend,
    StepObservation, VirtualTime,
};
use crucible_qemu_host::{
    QemuLiveNodeStepGateConfig, QemuPreparedRunDirectory, QemuProductionFreshLaunchAdmission,
};
use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;

type Factory = QemuAttemptProductionVmLifecycleFactory<
    ComposedQemuAttemptResourceGuardFactory<LinuxQemuAttemptHostResourceFactory>,
>;
type NativeGuard = <ComposedQemuAttemptResourceGuardFactory<LinuxQemuAttemptHostResourceFactory> as QemuAttemptResourceGuardFactory>::Guard;

pub(in crate::packaged_qemu_executor::tests::paging_native) struct AdmittedFlightFactory<'a> {
    factory: Factory,
    lifecycle: Arc<ProductionVmLifecycleConfig>,
    context: &'a AttemptExecutionContext,
    source: &'a ScenarioDefForm,
    catalog: &'a PackagedRamCatalogConfig,
    _evidence_resident: crucible_store::owned_decode::ResourceLoan,
}

impl<'a> AdmittedFlightFactory<'a> {
    pub(in crate::packaged_qemu_executor::tests::paging_native) fn new(
        config: &'a PackagedQemuExecutorConfig,
        context: &'a AttemptExecutionContext,
        source: &'a ScenarioDefForm,
    ) -> Result<Self, Box<dyn Error>> {
        Self::with_evidence_bound(
            config,
            context,
            source,
            super::driver::evidence_resident_bound()?,
        )
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn with_evidence_bound(
        config: &'a PackagedQemuExecutorConfig,
        context: &'a AttemptExecutionContext,
        source: &'a ScenarioDefForm,
        evidence_bytes: u64,
    ) -> Result<Self, Box<dyn Error>> {
        let (lifecycle, _park_drain_registration) =
            config_for_assignment_host_watchdog(config.admitted_lifecycle_config()?, context)?;
        let lifecycle = Arc::new(lifecycle);
        let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())?;
        let catalog = config
            .ram_catalog()
            .ok_or("native trace requires independently admitted catalog")?;
        let supervisor = context
            .host_operation_supervisor()
            .ok_or("assertion credit lacks original supervision")?;
        let evidence_resident = catalog.reserve_evidence_resident(evidence_bytes, supervisor)?;
        Ok(Self {
            _evidence_resident: evidence_resident,
            factory: Factory::new(
                lifecycle.clone(),
                ComposedQemuAttemptResourceGuardFactory::new(host),
            ),
            lifecycle,
            context,
            source,
            catalog,
        })
    }

    /// Retains this admitted fixture's evidence bank through the last sample.
    pub(in crate::packaged_qemu_executor::tests::paging_native) fn evidence_custody(
        &self,
    ) -> crucible_store::owned_decode::ResourceLoan {
        self._evidence_resident.clone()
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn observation_guard(
        &self,
    ) -> Result<crucible_host_resources::host_supervision::HostOperationGuard, Box<dyn Error>> {
        let supervisor = self
            .context
            .host_operation_supervisor()
            .ok_or("performance observation lacks original supervision")?;
        Ok(supervisor.begin(
            crucible_host_resources::host_supervision::HostOperationClass::CheckpointCapture,
        )?)
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn begin(
        &mut self,
        vcpus: u32,
        memory: u64,
        disk: u64,
    ) -> Result<AdmittedFlightOwner, Box<dyn Error>> {
        let node = self
            .source
            .world()
            .vm_nodes()
            .first()
            .ok_or("flight requires one authored node")?;
        if self.source.world().vm_nodes().len() != 1
            || u32::from(node.smp_vcpus) != vcpus
            || memory > self.context.resources().maximum_resident_bytes()
            || disk > self.context.resources().maximum_disk_bytes()
        {
            return Err(
                "flight launch differs from actual accepted shape or semantic limits".into(),
            );
        }
        // This fixture currently opens an independent host factory instead of
        // receiving Main's authentic normal pool and pre-reserved cleanup path.
        // Keep the positive driver unsatisfied until that real owner is wired;
        // a no-op before-effects callback would discard born Source custody.
        Err(crucible_qemu_host::QemuVmRealizationError::ExecutorUnavailable {
            operation: "admit production plugin flight Source",
            message: String::from(
                "plugin flight requires the retained Main-bound Source factory and its actual before-effects construction owner",
            ),
        }.into())
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn create_trace_spool(
        &self,
    ) -> Result<crate::packaged_qemu_executor::ram_catalog::CatalogEvidenceSpool, Box<dyn Error>>
    {
        let supervisor = self
            .context
            .host_operation_supervisor()
            .ok_or("trace lacks original supervision")?;
        Ok(self.catalog.create_evidence_spool(
            self.catalog.root(),
            256 * 1024 * 1024,
            supervisor,
        )?)
    }
}

pub(in crate::packaged_qemu_executor::tests::paging_native) struct AdmittedFlightOwner {
    guard: Rc<RefCell<NativeGuard>>,
    lifecycle: Arc<ProductionVmLifecycleConfig>,
    context: AttemptExecutionContext,
    node: String,
    vcpus: u32,
    declared_ram_bytes: u64,
    terminal: bool,
}

impl AdmittedFlightOwner {
    pub(in crate::packaged_qemu_executor::tests::paging_native) fn prepare_generation_run_directory(
        &mut self,
        requirements: crucible_qemu_host::QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, crucible_qemu_host::QemuVmRealizationError> {
        self.guard
            .borrow_mut()
            .prepare_generation_run_directory(requirements)
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn prepare_fresh_artifacts(
        &self,
        directory: &mut QemuPreparedRunDirectory,
        qemu: &std::path::Path,
    ) -> Result<(), Box<dyn Error>> {
        let guard = self.guard.borrow();
        Ok(directory.prepare_fresh_artifacts_guarded(
            qemu,
            None,
            guard.child_process_contract()?,
        )?)
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn configure_launch(
        &self,
        config: QemuLiveNodeStepGateConfig,
    ) -> Result<QemuLiveNodeStepGateConfig, Box<dyn Error>> {
        let registration = self
            .lifecycle
            .host_ram_registration_factory()
            .ok_or("actual RAM registrar missing")?
            .prepare(
                &self.node,
                config.process_generation(),
                self.declared_ram_bytes,
                self.vcpus,
            )?;
        Ok(config
            .with_ram_control_registration(registration)
            .with_host_operation_supervisor(
                self.context
                    .host_operation_supervisor()
                    .ok_or("actual live supervision missing")?
                    .clone(),
            ))
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn launch(
        &mut self,
        config: &QemuLiveNodeStepGateConfig,
        directory: &QemuPreparedRunDirectory,
        identity: crucible_qemu_host::QemuLiveNodeIdentity,
    ) -> Result<AdmittedFlightNode, Box<dyn Error>> {
        let result = {
            let guard = self.guard.borrow();
            let request = QemuProductionFreshLaunchAdmission::admit(
                config,
                directory,
                guard.child_process_contract()?,
                identity,
            )?;
            crucible_qemu_host::launch_qemu_production_fresh_node(config, request)
        };
        match result {
            Ok(node) => Ok(AdmittedFlightNode {
                node,
                context: self.context.clone(),
                guard: Rc::clone(&self.guard),
            }),
            Err(mut error) => {
                if error.has_retained_owner() {
                    self.guard.borrow_mut().quarantine();
                    self.terminal = true;
                }
                Err(error.into())
            }
        }
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn finish(
        &mut self,
    ) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        let result = self.guard.borrow_mut().finish();
        self.terminal = result.is_ok();
        result
    }
}

impl Drop for AdmittedFlightOwner {
    fn drop(&mut self) {
        if !self.terminal {
            self.guard.borrow_mut().quarantine();
        }
    }
}

pub(in crate::packaged_qemu_executor::tests::paging_native) struct AdmittedFlightNode {
    node: crucible_qemu_host::QemuNode,
    context: AttemptExecutionContext,
    guard: Rc<RefCell<NativeGuard>>,
}

impl AdmittedFlightNode {
    pub(in crate::packaged_qemu_executor::tests::paging_native) fn charge_quantum(
        &self,
    ) -> Result<(), BackendError> {
        self.context
            .charge_execution_quantum()
            .map_err(|error| BackendError::Rejected {
                message: error.to_string(),
            })?;
        self.guard
            .borrow_mut()
            .charge_execution_quantum()
            .map_err(|error| BackendError::Rejected {
                message: error.to_string(),
            })
    }
}

impl std::ops::Deref for AdmittedFlightNode {
    type Target = crucible_qemu_host::QemuNode;
    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl std::ops::DerefMut for AdmittedFlightNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

impl SimulationBackend for AdmittedFlightNode {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        self.charge_quantum()?;
        self.node.step_to(ceiling)
    }
    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        self.node.apply(effect, at)
    }
    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        self.node.snapshot()
    }
    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        self.node.restore(snapshot)
    }
    fn now(&self) -> VirtualTime {
        self.node.now()
    }
    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        SimulationBackend::fingerprint(&mut self.node, node)
    }
    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.node.shutdown()
    }
    fn drain_observable_events(
        &mut self,
    ) -> Result<Vec<crucible_engine::ObservableEvent>, BackendError> {
        self.node.drain_observable_events()
    }
    fn drain_rng_evidence(
        &mut self,
    ) -> Result<Vec<crucible_engine::BackendRngEvidence>, BackendError> {
        self.node.drain_rng_evidence()
    }
    fn drain_network_outputs(
        &mut self,
    ) -> Result<Vec<crucible_engine::BackendNetworkOutput>, BackendError> {
        self.node.drain_network_outputs()
    }
}

impl crate::packaged_qemu_executor::native_plugin_flight::admission::FlightAdmission
    for AdmittedFlightFactory<'_>
{
    fn begin(
        &mut self,
        _vcpus: u32,
        _memory: u64,
        _disk: u64,
    ) -> Result<
        crate::packaged_qemu_executor::native_plugin_flight::admission::FlightOwner<'_>,
        crate::NativeObservationError,
    > {
        Err(
            crucible_qemu_host::QemuVmRealizationError::ExecutorUnavailable {
                operation: "observe production plugin flight",
                message: String::from(
                    "the component process does not own the service Main Source factory",
                ),
            }
            .into(),
        )
    }
}
