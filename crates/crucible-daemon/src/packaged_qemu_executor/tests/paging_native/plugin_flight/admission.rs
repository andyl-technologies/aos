//! Genuine accepted-worker admission for the native plugin assertion driver.
//!
//! Each generation uses the production world partition, original supervision,
//! sealed native inventory handshake, and real process/quota guard. The node
//! charges both the execution and physical guard before each modeled advance.

use super::super::super::*;
use crate::qemu_campaign_lifecycle::config_for_assignment_host_watchdog;
use crate::{
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory,
};
use crucible::{
    BackendEffect, BackendError, BackendSnapshot, FingerprintSample, SimulationBackend,
    StepObservation, VirtualTime,
};
use crucible_qemu::{
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
    _evidence_resident: Arc<dyn Send + Sync>,
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
        let lifecycle = Arc::new(config_for_assignment_host_watchdog(
            config.admitted_lifecycle_config()?,
            context,
        )?);
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
    ) -> Arc<dyn Send + Sync> {
        Arc::clone(&self._evidence_resident)
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn observation_guard(
        &self,
    ) -> Result<crucible_linux_resource::host_supervision::HostOperationGuard, Box<dyn Error>> {
        let supervisor = self
            .context
            .host_operation_supervisor()
            .ok_or("performance observation lacks original supervision")?;
        Ok(supervisor.begin(
            crucible_linux_resource::host_supervision::HostOperationClass::CheckpointCapture,
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
        let guard =
            self.factory
                .begin_native_world_guard(self.context, self.source, &self.lifecycle)?;
        Ok(AdmittedFlightOwner {
            guard: Rc::new(RefCell::new(guard)),
            lifecycle: self.lifecycle.clone(),
            context: self.context.clone(),
            node: node.id.name.clone(),
            vcpus,
            declared_ram_bytes: u64::from(node.memory_mib) * 1024 * 1024,
            terminal: false,
        })
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
        requirements: crucible_qemu::QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, crucible_qemu::QemuVmRealizationError> {
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
        identity: crucible_qemu::QemuLiveNodeIdentity,
    ) -> Result<AdmittedFlightNode, Box<dyn Error>> {
        let result = {
            let guard = self.guard.borrow();
            let request = QemuProductionFreshLaunchAdmission::admit(
                config,
                directory,
                guard.child_process_contract()?,
                identity,
            )?;
            crucible_qemu::launch_qemu_production_fresh_node(config, request)
        };
        match result {
            Ok(node) => Ok(AdmittedFlightNode {
                node,
                context: self.context.clone(),
                guard: Rc::clone(&self.guard),
            }),
            Err(mut error) => {
                if let Some(child) = error.take_unreaped_child() {
                    self.guard.borrow_mut().retain_failed_launch_child(child);
                    self.guard.borrow_mut().quarantine();
                    self.terminal = true;
                }
                Err(error.into())
            }
        }
    }

    pub(in crate::packaged_qemu_executor::tests::paging_native) fn finish(
        &mut self,
    ) -> Result<(), crucible_qemu::QemuVmRealizationError> {
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
    node: crucible_qemu::QemuNode,
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
    type Target = crucible_qemu::QemuNode;
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
    fn drain_observable_events(&mut self) -> Result<Vec<crucible::ObservableEvent>, BackendError> {
        self.node.drain_observable_events()
    }
    fn drain_rng_evidence(&mut self) -> Result<Vec<crucible::BackendRngEvidence>, BackendError> {
        self.node.drain_rng_evidence()
    }
    fn drain_network_outputs(
        &mut self,
    ) -> Result<Vec<crucible::BackendNetworkOutput>, BackendError> {
        self.node.drain_network_outputs()
    }
}
