//! Borrows the actual Main-worker factory while retaining its observation body.
//!
//! The adapter supplies no issuer. The ordinary before-effects Source path
//! must admit and retain its real launcher first. The worker owns the evidence
//! loan and factory slot across diagnostic errors and unwinding.

use crate::qemu_campaign_lifecycle::NativeObservationOwner;
use crate::qemu_lifecycle_launcher::ObservedNativeNode;
use crate::{
    AttemptExecutionContext, QemuAttemptProcessResourceGuard,
    QemuAttemptProductionVmLifecycleError, QemuAttemptProductionVmLifecycleFactory,
    QemuAttemptResourceGuardFactory,
};
use crucible::{NodeId, ScenarioDefForm};
use crucible_cas::owned_decode::ResourceLoan;
use crucible_qemu::QemuLiveNodeStepGateConfig;
use std::error::Error;
use std::io::BufRead;

/// Borrows a flight owner without returning a backend guard or launch permit.
pub(crate) trait FlightAdmission {
    fn begin(
        &mut self,
        vcpus: u32,
        memory: u64,
        disk: u64,
    ) -> Result<FlightOwner<'_>, Box<dyn Error>>;
}

/// Keeps concrete factory ownership behind its existing Source operations.
trait MainFlightSource {
    fn begin(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError>;
    fn observation(
        &mut self,
    ) -> Result<&mut (dyn NativeObservationOwner + 'static), crucible_api::LifecycleApiError>;
    fn retire(&mut self) -> Result<(), QemuAttemptProductionVmLifecycleError>;
}

impl<R> MainFlightSource for QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn begin(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        self.begin_native_observation_default(context, source)
    }

    fn observation(
        &mut self,
    ) -> Result<&mut (dyn NativeObservationOwner + 'static), crucible_api::LifecycleApiError> {
        self.native_observation()
    }

    fn retire(&mut self) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        self.retire_native_observation()
    }
}

/// Lends the same factory that the paid Main worker already retains.
pub(super) struct MainFlightAdmission<'a> {
    factory: &'a mut dyn MainFlightSource,
    catalog: &'a super::super::ram_catalog::EvidenceCatalog,
    context: &'a AttemptExecutionContext,
    source: &'a ScenarioDefForm,
}

impl<'a> MainFlightAdmission<'a> {
    /// Reserves the actual diagnostic buffers in the worker's retained slot.
    pub(super) fn new<R>(
        factory: &'a mut QemuAttemptProductionVmLifecycleFactory<R>,
        evidence: &'a mut Option<ResourceLoan>,
        catalog: &'a super::super::ram_catalog::EvidenceCatalog,
        context: &'a AttemptExecutionContext,
        source: &'a ScenarioDefForm,
    ) -> Result<Self, Box<dyn Error>>
    where
        R: QemuAttemptResourceGuardFactory + Send + 'static,
        R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
    {
        if evidence.is_some() {
            return Err("previous native observation still retains its evidence credit".into());
        }
        let original = context
            .host_operation_supervisor()
            .ok_or("native flight lacks actual supervision")?;
        *evidence = Some(catalog.reserve(super::driver::evidence_resident_bound()?, original)?);
        Ok(Self {
            factory,
            catalog,
            context,
            source,
        })
    }
}

impl FlightAdmission for MainFlightAdmission<'_> {
    fn begin(
        &mut self,
        vcpus: u32,
        memory: u64,
        disk: u64,
    ) -> Result<FlightOwner<'_>, Box<dyn Error>> {
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
        self.factory.begin(self.context, self.source)?;
        Ok(FlightOwner {
            factory: self.factory,
            context: self.context,
            node: &node.id,
            catalog: self.catalog,
            generation: None,
        })
    }
}

/// Lends node operations while the factory retains all physical ownership.
pub(crate) struct FlightOwner<'a> {
    factory: &'a mut dyn MainFlightSource,
    context: &'a AttemptExecutionContext,
    node: &'a NodeId,
    catalog: &'a super::super::ram_catalog::EvidenceCatalog,
    generation: Option<u64>,
}

impl FlightOwner<'_> {
    pub(crate) fn launch<'a>(
        &'a mut self,
        profile: &QemuLiveNodeStepGateConfig,
        router: &str,
        crash: &str,
    ) -> Result<ObservedNativeNode<'a>, Box<dyn Error>> {
        self.factory
            .observation()?
            .launch_observation(self.node, profile, router, crash)?;
        self.generation = Some(profile.process_generation());
        Ok(self
            .factory
            .observation()?
            .borrow_observation(self.context)?)
    }

    pub(crate) fn liveness_tail(&mut self) -> Result<String, Box<dyn Error>> {
        let generation = self.generation.ok_or("flight has no launched generation")?;
        self.factory
            .observation()?
            .liveness_tail(self.node, generation)
    }

    pub(crate) fn inspect_trace<T>(
        &mut self,
        maximum_bytes: u64,
        inspect: impl FnOnce(&mut dyn BufRead) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        let generation = self.generation.ok_or("flight has no launched generation")?;
        let mut inspect = Some(inspect);
        let mut result = None;
        self.factory.observation()?.inspect_trace(
            self.node,
            generation,
            maximum_bytes,
            &mut |reader| {
                let inspect = inspect.take().ok_or("trace inspection callback repeated")?;
                result = Some(inspect(reader)?);
                Ok(())
            },
        )?;
        result.ok_or_else(|| "trace inspection callback was not entered".into())
    }

    pub(crate) fn create_trace_spool(
        &self,
    ) -> Result<super::super::ram_catalog::CatalogEvidenceSpool, Box<dyn Error>> {
        let original = self
            .context
            .host_operation_supervisor()
            .ok_or("trace lacks actual supervision")?;
        Ok(self.catalog.spool(256 * 1024 * 1024, original)?)
    }

    pub(crate) fn finish(&mut self) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        self.factory.retire()
    }
}
