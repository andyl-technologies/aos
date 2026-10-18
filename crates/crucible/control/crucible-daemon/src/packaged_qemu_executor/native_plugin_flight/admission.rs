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
use crucible_engine::{NodeId, ScenarioDefForm};
use crucible_store::owned_decode::ResourceLoan;
use crucible_qemu_host::QemuLiveNodeStepGateConfig;
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
    fn with_observation(
        &mut self,
        apply: &mut dyn FnMut(&mut dyn NativeObservationOwner) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>>;
    fn finish_body(&mut self) -> Result<(), QemuAttemptProductionVmLifecycleError>;
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

    fn with_observation(
        &mut self,
        apply: &mut dyn FnMut(&mut dyn NativeObservationOwner) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        self.with_native_observation(apply)
    }

    fn finish_body(&mut self) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        self.retry_native_observation_body()
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
    /// Executes an observation without exporting a borrowed Main-owned body.
    fn observe<T>(
        factory: &mut dyn MainFlightSource,
        apply: impl FnOnce(&mut dyn NativeObservationOwner) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        let mut apply = Some(apply);
        let mut output = None;
        factory.with_observation(&mut |owner| {
            let apply = apply.take().ok_or("native observation callback repeated")?;
            output = Some(apply(owner)?);
            Ok(())
        })?;
        output.ok_or_else(|| "native observation callback was not entered".into())
    }

    pub(crate) fn with_launch<T>(
        &mut self,
        profile: &QemuLiveNodeStepGateConfig,
        router: &str,
        crash: &str,
        inspect: impl FnOnce(&mut ObservedNativeNode<'_>) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        let node = self.node;
        let context = self.context;
        // A successful launch may precede an inspection refusal. Keep the real
        // generation selected even when that callback returns an error.
        let generation = &mut self.generation;
        Self::observe(self.factory, |owner| {
            owner.launch_observation(node, profile, router, crash)?;
            *generation = Some(profile.process_generation());
            let mut observed = owner.borrow_observation(context)?;
            inspect(&mut observed)
        })
    }

    pub(crate) fn liveness_tail(&mut self) -> Result<String, Box<dyn Error>> {
        let generation = self.generation.ok_or("flight has no launched generation")?;
        let node = self.node;
        Self::observe(self.factory, |owner| owner.liveness_tail(node, generation))
    }

    pub(crate) fn inspect_trace<T>(
        &mut self,
        maximum_bytes: u64,
        inspect: impl FnOnce(&mut dyn BufRead) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        let generation = self.generation.ok_or("flight has no launched generation")?;
        let node = self.node;
        Self::observe(self.factory, |owner| {
            let mut inspect = Some(inspect);
            let mut result = None;
            owner.inspect_trace(node, generation, maximum_bytes, &mut |reader| {
                let inspect = inspect.take().ok_or("trace inspection callback repeated")?;
                result = Some(inspect(reader)?);
                Ok(())
            })?;
            result.ok_or_else(|| "trace inspection callback was not entered".into())
        })
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
        self.factory.finish_body()
    }
}
