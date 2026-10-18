//! Keeps native observation and its evidence inside the actual paid Main worker.
//!
//! Normal execution delegates unchanged. An explicitly selected private flight
//! borrows its Source from the same admitted host factory facade. Every failure
//! leaves that factory and its evidence reachable by the worker retirement hook.

use super::admission::MainFlightAdmission;
use super::inputs::{NativePluginFlightInputs, NativePluginFlightKind};
use crate::ProductionVmLifecycleConfig;
use crate::qemu_campaign_lifecycle::NativeObservationRetirementError;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptWorkerFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, QemuAttemptProcessResourceGuard,
    QemuAttemptProductionVmLifecycleError, QemuAttemptProductionVmLifecycleFactory,
    QemuAttemptResourceGuardFactory, QemuAttemptStartReplayProof, QemuAttemptStartVerifier,
    QemuSavepointReplayProof, QemuSelectedOriginVerifier,
};
use crucible_cas::owned_decode::ResourceLoan;
use std::sync::Arc;

pub(in crate::packaged_qemu_executor) struct NativeFlightRunner<
    R,
    F: QemuAttemptResourceGuardFactory,
> {
    inner: R,
    source: QemuAttemptProductionVmLifecycleFactory<F>,
    lifecycle: Arc<ProductionVmLifecycleConfig>,
    catalog: Option<super::super::ram_catalog::EvidenceCatalog>,
    inputs: Option<NativePluginFlightInputs>,
    evidence: Option<ResourceLoan>,
}

#[derive(Debug, thiserror::Error)]
pub(in crate::packaged_qemu_executor) enum NativeFlightError<E> {
    #[error(transparent)]
    Inner(E),
    #[error(transparent)]
    Retirement(#[from] NativeObservationRetirementError),
    #[error("native observation Source: {first}; cleanup: {cleanup:?}")]
    SourceObservation {
        #[source]
        first: QemuAttemptProductionVmLifecycleError,
        cleanup: Option<NativeObservationRetirementError>,
    },
    #[error("native plugin assertions: {first}; cleanup: {cleanup:?}")]
    Observation {
        first: String,
        cleanup: Option<NativeObservationRetirementError>,
    },
    #[error("worker retirement failed: {first}; observation retirement: {cleanup}")]
    RetirementBoth {
        #[source]
        first: E,
        cleanup: NativeObservationRetirementError,
    },
    #[error("native plugin assertions completed and actual Source retirement was observed")]
    Complete,
}

impl<R, F: QemuAttemptResourceGuardFactory> NativeFlightRunner<R, F> {
    pub(in crate::packaged_qemu_executor) fn new(
        inner: R,
        source: QemuAttemptProductionVmLifecycleFactory<F>,
        lifecycle: Arc<ProductionVmLifecycleConfig>,
        catalog: Option<super::super::ram_catalog::EvidenceCatalog>,
        inputs: Option<NativePluginFlightInputs>,
    ) -> Self {
        Self {
            inner,
            source,
            lifecycle,
            catalog,
            inputs,
            evidence: None,
        }
    }
}

impl<R, F> NativeFlightRunner<R, F>
where
    R: CrucibleExecutionRunner,
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn observe(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        inputs: &NativePluginFlightInputs,
    ) -> Result<(), NativeFlightError<R::Error>> {
        // The preceding exact receipt is closed before another diagnostic loan
        // or Source birth. A historical report remains a real report once.
        self.source.retire_native_observation()?;
        if self.source.native_observation_is_closed() {
            self.evidence = None;
        }
        let outcome = (|| {
            let catalog = self
                .catalog
                .as_ref()
                .ok_or("native flight requires the deployed catalog")?;
            let mut factory = MainFlightAdmission::new(
                &mut self.source,
                &mut self.evidence,
                catalog,
                context,
                input.scenario(),
            )?;
            match inputs.body.kind {
                NativePluginFlightKind::FourVcpu => super::driver::run_four(
                    &mut factory,
                    self.lifecycle.executable(),
                    self.lifecycle.plugin(),
                    &inputs.body.kernel,
                    &inputs.body.initrd,
                    &inputs.body.firmware,
                    self.lifecycle.run_state_root(),
                ),
                NativePluginFlightKind::BlockRecovery => super::driver::run_block(
                    &mut factory,
                    self.lifecycle.executable(),
                    self.lifecycle.plugin(),
                    &inputs.body.kernel,
                    &inputs.body.initrd,
                    &inputs.body.firmware,
                    self.lifecycle.run_state_root(),
                ),
            }
        })();
        // Attempt cleanup on diagnostic errors too. The exact Source slot owns
        // any unfinished body before an error is rendered for the worker.
        let cleanup = self.source.retire_native_observation();
        if self.source.native_observation_is_closed() {
            self.evidence = None;
        }
        match (outcome, cleanup) {
            (Err(first), cleanup) => {
                match first.downcast::<QemuAttemptProductionVmLifecycleError>() {
                    Ok(first) => Err(NativeFlightError::SourceObservation {
                        first: *first,
                        cleanup: cleanup.err(),
                    }),
                    Err(first) => Err(NativeFlightError::Observation {
                        first: first.to_string(),
                        cleanup: cleanup.err(),
                    }),
                }
            }
            (Ok(()), Err(first)) => Err(NativeFlightError::Retirement(first)),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl<R, F> CrucibleExecutionRunner for NativeFlightRunner<R, F>
where
    R: CrucibleExecutionRunner,
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Error = NativeFlightError<R::Error>;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        let Some(inputs) = self.inputs.clone() else {
            return self.inner.execute(input, context).map_err(map_inner);
        };
        self.observe(input, context, &inputs)
            .map_err(AttemptWorkerFailure::Terminal)?;
        // The required positive assertions ran in this actual accepted worker;
        // cancellation follows their real physical cleanup, as in the original driver.
        println!("gate=gate:production-rust-plugin-flight");
        println!("production_accepted_assignment=true");
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(NativeFlightError::Complete))
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.inner
            .reconcile_execution(disposition)
            .map_err(map_inner)
    }

    fn try_retire_original(
        &mut self,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        let inner = self.inner.try_retire_original(original);
        let source = self.source.retire_native_observation();
        if self.source.native_observation_is_closed() {
            self.evidence = None;
        }
        match (inner, source) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), Ok(())) => Err(NativeFlightError::Inner(first)),
            (Ok(()), Err(first)) => Err(NativeFlightError::Retirement(first)),
            (Err(first), Err(cleanup)) => Err(NativeFlightError::RetirementBoth { first, cleanup }),
        }
    }

    fn quarantine_pending_execution(&mut self) {
        self.inner.quarantine_pending_execution();
        // Observation custody remains in source, not a local body to discard.
    }
}

impl<R, F> QemuAttemptStartVerifier for NativeFlightRunner<R, F>
where
    R: QemuAttemptStartVerifier,
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn verify_attempt_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuAttemptStartReplayProof, AttemptWorkerFailure<Self::Error>> {
        self.inner
            .verify_attempt_start(input, context)
            .map_err(map_inner)
    }
}

impl<R, F> QemuSelectedOriginVerifier for NativeFlightRunner<R, F>
where
    R: QemuSelectedOriginVerifier,
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn verify_selected_origin(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
    ) -> Result<QemuSavepointReplayProof, AttemptWorkerFailure<Self::Error>> {
        self.inner
            .verify_selected_origin(input, context, target)
            .map_err(map_inner)
    }
}

fn map_inner<E>(failure: AttemptWorkerFailure<E>) -> AttemptWorkerFailure<NativeFlightError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(first) => {
            AttemptWorkerFailure::Retryable(NativeFlightError::Inner(first))
        }
        AttemptWorkerFailure::Canceled(first) => {
            AttemptWorkerFailure::Canceled(NativeFlightError::Inner(first))
        }
        AttemptWorkerFailure::Terminal(first) => {
            AttemptWorkerFailure::Terminal(NativeFlightError::Inner(first))
        }
    }
}
