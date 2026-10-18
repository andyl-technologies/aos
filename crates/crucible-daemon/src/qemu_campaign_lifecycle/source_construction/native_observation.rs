//! Lends native observations from the exact Main-held Source launcher.
//!
//! A driver borrows operations from the existing factory cell. The same Box,
//! saved Originals, body loan and reservation stay there until publication to
//! Main cleanup; a panic or semantic failure cannot drop a local owner.

use super::*;
use crate::qemu_lifecycle_launcher::ObservedNativeNode;
use std::error::Error;
use std::io::BufRead;

/// Exposes operations, never a movable backend guard or an admission recipe.
pub(crate) trait NativeObservationOwner {
    fn launch_observation(
        &mut self,
        node: &crucible::NodeId,
        profile: &crucible_qemu::QemuLiveNodeStepGateConfig,
        router: &str,
        crash: &str,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError>;

    fn borrow_observation<'a>(
        &'a mut self,
        context: &'a AttemptExecutionContext,
    ) -> Result<ObservedNativeNode<'a>, LifecycleApiError>;

    fn inspect_trace(
        &self,
        node: &crucible::NodeId,
        generation: u64,
        maximum_bytes: u64,
        inspect: &mut dyn FnMut(&mut dyn BufRead) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>>;

    fn liveness_tail(
        &self,
        node: &crucible::NodeId,
        generation: u64,
    ) -> Result<String, Box<dyn Error>>;
}

impl<G, F> NativeObservationOwner for QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard + Send + 'static,
    F: Send + 'static,
{
    fn launch_observation(
        &mut self,
        node: &crucible::NodeId,
        profile: &crucible_qemu::QemuLiveNodeStepGateConfig,
        router: &str,
        crash: &str,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        self.launch_native_observation(node, profile, router, crash)
    }

    fn borrow_observation<'a>(
        &'a mut self,
        context: &'a AttemptExecutionContext,
    ) -> Result<ObservedNativeNode<'a>, LifecycleApiError> {
        self.borrow_native_observation(context)
    }

    fn inspect_trace(
        &self,
        node: &crucible::NodeId,
        generation: u64,
        maximum_bytes: u64,
        inspect: &mut dyn FnMut(&mut dyn BufRead) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        self.inspect_native_observation_trace(node, generation, maximum_bytes, inspect)
    }

    fn liveness_tail(
        &self,
        node: &crucible::NodeId,
        generation: u64,
    ) -> Result<String, Box<dyn Error>> {
        self.native_observation_liveness_tail(node, generation)
    }
}

/// Keeps actual whole-role refusal or terminal history at the outer runner.
pub(crate) enum NativeObservationRetirementError {
    Pending {
        retirement: crate::lifecycle_cleanup::PreparedSourceRetirement,
        refusal: Option<crate::lifecycle_cleanup::PreparedSourceRefusal>,
    },
    Terminal(std::sync::Mutex<crate::ProductionVmConstructionPostBody>),
}

impl std::fmt::Debug for NativeObservationRetirementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending { refusal, .. } => formatter
                .debug_struct("NativeObservationRetirementPending")
                .field("refusal", refusal)
                .finish_non_exhaustive(),
            Self::Terminal(body) => formatter
                .debug_tuple("NativeObservationTerminal")
                .field(body)
                .finish(),
        }
    }
}

impl std::fmt::Display for NativeObservationRetirementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending {
                retirement,
                refusal,
            } => {
                write!(
                    formatter,
                    "same native observation retirement remains pending: {refusal:?}"
                )?;
                let mut result = Ok(());
                retirement.with_history(|phase, first| {
                    if result.is_ok() {
                        result = write!(formatter, "; {phase}: {first}");
                    }
                });
                result
            }
            Self::Terminal(body) => match body.try_lock() {
                Ok(body) => write!(
                    formatter,
                    "native observation returned with history: {body}"
                ),
                Err(std::sync::TryLockError::Poisoned(poison)) => write!(
                    formatter,
                    "native observation returned with retained history: {}",
                    &**poison.get_ref()
                ),
                Err(std::sync::TryLockError::WouldBlock) => formatter
                    .write_str("native observation returned with borrowed terminal history"),
            },
        }
    }
}

impl Error for NativeObservationRetirementError {}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Configures the actual retained launcher before Flight observation IO.
    pub(crate) fn begin_native_observation_default(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        // Main owns the Pending before even an admitted configuration copy.
        let prepared = self.selected_prepared_source()?;
        let result = prepared.with_pending(|pending| {
            pending.require_pristine_request()?;
            let inputs = self
                .config
                .try_clone_admitted()
                .map_err(|first| QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(first)))
                .and_then(|config| config_for_assignment_host_watchdog(config, context));
            let (config, registration) = match inputs {
                Ok(inputs) => inputs,
                Err(first) => {
                    pending.record_construction_first(first);
                    return Err(());
                }
            };
            pending.prepare_native_observation_launcher(
                context,
                source,
                config,
                registration,
                self.terminal_checkpoints.clone(),
            )
        });
        complete_prepared_request(&prepared, result)
    }

    /// Borrows only operations while Main keeps the same actual native owner.
    pub(crate) fn with_native_observation(
        &mut self,
        apply: &mut dyn FnMut(&mut dyn NativeObservationOwner) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        let prepared = self.prepared_source_handle()?;
        prepared.with_native_observation(apply)
    }

    /// Observes actual whole-role disposal, never diagnostic or body absence.
    pub(crate) fn native_observation_is_closed(&self) -> bool {
        self.prepared_source
            .as_ref()
            .is_none_or(|prepared| matches!(prepared.is_released(), Ok(true)))
    }

    /// Closes only the owned body before the inner Flight returns its evidence.
    pub(crate) fn retry_native_observation_body(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        let Some(prepared) = self.prepared_source.as_ref() else {
            return Ok(());
        };
        match prepared.service_main_handle().retry_prepared_body() {
            Ok(true) => Ok(()),
            Ok(false) => Err(prepared
                .failure("native observation body remains retained")
                .into()),
            Err(raw) => Err(prepared
                .failure_with_refusal("retire native observation body", raw)
                .into()),
        }
    }

    /// Drives the same saved Cleanup and preserves every actual terminal cause.
    pub(crate) fn retire_native_observation(
        &mut self,
    ) -> Result<(), NativeObservationRetirementError> {
        let Some(prepared) = self.prepared_source.as_ref() else {
            return Ok(());
        };
        if matches!(prepared.is_released(), Ok(true)) {
            return Ok(());
        }
        let mut retirement = prepared.clone().into_retirement();
        match retirement.retry() {
            Ok(true) => {}
            result => {
                return Err(NativeObservationRetirementError::Pending {
                    retirement,
                    refusal: result.err(),
                });
            }
        }
        match retirement.finish() {
            Ok(body) if body.first_failure().is_none() => {
                // Actual terminal payload destruction precedes the role's Free
                // journal. No diagnostic move is mistaken for that disposal.
                drop(body);
                Ok(())
            }
            Ok(body) => Err(NativeObservationRetirementError::Terminal(
                std::sync::Mutex::new(body),
            )),
            Err(retirement) => Err(NativeObservationRetirementError::Pending {
                retirement,
                refusal: None,
            }),
        }
    }
}
