//! Admits and runs a native Target through its actual containing Main owner.
//!
//! The same factory keeps refused preclaim input or the original retirement
//! observer in fixed slots. No Source checkout, partial child, cleanup loan or
//! API frame is published in an owning error allocated after native effects.

use super::runtime::{PreparedTargetRuntime, TargetRetirement};
use super::target_construction::{TargetConstructionInput, TargetService, reserve_target_main};
use super::*;

/// Selects one already installed Target across independent Service startup.
#[must_use = "the original Main constructor remains occupied until retirement"]
pub(crate) struct PreparedTargetLaunch<F> {
    selector: crate::PreparedSourceSelector,
    key: QemuHotForkSourceWorldKey,
    runtime_basis: crate::AttemptExecutionRuntimeBasis,
    service: TargetService,
    factory: std::marker::PhantomData<fn() -> F>,
}

impl<F> PreparedTargetLaunch<F> {
    /// Borrows startup operations for this actual Target role only.
    pub(crate) fn service_main_handle(&self) -> crate::lifecycle_cleanup::ServiceMainHandle {
        self.selector.service_main_handle()
    }
}

impl<S, R> QemuProductionHotForkWorldLifecycleFactory<S, R>
where
    S: QemuHotForkSourceWorldProvider,
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
{
    /// Installs and runs one ordinary Execution-funded Target.
    pub(super) fn start_retained_target(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        selected: SelectedTargetSource,
    ) -> Result<
        QemuHotForkWorldLifecycleStart<PreparedTargetRuntime<R>>,
        AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<S::Error>>,
    > {
        let prepared = self.reserve_selected_target(selected, TargetService::Execution)?;
        self.finish_prepared_target(prepared, input, context)
    }

    /// Preclaims a real Target role before independently funded Service startup.
    ///
    /// # Errors
    /// Preserves source checkout and authentic Main refusal before native effects.
    pub(crate) fn prepare_independent_target(
        &mut self,
        input: &CrucibleAttemptExecution,
        original: &AttemptExecutionContext,
    ) -> Result<
        Option<PreparedTargetLaunch<R>>,
        AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<S::Error>>,
    > {
        let Some(selected) = self.select_source_for_attempt(input, original)? else {
            return Ok(None);
        };
        self.reserve_selected_target(selected, TargetService::Independent)
            .map(Some)
    }

    fn reserve_selected_target(
        &mut self,
        selected: SelectedTargetSource,
        service: TargetService,
    ) -> Result<
        PreparedTargetLaunch<R>,
        AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<S::Error>>,
    > {
        let SelectedTargetSource {
            key,
            lease: source_lease,
            world: source_world,
            continuation,
            runtime_basis,
        } = selected;
        type FactoryError<P> = QemuProductionHotForkWorldLifecycleFactoryError<P>;
        let selected = source_world
            .try_lock()
            .ok()
            .and_then(|source| source.prepared_source_selector());
        let Some(selected) = selected else {
            drop(source_world);
            self.sources.restore(source_lease);
            return Err(AttemptWorkerFailure::Retryable(FactoryError::Source(
                String::from("launcher has no genuine source target issuer"),
            )));
        };
        let (Some(producer), Some(factory)) = (
            self.resources.source_main_producer(),
            self.resources.retain_fork_target_factory(),
        ) else {
            drop(source_world);
            self.sources.restore(source_lease);
            return Err(AttemptWorkerFailure::Retryable(FactoryError::Source(
                String::from("target factory has no genuine containing Main owner"),
            )));
        };
        let prepared = match reserve_target_main(
            &producer,
            TargetConstructionInput {
                factory,
                source: source_lease,
                source_selector: selected,
                continuation,
            },
            service,
        ) {
            Ok(prepared) => prepared,
            Err(failure) => {
                drop(source_world);
                return match failure.try_restore_source() {
                    Ok((source, first)) => {
                        self.sources.restore(source);
                        Err(AttemptWorkerFailure::Retryable(
                            FactoryError::TargetAdmission(first),
                        ))
                    }
                    Err(failure) => {
                        self.retained_target_admission = Some(failure);
                        Err(AttemptWorkerFailure::Retryable(
                            FactoryError::RetainedTargetAdmission,
                        ))
                    }
                };
            }
        };
        let observer = match prepared.observe_retirement() {
            Ok(observer) => observer,
            Err(first) => {
                // The actual Pending already owns the checkout. This report
                // retains its same counted role before retiring any work.
                return Err(AttemptWorkerFailure::Terminal(FactoryError::TargetCleanup(
                    crate::ProductionVmConstructionCleanupError::Prepared(
                        prepared
                            .failure_with_refusal("retain original Target runtime observer", first),
                    ),
                )));
            }
        };
        self.retained_target = Some(TargetRetirement::new(observer));
        let selector = prepared.erase();
        self.preclaimed_target = Some(selector.clone());
        Ok(PreparedTargetLaunch {
            selector,
            key,
            runtime_basis,
            service,
            factory: std::marker::PhantomData,
        })
    }

    /// Runs the same preclaimed Target after its actual Context is available.
    ///
    /// # Errors
    /// Refuses foreign factories, changed semantic provenance or retained setup
    /// while preserving the same Main-owned body and original checkout.
    pub(crate) fn finish_prepared_target(
        &mut self,
        launch: PreparedTargetLaunch<R>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<
        QemuHotForkWorldLifecycleStart<PreparedTargetRuntime<R>>,
        AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<S::Error>>,
    > {
        type FactoryError<P> = QemuProductionHotForkWorldLifecycleFactoryError<P>;
        if !self
            .preclaimed_target
            .as_ref()
            .is_some_and(|selected| selected.same_role(&launch.selector))
        {
            return Err(AttemptWorkerFailure::Terminal(FactoryError::Source(
                String::from("preclaimed Target belongs to another containing factory"),
            )));
        }
        let runtime_basis = context
            .runtime_basis()
            .ok_or_else(|| AttemptWorkerFailure::Terminal(FactoryError::MissingRuntimeBasis))?;
        let key = QemuHotForkSourceWorldKey::for_execution(input, context, runtime_basis)
            .map_err(|first| AttemptWorkerFailure::Terminal(FactoryError::SourceKey(first)))?;
        if key != launch.key || runtime_basis != launch.runtime_basis {
            return Err(AttemptWorkerFailure::Terminal(FactoryError::Source(
                String::from("preclaimed Target semantic/runtime provenance changed"),
            )));
        }
        self.preclaimed_target = None;
        let prepared = launch
            .selector
            .typed::<super::target_construction::PendingTargetConstruction<R>>();
        let preflight = prepared.with_prepared(|pending| {
            pending.with_launch_basis(|source, continuation| {
                self.prepare_native_target_ram(context, source, continuation, launch.service)
            })
        });
        let preflight = match preflight {
            Ok(Some(preflight)) => preflight,
            Ok(None) => {
                return Err(AttemptWorkerFailure::Terminal(
                    FactoryError::TargetConstruction(
                        prepared.failure("original Target launch basis is absent"),
                    ),
                ));
            }
            Err(first) => {
                return Err(AttemptWorkerFailure::Terminal(
                    FactoryError::TargetConstruction(
                        prepared.failure_with_refusal("borrow original Target launch basis", first),
                    ),
                ));
            }
        };
        let (ram, limits) = match preflight {
            Ok(preflight) => preflight,
            Err(message) => {
                let _retained = prepared.with_prepared(|pending| {
                    pending.retain_api_failure(crucible_control_api::LifecycleApiError::LoopFactory {
                        message,
                    });
                });
                return Err(AttemptWorkerFailure::Terminal(
                    FactoryError::TargetConstruction(
                        prepared.failure("prepare original Target RAM"),
                    ),
                ));
            }
        };
        let scenario = input.scenario().scenario_def();
        let auxiliary = self.auxiliary_resources.clone();
        let configured = prepared.with_prepared(|pending| {
            pending.bind_auxiliary(auxiliary)
                && pending.launch_prepared(
                    &NativeTargetOperations,
                    input,
                    context,
                    limits,
                    ram.as_ref(),
                    self.shutdown_policy,
                    self.async_policy,
                )
                && pending.prepare_api_frame(
                    &scenario,
                    input.scenario(),
                    self.run_state_root.clone(),
                    self.terminal_checkpoints.clone(),
                    context.cancellation().clone(),
                )
        });
        if !matches!(configured, Ok(true)) {
            let failure = match configured {
                Err(first) => {
                    prepared.failure_with_refusal("borrow original Target construction", first)
                }
                Ok(_) => prepared.failure("construct original Target"),
            };
            return Err(AttemptWorkerFailure::Retryable(
                FactoryError::TargetConstruction(failure),
            ));
        }
        let exported = prepared.with_prepared(|pending| pending.export_lifecycle());
        let body = match exported {
            Ok(Some(body)) => body,
            Ok(None) => {
                return Err(AttemptWorkerFailure::Retryable(
                    FactoryError::TargetConstruction(
                        prepared.failure("export original Target body"),
                    ),
                ));
            }
            Err(first) => {
                return Err(AttemptWorkerFailure::Retryable(
                    FactoryError::TargetConstruction(
                        prepared.failure_with_refusal("borrow original Target export", first),
                    ),
                ));
            }
        };
        let Some(retirement) = self.retained_target.take() else {
            // The operation-only body returns itself to its actual Main on Drop.
            drop(body);
            return Err(AttemptWorkerFailure::Terminal(FactoryError::RetainedTarget));
        };
        Ok(QemuHotForkWorldLifecycleStart::Started(
            PreparedTargetRuntime::new(body, prepared.erase(), retirement, runtime_basis),
        ))
    }

    /// Preserves the existing RAM geometry and attempt resource validation.
    fn prepare_native_target_ram(
        &self,
        context: &AttemptExecutionContext,
        source: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        continuation: &crate::ProductionVmHotForkWorldContinuation,
        service: TargetService,
    ) -> Result<
        (
            Arc<dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory>,
            AttemptResourceLimits,
        ),
        String,
    > {
        #[cfg(test)]
        let ram = if let Some(mode) = self.native_qualification_ram_mode {
            crate::qemu_campaign_lifecycle::create_native_qualification_ram_registration_factory(
                context, mode,
            )
        } else {
            crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(context)
        }
        .map_err(|first| first.to_string())?;
        #[cfg(not(test))]
        let ram = crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(context)
            .map_err(|first| first.to_string())?;
        let mut shapes = Vec::new();
        {
            let mut source = source.try_lock().map_err(|_| {
                String::from(
                    "original Source ownership lock is unavailable during Target RAM preflight",
                )
            })?;
            if matches!(service, TargetService::Independent) {
                // Preclaim used the original caller before this Service
                // existed. Native work must borrow the actual child's
                // supervision, while the Source retains its physical charge.
                let supervisor = context.host_operation_supervisor().ok_or_else(|| {
                    String::from("independent Target has no admitted host operation supervisor")
                })?;
                source
                    .attach_borrowed_host_operation_supervisor(supervisor)
                    .map_err(|first| first.to_string())?;
            }
            for boundary in continuation.nodes() {
                if boundary.service_state()
                    == ProductionVmHotForkNodeServiceState::PermanentlyFailed
                {
                    continue;
                }
                let launch = source
                    .prepared_launch_resources(boundary.node())
                    .map_err(|first| first.to_string())?;
                shapes.push(
                    crucible_control_api::host_operational::ProductionHostRamLaunchShape {
                        node: boundary.node().name.clone(),
                        declared_ram_bytes: launch.guest_memory_bytes(),
                        vcpus: launch.virtual_cpus(),
                    },
                );
            }
        }
        ram.configure_world(&shapes)
            .map_err(|first| first.to_string())?;
        let native = ram
            .native_world_limits()
            .map_err(|first| first.to_string())?;
        let remaining = context
            .process_resources()
            .map_err(|first| first.to_string())?;
        let limits = AttemptResourceLimits::new(
            native.cpu_slots,
            native.resident_bytes,
            native.writable_bytes,
            remaining.maximum_execution_quanta(),
        )
        .map_err(|first| first.to_string())?;
        Ok((ram, limits))
    }
}
