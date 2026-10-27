//! Retains the contacted Inventory catalog pass on its actual Runtime.
//!
//! The same paid source model precedes request construction. The fixed reply
//! is priced separately from the transient physical worker, whose exclusive
//! flight is obtained through the genuine Inventory-purpose lender.

use super::*;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use crate::observation_protocol::WorkspaceCatalogCustodyBindingV1;
use crate::pin_worker_runtime::FreshWorkspaceCatalogObservationV1;
use crate::workspace_catalog::{
    ActivatedStorageWorkspaceCatalogV1,
    StorageWorkspaceCatalogActivationPromotionFailureV1, StorageWorkspaceCatalogPlanV1,
};

type Composition = (StorageWorkspaceCatalogPlanV1, Option<AuthenticatedWorkspaceCatalogPhysicalPlanV1>);

// Only this module constructs the original variant from the real borrowed
// Inventory turn. The ordinary adapter carries no financial or authority DATA.
enum CatalogWorker<'stage, 'cut, 'original> {
    Ordinary,
    GuestRootPublication31 {
        receiving: &'stage mut crate::state::encoding::StateEncodingLoanV1<'cut, 'original>,
        request: &'stage aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    },
    Inventory(&'stage mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'original>),
    State(&'stage mut crate::state::encoding::StateEncodingLoanV1<'cut, 'original>),
    RootExport(&'stage mut aos_sandbox_controller_domain::StorageRootLaunchExportReceivingLoanV2<'cut, 'original>),
}

#[derive(Clone, Copy)]
enum Failure {
    Gate,
    Clock,
    Composition,
    Nonce,
    Request,
    Preparation,
    Encoding,
    Worker,
    Recomposition,
    Custody,
    ReconstructedRequest,
    PromotionClock,
    Promotion,
    Lifecycle,
    Readback,
    CompleteReadbackDemand,
    CompleteReadbackPayment,
    ClosingClock,
}

/// Owns actual inputs and returned results until the outer Inventory posts finish.
#[derive(Default)]
pub(super) struct InventoryCatalogOriginalV1 {
    validated: Option<ValidatedPendingStorageWorkspaceCatalogV1>,
    composition: Option<Result<Composition, StorageBrokerError>>,
    nonce: Option<Result<[u8; 32], ZfsWorkerError>>,
    request: Option<Result<WorkspaceCatalogObservationRequestV1, StorageRuntimeError>>,
    preparation: Option<Result<(), StorageWorkspaceCatalogError>>,
    candidate: Option<StorageWorkspaceCatalogActivationCandidateV1>,
    encoding: Option<Result<Vec<u8>, ZfsWorkerError>>,
    worker: Option<Result<FreshWorkspaceCatalogObservationV1, ZfsWorkerError>>,
    recomposition: Option<Result<Composition, StorageBrokerError>>,
    custody: Option<Result<WorkspaceCatalogCustodyBindingV1, ZfsWorkerError>>,
    reconstructed_request: Option<Result<WorkspaceCatalogObservationRequestV1, ZfsWorkerError>>,
    clock: Option<Result<u64, ZfsWorkerError>>,
    promotion_clock: Option<Result<u64, ZfsWorkerError>>,
    promotion: Option<Result<ActivatedStorageWorkspaceCatalogV1, StorageWorkspaceCatalogActivationPromotionFailureV1>>,
    workspace_body: Option<Vec<u8>>,
    lifecycle: Option<Result<Vec<u8>, StorageRuntimeError>>,
    lifecycle_source: Option<Vec<u8>>,
    readback: Option<Result<Vec<u8>, crate::guest_root_inventory::GuestRootInventoryErrorV1>>,
    readback_original: crate::guest_root_inventory::GuestRootInventoryReadbackOriginalV1,
    complete_readback_demand: Option<Result<ResourceVector, AccountingError>>,
    complete_readback_payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    closing_clock: Option<Result<u64, ZfsWorkerError>>,
    refused_body: Option<Vec<u8>>,
    gate: Option<StorageRuntimeError>,
    first: Option<Failure>,
    entered: bool,
}

impl InventoryCatalogOriginalV1 {
    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, AccountingError> {
        use crate::receiving_demand::{add, count, multiply};
        let returned = crate::pin_worker_runtime::inventory_catalog_returned_model_demand_v1()
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        // Fixed frame and call operands consume bytes, not namespace entries.
        // Actual resident State/workspace rows are priced by their own shape.
        let work = std::mem::size_of::<(
            WorkspaceCatalogObservationBindingsV1, WorkspaceCatalogCustodyBindingV1,
            ObjectDigest, [u8; 32], u64,
        )>();
        let memory = add(multiply(count(std::mem::size_of::<Self>())?, 3)?,
            multiply(count(work)?, 41)?)?;
        ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .checked_add(returned)
    }

    fn fail<T>(&mut self, first: Failure) -> Result<T, StorageRuntimeError> {
        self.first.get_or_insert(first);
        Err(StorageRuntimeError::Receiving)
    }

    pub(super) fn retain_refused_body(&mut self, body: Vec<u8>) {
        if self.refused_body.is_none() {
            self.refused_body = Some(body);
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            value.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
        }
        match self.first? {
            Failure::Gate => self.gate.as_ref().map(|cause| cause as &dyn std::error::Error),
            Failure::Clock => error(&self.clock),
            Failure::Composition => error(&self.composition),
            Failure::Nonce => error(&self.nonce),
            Failure::Request => error(&self.request),
            Failure::Preparation => error(&self.preparation),
            Failure::Encoding => error(&self.encoding),
            Failure::Worker => {
                let cause = self.worker.as_ref()?.as_ref().err()?;
                // Resolve only the real chronological Native refusal marker.
                // A later owed post never replaces an earlier IO/decoder cause.
                match cause.physical_native_refusal_v1() {
                    Some(marker) => Some(marker),
                    None => Some(cause),
                }
            }
            Failure::Recomposition => error(&self.recomposition),
            Failure::Custody => error(&self.custody),
            Failure::ReconstructedRequest => error(&self.reconstructed_request),
            Failure::PromotionClock => error(&self.promotion_clock),
            Failure::Promotion => self.promotion.as_ref()?.as_ref().err()
                .map(StorageWorkspaceCatalogActivationPromotionFailureV1::actual_failure_v1),
            Failure::Lifecycle => error(&self.lifecycle),
            Failure::Readback => self.readback_original.failure().or_else(|| error(&self.readback)),
            Failure::CompleteReadbackDemand => error(&self.complete_readback_demand),
            Failure::CompleteReadbackPayment => error(&self.complete_readback_payment),
            Failure::ClosingClock => error(&self.closing_clock),
        }
    }

    fn finish_body(
        &mut self,
        body: Vec<u8>,
        template: Option<&crate::guest_root_inventory::ProtectedGuestRootTemplateV1>,
        deadline: u64,
        retaining: bool,
        coordinator: Option<&StorageAdmissionCoordinator>,
        receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        self.lifecycle_source = Some(body);
        if let Some(template) = template {
            let Some(body) = self.lifecycle_source.as_ref() else {
                return self.fail(Failure::Gate);
            };
            self.readback = Some(if matches!(self.complete_readback_payment, Some(Ok(()))) {
                let coordinator = coordinator.ok_or(StorageRuntimeError::Receiving)?;
                let mut labels = crate::guest_root_inventory::GuestRootLabelReceivingV2::state_v2(
                    coordinator.recovery_encoding_journal_v1(),
                    receiving.ok_or(StorageRuntimeError::Receiving)?,
                );
                crate::guest_root_inventory::attach_guest_root_publication_readback_current_v2(
                    body, template, &mut self.readback_original, coordinator, &mut labels,
                )
            } else if retaining {
                crate::guest_root_inventory::attach_guest_root_publication_readback_retaining_v1(
                    body, template, &mut self.readback_original,
                )
            } else {
                attach_guest_root_publication_readback_v1(body, template)
            });
            if !self.readback.as_ref().is_some_and(Result::is_ok) {
                return self.fail(Failure::Readback);
            }
        }
        self.closing_clock = Some(boottime_now_nanoseconds());
        let Some(Ok(now)) = self.closing_clock.as_ref() else {
            return self.fail(Failure::ClosingClock);
        };
        if *now >= deadline {
            self.gate = Some(StorageRuntimeError::Recovery);
            return self.fail(Failure::Gate);
        }
        match self.readback.take() {
            Some(Ok(body)) => Ok(body),
            None => self.lifecycle_source.take().ok_or(StorageRuntimeError::Receiving),
            Some(Err(error)) => {
                self.readback = Some(Err(error));
                self.fail(Failure::Readback)
            }
        }
    }

    pub(super) fn finished_inventory_v1(&self) -> bool {
        self.entered && self.first.is_none()
            && matches!(self.closing_clock, Some(Ok(_)))
            && matches!(self.worker, Some(Ok(_)))
            && self.workspace_body.is_some()
    }

    pub(super) fn into_ordinary_result(mut self) -> Result<
        (ValidatedPendingStorageWorkspaceCatalogV1, Vec<u8>),
        (Option<ValidatedPendingStorageWorkspaceCatalogV1>, StorageRuntimeError),
    > {
        fn take_error<T, E>(value: &mut Option<Result<T, E>>) -> Option<E> {
            match value.take() {
                Some(Err(error)) => Some(error),
                other => {
                    *value = other;
                    None
                }
            }
        }

        if self.first.is_none() {
            if let (Some(validated), Some(body)) = (self.validated.take(), self.workspace_body.take()) {
                // The original logical plan is the final owned pipeline local.
                if let Some(Ok((plan, physical))) = self.composition.take() {
                    drop(physical);
                    drop(plan);
                }
                return Ok((validated, body));
            }
        }

        let mut validated = self.validated.take();
        let error = match self.first {
            Some(Failure::Composition) => take_error(&mut self.composition).map(Into::into),
            Some(Failure::Nonce) => take_error(&mut self.nonce).map(Into::into),
            Some(Failure::Request) => take_error(&mut self.request),
            Some(Failure::Preparation) => take_error(&mut self.preparation).map(Into::into),
            Some(Failure::Encoding) => take_error(&mut self.encoding).map(Into::into),
            Some(Failure::Worker) => take_error(&mut self.worker).map(Into::into),
            Some(Failure::Recomposition) => take_error(&mut self.recomposition).map(Into::into),
            Some(Failure::Custody) => {
                // Preserve the existing ordinary coarse scope classification.
                Some(StorageRuntimeError::WorkspacePinScope)
            }
            Some(Failure::ReconstructedRequest) => take_error(&mut self.reconstructed_request).map(Into::into),
            Some(Failure::PromotionClock) => take_error(&mut self.promotion_clock).map(Into::into),
            Some(Failure::Promotion) => {
                take_error(&mut self.promotion).map(|failure| {
                    let (original, error) = failure.into_parts();
                    let reopen = original.as_ref().is_some_and(
                        ValidatedPendingStorageWorkspaceCatalogV1::startup_materialization_failed_v1,
                    );
                    validated = original;
                    if reopen { StorageRuntimeError::ReopenRequired } else { error.into() }
                })
            }
            _ => self.gate.take(),
        }.unwrap_or(StorageRuntimeError::Recovery);

        // Error expressions first recover structural custody at the old helper
        // boundary, before encoded bytes or any completed Fresh reply dispose.
        if let Some(candidate) = self.candidate.take() {
            validated = Some(candidate.into_validated());
        }
        drop(self.encoding.take());
        drop(self.custody.take());
        drop(self.reconstructed_request.take());
        if let Some(Ok((plan, physical))) = self.recomposition.take() {
            drop(physical);
            drop(plan);
        }
        drop(self.worker.take());
        if let Some(Ok((plan, physical))) = self.composition.take() {
            drop(physical);
            drop(plan);
        }
        Err((validated, error))
    }

    pub(super) fn observe_state_receiving_v1(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        pin_io: &mut dyn WorkspacePinRuntimeIo,
        configuration_binding: ObjectDigest,
        broker_instance_id: [u8; 16],
        deadline: u64,
        cutoff: u64,
        operator_startup: Option<&operator_startup::DeferredOperatorStartupV4>,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageRuntimeError> {
        self.observe(coordinator, pin_io, configuration_binding, broker_instance_id,
            deadline, cutoff, operator_startup, CatalogWorker::State(receiving))
    }

    pub(super) fn park_validated_v1(&mut self, validated: ValidatedPendingStorageWorkspaceCatalogV1) {
        self.validated = Some(validated);
    }

    pub(super) fn take_positive_validated_v1(&mut self)
        -> Option<ValidatedPendingStorageWorkspaceCatalogV1>
    {
        if self.first.is_some() { return None; }
        self.validated.take()
    }

    fn observe(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        pin_io: &mut dyn WorkspacePinRuntimeIo,
        configuration_binding: ObjectDigest,
        broker_instance_id: [u8; 16],
        deadline: u64,
        cutoff: u64,
        operator_startup: Option<&operator_startup::DeferredOperatorStartupV4>,
        mut worker: CatalogWorker<'_, '_, '_>,
    ) -> Result<(), StorageRuntimeError> {
        if self.entered || self.first.is_some() {
            return Err(StorageRuntimeError::Receiving);
        }
        self.entered = true;
        let retained = !matches!(&worker, CatalogWorker::Ordinary);
        self.composition = Some(coordinator.workspace_catalog_activation_plan());
        let Some(Ok((plan, Some(physical)))) = self.composition.as_ref() else {
            if self.composition.as_ref().is_some_and(Result::is_ok) {
                self.gate = Some(StorageRuntimeError::Recovery);
                return self.fail(Failure::Gate);
            }
            return self.fail(Failure::Composition);
        };
        self.nonce = Some(catalog_observation_nonce());
        let Some(Ok(nonce)) = self.nonce.as_ref() else {
            return self.fail(Failure::Nonce);
        };
        let Some(validated) = self.validated.as_ref() else {
            self.gate = Some(StorageRuntimeError::Recovery);
            return self.fail(Failure::Gate);
        };
        self.request = Some(build_catalog_observation_request(
            configuration_binding, broker_instance_id, pin_io,
            validated, plan, physical, *nonce, deadline,
        ));
        if !self.request.as_ref().is_some_and(Result::is_ok) {
            return self.fail(Failure::Request);
        }
        let Some(validated) = self.validated.take() else {
            return self.fail(Failure::Gate);
        };
        let Some(Ok((_, physical))) = self.composition.as_mut() else {
            return self.fail(Failure::Gate);
        };
        let Some(physical) = physical.take() else {
            return self.fail(Failure::Gate);
        };
        let Some(Ok(request)) = self.request.take() else {
            return self.fail(Failure::Gate);
        };
        let preparation = StorageWorkspaceCatalogActivationCandidateV1::new(
            validated, physical, request,
        );
        match preparation {
            Ok(candidate) => {
                self.candidate = Some(candidate);
                self.preparation = Some(Ok(()));
            }
            Err(failure) => {
                let (validated, error) = failure.into_parts();
                self.validated = Some(validated);
                self.preparation = Some(Err(error));
                return self.fail(Failure::Preparation);
            }
        }
        let Some(candidate) = self.candidate.as_ref() else {
            return self.fail(Failure::Gate);
        };
        self.encoding = Some(encode_request(candidate.request()));
        let Some(Ok(bytes)) = self.encoding.as_ref() else {
            return self.fail(Failure::Encoding);
        };
        self.worker = Some(match &mut worker {
            CatalogWorker::Ordinary => pin_io.observe_catalog(bytes, candidate.request(), cutoff),
            CatalogWorker::Inventory(receiving) => {
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::inventory(
                    receiving, coordinator.recovery_encoding_journal_v1(),
                );
                pin_io.observe_catalog_receiving_v1(bytes, candidate.request(), cutoff, &mut stage)
            }
            CatalogWorker::RootExport(receiving) => {
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::root_export_v2(
                    receiving, coordinator.recovery_encoding_journal_v1(),
                );
                pin_io.observe_catalog_receiving_v1(bytes, candidate.request(), cutoff, &mut stage)
            }
            CatalogWorker::GuestRootPublication31 { receiving, request } => {
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::guest_root_publication_v2(
                    receiving, coordinator.recovery_encoding_journal_v1(), request,
                );
                pin_io.observe_catalog_receiving_v1(bytes, candidate.request(), cutoff, &mut stage)
            }
            CatalogWorker::State(receiving) => {
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::state(
                    receiving, coordinator.recovery_encoding_journal_v1(),
                );
                pin_io.observe_catalog_receiving_v1(bytes, candidate.request(), cutoff, &mut stage)
            }
        });
        if !self.worker.as_ref().is_some_and(Result::is_ok) {
            return self.fail(Failure::Worker);
        }

        if !retained {
            drop(self.encoding.take());
        }

        let original_request = candidate.request();
        let nonce = original_request.nonce();
        let bindings = original_request.bindings();
        let deadline = original_request.deadline_boottime_nanoseconds();
        self.recomposition = Some(coordinator.workspace_catalog_activation_plan());
        let Some(Ok((_, Some(physical)))) = self.recomposition.as_ref() else {
            if self.recomposition.as_ref().is_some_and(Result::is_ok) {
                self.gate = Some(StorageRuntimeError::Recovery);
                return self.fail(Failure::Gate);
            }
            return self.fail(Failure::Recomposition);
        };
        self.custody = Some(pin_io.catalog_binding());
        let Some(Ok(custody)) = self.custody.as_ref() else {
            return self.fail(Failure::Custody);
        };
        self.reconstructed_request = Some(WorkspaceCatalogObservationRequestV1::new(
            nonce, deadline, bindings, *custody, physical.roots().to_vec(),
            physical.allowed_objects().to_vec(), physical.targets().to_vec(),
        ));
        if !self.reconstructed_request.as_ref().is_some_and(Result::is_ok) {
            return self.fail(Failure::ReconstructedRequest);
        }
        self.promotion_clock = Some(boottime_now_nanoseconds());
        let Some(Ok(now)) = self.promotion_clock.as_ref() else {
            return self.fail(Failure::PromotionClock);
        };
        let now = *now;
        let Some(candidate) = self.candidate.take() else {
            return self.fail(Failure::Gate);
        };
        let Some(Ok((plan, Some(physical)))) = self.recomposition.take() else {
            self.candidate = Some(candidate);
            return self.fail(Failure::Gate);
        };
        let Some(Ok(request)) = self.reconstructed_request.take() else {
            self.candidate = Some(candidate);
            return self.fail(Failure::Gate);
        };
        let Some(Ok(fresh)) = self.worker.take() else {
            self.candidate = Some(candidate);
            return self.fail(Failure::Gate);
        };
        let terminal_readonly = operator_startup.is_some_and(
            operator_startup::DeferredOperatorStartupV4::has_debt,
        );
        self.promotion = Some(if terminal_readonly {
            candidate.activate_operator_terminal_readonly_v4(plan, physical, request, fresh, now)
        } else {
            match &mut worker {
                CatalogWorker::State(receiving) => candidate.activate_state_receiving_v1(
                    plan, physical, request, fresh, now, receiving,
                    coordinator.recovery_encoding_journal_v1(),
                ),
                CatalogWorker::Inventory(_) | CatalogWorker::RootExport(_)
                | CatalogWorker::GuestRootPublication31 { .. } => candidate.activate_retaining_v1(
                    plan, physical, request, fresh, now,
                ),
                CatalogWorker::Ordinary => candidate.activate(plan, physical, request, fresh, now),
            }
        });
        if !self.promotion.as_ref().is_some_and(Result::is_ok) {
            return self.fail(Failure::Promotion);
        }
        let Some(Ok(activated)) = self.promotion.take() else {
            return self.fail(Failure::Gate);
        };
        let (validated, body) = activated.into_inventory();
        self.validated = Some(validated);
        self.workspace_body = Some(body);
        Ok(())
    }
}

impl StorageBrokerRuntime {
    pub(super) fn inventory_from_validated_shared_v1(
        &mut self,
        validated: ValidatedPendingStorageWorkspaceCatalogV1,
        deadline: u64,
        cutoff: u64,
    ) -> Result<
        (ValidatedPendingStorageWorkspaceCatalogV1, Vec<u8>),
        (Option<ValidatedPendingStorageWorkspaceCatalogV1>, StorageRuntimeError),
    > {
        let result = ordinary_from_validated_v1(
            &self.coordinator, self.pin_io.as_mut(), self.configuration_binding,
            self.broker_instance_id, self.operator_startup.as_ref(), validated, deadline, cutoff,
        );
        if matches!(&result, Err((_, StorageRuntimeError::ReopenRequired))) {
            self.latch_reopen_required();
        }
        result
    }

    /// Uses the actual Inventory-stage lender and same observer implementation.
    pub(crate) fn complete_lifecycle_inventory_resources_receiving_v1(
        &mut self,
        deadline: u64,
        cutoff: u64,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        if self.receiving_inventory_catalog.is_some()
            || !self.receiving_inventory_demand.as_ref().is_some_and(Result::is_ok)
        {
            return Err(StorageRuntimeError::Receiving);
        }
        self.receiving_inventory_catalog = Some(Box::new(InventoryCatalogOriginalV1::default()));
        self.complete_catalog_inventory_receiving_v1(deadline, cutoff, CatalogWorker::Inventory(receiving))
    }

    pub(crate) fn complete_lifecycle_inventory_state_receiving_v1(
        &mut self,
        deadline: u64,
        cutoff: u64,
        template: Option<&crate::guest_root_inventory::ProtectedGuestRootTemplateV1>,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        self.reserve_lifecycle_inventory_models_v1(receiving)?;
        let body = self.complete_catalog_inventory_receiving_v1(
            deadline, cutoff, CatalogWorker::State(receiving),
        )?;
        if let Some(template) = template {
            let rows = self.inventory_workspace_rows_v2();
            let original = &mut self.startup_reconciliation.catalog;
            original.complete_readback_demand = Some(rows.and_then(|rows|
                crate::guest_root_inventory::additional_complete_marker_readback_demand_v2(rows, template)));
            let Some(Ok(demand)) = original.complete_readback_demand.as_ref() else {
                return original.fail(Failure::CompleteReadbackDemand);
            };
            original.complete_readback_payment = Some(receiving.reserve_inventory_readback_v1(
                self.coordinator.recovery_encoding_journal_v1(), *demand,
            ));
            if !matches!(original.complete_readback_payment, Some(Ok(()))) {
                return original.fail(Failure::CompleteReadbackPayment);
            }
            original.readback_original.mark_complete_projection_prepaid_v2();
        }
        self.startup_reconciliation.catalog.finish_body(body, template, deadline, true, Some(&self.coordinator), Some(receiving))
    }

    fn complete_catalog_inventory_receiving_v1(
        &mut self,
        deadline: u64,
        cutoff: u64,
        worker: CatalogWorker<'_, '_, '_>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        self.complete_catalog_inventory_engine_v2(deadline, cutoff, worker, None)
    }

    pub(super) fn complete_root_export_inventory_v2(
        &mut self,
        original: &mut InventoryCatalogOriginalV1,
        deadline: u64,
        cutoff: u64,
        receiving: &mut aos_sandbox_controller_domain::StorageRootLaunchExportReceivingLoanV2<'_, '_>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        self.complete_catalog_inventory_engine_v2(
            deadline, cutoff, CatalogWorker::RootExport(receiving), Some(original),
        )
    }

    /// Runs one retained method31 catalog pass through the sole observer.
    ///
    /// The caller owns a distinct before or after capsule and pays its full
    /// model first. Neither pass resets the startup/Inventory once original.
    pub(super) fn complete_guest_root_catalog_v2(
        &mut self,
        original: &mut InventoryCatalogOriginalV1,
        deadline: u64,
        cutoff: u64,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        self.complete_catalog_inventory_engine_v2(
            deadline,
            cutoff,
            CatalogWorker::GuestRootPublication31 { receiving, request },
            Some(original),
        )
    }

    fn complete_catalog_inventory_engine_v2(
        &mut self,
        deadline: u64,
        cutoff: u64,
        worker: CatalogWorker<'_, '_, '_>,
        root_original: Option<&mut InventoryCatalogOriginalV1>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let initial = matches!(&worker, CatalogWorker::Inventory(_));
        let external = matches!(&worker, CatalogWorker::RootExport(_)
            | CatalogWorker::GuestRootPublication31 { .. });
        let ready = self.is_inventory_ready();
        let original = if external {
            root_original.ok_or(StorageRuntimeError::Receiving)?
        } else if initial {
            self.receiving_inventory_catalog.as_deref_mut().ok_or(StorageRuntimeError::Receiving)?
        } else {
            &mut self.startup_reconciliation.catalog
        };
        let dispatch = match self.worker_dispatch.enter() {
            Ok(dispatch) => dispatch,
            Err(()) => {
                original.gate = Some(StorageRuntimeError::Recovery);
                return original.fail(Failure::Gate);
            }
        };
        original.clock = Some(boottime_now_nanoseconds());
        let Some(Ok(now)) = original.clock.as_ref() else {
            return original.fail(Failure::Clock);
        };
        if !ready || *now >= cutoff || cutoff >= deadline {
            original.gate = Some(StorageRuntimeError::Recovery);
            return original.fail(Failure::Gate);
        }
        original.validated = self.workspaces.take();
        let observation = original.observe(
            &self.coordinator, self.pin_io.as_mut(), self.configuration_binding,
            self.broker_instance_id, deadline, cutoff, self.operator_startup.as_ref(), worker,
        );
        if let Err(error) = observation {
            let reopen = original.promotion.as_ref().and_then(|result| result.as_ref().err())
                .is_some_and(|failure| failure.startup_materialization_failed_v1());
            if reopen {
                self.latch_reopen_required();
                return Err(StorageRuntimeError::ReopenRequired);
            }
            return Err(error);
        }
        self.workspaces = original.validated.take();
        drop(dispatch);

        let body = original.workspace_body.as_ref().ok_or(StorageRuntimeError::Receiving)?;
        original.lifecycle = Some(complete_lifecycle_body_v1(&self.coordinator, body));
        if !original.lifecycle.as_ref().is_some_and(Result::is_ok) {
            return original.fail(Failure::Lifecycle);
        }
        match original.lifecycle.take() {
            Some(Ok(body)) => Ok(body),
            _ => Err(StorageRuntimeError::Receiving),
        }
    }

    pub(crate) fn finish_inventory_body_receiving_v1(
        &mut self,
        body: Vec<u8>,
        template: Option<&crate::guest_root_inventory::ProtectedGuestRootTemplateV1>,
        deadline: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let Some(original) = self.receiving_inventory_catalog.as_mut() else {
            return Err(StorageRuntimeError::Receiving);
        };
        original.finish_body(body, template, deadline, true, Some(&self.coordinator), None)
    }

    pub(crate) fn finish_inventory_body_ordinary_v1(
        &mut self,
        body: Vec<u8>,
        template: Option<&crate::guest_root_inventory::ProtectedGuestRootTemplateV1>,
        deadline: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let mut original = InventoryCatalogOriginalV1::default();
        let result = original.finish_body(body, template, deadline, false, Some(&self.coordinator), None);
        // Preserve the old ordinary coarse readback/clock error and exact
        // output-before-input disposal boundary. Selected retains both.
        drop(original.closing_clock.take());
        drop(original.readback.take());
        drop(original.lifecycle_source.take());
        result.map_err(|_| StorageRuntimeError::Recovery)
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn plan(sequence: u64) -> StorageWorkspaceCatalogPlanV1 {
        StorageWorkspaceCatalogPlanV1::new(
            sequence, ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32]),
            4, ObjectDigest::from_bytes([5; 32]), Vec::new(),
        ).unwrap()
    }

    fn candidate(directory: &TempDir) -> StorageWorkspaceCatalogActivationCandidateV1 {
        let identity_pool = StorageIdentityPoolV1::new(65_536, 65_536).unwrap();
        let validated = PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
            .unwrap().validate_plan(plan(1)).unwrap();
        let snapshot = validated.snapshot();
        let request = WorkspaceCatalogObservationRequestV1::new(
            [6; 32], 100,
            WorkspaceCatalogObservationBindingsV1::new(
                ObjectDigest::from_bytes([7; 32]), [8; 16],
                1, ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32]),
                4, ObjectDigest::from_bytes([5; 32]), snapshot.journal_sequence(),
                snapshot.digest(), snapshot.catalog_generation().unwrap_or(1),
                identity_pool.range_start(), identity_pool.range_size(),
            ).unwrap(),
            WorkspaceCatalogCustodyBindingV1::new([9; 16], 10, 11, 12, 13, 14).unwrap(),
            Vec::new(), Vec::new(), Vec::new(),
        ).unwrap();
        StorageWorkspaceCatalogActivationCandidateV1::new(
            validated,
            AuthenticatedWorkspaceCatalogPhysicalPlanV1::new_for_test(Vec::new(), Vec::new(), Vec::new()),
            request,
        ).ok().unwrap()
    }

    #[test]
    fn ordinary_projection_preserves_worker_error_class_and_validated_cut() {
        let directory = TempDir::new().unwrap();
        let candidate = candidate(&directory);
        let bytes = encode_request(candidate.request()).unwrap();
        let before = candidate.request().bindings();
        let mut original = InventoryCatalogOriginalV1::default();
        original.candidate = Some(candidate);
        original.encoding = Some(Ok(bytes));
        original.worker = Some(Err(ZfsWorkerError::Protocol("actual observer refusal")));
        original.first = Some(Failure::Worker);

        let (validated, error) = original.into_ordinary_result().err().unwrap();

        assert!(matches!(error, StorageRuntimeError::Worker(
            ZfsWorkerError::Protocol("actual observer refusal")
        )));
        let validated = validated.unwrap();
        assert_eq!(validated.snapshot().journal_sequence(), before.workspace_journal_sequence());
        assert_eq!(validated.snapshot().digest(), before.workspace_snapshot_digest());
        assert!(!validated.is_initialized());
    }

    #[test]
    fn ordinary_projection_keeps_promotion_validation_error_and_same_journal() {
        let directory = TempDir::new().unwrap();
        let candidate = candidate(&directory);
        let request = candidate.request().clone();
        let before = request.bindings();
        let digest = ObjectDigest::from_bytes([15; 32]);
        let result = crate::observation_protocol::WorkspaceCatalogObservationResultV1::matched(
            &request, digest, digest, digest, digest,
        ).unwrap();
        let promotion = candidate.activate(
            plan(2),
            AuthenticatedWorkspaceCatalogPhysicalPlanV1::new_for_test(Vec::new(), Vec::new(), Vec::new()),
            request, FreshWorkspaceCatalogObservationV1::new_for_test(result), 99,
        );
        let mut original = InventoryCatalogOriginalV1::default();
        original.promotion = Some(promotion);
        original.first = Some(Failure::Promotion);

        let (validated, error) = original.into_ordinary_result().err().unwrap();

        assert!(matches!(error, StorageRuntimeError::WorkspaceCatalog(
            StorageWorkspaceCatalogError::InvalidCandidate
        )));
        let validated = validated.unwrap();
        assert_eq!(validated.snapshot().journal_sequence(), before.workspace_journal_sequence());
        assert_eq!(validated.snapshot().digest(), before.workspace_snapshot_digest());
        assert!(!validated.is_initialized());
    }

    #[test]
    fn shared_nonexport_body_moves_the_original_buffer_without_a_clone() {
        let body = vec![1, 2, 3, 4];
        let pointer = body.as_ptr();
        let mut original = InventoryCatalogOriginalV1::default();

        let returned = original.finish_body(body, None, u64::MAX, false, None, None).unwrap();

        assert_eq!(returned.as_ptr(), pointer);
        assert_eq!(returned, [1, 2, 3, 4]);
        assert!(original.lifecycle_source.is_none());
        assert!(original.first.is_none());
    }

    #[test]
    fn shared_body_retains_the_original_buffer_on_final_deadline_refusal() {
        let body = vec![1, 2, 3, 4];
        let pointer = body.as_ptr();
        let mut original = InventoryCatalogOriginalV1::default();

        assert!(original.finish_body(body, None, 0, false, None, None).is_err());

        assert_eq!(original.lifecycle_source.as_ref().unwrap().as_ptr(), pointer);
        assert!(matches!(original.failure().unwrap().downcast_ref::<StorageRuntimeError>(),
            Some(StorageRuntimeError::Recovery)));
        assert!(matches!(original.closing_clock, Some(Ok(_))));
    }


    #[test]
    fn fixed_reply_and_control_bytes_do_not_create_namespace_entries() {
        use aos_sandbox_model::{ResourceAccount, ResourceCeilings};
        let demand = InventoryCatalogOriginalV1::fixed_demand_v1().unwrap();
        assert!(demand.get(D::MemoryBytes) > 0);
        assert_eq!(demand.get(D::MetadataEntries), 0);
        let account = ResourceAccount::new(ResourceCeilings::bounded(demand));

        let account = account.reserve(demand).unwrap();
        let actual_namespace_growth = ResourceVector::ZERO.with(D::MetadataEntries, 1);

        assert!(matches!(account.reserve(actual_namespace_growth),
            Err(AccountingError::LimitExceeded {
                dimension: D::MetadataEntries, limit: 0, attempted: 1,
            })));
    }

}

pub(super) fn ordinary_from_validated_v1(
    coordinator: &StorageAdmissionCoordinator,
    pin_io: &mut dyn WorkspacePinRuntimeIo,
    configuration_binding: ObjectDigest,
    broker_instance_id: [u8; 16],
    operator_startup: Option<&operator_startup::DeferredOperatorStartupV4>,
    validated: ValidatedPendingStorageWorkspaceCatalogV1,
    deadline: u64,
    cutoff: u64,
) -> Result<(ValidatedPendingStorageWorkspaceCatalogV1, Vec<u8>),
    (Option<ValidatedPendingStorageWorkspaceCatalogV1>, StorageRuntimeError)>
{
    let mut original = InventoryCatalogOriginalV1::default();
    original.validated = Some(validated);
    let _result = original.observe(coordinator, pin_io, configuration_binding,
        broker_instance_id, deadline, cutoff, operator_startup, CatalogWorker::Ordinary);
    original.into_ordinary_result()
}


// The ordinary and both selected Inventory paths attach the same five lifecycle
// families and repair commits. This helper performs no native acquisition.
pub(super) fn complete_lifecycle_body_v1(
    coordinator: &StorageAdmissionCoordinator,
    inventory: &[u8],
) -> Result<Vec<u8>, StorageRuntimeError> {
    let inventory = crate::lifecycle_inventory::attach_complete_lifecycle_inventory(
        coordinator,
        &inventory,
    )
    .map_err(|_| StorageRuntimeError::Recovery)?;
    // Repair commits are valid only on the completed V3 lifecycle source.
    let commits = coordinator
        .operator_recovery_satisfied_workspace_pin_commits()
        .map_err(|_| StorageRuntimeError::Recovery)?;
    let mut response = InventoryStorageResourcesResponse::decode_from_slice(&inventory)
        .map_err(|_| StorageRuntimeError::Recovery)?;
    response.operator_repair_commits = commits
        .into_iter()
        .map(
            |(operation_id, workspace_handle, request_digest, effect_commit_digest)| {
                StorageOperatorRepairCommitRecordV1 {
                    operation_id: operation_id.to_vec(),
                    workspace_handle: workspace_handle.to_vec(),
                    request_digest: request_digest.to_vec(),
                    effect_commit_digest: effect_commit_digest.to_vec(),
                    ..Default::default()
                }
            },
        )
        .collect();
    let inventory = response.encode_to_vec();
    decode_storage_resource_inventory_response(&inventory, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| StorageRuntimeError::Recovery)?;
    Ok(inventory)
}
