//! Owns one recurring method31 publication on the same State/F interval.
//!
//! Distinct retained catalog passes surround the existing physical worker.
//! The current-publication binding becomes durable Complete only after that
//! worker's actual disposition and a complete native marker/tree/label read.
//! Every negative owner stays on Runtime through its independent outer posts.

use super::*;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use crate::broker::GuestRootAdmissionOriginalV2;
use crate::guest_root_inventory::{GuestRootInventoryErrorV1, GuestRootTargetReadbackOriginalV2};
use crate::state::{GuestRootStateRecordOriginalV2, encoding::StateEncodingLoanV1};
use aos_sandbox_protocol::ValidatedStorageInventory;
use aos_sandbox_broker::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};

#[derive(Debug, thiserror::Error)]
enum PublicationClockErrorV2 {
    #[error("guest-root publication clock changed or expired")]
    Stale,
    #[error(transparent)]
    Linux(aos_sandbox_linux::Error),
}

impl KernelPairedClockErrorV1 for PublicationClockErrorV2 {
    fn stale() -> Self { Self::Stale }
    fn kernel(cause: aos_sandbox_linux::Error) -> Self { Self::Linux(cause) }
}

type FinalClock = RetainedKernelPairedClockAttemptV1<PublicationClockErrorV2>;

#[derive(Clone, Copy)]
enum Failure {
    Gate, Semantics, Before, BeforeModel, Quiescence,
    ReadbackDemand, ReadbackPayment, Publisher, Admission, Worker,
    AfterClock, Cutoff, After, AfterModel, Readback, FinalClock, Complete,
}

/// Keeps the entire entered publication until the genuine Sent disposition.
pub(super) struct GuestRootPublicationOriginalV2 {
    before: inventory_catalog::InventoryCatalogOriginalV1,
    after: inventory_catalog::InventoryCatalogOriginalV1,
    before_body: Option<Result<Vec<u8>, StorageRuntimeError>>,
    after_body: Option<Result<Vec<u8>, StorageRuntimeError>>,
    before_model: Option<Result<ValidatedStorageInventory, aos_sandbox_protocol::ProtocolValidationError>>,
    after_model: Option<Result<ValidatedStorageInventory, aos_sandbox_protocol::ProtocolValidationError>>,
    semantics: Option<Result<CanonicalStorageGuestRootSemanticsV1, aos_sandbox_protocol::ProtocolValidationError>>,
    readback_demand: Option<Result<ResourceVector, AccountingError>>,
    readback_payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    quiescence: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    publisher_open: crate::pin_worker_runtime::GuestRootPublisherOpenOriginalV2,
    publisher: Option<Result<SystemdGuestRootPublisherClientV1, ZfsWorkerError>>,
    admission: GuestRootAdmissionOriginalV2,
    admission_result: Option<Result<(), StorageBrokerError>>,
    worker: Option<Result<GuestRootPublicationProofV1, ZfsWorkerError>>,
    readback: GuestRootTargetReadbackOriginalV2,
    readback_result: Option<Result<(), GuestRootInventoryErrorV1>>,
    completion: GuestRootStateRecordOriginalV2,
    completion_result: Option<Result<(), StorageStateError>>,
    after_clock: Option<Result<u64, ZfsWorkerError>>,
    cutoff: [Option<Result<u64, StorageRuntimeError>>; 2],
    final_clock: FinalClock,
    final_clock_result: Option<Result<RawPairedClockSample, PublicationClockErrorV2>>,
    gate: Option<StorageRuntimeError>,
    first: Option<Failure>,
    entered: bool,
    completed: bool,
    disposed: bool,
}

impl GuestRootPublicationOriginalV2 {
    fn new() -> Self {
        Self {
            before: inventory_catalog::InventoryCatalogOriginalV1::default(),
            after: inventory_catalog::InventoryCatalogOriginalV1::default(),
            before_body: None, after_body: None, before_model: None, after_model: None,
            semantics: None, readback_demand: None, readback_payment: None,
            quiescence: None, publisher_open: crate::pin_worker_runtime::GuestRootPublisherOpenOriginalV2::new(),
            publisher: None,
            admission: GuestRootAdmissionOriginalV2::new(), admission_result: None,
            worker: None, readback: GuestRootTargetReadbackOriginalV2::new(),
            readback_result: None, completion: GuestRootStateRecordOriginalV2::new(),
            completion_result: None, after_clock: None, cutoff: [None, None],
            final_clock: FinalClock::default(), final_clock_result: None,
            gate: None, first: None, entered: false, completed: false, disposed: false,
        }
    }

    fn fail<T>(&mut self, site: Failure) -> Result<T, StorageRuntimeError> {
        self.first.get_or_insert(site);
        if matches!(site, Failure::Gate) {
            self.gate.get_or_insert(StorageRuntimeError::Recovery);
        }
        Err(StorageRuntimeError::Receiving)
    }

    pub(super) fn dispose_after_positive_posts_v2(&mut self) {
        // The enclosing actual Sent token checked every native/State post
        // before this infallible upper disposition was made available.
        self.disposed = true;
    }

    pub(super) fn completed_v2(&self) -> bool {
        self.completed && self.first.is_none()
            && self.completion.attempt_v2().is_some_and(|attempt|
                attempt.phase == crate::guest_root_attempt::GuestRootAttemptPhaseV2::Complete)
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            Failure::Gate => self.gate.as_ref().map(|cause| cause as _),
            Failure::Semantics => error(&self.semantics),
            Failure::Before => self.before.failure().or_else(|| error(&self.before_body)),
            Failure::BeforeModel => error(&self.before_model),
            Failure::Quiescence => error(&self.quiescence),
            Failure::ReadbackDemand => error(&self.readback_demand),
            Failure::ReadbackPayment => error(&self.readback_payment),
            Failure::Publisher => self.publisher_open.failure_v2().or_else(|| error(&self.publisher)),
            Failure::Admission => self.admission.failure().or_else(|| error(&self.admission_result)),
            Failure::Worker => error(&self.worker).map(|cause| {
                cause.downcast_ref::<ZfsWorkerError>()
                    .and_then(ZfsWorkerError::physical_native_refusal_v1)
                    .map_or(cause, |native| native as &dyn std::error::Error)
            }),
            Failure::AfterClock => error(&self.after_clock),
            Failure::Cutoff => self.cutoff.iter().find_map(error),
            Failure::FinalClock => self.final_clock.failure().map(|cause| cause as &dyn std::error::Error)
                .or_else(|| error(&self.final_clock_result)),
            Failure::After => self.after.failure().or_else(|| error(&self.after_body)),
            Failure::AfterModel => error(&self.after_model),
            Failure::Readback => self.readback.failure().or_else(|| error(&self.readback_result)),
            Failure::Complete => self.completion.failure().or_else(|| error(&self.completion_result)),
        }
    }

    /// Prices both real source/model passes and this retained boxed owner.
    fn receiving_demand_v2(
        runtime: &StorageBrokerRuntime,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<ResourceVector, AccountingError> {
        use crate::receiving_demand::{add, count, multiply};
        let artifacts = request.authorization().ok_or(AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        })?;
        let wire = count(request.exact_body().len())?;
        // The same strict protobuf decoder owns at most one unknown-field
        // cell per two input bytes. These Vec/parser carriers consume bytes,
        // not named namespace entries.
        let unknown = (wire / 2).min(count(buffa::DEFAULT_UNKNOWN_FIELD_LIMIT)?);
        let unknown_bytes = multiply(add(multiply(unknown, 8)?, 8)?,
            count(3 * std::mem::size_of::<buffa::UnknownField>())?)?;
        let fixed = multiply(count(std::mem::size_of::<Self>())?, 3)?;
        let authority = crate::authorization::receiving_authorization_memory_v1(artifacts)?;
        let memory = add(add(fixed, unknown_bytes)?, add(multiply(wire, 16)?, authority)?)?;
        let catalog = runtime.inventory_retention_demand_v1()?;
        let clock_bytes = FinalClock::dominant_requested_bytes_v1()
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let clock_names = FinalClock::receiving_metadata_cells_v1()
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MetadataEntries })?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, add(memory, count(clock_bytes)?)?)
            .with(D::MetadataEntries, count(clock_names)?)
            .with(D::OpenFiles, count(FinalClock::MAXIMUM_RETAINED_FILES_V1)?);
        let publisher = crate::pin_worker_runtime::GuestRootPublisherOpenOriginalV2::receiving_demand_v2()
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        catalog.checked_add(catalog)?.checked_add(fixed)?.checked_add(publisher)
    }

    fn run_once_v2(
        &mut self,
        runtime: &mut StorageBrokerRuntime,
        request: &AuthenticatedBrokerMethodRequestV1,
        protocol: ProtocolVersion,
        clock: &RawPairedClockSample,
        template: &ProtectedGuestRootTemplateV1,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<GuestRootPublicationProofV1, StorageRuntimeError> {
        if self.entered {
            self.completed = false;
            return self.fail(Failure::Gate);
        }
        self.entered = true;
        let primary = self.run_body_v2(runtime, request, protocol, clock, template, receiving);
        self.final_clock_result = Some(self.final_clock.observe_once(Some(*clock)));
        if !matches!(self.final_clock_result, Some(Ok(_))) {
            self.first.get_or_insert(Failure::FinalClock);
        }
        let proof = primary?;
        let Some(Ok(final_clock)) = self.final_clock_result.as_ref() else {
            return Err(StorageRuntimeError::Receiving);
        };
        let Some(pending) = self.admission.pending_v2() else { return self.fail(Failure::Gate); };
        let Some(attempt) = pending.attempt_v2() else { return self.fail(Failure::Gate); };
        if final_clock.boottime_nanoseconds() >= request.deadline_boottime_nanoseconds()
            || final_clock.boottime_nanoseconds() >= attempt.effect_deadline_boottime_nanoseconds
        { return self.fail(Failure::Gate); }
        self.completion_result = Some(runtime.coordinator.complete_guest_root_publication_v2(
            &mut self.completion, pending, &self.readback, receiving,
        ));
        if !matches!(self.completion_result, Some(Ok(()))) { return self.fail(Failure::Complete); }
        self.completed = true;
        Ok(proof)
    }

    fn completed_current_publication_v2(&self)
        -> Option<aos_sandbox_protocol::semantics::StorageGuestRootCurrentPublicationDataV2>
    {
        self.completed_v2().then(|| self.completion.attempt_v2().map(|attempt|
            attempt.current_publication)).flatten()
    }

    #[allow(clippy::too_many_arguments)]
    fn run_body_v2(
        &mut self,
        runtime: &mut StorageBrokerRuntime,
        request: &AuthenticatedBrokerMethodRequestV1,
        protocol: ProtocolVersion,
        clock: &RawPairedClockSample,
        template: &ProtectedGuestRootTemplateV1,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<GuestRootPublicationProofV1, StorageRuntimeError> {
        let Some(artifacts) = request.authorization() else { return self.fail(Failure::Gate); };
        self.semantics = Some(CanonicalStorageGuestRootSemanticsV1::decode(
            request.exact_body(), request.peer(), request.peer_policy(), clock.boottime_nanoseconds(),
        ));
        let Some(Ok(semantics)) = self.semantics.as_ref() else { return self.fail(Failure::Semantics); };
        if semantics.header().protocol_version() != protocol
            || semantics.header().request_id() != &request.request_id()
            || semantics.header().deadline_boottime_nanoseconds() != request.deadline_boottime_nanoseconds()
        { return self.fail(Failure::Gate); }
        let deadline = semantics.header().deadline_boottime_nanoseconds();
        let handle = semantics.workspace_handle();
        let creation = semantics.creation_operation_id();
        self.cutoff[0] = Some(guest_root_inventory_cutoff(clock.boottime_nanoseconds(), deadline));
        let Some(Ok(cutoff)) = self.cutoff[0].as_ref() else { return self.fail(Failure::Cutoff); };
        let cutoff = *cutoff;
        self.before_body = Some(runtime.complete_guest_root_catalog_v2(
            &mut self.before, deadline, cutoff, request, receiving,
        ));
        let Some(Ok(bytes)) = self.before_body.as_ref() else { return self.fail(Failure::Before); };
        self.before_model = Some(decode_storage_resource_inventory_response(bytes, MAXIMUM_RESPONSE_BYTES));
        let Some(Ok(before)) = self.before_model.as_ref() else { return self.fail(Failure::BeforeModel); };
        let Some(workspace) = before.workspaces().iter().find(|row|
            row.workspace_handle() == &handle && row.creation_operation_id() == &creation)
        else { return self.fail(Failure::Gate); };
        let expected = template.expected_proof(workspace);

        // Refuse insufficient full mutable-workspace readback capacity before
        // admitting or dispatching a byte of the publication effect.
        self.readback_demand = Some(GuestRootTargetReadbackOriginalV2::receiving_demand_v2(template, workspace));
        let Some(Ok(demand)) = self.readback_demand.as_ref() else { return self.fail(Failure::ReadbackDemand); };
        self.readback_payment = Some(receiving.reserve_guest_root_publication_models_v2(
            runtime.coordinator.recovery_encoding_journal_v1(), request, *demand,
        ));
        if !matches!(self.readback_payment, Some(Ok(()))) { return self.fail(Failure::ReadbackPayment); }
        self.quiescence = Some((|| {
            let mut scan = receiving.borrow_guest_root_quiescence_once_v2(
                runtime.coordinator.recovery_encoding_journal_v1(), request,
            )?;
            scan.recover_quiescence_once_v2()?;
            scan.complete_after_quiescence_v2()
        })());
        if !matches!(self.quiescence, Some(Ok(()))) { return self.fail(Failure::Quiescence); }
        self.publisher = Some(self.publisher_open.open_once_v2());
        if !matches!(self.publisher, Some(Ok(_))) { return self.fail(Failure::Publisher); }
        self.admission_result = Some(self.admission.begin_once_v2(
            &mut runtime.coordinator, semantics, request.exact_body(), artifacts, protocol,
            request.peer(), request.peer_policy(), clock, workspace, expected, receiving,
        ));
        if !matches!(self.admission_result, Some(Ok(()))) { return self.fail(Failure::Admission); }
        let Some(pending) = self.admission.pending_v2() else { return self.fail(Failure::Gate); };
        let Some(attempt) = pending.attempt_v2() else { return self.fail(Failure::Gate); };
        let Some(encoded) = self.admission.request_v2() else { return self.fail(Failure::Gate); };
        let Some(Ok(publisher)) = self.publisher.as_mut() else { return self.fail(Failure::Gate); };
        let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::guest_root_publication_v2(
            receiving, runtime.coordinator.recovery_encoding_journal_v1(), request,
        );
        self.worker = Some(publisher.publish_receiving_v2(
            encoded, attempt, attempt.effect_deadline_boottime_nanoseconds, &mut stage,
        ));
        drop(stage);
        let Some(Ok(proof)) = self.worker.as_ref() else { return self.fail(Failure::Worker); };
        let proof = *proof;
        self.after_clock = Some(boottime_now_nanoseconds());
        let Some(Ok(now)) = self.after_clock.as_ref() else { return self.fail(Failure::AfterClock); };
        self.cutoff[1] = Some(guest_root_inventory_cutoff(*now, deadline));
        let Some(Ok(cutoff)) = self.cutoff[1].as_ref() else { return self.fail(Failure::Cutoff); };
        let cutoff = *cutoff;
        self.after_body = Some(runtime.complete_guest_root_catalog_v2(
            &mut self.after, deadline, cutoff, request, receiving,
        ));
        let Some(Ok(bytes)) = self.after_body.as_ref() else { return self.fail(Failure::After); };
        self.after_model = Some(decode_storage_resource_inventory_response(bytes, MAXIMUM_RESPONSE_BYTES));
        let Some(Ok(after)) = self.after_model.as_ref() else { return self.fail(Failure::AfterModel); };
        let Some(after_workspace) = after.workspaces().iter().find(|row|
            row.workspace_handle() == &handle && row.creation_operation_id() == &creation)
        else { return self.fail(Failure::Gate); };
        if workspace != after_workspace { return self.fail(Failure::Gate); }
        self.readback_result = Some(self.readback.observe_once_v2(template, after_workspace, pending, proof,
            runtime.coordinator.recovery_encoding_journal_v1(), receiving));
        if !matches!(self.readback_result, Some(Ok(()))) { return self.fail(Failure::Readback); }
        Ok(proof)
    }
}

impl Drop for GuestRootPublicationOriginalV2 {
    fn drop(&mut self) {
        // This first Runtime field prevents failed native prefixes from being
        // destroyed during unwinding or an accidentally abandoned method31.
        if self.entered && !self.disposed {
            std::process::abort();
        }
    }
}

impl StorageBrokerRuntime {
    pub(super) fn guest_root_publication_failure_v2(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.guest_root_publication_demand.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.guest_root_publication_payment.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.guest_root_publication.as_ref()?.failure_v2())
    }

    pub(crate) fn populate_guest_root_receiving_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        protocol: ProtocolVersion,
        clock: &RawPairedClockSample,
        template: &ProtectedGuestRootTemplateV1,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(GuestRootPublicationProofV1, aos_sandbox_protocol::semantics::StorageGuestRootCurrentPublicationDataV2), StorageRuntimeError> {
        self.require_git_coverage_new_admission_v1()?;
        if self.guest_root_publication.is_some() || self.guest_root_publication_demand.is_some() {
            return Err(StorageRuntimeError::Receiving);
        }
        self.guest_root_publication_demand = Some(GuestRootPublicationOriginalV2::receiving_demand_v2(self, request));
        let Some(Ok(demand)) = self.guest_root_publication_demand.as_ref() else {
            return Err(StorageRuntimeError::Receiving);
        };
        // Pay the payload and all compiler move/header backing before Box::new.
        self.guest_root_publication_payment = Some(receiving.reserve_guest_root_publication_models_v2(
            self.coordinator.recovery_encoding_journal_v1(), request, *demand,
        ));
        if !matches!(self.guest_root_publication_payment, Some(Ok(()))) {
            return Err(StorageRuntimeError::Receiving);
        }
        let mut owner = Box::new(GuestRootPublicationOriginalV2::new());
        let result = owner.run_once_v2(self, request, protocol, clock, template, receiving)
            .and_then(|proof| owner.completed_current_publication_v2()
                .map(|current| (proof, current)).ok_or(StorageRuntimeError::Receiving));
        self.guest_root_publication = Some(owner);
        if result.is_err() {
            self.latch_recovery_required();
        }
        result
    }
}
