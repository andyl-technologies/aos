//! Retains the actual signed63 sources through the sole durable dispatch issuer.
//!
//! The original request and sealed-content models come from the same protected
//! Session receiver. Signed admission precedes any protected local reservation;
//! exact append costs and the same verified effect clock gate every State write.

use aos_sandbox_broker::receiving::NetworkServiceReceivingLoanV4;
use aos_sandbox_model::{AccountingError, CanonicalAssignmentManifestV1, ResourceDimension as D,
    ResourceVector, model::SandboxSpec};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

use crate::broker::{NetworkAdmissionOutcome, NetworkBrokerError, NetworkCreationAdmissionOriginalV4,
    NetworkLifecycleAdmissionCoordinator, NetworkPrepareExecutionOutcomeV1};
use crate::preparation_catalog::{NetworkPreparationCatalogV1, NetworkPreparationReservationV1,
    NetworkPreparationCatalogOutcomeV1, NetworkPreparationCatalogError};
use super::receiving::{NetworkReceivingErrorV4, NetworkReceivingOriginalV4, NetworkPrepareEffectReceivingV4};
use super::Closed;

mod custody;
pub(super) use custody::NetworkSourceCustodyReceivingV4;

#[derive(Clone, Copy)]
enum First { Receiving, Request, Verification, Narrow, Reservation, Reference, Reserved, Resolved, Admission, Dispatch, Custody, Order }

pub(crate) struct NetworkPrepareSourcesOriginalV4 {
    pub(super) admission: NetworkCreationAdmissionOriginalV4,
    pub(super) receiving: NetworkReceivingOriginalV4,
    request_check: Option<Result<(), NetworkBrokerError>>,
    verification: Option<Result<(), NetworkBrokerError>>,
    narrow: Option<Result<(), Closed>>,
    reservation: Option<Result<NetworkPreparationReservationV1, NetworkPreparationCatalogError>>,
    reference: Option<Result<(), NetworkPreparationCatalogError>>,
    pub(super) reserved: Option<Result<NetworkPreparationCatalogOutcomeV1, NetworkBrokerError>>,
    resolved: Option<Result<(crate::catalog::AuthenticatedNetworkPreparationV1,
        crate::NetworkKernelPlanV1), NetworkBrokerError>>,
    admitted: Option<Result<NetworkAdmissionOutcome, NetworkBrokerError>>,
    pub(super) dispatch: Option<Result<NetworkPrepareExecutionOutcomeV1, NetworkBrokerError>>,
    custody_check: Option<Result<(), NetworkBrokerError>>,
    custody: Option<Result<crate::NetworkNamespaceCustodyV1, NetworkBrokerError>>,
    custody_entered: bool,
    first: Option<First>,
    original_selected: bool,
    entered: bool,
}

impl NetworkPrepareSourcesOriginalV4 {
    /// Requires this exact completed source before its owning worker retires it.
    /// The enclosing borrower already requires the genuine finished63 loan.
    pub(in crate::service_original) fn require_completed_preparation_sources_v5(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), super::NetworkServiceClosedV4> {
        use sha2::{Digest as _, Sha256};
        let verified = self
            .observer_verified_original_v2()
            .ok_or(super::NetworkServiceClosedV4)?;
        if request.method() as u32 != 63
            || !self.custody_entered
            || !matches!(self.custody, Some(Ok(_)))
            || verified.effect.request_id() != &request.request_id()
            || verified.effect.transport_request_digest().as_bytes()
                != &<[u8; 32]>::from(Sha256::digest(request.exact_body()))
        {
            return Err(super::NetworkServiceClosedV4);
        }
        Ok(())
    }

    /// Borrows the same completed signed original for the public O handoff.
    /// No unissued, failed or ambiguous-only source can supply this borrower.
    pub(crate) fn observer_verified_original_v2(&self) -> Option<&aos_sandbox_broker::VerifiedBrokerAdmission> {
        self.dispatch_v4()?;
        self.admission.verified_v4()
    }

    pub(crate) fn new() -> Self {
        Self { admission: NetworkCreationAdmissionOriginalV4::new(),
            receiving: NetworkReceivingOriginalV4::new(), request_check: None, verification: None,
            narrow: None, reservation: None, reference: None, reserved: None, resolved: None,
            admitted: None, dispatch: None, custody_check: None, custody: None, custody_entered: false,
            first: None, original_selected: false, entered: false }
    }

    pub(crate) fn prepare_once_v4(&mut self, coordinator: &mut NetworkLifecycleAdmissionCoordinator,
        preparations: &mut NetworkPreparationCatalogV1, request: &AuthenticatedBrokerMethodRequestV1,
        manifest: &CanonicalAssignmentManifestV1, specification: &SandboxSpec,
        loan: &mut NetworkServiceReceivingLoanV4<'_>) -> Result<(), super::NetworkServiceClosedV4> {
        if self.entered { self.first.get_or_insert(First::Order); return Err(super::NetworkServiceClosedV4); }
        self.entered = true;
        let result = self.prepare_inner_v4(coordinator, preparations, request, manifest, specification, loan);
        if result.is_err() && self.receiving.original_failure_selected_v4() { self.original_selected = true; }
        result
    }

    fn prepare_inner_v4(&mut self, coordinator: &mut NetworkLifecycleAdmissionCoordinator,
        preparations: &mut NetworkPreparationCatalogV1, request: &AuthenticatedBrokerMethodRequestV1,
        manifest: &CanonicalAssignmentManifestV1, specification: &SandboxSpec,
        loan: &mut NetworkServiceReceivingLoanV4<'_>) -> Result<(), super::NetworkServiceClosedV4> {
        let closed = super::NetworkServiceClosedV4;
        self.request_check = Some((|| {
            loan.require_network_prepare_current_v4().map_err(|_| {
                self.original_selected = true; NetworkBrokerError::Authority
            })?;
            let semantic = request.network_preparation_data_v2().ok_or(NetworkBrokerError::Request)?;
            let assignment = manifest.broker_assignment().map_err(|_| NetworkBrokerError::Request)?;
            if semantic.fence().broker_assignment().ok() != Some(assignment) {
                return Err(NetworkBrokerError::Request);
            }
            Ok(())
        })());
        if !matches!(self.request_check, Some(Ok(()))) { self.first = Some(First::Request); return Err(closed); }
        let semantic = request.network_preparation_data_v2().ok_or(closed)?;
        let reference = semantic.preparation_content_reference_v2().ok_or(closed)?;
        let artifacts = request.authorization().ok_or(closed)?;
        self.receiving.admit_additional_v4(loan,
            coordinator.signed_preparation_receiving_demand_v4(artifacts).map_err(NetworkReceivingErrorV4::from))
            .map_err(|_| { self.first = Some(First::Receiving); closed })?;
        // Existing local-record codecs, canonical validation, reservation and
        // dispatch models are separately co-live with the Session's originals.
        let preconstruction = source_model_demand_v4(reference.content_bytes())
            .map_err(NetworkReceivingErrorV4::from);
        self.receiving.admit_additional_v4(loan, preconstruction)
            .map_err(|_| { self.first = Some(First::Receiving); closed })?;
        let (clock, _) = loan.retained_network_horizon_data_v4().map_err(|_| {
            self.original_selected = true; self.first = Some(First::Narrow); closed
        })?;
        self.verification = Some(coordinator.verify_preparation_sources_once_v4(request, &clock, &mut self.admission));
        if !matches!(self.verification, Some(Ok(()))) { self.first = Some(First::Verification); return Err(closed); }
        let verified = self.admission.verified_v4().ok_or(closed)?;
        self.narrow = Some(loan.narrow_deadline_data_v4(verified.effect.effect_deadline_boottime_nanoseconds(),
            Some(verified.effect.plan_expires_seconds().min(verified.effect.authority_expires_seconds()))));
        if !matches!(self.narrow, Some(Ok(()))) {
            self.original_selected = true; self.first = Some(First::Narrow); return Err(closed);
        }
        self.reservation = Some(NetworkPreparationReservationV1::new(manifest, specification));
        if !matches!(self.reservation, Some(Ok(_))) { self.first = Some(First::Reservation); return Err(closed); }
        let reservation = self.reservation.as_ref().and_then(|value| value.as_ref().ok()).ok_or(closed)?;
        self.reference = Some(reservation.require_content_reference_v4(&reference));
        if !matches!(self.reference, Some(Ok(()))) { self.first = Some(First::Reference); return Err(closed); }
        self.receiving.admit_additional_v4(loan,
            reservation.materialization_receiving_demand_v4().map_err(NetworkReceivingErrorV4::from))
            .map_err(|_| { self.first = Some(First::Receiving); closed })?;
        let Some(Ok(reservation)) = self.reservation.take() else { std::process::abort() };
        let mut receiving = NetworkPrepareEffectReceivingV4 { original: &mut self.receiving, loan };
        self.reserved = Some(coordinator.reserve_preparation_sources_guarded_v4(preparations,
            reservation, semantic, verified, &mut receiving));
        if !matches!(self.reserved, Some(Ok(_))) { self.first = Some(First::Reserved); return Err(closed); }
        self.resolved = Some(coordinator.resolve_session_request_preparation(preparations,
            manifest.broker_assignment().map_err(|_| closed)?, None));
        if !matches!(self.resolved, Some(Ok(_))) { self.first = Some(First::Resolved); return Err(closed); }
        let (catalog, _) = self.resolved.as_ref().and_then(|value| value.as_ref().ok()).ok_or(closed)?;
        // The retained signed original is reused inside admission, never verified again.
        self.admitted = Some(coordinator.admit_preparation_retaining_v4(request, catalog, &clock,
            &mut self.admission, &mut |authority, admission, journal, transaction| {
                self.receiving.before_append_v4(loan, authority, &admission.effect, journal, transaction)
            }));
        let Some(Ok(NetworkAdmissionOutcome::Prepared { effect_digest })) = self.admitted.as_ref() else {
            self.first = Some(First::Admission); return Err(closed);
        };
        let effect_digest = *effect_digest;
        let request_id = *semantic.header().request_id();
        let Some(Ok((_catalog, plan))) = self.resolved.take() else { std::process::abort() };
        // The exact authenticated reservation remains in `reserved` and State.
        // The one canonical plan moves into the existing dispatch issuer.
        let verified = self.admission.verified_v4().ok_or(closed)?;
        let mut receiving = NetworkPrepareEffectReceivingV4 { original: &mut self.receiving, loan };
        self.dispatch = Some(coordinator.begin_prepare_effect_guarded_v4(request_id, effect_digest,
            request.exact_body(), plan, &mut receiving, &verified.effect));
        if !matches!(self.dispatch, Some(Ok(NetworkPrepareExecutionOutcomeV1::Dispatch(_)))) {
            self.first = Some(First::Dispatch); return Err(closed);
        }
        Ok(())
    }

    pub(crate) fn dispatch_v4(&self) -> Option<&crate::NetworkPrepareWorkerDispatchV1> {
        if self.first.is_some() { return None; }
        match self.dispatch.as_ref()? { Ok(NetworkPrepareExecutionOutcomeV1::Dispatch(dispatch)) => Some(dispatch), _ => None }
    }

    pub(crate) fn original_failure_selected_v4(&self) -> bool {
        self.original_selected || self.receiving.original_failure_selected_v4()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)> { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            First::Receiving => self.receiving.failure(),
            First::Request => cause(&self.request_check),
            First::Verification => self.admission.failure().or_else(|| cause(&self.verification)),
            First::Reservation => cause(&self.reservation),
            First::Reference => cause(&self.reference),
            First::Reserved => self.receiving.failure().or_else(|| cause(&self.reserved)),
            First::Resolved => cause(&self.resolved),
            First::Admission => self.receiving.failure().or_else(|| self.admission.failure()).or_else(|| cause(&self.admitted)),
            First::Dispatch => self.receiving.failure().or_else(|| cause(&self.dispatch)),
            First::Custody => self.receiving.failure().or_else(|| cause(&self.custody_check)).or_else(|| cause(&self.custody)),
            First::Narrow | First::Order => None,
        }
    }
}

fn source_model_demand_v4(content_bytes: u64) -> Result<ResourceVector, AccountingError> {
    let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
    let content = usize::try_from(content_bytes).map_err(|_| overflow())?;
    let (models, names) = aos_sandbox_protocol::semantics::network::preparation_content::
        network_preparation_models_receiving_obligations_v2(
            content.min(aos_sandbox_model::DecodeLimits::default().maximum_bytes),
            content.min(aos_sandbox_model::DecodeLimits::default().maximum_bytes)).ok_or_else(overflow)?;
    // Actual protected State codec has a96KiB record bound. Its retained
    // record/fence/transaction copies and bounded sealer frame are Memory only.
    let bytes = content.checked_mul(8).and_then(|bytes| bytes.checked_add(models))
        .and_then(|bytes| bytes.checked_add(16 * 96 * 1024))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::NetworkPrepareWorkerDispatchV1>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(std::mem::align_of::<crate::NetworkPrepareWorkerDispatchV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<NetworkSourceCustodyReceivingV4<'_>>().checked_mul(2)?))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(overflow)?;
    let content = ResourceVector::ZERO.with(D::MemoryBytes, bytes)
        .with(D::MetadataEntries, u64::try_from(names).map_err(|_| overflow())?);
    // Local policy can expand independently of the portable content length.
    // Pay the actual bounded kernel codec and new State index before either
    // reservation/plan resolution or the first durable admission is entered.
    let finalizer = std::mem::size_of::<super::finalization::NetworkPreparationFinalizationOriginalV4>()
        .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(overflow)?;
    content.checked_add(crate::kernel_plan::compilation_receiving_demand_v4()?)?
        .checked_add(crate::state::creation_record_receiving_demand_v4()?)?
        // The publication's future retained native pin and codec plane are
        // reserved before the first worker issue, alongside the actual plan.
        // Exact append traffic is still admitted before that later write.
        .checked_add(crate::NetworkNamespaceCatalogV1::publication_receiving_demand_v4()?)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, finalizer))
}
