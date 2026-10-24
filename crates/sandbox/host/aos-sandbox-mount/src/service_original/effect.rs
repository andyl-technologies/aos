//! Retains Mount62 admission, durable intent and the same namespace effect.
//!
//! The authenticated Session receipt owns the exact signed packet. This owner
//! retains all derived models, typed causes, transactions and physical prefixes
//! through the independent service posts and actual terminal send.

use aos_sandbox_api::aos::sandbox::local::v1::{ApplyAttachmentAnchorResponseV1, BrokerMethod};
use aos_sandbox_mount_native::{CommitResult, IdempotencyKey, IdempotencyOutcome,
    JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker::{BrokerAdmissionError, BrokerEffectIntentV1,
    BrokerEffectStatusV1, BrokerSignedAdmissionOriginalV4, VerifiedBrokerAdmission};
use aos_sandbox_broker::receiving::MountAttachmentAnchorReceivingLoanV4;
use aos_sandbox_model::{OperationId, RawPairedClockSample, ResourceDimension as D};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::mount_attachment_anchor::{
    ValidatedAttachmentAnchorRequestV1,
    ValidatedAttachmentAnchorResourceV1, attachment_anchor_request_decoding_demand_v4,
    decode_attachment_anchor_request_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::destination_slot::{MountAttachmentAnchorOriginalV4,
    MountAttachmentAnchorPhysicalShapeDataV1};
use super::*;

#[derive(Debug, thiserror::Error)]
enum EffectErrorV4 {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error(transparent)]
    Authority(#[from] BrokerAdmissionError),
    #[error(transparent)]
    Transaction(#[from] aos_sandbox_protocol::domain_ledger::JournalTransactionDataError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Mount(#[from] MountError),
    #[error("Mount service request does not match its original")]
    Association,
}

/// Retains one actual signed namespace request and its native/durable outcome.
///
/// Construction is inert. The same image-enrolled Mount62 loan must admit
/// every representation plane before decoding, sealing, allocating or entering
/// native work. A failed or unfinished owner cannot be reset with new input.
#[must_use]
pub struct MountServiceEffectOriginalV4 {
    entered: bool,
    reap_only: bool,
    identity: Option<([u8; 16], [u8; 32])>,
    geometry: Option<std::result::Result<ResourceVector, EffectErrorV4>>,
    payments: [Option<std::result::Result<(), Closed>>; 3],
    opening: Option<std::result::Result<RawPairedClockSample, Closed>>,
    decoded: Option<std::result::Result<ValidatedAttachmentAnchorRequestV1,
        aos_sandbox_protocol::ProtocolValidationError>>,
    signed: BrokerSignedAdmissionOriginalV4,
    admission: Option<std::result::Result<VerifiedBrokerAdmission, BrokerAdmissionError>>,
    physical_shape: Option<Result<MountAttachmentAnchorPhysicalShapeDataV1>>,
    physical: MountAttachmentAnchorOriginalV4,
    physical_result: Option<Result<ValidatedAttachmentAnchorResourceV1>>,
    sealed_fence: Option<std::result::Result<Vec<u8>, BrokerAdmissionError>>,
    sealed_pending: Option<std::result::Result<Vec<u8>, BrokerAdmissionError>>,
    idempotency: Option<std::result::Result<IdempotencyKey,
        aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>,
    intent: Option<std::result::Result<JournalTransaction,
        aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>,
    intent_commit: Option<std::result::Result<CommitResult, JournalError>>,
    reopened: Option<std::result::Result<BrokerEffectIntentV1, BrokerAdmissionError>>,
    completion: Option<std::result::Result<BrokerEffectIntentV1,
        aos_sandbox_broker::AuthorizationRecordError>>,
    sealed_complete: Option<std::result::Result<Vec<u8>, BrokerAdmissionError>>,
    completion_transaction: Option<std::result::Result<JournalTransaction,
        aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>,
    completion_commit: Option<std::result::Result<CommitResult, JournalError>>,
    guards: [Option<Result<()>>; 2],
    authority_guards: [Option<std::result::Result<(), BrokerAdmissionError>>; 12],
    authority_guards_used: usize,
    response: Option<Vec<u8>>,
    result: Option<std::result::Result<(), EffectErrorV4>>,
    original_failure: bool,
    physical_failure: bool,
    order: Option<EffectErrorV4>,
}

impl Default for MountServiceEffectOriginalV4 {
    fn default() -> Self {
        Self {
            entered: false, reap_only: false, identity: None, geometry: None,
            payments: std::array::from_fn(|_| None), opening: None, decoded: None,
            signed: Default::default(), admission: None,
            physical_shape: None, physical: Default::default(), physical_result: None,
            sealed_fence: None, sealed_pending: None, idempotency: None,
            intent: None, intent_commit: None, reopened: None, completion: None,
            sealed_complete: None, completion_transaction: None, completion_commit: None,
            guards: std::array::from_fn(|_| None), response: None, result: None,
            authority_guards: std::array::from_fn(|_| None), authority_guards_used: 0,
            original_failure: false, physical_failure: false, order: None,
        }
    }
}

impl MountServiceEffectOriginalV4 {
    /// Creates an empty original without parsing or native work.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates the inert sole later Reap62 destination of the finite service.
    #[must_use]
    pub fn new_reap_v5() -> Self {
        let mut original = Self::default();
        original.reap_only = true;
        original
    }

    /// Retires only completed positive physical scratch after actual SDK posts.
    ///
    /// The service retains this header, response DATA, Source charges and the
    /// Store's original namespace pin. Failed or ambiguous custody never drops.
    ///
    /// # Errors
    /// Refuses a different request, failed body or unfinished native interval.
    pub fn retire_completed_physical_once_v5(&mut self,
        loan: &MountAttachmentAnchorReceivingLoanV4<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        loan.require_completed_mount_attachment_interval_v5()
            .map_err(|_| closed("Mount62 native interval is unfinished"))?;
        if !self.entered || !matches!(self.result, Some(Ok(()))) || self.failure().is_some()
            || self.identity != Some((request.request_id(), request.signed_request_digest()))
            || request.method() != BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1 {
            return Err(closed("Mount62 positive native retirement refused"));
        }
        if self.physical_result.is_some() {
            self.physical.retire_completed_positive_native_once_v5()
        } else if self.reopened.as_ref().and_then(|result| result.as_ref().ok())
            .is_some_and(|effect| effect.status() == BrokerEffectStatusV1::Complete) {
            // A replayed materialization opened no new physical original.
            Ok(())
        } else {
            Err(closed("Mount62 completed physical original is absent"))
        }
    }

    /// Supplies this actual inline header and construction overlap as cost DATA.
    ///
    /// # Errors
    /// Refuses checked compiled-layout overflow.
    pub fn fixed_receiving_demand_v4() -> std::result::Result<ResourceVector, AccountingError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Borrows the original typed refusal without another observation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.original_failure {
            return Some(&Closed);
        }
        if self.physical_failure {
            return self.physical.failure().or_else(|| self.physical_result.as_ref()?
                .as_ref().err().map(|cause| cause as _));
        }
        self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.decoded.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.signed.failure())
            .or_else(|| self.admission.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.authority_guards.iter().find_map(|value|
                value.as_ref()?.as_ref().err().map(|cause| cause as _)))
            .or_else(|| self.physical_shape.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.idempotency.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.sealed_fence.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.sealed_pending.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.intent.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.guards[0].as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.intent_commit.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reopened.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.completion.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.sealed_complete.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.completion_transaction.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.guards[1].as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.completion_commit.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.order.as_ref().map(|cause| cause as _))
    }

    /// Identifies a refused native/financial gate whose cause stays in its loan.
    #[must_use]
    pub const fn original_failure_selected_v4(&self) -> bool {
        self.original_failure
    }

    fn pay(&mut self, loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        shape: std::result::Result<ResourceVector, EffectErrorV4>, stage: usize,
    ) -> std::result::Result<(), EffectErrorV4> {
        self.geometry = Some(shape);
        let shape = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(EffectErrorV4::Association)?;
        self.payments[stage] = Some(loan.require_additional_representation_v4(shape));
        if !matches!(self.payments[stage], Some(Ok(()))) {
            self.original_failure = true;
            return Err(EffectErrorV4::Association);
        }
        Ok(())
    }
}

impl Drop for MountServiceEffectOriginalV4 {
    fn drop(&mut self) {
        if self.entered {
            // The installed fixed service retains each actual entered prefix
            // through process lifetime. No response DATA retires native debt.
            std::process::abort();
        }
    }
}

impl MountServiceDomainCallsiteV4<'_> {
    /// Applies only the actual authenticated signed Mount62 request once.
    ///
    /// # Errors
    /// Retains hostile decode, signed authority, complete receiving, durable
    /// journal and native directory prefixes. This produces no Session send or
    /// post-completion grant; those remain with the same protected receiver.
    pub fn apply_attachment_once_v4<'held>(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        original: &'held mut MountServiceEffectOriginalV4,
    ) -> Result<MountServiceObservationV4<'held>> {
        if original.entered {
            original.order.get_or_insert(EffectErrorV4::Association);
            return Err(closed("Mount namespace original cannot reenter"));
        }
        original.entered = true;
        original.identity = Some((request.request_id(), request.signed_request_digest()));
        original.result = Some(self.apply_attachment_inner(request, loan, original));
        if !matches!(original.result, Some(Ok(()))) {
            return Err(closed("Mount namespace original retained a refusal"));
        }
        let body = original.response.as_deref().ok_or_else(|| closed("Mount namespace response absent"))?;
        Ok(MountServiceObservationV4 {
            body, request_id: request.request_id(), method: 62,
            signed_request_digest: request.signed_request_digest(),
        })
    }

    fn apply_attachment_inner(
        &mut self,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        original: &mut MountServiceEffectOriginalV4,
    ) -> std::result::Result<(), EffectErrorV4> {
        if self.method != 62 || authenticated.method() != BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1 {
            return Err(EffectErrorV4::Association);
        }
        self.state.ensure_healthy()?;
        loan.require_current_v4().map_err(|_| {
            original.original_failure = true;
            EffectErrorV4::Association
        })?;
        let artifacts = authenticated.authorization().ok_or(EffectErrorV4::Association)?;
        let shape = (|| {
            MountServiceEffectOriginalV4::fixed_receiving_demand_v4()?
                .checked_add(attachment_anchor_request_decoding_demand_v4(authenticated.exact_body().len())?)?
                .checked_add(self.authority.signed_admission_receiving_demand_v4(artifacts)?)
                .map_err(Into::into)
        })();
        original.pay(loan, shape, 0)?;
        original.opening = Some(loan.retained_opening_clock_data_v4());
        let clock = original.opening.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or_else(|| {
                original.original_failure = true;
                EffectErrorV4::Association
            })?;
        original.decoded = Some(decode_attachment_anchor_request_v1(authenticated.exact_body(),
            authenticated.peer(), authenticated.peer_policy(), clock.boottime_nanoseconds()));
        let decoded = original.decoded.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        if original.reap_only && decoded.action() != aos_sandbox_api::aos::sandbox::local::v1::AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP {
            return Err(EffectErrorV4::Association);
        }
        if decoded.header().request_id() != &authenticated.request_id()
            || decoded.header().deadline_boottime_nanoseconds() != authenticated.deadline_boottime_nanoseconds()
        {
            return Err(EffectErrorV4::Association);
        }
        let prior = self.state.get(RecordNamespace::DesiredState, decoded.fence().sandbox_id());
        original.admission = Some(self.authority.admit_attachment_anchor_v4(artifacts,
            decoded, authenticated.exact_body(), decoded.header().protocol_version(),
            &clock, prior, &mut original.signed));
        let admission = original.admission.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        loan.narrow_deadline_data_v4(admission.effect.effect_deadline_boottime_nanoseconds(),
            Some(admission.effect.plan_expires_seconds().min(admission.effect.authority_expires_seconds())))
            .map_err(|_| {
                original.original_failure = true;
                EffectErrorV4::Association
            })?;

        original.physical_shape = Some(MountAttachmentAnchorPhysicalShapeDataV1::for_current_v4(
            self.state, self.store, admission));
        let shape = original.physical_shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?.receiving_demand_v4().map_err(Into::into);
        original.pay(loan, shape, 1)?;
        self.persist_and_materialize(authenticated, loan, original)
    }

    fn persist_and_materialize(
        &mut self,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        original: &mut MountServiceEffectOriginalV4,
    ) -> std::result::Result<(), EffectErrorV4> {
        let decoded = original.decoded.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        let admission = original.admission.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        let request_id = authenticated.request_id();
        let request_digest: [u8; 32] = Sha256::digest(authenticated.exact_body()).into();
        original.idempotency = Some(IdempotencyKey::new(request_id.to_vec()));
        let idempotency = original.idempotency.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        match self.state.check_idempotency(idempotency, request_digest) {
            IdempotencyOutcome::Conflict => return Err(EffectErrorV4::Association),
            IdempotencyOutcome::Replay(operation) => {
                if operation != OperationId::from_bytes(request_id) {
                    return Err(EffectErrorV4::Association);
                }
            }
            IdempotencyOutcome::Vacant => {
                original.sealed_fence = Some(self.authority.seal_fence(decoded.fence().sandbox_id(), &admission.fence));
                original.sealed_pending = Some(self.authority.seal_effect(&request_id, &admission.effect));
                let fence = original.sealed_fence.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(EffectErrorV4::Association)?;
                let pending = original.sealed_pending.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(EffectErrorV4::Association)?;
                original.intent = Some(JournalTransaction::new(
                    crate::broker::destination_slot_transaction(b"aos.mount.namespace.intent.v1\0", &request_id),
                    vec![JournalRecord::put(RecordNamespace::DesiredState, decoded.fence().sandbox_id().to_vec(), fence.clone()),
                        JournalRecord::idempotency(idempotency, request_digest, OperationId::from_bytes(request_id)),
                        JournalRecord::put(RecordNamespace::Effect, request_id.to_vec(), pending.clone())]));
                let transaction = original.intent.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(EffectErrorV4::Association)?;
                original.guards[0] = Some(effect_guard(self.authority, &admission.effect, loan,
                    &mut original.authority_guards, &mut original.authority_guards_used));
                if !matches!(original.guards[0], Some(Ok(()))) {
                    original.original_failure = loan.failure().is_some();
                    return Err(EffectErrorV4::Association);
                }
                original.intent_commit = Some(self.state.commit(transaction));
                if !matches!(original.intent_commit, Some(Ok(_))) {
                    return Err(EffectErrorV4::Association);
                }
            }
        }
        let effect_bytes = self.state.get(RecordNamespace::Effect, &request_id)
            .ok_or(EffectErrorV4::Association)?;
        original.reopened = Some(self.authority.open_effect(&request_id, effect_bytes));
        let effect = original.reopened.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        crate::broker::validate_effect_matches(effect, admission, request_digest)?;
        if effect.plan_digest() != admission.effect.plan_digest()
            || effect.lease_digest() != admission.effect.lease_digest()
        {
            return Err(EffectErrorV4::Association);
        }
        if effect.status() == BrokerEffectStatusV1::Complete {
            let clock = original.opening.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(EffectErrorV4::Association)?;
            self.authority.validate_effect_clock(effect, clock)?;
            if decoded.action() == aos_sandbox_api::aos::sandbox::local::v1::AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP {
                // A durable Complete receipt is not a fresh native absence
                // proof. Reap replay must still join the exact Released row,
                // no retained Mount pin and the same protected named absence.
                self.store.require_released_namespace_replay_v5(decoded, authenticated.exact_body())?;
                original.physical_result = Some(self.store.materialize_namespace_anchor_once_v4(
                    self.state, decoded, authenticated.exact_body(), admission, loan, &mut original.physical,
                    &mut |loan| effect_guard(self.authority, effect, loan,
                        &mut original.authority_guards, &mut original.authority_guards_used)));
                let resource = match original.physical_result.as_ref().and_then(|value| value.as_ref().ok()) {
                    Some(resource) => resource,
                    None => {
                        original.original_failure = loan.failure().is_some();
                        original.physical_failure = !original.original_failure;
                        return Err(EffectErrorV4::Association);
                    }
                };
                let response = ApplyAttachmentAnchorResponseV1 {
                    resource: Some(resource.wire_v1()).into(), ..Default::default()
                }.encode_to_vec();
                if response != effect.receipt() { return Err(EffectErrorV4::Association); }
                original.response = Some(response);
                return Ok(());
            }
            original.response = Some(effect.receipt().to_vec());
            return Ok(());
        }
        original.physical_result = Some(self.store.materialize_namespace_anchor_once_v4(
            self.state, decoded, authenticated.exact_body(), admission, loan, &mut original.physical,
            &mut |loan| effect_guard(self.authority, effect, loan,
                &mut original.authority_guards, &mut original.authority_guards_used)));
        let resource = match original.physical_result.as_ref().and_then(|value| value.as_ref().ok()) {
            Some(resource) => resource,
            None => {
                original.original_failure = loan.failure().is_some();
                original.physical_failure = !original.original_failure;
                return Err(EffectErrorV4::Association);
            }
        };
        original.response = Some(ApplyAttachmentAnchorResponseV1 {
            resource: Some(resource.wire_v1()).into(), ..Default::default()
        }.encode_to_vec());
        let response = original.response.as_ref().ok_or(EffectErrorV4::Association)?;
        if response.len() > authenticated.maximum_response_bytes() as usize {
            return Err(EffectErrorV4::Association);
        }
        original.completion = Some(effect.clone().complete(response.clone()));
        let complete = original.completion.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        original.sealed_complete = Some(self.authority.seal_effect(&request_id, complete));
        let sealed = original.sealed_complete.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        original.completion_transaction = Some(JournalTransaction::new(
            crate::broker::destination_slot_transaction(b"aos.mount.namespace.complete.v1\0", &request_digest),
            vec![JournalRecord::put(RecordNamespace::Effect, request_id.to_vec(), sealed.clone())]));
        let transaction = original.completion_transaction.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(EffectErrorV4::Association)?;
        original.guards[1] = Some(effect_guard(self.authority, effect, loan,
            &mut original.authority_guards, &mut original.authority_guards_used));
        if !matches!(original.guards[1], Some(Ok(()))) {
            original.original_failure = loan.failure().is_some();
            return Err(EffectErrorV4::Association);
        }
        original.completion_commit = Some(self.state.commit(transaction));
        if !matches!(original.completion_commit, Some(Ok(_))) {
            return Err(EffectErrorV4::Association);
        }
        Ok(())
    }
}

fn effect_guard(authority: &MountAuthorityV1, effect: &BrokerEffectIntentV1,
    loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
    results: &mut [Option<std::result::Result<(), BrokerAdmissionError>>; 12],
    used: &mut usize,
) -> Result<()> {
    let slot = results.get_mut(*used).ok_or_else(|| closed("Mount native mutation roster exhausted"))?;
    if slot.is_some() {
        return Err(closed("Mount native mutation clock cannot reenter"));
    }
    *slot = Some(authority.check_before_effect(effect, &mut || loan.fresh_before_effect_clock_v4()
        .map_err(|_| BrokerAdmissionError::RequestMismatch)));
    *used += 1;
    if matches!(slot, Some(Ok(()))) { Ok(()) }
    else { Err(closed("Mount namespace signed pre-effect guard refused")) }
}
