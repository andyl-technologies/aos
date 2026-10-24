//! Reauthenticates the actual once-observation and lends its scheduling owner.
//!
//! A phase label or returned model DTO is not evidence. This loan retains the
//! actual shared Source association, immutable Controller and (for the effect
//! result) owned Core claim. Its callbacks run beneath a fresh owning Source
//! read, after current Observe, World and complete historical correspondence.

use super::super::restoration_activation;
use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::{
    PacketNativeRestoredCommitHold,
    activation::{
        PacketRestorationActivationScope,
        authenticate_restoration_activation_held_correspondence_data,
    },
};

/// Borrows actual authenticated observation custody without issuing readiness.
///
/// No public constructor, Clone, decoder or portable conversion exists. The
/// same complete Core Window must consume this genuine evidence and private
/// once ledger after the final member/kernel fence.
#[must_use = "authenticate this same original evidence before recording observation completion"]
pub struct OriginalSourceRestorationObservationVerifiedPhase<'a> {
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    association: std::cell::Ref<'a, Option<OriginalAckPeerAssociation>>,
    claim: Option<OriginalInstalledRestorationObservationClaim>,
}

impl<'a> OriginalSourceRestorationObservationVerifiedPhase<'a> {
    pub(super) fn new(
        source: &'a PacketCompleteSemanticSource,
        controller: &'a CnpController,
        claim: Option<OriginalInstalledRestorationObservationClaim>,
    ) -> Result<Self, RuntimeError> {
        let association = source
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = original
            .restoration_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.authenticate_verified()?;
        attempt.scheduling()?;
        Ok(Self {
            source,
            controller,
            association,
            claim,
        })
    }

    /// Borrows the original effect claim while its Core phase is still started.
    ///
    /// # Errors
    /// Refuses read-only evidence, which never owns an effect claim. This loan
    /// cannot clone, reconstruct or renew the private Window capability.
    pub(crate) fn original_effect_claim_data(
        &self,
    ) -> Result<&OriginalInstalledRestorationObservationClaim, RuntimeError> {
        self.claim.as_ref().ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Borrows actual retained scheduling DATA; a current fence remains required.
    ///
    /// # Errors
    /// Refuses missing/unfinished Source custody. Callers must use the fenced
    /// callback before cloning, comparing or adopting this DATA into the runtime.
    pub(crate) fn scheduling_observation_data(
        &self,
    ) -> Result<&NativeSchedulingObservation, RuntimeError> {
        self.association
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .restoration_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scheduling()
    }

    pub(crate) fn authenticate_current(
        &self,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationObservationConstructionData,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate(
            inputs,
            admitted,
            |held, reference| inputs.authenticate_original_observation_hold_data(held, reference),
            |_| Ok(()),
            final_currency,
        )
    }

    pub(crate) fn authenticate_continuation_data(
        &self,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationObservationConstructionData,
        validate_held: impl FnOnce(
            &PacketNativeRestoredCommitHold,
            &ContentRef,
        ) -> Result<(), RuntimeError>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate(inputs, admitted, validate_held, |_| Ok(()), final_currency)
    }

    /// Lends the same actual scheduling owner under its complete Source fence.
    ///
    /// Node clones stay in its original sticky slots before the terminal fence;
    /// a failed callback cannot discard them or complete Core's private ledger.
    ///
    /// # Errors
    /// Refuses changed observation, World/history, quota, currentness or either
    /// callback. Portable equality alone cannot create an observation claim.
    pub(crate) fn with_scheduling_observation_data(
        &self,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationObservationConstructionData,
        inspect: impl FnOnce(&NativeSchedulingObservation) -> Result<(), RuntimeError>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate(
            inputs,
            admitted,
            |held, reference| inputs.authenticate_original_observation_hold_data(held, reference),
            inspect,
            final_currency,
        )
    }

    /// Lends the genuine initial native model under its existing complete fence.
    ///
    /// This loan seeds separate suffix custody. It cannot stand in for a native
    /// record after subsequent execution has advanced the actual model cursor.
    ///
    /// # Errors
    /// Refuses every old observation/currentness failure and either callback.
    pub(crate) fn with_original_suffix_seed_data(
        &self,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationObservationConstructionData,
        inspect: impl FnOnce(
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &NativeSchedulingObservation,
        ) -> Result<(), RuntimeError>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate(
            inputs,
            admitted,
            |held, reference| inputs.authenticate_original_observation_hold_data(held, reference),
            |scheduling| {
                let original = self
                    .association
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let attempt = original
                    .restoration_observation
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                inspect(attempt.record()?, attempt.underlying()?, scheduling)
            },
            final_currency,
        )
    }

    fn authenticate(
        &self,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationObservationConstructionData,
        validate_held: impl FnOnce(
            &PacketNativeRestoredCommitHold,
            &ContentRef,
        ) -> Result<(), RuntimeError>,
        inspect: impl FnOnce(&NativeSchedulingObservation) -> Result<(), RuntimeError>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.source.storage_origin_with_error::<RuntimeError>()?;
        if !self
            .source
            .is_original_restoration_observation_declaration_data()?
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        admitted.authenticate_original(self.source, self.controller)?;
        admitted.authenticate_same_construction_data(inputs.source_construction)?;
        admitted
            .provider
            .authenticate_same_construction_data(inputs.observation_data)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if let Some(claim) = &self.claim {
            claim.authenticate_current(self.source)?;
        }
        // Historical World inspection uses its own earlier, completed read.
        // It ends before this NEW owning call; no ordinary idle API is invoked
        // after the new owner's busy/armed fence has begun.
        let world = self.source.original_verified_restoration_activation_data(
            self.controller,
            inputs.activation,
            &admitted.activation,
        )?;
        drop(world);
        let original = self
            .association
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = original
            .restoration_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.authenticate_verified()?;
        let birth = self
            .source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let key = birth
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_query_key_data()?;
        let mut scratch = native.original_fresh_current_scratch()?;
        let call = native.begin_original_fresh_query_call_data(&mut scratch)?;
        authenticate_saved_pair(
            self.source,
            attempt,
            self.controller,
            emitter,
            key,
            admitted,
        )?;
        let pair = self
            .controller
            .original_completed_installed_restoration_observation(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if pair.original().request_id.0.as_ref() != Some(inputs.request_id) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let request: PacketRestorationObservationRequest =
            serde::Deserialize::deserialize(attempt.value(0)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        admitted.authenticate_request_data(&request, inputs.request_id)?;
        let reference =
            effect::authenticate_terminal(pair.response_body_data(), &request, pair.original())?;
        let record = attempt.record()?;
        let bytes = self
            .controller
            .content(&record.native_receipt.native_record)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let observed = self
            .controller
            .authenticate_original_installed_restoration_observation_evidence_data(
                emitter, record, bytes,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        restoration_activation::with_verified_world_under_read_data(
            self.source,
            self.controller,
            original,
            inputs.activation,
            &admitted.activation,
            key,
            || call.ensure_original_fresh_current_before_effect_data(&mut scratch),
            |scope, held_reference, held| {
                authenticate_scope(&request.scope, scope)?;
                authenticate_restoration_activation_held_correspondence_data(
                    record, &observed, held,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
                effect::authenticate_terminal_inventory_data(
                    pair.response_body_data(),
                    &held.inventory_hash,
                )?;
                validate_held(held, held_reference)?;
                let actual = attempt.scheduling()?;
                if actual.proof_ref != *reference {
                    return Err(RuntimeError::InvalidReceipt);
                }
                scheduling::authenticate_bound(actual, admitted.scheduling)?;
                inspect(actual)
            },
        )?;
        call.complete(&mut scratch, || {
            if let Some(claim) = &self.claim {
                claim.authenticate_current(self.source)?;
            }
            final_currency()
        })
    }
}

impl PacketCompleteSemanticSource {
    /// Rechecks cached real observation evidence without issuing another claim.
    ///
    /// # Errors
    /// Refuses absent, foreign, stale, altered or unfinished observation custody.
    pub(crate) fn original_verified_restoration_observation_data<'a>(
        &'a self,
        controller: &'a CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        admitted: &OriginalSourceRestorationObservationConstructionData,
    ) -> Result<OriginalSourceRestorationObservationVerifiedPhase<'a>, RuntimeError> {
        let evidence =
            OriginalSourceRestorationObservationVerifiedPhase::new(self, controller, None)?;
        evidence.authenticate_current(inputs, admitted, || {
            inputs.activation.inspection.authenticate_current()
        })?;
        Ok(evidence)
    }
}

pub(super) fn authenticate_saved_pair(
    source: &PacketCompleteSemanticSource,
    attempt: &OriginalSourceRestorationObservationAttempt,
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    key: &[u8; 32],
    admitted: &OriginalSourceRestorationObservationConstructionData,
) -> Result<(), RuntimeError> {
    let pair = controller
        .original_completed_installed_restoration_observation(emitter)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if pair
        .original()
        .extensions
        .get(PACKET_RESTORATION_OBSERVE_FEATURE)
        != Some(attempt.value(1)?)
        || serde_json::to_value(pair.original()).map_err(|_| RuntimeError::InvalidReceipt)?
            != *attempt.value(2)?
        || serde_json::to_value(pair.response()).map_err(|_| RuntimeError::InvalidReceipt)?
            != *attempt.value(3)?
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let artifact: PacketRestorationObservationArtifact =
        serde::Deserialize::deserialize(attempt.value(1)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let request: PacketRestorationObservationRequest =
        serde::Deserialize::deserialize(attempt.value(0)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    if artifact.request != request {
        return Err(RuntimeError::InvalidReceipt);
    }
    let id = pair
        .original()
        .request_id
        .0
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    admitted.authenticate_request_data(&request, id)?;
    let binding=crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_scope_digest_data(&request.scope).map_err(|_|RuntimeError::InvalidReceipt)?;
    // The saved Source owner authenticates the actual process/thread, Source,
    // Controller and full common scope, independently of a decoded artifact.
    attempt.authenticate_original(source, controller, binding)?;
    let assigned = restoration_observe_assigned_request_digest(pair.original(), admitted.frame)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let context = PacketRestorationObservationContext {
        request,
        assigned_request: Bytes::new(assigned.to_vec()),
    };
    verify_restoration_observe_proof_data(key, &context, &artifact.proof)
        .map_err(|_| RuntimeError::InvalidReceipt)
}

fn authenticate_scope(
    actual: &PacketRestorationActivationScope,
    expected: &PacketRestorationActivationScope,
) -> Result<(), RuntimeError> {
    if actual != expected {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    use crucible_node_transport::{
        bodies::{MethodResult, ObserveResult},
        envelope::Envelope,
    };
    size_of::<OriginalSourceRestorationObservationVerifiedPhase<'static>>()
        + size_of::<Result<OriginalSourceRestorationObservationVerifiedPhase<'static>, RuntimeError>>(
        )
        + size_of::<Option<OriginalInstalledRestorationObservationClaim>>()
        + size_of::<Option<&OriginalInstalledRestorationObservationClaim>>()
        + size_of::<Result<&OriginalInstalledRestorationObservationClaim, RuntimeError>>()
        + size_of::<std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>>()
        + size_of::<
            Result<
                std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>,
                std::cell::BorrowError,
            >,
        >()
        + size_of::<&OriginalAckPeerAssociation>()
        + size_of::<&OriginalInstalledRestorationObservationSigningInputs<'static>>()
        + size_of::<&OriginalSourceRestorationObservationConstructionData>()
        + size_of::<&PacketRestorationActivationScope>()
        + size_of::<&PacketNativeRestoredCommitHold>()
        + size_of::<&ContentRef>()
        + 2 * size_of::<&crucible_node_format::HashRef>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<&NativeSchedulingObservation>()
        + size_of::<&ResponseBody>()
        + size_of::<&ObserveResult>()
        + size_of::<&crucible_node_format::ObservationBatch>()
        + size_of::<&Envelope>()
        + size_of::<&PacketRestorationObservationRequest>()
        + size_of::<Option<&MethodResult>>()
        + size_of::<&crucible_node_format::Extensions>()
        + size_of::<Result<&ContentRef, RuntimeError>>()
        + size_of::<Result<ContentRef, crucible_node_format::ContractError>>()
        + size_of::<Result<ContentRef, crucible_node_transport::ProviderError>>()
        + size_of::<Result<PacketNative5UnderlyingRecord, crucible_node_transport::ProviderError>>()
        + size_of::<Result<(), RuntimeError>>()
}
