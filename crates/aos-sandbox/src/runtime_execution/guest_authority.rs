//! Protected-owner composition for dormant guest execution.
//!
//! Reservation and terminal durability are routed through the exact retained
//! [`DormantRuntimeExecutionClaimV1`]. The public controller surface accepts no
//! generic CAS implementation and no caller-provided phase/result tuple.

use aos_sandbox_agent::{
    AgentExecutionOutcomeV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1,
    AgentOperationRequestV1, SignedAgentOutcomePacketV1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::agent_execution_adapter::{
    DormantGuestExecutionAdapterV1, DormantGuestExecutionPreparationV1,
    GuestExecutableCredentialV1, GuestExecutionAdapterErrorV1, GuestLocalExecutionHandoffV1,
    ObservedGuestLocalExecutionV1,
};
use super::agent_process_effect::{
    DormantGuestProcessAttemptDispositionV1, DormantGuestProcessEffectAdapterV1,
    DormantGuestProcessEffectErrorV1, DormantGuestProcessEffectV1, DormantGuestProcessEffectsV1,
    DormantGuestProcessSupervisorErrorV1, DormantGuestProcessSupervisorV1,
    PreparedDormantGuestProcessEffectV1,
};
use super::agent_reducer::{
    AgentHandshakeSigner, AgentOperationRecoveryCas, AgentOperationReservationV1,
    AgentOutcomeRecoveryTokenV1, AgentOutcomeSigner, AgentRecoveredOperationV1,
    AgentRecoveredOutcomeCommitV1, AgentRecoveredReservationV1, AgentReducerError,
    AgentReplayDispositionV1, AgentReservationDispositionV1, AgentReservationRecoveryTokenV1,
    GuestAgentReducerV1, SignedRecoveredAgentOutcomeV1, recovered_agent_outcome_signing_message_v1,
    verify_signed_recovered_agent_outcome_v1,
};

use super::DormantRuntimeExecutionClaimV1;

/// Retains the exact operation whose matching checkpoint append was ambiguous.
#[derive(Debug, Eq, PartialEq)]
pub struct DormantGuestCheckpointRecoveryTokenV1 {
    request_commitment: aos_sandbox_core::ObjectDigest,
    handoff_binding: aos_sandbox_core::ObjectDigest,
    outcome_commitment: Option<aos_sandbox_core::ObjectDigest>,
}

impl DormantGuestCheckpointRecoveryTokenV1 {
    fn reservation(handoff: &GuestLocalExecutionHandoffV1) -> Self {
        Self {
            request_commitment: handoff.prepared().request().request_commitment(),
            handoff_binding: handoff.handoff_binding(),
            outcome_commitment: None,
        }
    }

    fn outcome(
        observed: &ObservedGuestLocalExecutionV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Self {
        Self {
            request_commitment: observed.prepared().request().request_commitment(),
            handoff_binding: observed.handoff_binding(),
            outcome_commitment: Some(outcome.outcome_commitment()),
        }
    }
}

/// Names an authenticated negative or indeterminate Reserved-effect readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantGuestReservedReadbackDispositionV1 {
    /// Protected readback proves the effect did not cross.
    NotObserved,
    /// Protected readback cannot determine whether the effect crossed.
    Unknown,
}

/// Carries signed protected readback for one checkpointed Reserved operation.
#[must_use = "Reserved readback must be reconciled or retained"]
pub enum DormantGuestReservedReadbackEvidenceV1 {
    /// Protected readback recovered one exact terminal outcome.
    Resolved {
        /// Exact result bound to the checkpointed request.
        outcome: AgentExecutionOutcomeV1,
        /// Recovery-key signature over the canonical recovered outcome.
        signature: [u8; 64],
    },
    /// Protected readback proves the effect never crossed.
    NotObserved {
        /// Recovery-key signature over the exact request, handoff, and state.
        signature: [u8; 64],
    },
    /// Protected readback cannot prove either absence or a terminal result.
    Unknown {
        /// Recovery-key signature over the exact request, handoff, and state.
        signature: [u8; 64],
    },
}

impl DormantGuestReservedReadbackEvidenceV1 {
    fn retained_copy(&self) -> Self {
        match self {
            Self::Resolved { outcome, signature } => Self::Resolved {
                outcome: outcome.clone(),
                signature: *signature,
            },
            Self::NotObserved { signature } => Self::NotObserved {
                signature: *signature,
            },
            Self::Unknown { signature } => Self::Unknown {
                signature: *signature,
            },
        }
    }
}

/// Reports the protected resolution of a checkpointed Reserved operation.
#[must_use]
pub enum DormantGuestReservedReconciliationV1 {
    /// Authenticated terminal readback was durably committed and checkpointed.
    Resolved(AgentExecutionOutcomeV1),
    /// Authenticated absence is reported without redispatching the reservation.
    NotObserved,
    /// Indeterminate readback retains the reservation without redispatch.
    Unknown,
}

/// Returns the canonical message for negative or unknown Reserved readback.
#[must_use]
pub fn dormant_guest_reserved_readback_signing_message_v1(
    request: &AgentOperationRequestV1,
    handoff_binding: aos_sandbox_core::ObjectDigest,
    disposition: DormantGuestReservedReadbackDispositionV1,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-guest-reserved-readback-v1\0");
    digest.update(request.session().digest().as_bytes());
    digest.update(request.sequence().get().to_be_bytes());
    digest.update(request.operation_id().as_bytes());
    digest.update(request.request_commitment().as_bytes());
    digest.update(handoff_binding.as_bytes());
    digest.update([match disposition {
        DormantGuestReservedReadbackDispositionV1::NotObserved => 1,
        DormantGuestReservedReadbackDispositionV1::Unknown => 2,
    }]);
    digest.finalize().into()
}

/// Returns the canonical message for a resolved Reserved readback outcome.
#[must_use]
pub fn dormant_guest_reserved_outcome_signing_message_v1(
    request: &AgentOperationRequestV1,
    outcome: &AgentExecutionOutcomeV1,
) -> [u8; 32] {
    recovered_agent_outcome_signing_message_v1(request, outcome)
}

/// Owns the reducer while borrowing its sole protected reservation/CAS owner.
pub struct DormantProtectedGuestExecutionControllerV1<'claim, 'owner> {
    reducer: GuestAgentReducerV1,
    adapter: DormantGuestExecutionAdapterV1,
    recovered_handoff: Option<GuestLocalExecutionHandoffV1>,
    cold_reopened: bool,
    checkpoint_recovery_required: bool,
    owner: &'claim mut DormantRuntimeExecutionClaimV1<'owner>,
}

impl<'claim, 'owner> DormantProtectedGuestExecutionControllerV1<'claim, 'owner> {
    /// Constructs the dormant controller around an exact fixed-root claim.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] when portable guest
    /// provisioning differs from protected currentness or durable state already
    /// exists and therefore must be cold-reopened instead of reset.
    pub fn new(
        provisioning: super::AgentProvisioningV1,
        executable: GuestExecutableCredentialV1,
        owner: &'claim mut DormantRuntimeExecutionClaimV1<'owner>,
    ) -> Result<Self, DormantProtectedGuestExecutionErrorV1> {
        owner.authenticate_guest_provisioning(&provisioning)?;
        if owner
            .load_agent_checkpoint()
            .map_err(|_| DormantProtectedGuestExecutionErrorV1::Checkpoint)?
            .is_some()
        {
            return Err(DormantProtectedGuestExecutionErrorV1::ColdReopenRequired);
        }
        Ok(Self {
            reducer: GuestAgentReducerV1::new(provisioning),
            adapter: DormantGuestExecutionAdapterV1::new(executable),
            recovered_handoff: None,
            cold_reopened: false,
            checkpoint_recovery_required: false,
            owner,
        })
    }

    /// Reconstructs the controller exclusively from a cold-opened owner claim.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] when no authenticated
    /// checkpoint exists or its provisioning/full-history replay is invalid.
    pub fn reopen(
        provisioning: super::AgentProvisioningV1,
        executable: GuestExecutableCredentialV1,
        owner: &'claim mut DormantRuntimeExecutionClaimV1<'owner>,
    ) -> Result<Self, DormantProtectedGuestExecutionErrorV1> {
        owner.authenticate_guest_provisioning(&provisioning)?;
        let checkpoint = owner
            .load_agent_checkpoint()
            .map_err(|_| DormantProtectedGuestExecutionErrorV1::Checkpoint)?
            .ok_or(DormantProtectedGuestExecutionErrorV1::MissingCheckpoint)?;
        let reducer = checkpoint.restore(provisioning)?;
        let mut controller = Self {
            reducer,
            adapter: DormantGuestExecutionAdapterV1::new(executable),
            recovered_handoff: None,
            cold_reopened: true,
            checkpoint_recovery_required: false,
            owner,
        };
        controller.recovered_handoff = controller.heal_operation_ahead_checkpoint()?;
        Ok(controller)
    }

    /// Takes the one recovered handoff whose effect was never issued.
    ///
    /// This authority exists only when cold reopen proved one exact reservation
    /// committed ahead of its checkpoint. The original call could not return a
    /// handoff before that checkpoint, so consuming this value once cannot
    /// duplicate a process effect. An ordinary checkpointed `Reserved` row is
    /// deliberately ineligible and still requires signed process readback.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] unless the exact
    /// authenticated session, sequence, and request match the recovered row,
    /// or when this one-shot authority was already consumed.
    pub fn take_recovered_unissued_reservation_after_cold_reopen(
        &mut self,
        request: &AgentOperationRequestV1,
    ) -> Result<DormantGuestExecutionPreparationV1, DormantProtectedGuestExecutionErrorV1> {
        if !self.cold_reopened || self.checkpoint_recovery_required {
            return Err(DormantProtectedGuestExecutionErrorV1::ColdReopenRequired);
        }
        let Some(handoff) = self.recovered_handoff.as_ref() else {
            return Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation);
        };
        if handoff.prepared().request() != request
            || handoff.prepared().request().session() != request.session()
            || handoff.prepared().request().sequence() != request.sequence()
        {
            return Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation);
        }
        let handoff = self
            .recovered_handoff
            .take()
            .ok_or(DormantProtectedGuestExecutionErrorV1::InvalidObservation)?;
        Ok(DormantGuestExecutionPreparationV1::Handoff(handoff))
    }

    /// Recovers a handoff whose matching checkpoint append was ambiguous.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] unless this controller
    /// was cold-reopened and its healed or retained reservation exactly matches
    /// the move-only ambiguity token and request.
    pub fn recover_checkpointed_reservation_after_cold_reopen(
        &mut self,
        token: DormantGuestCheckpointRecoveryTokenV1,
        request: &AgentOperationRequestV1,
    ) -> Result<DormantGuestExecutionPreparationV1, DormantProtectedGuestExecutionErrorV1> {
        if !self.cold_reopened
            || self.checkpoint_recovery_required
            || token.outcome_commitment.is_some()
            || token.request_commitment != request.request_commitment()
        {
            return Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation);
        }
        let handoff = if let Some(recovered) = self.recovered_handoff.as_ref() {
            if recovered.prepared().request() != request
                || recovered.handoff_binding() != token.handoff_binding
            {
                return Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation);
            }
            self.recovered_handoff
                .take()
                .ok_or(DormantProtectedGuestExecutionErrorV1::InvalidObservation)?
        } else {
            let prepared = self.reducer.checkpointed_prepared(request)?;
            self.adapter.compile_reserved(prepared)?
        };
        if handoff.handoff_binding() != token.handoff_binding {
            return Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation);
        }
        Ok(DormantGuestExecutionPreparationV1::Handoff(handoff))
    }

    /// Recovers a terminal result whose matching checkpoint append was ambiguous.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestCompletionErrorV1`] unless cold reopen
    /// authenticated both the operation row and the healed checkpoint outcome.
    pub fn recover_checkpointed_terminal_after_cold_reopen(
        &mut self,
        token: DormantGuestCheckpointRecoveryTokenV1,
        observed: ObservedGuestLocalExecutionV1,
    ) -> Result<AgentExecutionOutcomeV1, DormantProtectedGuestCompletionErrorV1> {
        if !self.cold_reopened || self.checkpoint_recovery_required {
            return Err(DormantProtectedGuestCompletionErrorV1 {
                error: DormantProtectedGuestExecutionErrorV1::ColdReopenRequired,
                observed,
                recovery_token: None,
            });
        }
        let outcome = match AgentExecutionOutcomeV1::new(
            observed.prepared().request(),
            observed.phase(),
            observed.result_bytes().to_vec(),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(DormantProtectedGuestCompletionErrorV1 {
                    error: AgentReducerError::from(error).into(),
                    observed,
                    recovery_token: None,
                });
            }
        };
        if token.request_commitment != outcome.request_commitment()
            || token.handoff_binding != observed.handoff_binding()
            || token.outcome_commitment != Some(outcome.outcome_commitment())
            || !self.reducer.contains_completed_outcome(&outcome)
        {
            return Err(DormantProtectedGuestCompletionErrorV1 {
                error: DormantProtectedGuestExecutionErrorV1::InvalidObservation,
                observed,
                recovery_token: None,
            });
        }
        match self.owner.recover_operation(
            observed.prepared().reservation(),
            observed.prepared().request(),
        ) {
            Ok(AgentRecoveredOperationV1::Completed(committed)) if committed == outcome => {
                Ok(outcome)
            }
            Ok(_) | Err(_) => Err(DormantProtectedGuestCompletionErrorV1 {
                error: DormantProtectedGuestExecutionErrorV1::InvalidObservation,
                observed,
                recovery_token: None,
            }),
        }
    }

    /// Authenticates the incarnation handshake without exposing reducer mutation.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] when provisioning,
    /// session, protected signing, or checkpoint durability does not match.
    pub fn accept_handshake<S: AgentHandshakeSigner>(
        &mut self,
        request: AgentHandshakeRequestV1,
        signer: &mut S,
    ) -> Result<AgentHandshakeResponseV1, DormantProtectedGuestExecutionErrorV1> {
        self.require_current_checkpoint()?;
        let retained_request = request.clone();
        let response = self.reducer.accept_handshake(request, signer)?;
        self.commit_handshake_checkpoint(&retained_request, &response)?;
        Ok(response)
    }

    /// Reserves through the retained protected owner before compiling an effect.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] for protected CAS,
    /// reducer, or closed effect-projection failure.
    pub fn prepare(
        &mut self,
        request: AgentOperationRequestV1,
    ) -> Result<DormantGuestExecutionPreparationV1, DormantProtectedGuestExecutionErrorV1> {
        self.require_current_checkpoint()?;
        match self.reducer.prepare_operation(request, self.owner)? {
            AgentReplayDispositionV1::Prepared(prepared) => {
                let handoff = self.adapter.compile_reserved(prepared)?;
                self.commit_reservation_checkpoint(&handoff)?;
                Ok(DormantGuestExecutionPreparationV1::Handoff(handoff))
            }
            AgentReplayDispositionV1::ExactReplay(outcome) => {
                Ok(DormantGuestExecutionPreparationV1::ExactReplay(outcome))
            }
            AgentReplayDispositionV1::OutstandingExact => {
                Ok(DormantGuestExecutionPreparationV1::OutstandingRecoveryRequired)
            }
            AgentReplayDispositionV1::ReservationRecoveryRequired(token) => {
                self.checkpoint_recovery_required = true;
                Ok(DormantGuestExecutionPreparationV1::ReservationRecoveryRequired(token))
            }
        }
    }

    /// Authenticates and consumes a handoff into protected effect authority.
    ///
    /// The process adapter's descriptor projection is deliberately
    /// nonauthorizing. Only this method checks that its reservation is still
    /// present in the fixed protected owner before wrapping it for execution.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuestProcessPreparationErrorV1`] with the exact handoff
    /// for absent, completed, substituted, or unavailable reservation state,
    /// or invalid projection.
    pub fn prepare_process_effect<'effect>(
        &'effect mut self,
        handoff: GuestLocalExecutionHandoffV1,
    ) -> Result<
        ProtectedDormantGuestProcessEffectV1<'effect, 'claim, 'owner>,
        DormantGuestProcessPreparationErrorV1,
    > {
        if let Err(error) = self.require_current_checkpoint() {
            return Err(DormantGuestProcessPreparationErrorV1 { error, handoff });
        }
        if let Err(error) = self
            .owner
            .authenticate_guest_reservation(handoff.prepared())
        {
            return Err(DormantGuestProcessPreparationErrorV1 {
                error: error.into(),
                handoff,
            });
        }
        let effect = match DormantGuestProcessEffectAdapterV1::new().prepare(handoff) {
            Ok(effect) => effect,
            Err(failure) => {
                let (error, handoff) = failure.into_parts();
                return Err(DormantGuestProcessPreparationErrorV1 {
                    error: error.into(),
                    handoff,
                });
            }
        };
        Ok(ProtectedDormantGuestProcessEffectV1 {
            effect,
            controller: self,
        })
    }

    /// Commits an adapter-minted observation through the retained protected owner.
    ///
    /// The observation type has no public constructor. In particular, this
    /// method accepts no caller-echoed handoff binding, phase, or result bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestCompletionErrorV1`] with the intact
    /// observation when adapter authentication, reducer validation, or durable
    /// terminal CAS fails.
    pub fn complete(
        &mut self,
        observed: ObservedGuestLocalExecutionV1,
    ) -> Result<AgentExecutionOutcomeV1, DormantProtectedGuestCompletionErrorV1> {
        if let Err(error) = self.require_current_checkpoint() {
            return Err(DormantProtectedGuestCompletionErrorV1 {
                error,
                observed,
                recovery_token: None,
            });
        }
        if !self.adapter.authenticates(&observed) {
            return Err(DormantProtectedGuestCompletionErrorV1 {
                error: DormantProtectedGuestExecutionErrorV1::InvalidObservation,
                observed,
                recovery_token: None,
            });
        }
        match self.reducer.complete_operation(
            observed.prepared(),
            observed.phase(),
            observed.result_bytes(),
            self.owner,
        ) {
            Ok(outcome) => {
                if self.commit_reducer_checkpoint().is_err() {
                    return Err(DormantProtectedGuestCompletionErrorV1 {
                        error: DormantProtectedGuestExecutionErrorV1::CheckpointRecoveryRequired(
                            DormantGuestCheckpointRecoveryTokenV1::outcome(&observed, &outcome),
                        ),
                        observed,
                        recovery_token: None,
                    });
                }
                Ok(outcome)
            }
            Err(error) => {
                let recovery_token = match &error {
                    AgentReducerError::OutcomeRecoveryRequired(token) => Some(*token),
                    _ => None,
                };
                if recovery_token.is_some() {
                    self.checkpoint_recovery_required = true;
                }
                Err(DormantProtectedGuestCompletionErrorV1 {
                    error: error.into(),
                    observed,
                    recovery_token,
                })
            }
        }
    }

    /// Signs one exact durably completed outcome for the Host/guest wire.
    ///
    /// The protected checkpoint must already contain this result. The supplied
    /// request is checked against the completed outcome before its Host-bound
    /// transcript is signed, and the signature must verify against the fixed
    /// protected agent peer key. The complete signed packet is committed and
    /// read back before it is returned for send. This method does not
    /// redispatch an effect.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] for stale protected
    /// currentness, unresolved checkpoint durability, a foreign outcome, or
    /// unavailable or mismatched signing custody.
    pub fn sign_completed_outcome_packet<S: AgentOutcomeSigner>(
        &mut self,
        request: &AgentOperationRequestV1,
        outcome: AgentExecutionOutcomeV1,
        signer: &mut S,
    ) -> Result<SignedAgentOutcomePacketV1, DormantProtectedGuestExecutionErrorV1> {
        self.require_current_checkpoint()?;
        self.owner.revalidate()?;
        if outcome.session() != request.session()
            || outcome.sequence() != request.sequence()
            || outcome.operation_id() != request.operation_id()
            || outcome.request_commitment() != request.request_commitment()
            || !self.reducer.contains_completed_outcome(&outcome)
        {
            return Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation);
        }
        if let Some(committed) = self
            .owner
            .load_signed_guest_outcome_packet(request.session(), request.sequence())?
        {
            return if committed.outcome() == &outcome {
                Ok(committed)
            } else {
                Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation)
            };
        }

        let peer = self.owner.agent_peer();
        let message = super::agent_reducer::agent_outcome_signing_message_v1(
            peer.channel_binding(),
            request,
            &outcome,
        );
        let signature = signer.sign_outcome(&message)?;
        let public_key = VerifyingKey::from_bytes(&peer.public_key())
            .map_err(|_| DormantProtectedGuestExecutionErrorV1::InvalidObservation)?;
        public_key
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| DormantProtectedGuestExecutionErrorV1::InvalidObservation)?;
        let packet = SignedAgentOutcomePacketV1::new(outcome, signature)
            .map_err(|_| DormantProtectedGuestExecutionErrorV1::InvalidObservation)?;
        self.owner.commit_signed_guest_outcome_packet(&packet)?;
        Ok(packet)
    }

    /// Recovers the exact committed signed packet without invoking the signer.
    ///
    /// A missing packet is not evidence that an earlier append failed; the
    /// caller must retain the completed outcome and use the signing path only
    /// after cold protected replay has classified the prior attempt.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] for stale currentness,
    /// unresolved checkpoint durability, corrupt signed custody, or a packet
    /// unrelated to the supplied request and completed reducer history.
    pub fn recover_committed_signed_outcome_packet(
        &mut self,
        request: &AgentOperationRequestV1,
    ) -> Result<Option<SignedAgentOutcomePacketV1>, DormantProtectedGuestExecutionErrorV1> {
        self.require_current_checkpoint()?;
        let packet = self
            .owner
            .load_signed_guest_outcome_packet(request.session(), request.sequence())?;
        let Some(packet) = packet else {
            return Ok(None);
        };
        let outcome = packet.outcome();
        if outcome.operation_id() != request.operation_id()
            || outcome.request_commitment() != request.request_commitment()
            || !self.reducer.contains_completed_outcome(outcome)
        {
            return Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation);
        }
        Ok(Some(packet))
    }

    /// Reconciles a reservation ambiguity through a newly opened owner claim.
    ///
    /// The controller must itself be reconstructed from the protected
    /// checkpoint after closing the claim on which the ambiguity occurred.
    /// This path never reserves or dispatches the operation again.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestExecutionErrorV1`] when the token/request
    /// binding or cold-reopened protected state is not exact.
    pub fn reconcile_reservation_after_cold_reopen(
        &mut self,
        token: AgentReservationRecoveryTokenV1,
        request: AgentOperationRequestV1,
    ) -> Result<DormantGuestExecutionPreparationV1, DormantProtectedGuestExecutionErrorV1> {
        if !self.cold_reopened || self.checkpoint_recovery_required {
            return Err(DormantProtectedGuestExecutionErrorV1::ColdReopenRequired);
        }
        match self
            .owner
            .recover_reservation(&token, &request)
            .map_err(AgentReducerError::from)?
        {
            AgentRecoveredReservationV1::Committed(reservation) => {
                if let Some(recovered) = self.recovered_handoff.as_ref() {
                    if recovered.prepared().request() != &request
                        || recovered.prepared().reservation() != &reservation
                    {
                        return Err(DormantProtectedGuestExecutionErrorV1::InvalidObservation);
                    }
                    let handoff = self
                        .recovered_handoff
                        .take()
                        .ok_or(DormantProtectedGuestExecutionErrorV1::InvalidObservation)?;
                    // Reopen installed this exact committed reservation and
                    // durably checkpointed it before returning the controller.
                    return Ok(DormantGuestExecutionPreparationV1::Handoff(handoff));
                }
                let prepared = self
                    .reducer
                    .install_cold_recovered_reservation(request, reservation)?;
                let handoff = self.adapter.compile_reserved(prepared)?;
                self.commit_reservation_checkpoint(&handoff)?;
                Ok(DormantGuestExecutionPreparationV1::Handoff(handoff))
            }
            AgentRecoveredReservationV1::Absent => self.prepare(request),
        }
    }

    /// Reconciles an ambiguous terminal append through a newly opened claim.
    ///
    /// An absent append is retried with the retained opaque observation; a
    /// committed append only advances the reducer from protected replay.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedGuestCompletionErrorV1`] for token
    /// substitution, protected replay failure, or a second ambiguous append.
    pub fn reconcile_terminal_after_cold_reopen(
        &mut self,
        token: AgentOutcomeRecoveryTokenV1,
        observed: ObservedGuestLocalExecutionV1,
    ) -> Result<AgentExecutionOutcomeV1, DormantProtectedGuestCompletionErrorV1> {
        if !self.cold_reopened || self.checkpoint_recovery_required {
            return Err(DormantProtectedGuestCompletionErrorV1 {
                error: DormantProtectedGuestExecutionErrorV1::ColdReopenRequired,
                observed,
                recovery_token: Some(token),
            });
        }
        let outcome = match AgentExecutionOutcomeV1::new(
            observed.prepared().request(),
            observed.phase(),
            observed.result_bytes().to_vec(),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(DormantProtectedGuestCompletionErrorV1 {
                    error: AgentReducerError::from(error).into(),
                    observed,
                    recovery_token: Some(token),
                });
            }
        };
        let recovered = match self.owner.recover_guest_outcome_commit(
            &token,
            observed.prepared().reservation(),
            &outcome,
        ) {
            Ok(recovered) => recovered,
            Err(error) => {
                return Err(DormantProtectedGuestCompletionErrorV1 {
                    error: error.into(),
                    observed,
                    recovery_token: Some(token),
                });
            }
        };
        match recovered {
            AgentRecoveredOutcomeCommitV1::Committed(commitment)
                if commitment == outcome.outcome_commitment() =>
            {
                if self.reducer.contains_completed_outcome(&outcome) {
                    // Reopen advanced and checkpointed this exact committed
                    // terminal row before exposing recovery authority.
                    return Ok(outcome);
                }
                if let Err(error) = self.reducer.reconcile_outstanding(self.owner) {
                    return Err(DormantProtectedGuestCompletionErrorV1 {
                        error: error.into(),
                        observed,
                        recovery_token: Some(token),
                    });
                }
                if self.commit_reducer_checkpoint().is_err() {
                    return Err(DormantProtectedGuestCompletionErrorV1 {
                        error: DormantProtectedGuestExecutionErrorV1::CheckpointRecoveryRequired(
                            DormantGuestCheckpointRecoveryTokenV1::outcome(&observed, &outcome),
                        ),
                        observed,
                        recovery_token: Some(token),
                    });
                }
                Ok(outcome)
            }
            AgentRecoveredOutcomeCommitV1::Absent => self.complete(observed),
            AgentRecoveredOutcomeCommitV1::Committed(_) => {
                Err(DormantProtectedGuestCompletionErrorV1 {
                    error: DormantProtectedGuestExecutionErrorV1::InvalidObservation,
                    observed,
                    recovery_token: Some(token),
                })
            }
        }
    }

    /// Reconciles an ordinary checkpointed Reserved row through signed readback.
    ///
    /// A resolved terminal observation is verified, committed through the
    /// protected owner, and checkpointed. Authenticated absence and unknown
    /// readback retain the reservation and never redispatch it.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuestReservedReadbackReconciliationErrorV1`] with the
    /// signed evidence retained unless this is a cold reopen of an exact
    /// `Reserved` row and the fixed peer signed the exact request, handoff, and
    /// claimed readback state.
    pub fn reconcile_checkpointed_reservation_readback_after_cold_reopen(
        &mut self,
        evidence: DormantGuestReservedReadbackEvidenceV1,
    ) -> Result<
        DormantGuestReservedReconciliationV1,
        DormantGuestReservedReadbackReconciliationErrorV1,
    > {
        let retained_evidence = evidence.retained_copy();
        if !self.cold_reopened
            || self.checkpoint_recovery_required
            || self.recovered_handoff.is_some()
        {
            return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                DormantProtectedGuestExecutionErrorV1::ColdReopenRequired,
                retained_evidence,
                None,
            ));
        }
        let prepared = self
            .reducer
            .checkpointed_outstanding_prepared()
            .map_err(|error| {
                DormantGuestReservedReadbackReconciliationErrorV1::new(
                    error.into(),
                    retained_evidence.retained_copy(),
                    None,
                )
            })?;
        self.owner
            .authenticate_guest_reservation(&prepared)
            .map_err(|error| {
                DormantGuestReservedReadbackReconciliationErrorV1::new(
                    error.into(),
                    retained_evidence.retained_copy(),
                    None,
                )
            })?;
        let handoff = self.adapter.compile_reserved(prepared).map_err(|error| {
            DormantGuestReservedReadbackReconciliationErrorV1::new(
                error.into(),
                retained_evidence.retained_copy(),
                None,
            )
        })?;
        let public_key = self.owner.agent_peer().public_key();
        let authority_binding = self.owner.agent_peer().authority_binding();

        match evidence {
            DormantGuestReservedReadbackEvidenceV1::Resolved { outcome, signature } => {
                let request = handoff.prepared().request();
                let authenticated = verify_signed_recovered_agent_outcome_v1(
                    request,
                    &public_key,
                    authority_binding,
                    SignedRecoveredAgentOutcomeV1::new(outcome, signature),
                )
                .map_err(|error| {
                    DormantGuestReservedReadbackReconciliationErrorV1::new(
                        AgentReducerError::from(error).into(),
                        retained_evidence.retained_copy(),
                        None,
                    )
                })?;
                let outcome = match self
                    .reducer
                    .resolve_reserved_outstanding(self.owner, authenticated)
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        let recovery_token = match &error {
                            AgentReducerError::OutcomeRecoveryRequired(token) => {
                                self.checkpoint_recovery_required = true;
                                Some(*token)
                            }
                            _ => None,
                        };
                        return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                            error.into(),
                            retained_evidence,
                            recovery_token,
                        ));
                    }
                };
                self.commit_reducer_checkpoint().map_err(|error| {
                    DormantGuestReservedReadbackReconciliationErrorV1::new(
                        error,
                        retained_evidence,
                        None,
                    )
                })?;
                Ok(DormantGuestReservedReconciliationV1::Resolved(outcome))
            }
            DormantGuestReservedReadbackEvidenceV1::NotObserved { signature } => {
                verify_reserved_readback_signature(
                    handoff.prepared().request(),
                    handoff.handoff_binding(),
                    DormantGuestReservedReadbackDispositionV1::NotObserved,
                    &public_key,
                    &signature,
                )
                .map_err(|error| {
                    DormantGuestReservedReadbackReconciliationErrorV1::new(
                        error,
                        retained_evidence,
                        None,
                    )
                })?;
                Ok(DormantGuestReservedReconciliationV1::NotObserved)
            }
            DormantGuestReservedReadbackEvidenceV1::Unknown { signature } => {
                verify_reserved_readback_signature(
                    handoff.prepared().request(),
                    handoff.handoff_binding(),
                    DormantGuestReservedReadbackDispositionV1::Unknown,
                    &public_key,
                    &signature,
                )
                .map_err(|error| {
                    DormantGuestReservedReadbackReconciliationErrorV1::new(
                        error,
                        retained_evidence,
                        None,
                    )
                })?;
                Ok(DormantGuestReservedReconciliationV1::Unknown)
            }
        }
    }

    /// Classifies and reconciles an ambiguous signed terminal readback append.
    ///
    /// Cold reopen first establishes whether the exact append committed. A
    /// committed append is accepted only from the replayed completed outcome;
    /// an absent append may be retried from the retained signed evidence without
    /// reissuing the guest effect.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuestReservedReadbackReconciliationErrorV1`] with both
    /// the signed evidence and terminal ambiguity token retained when any exact
    /// binding, protected classification, retry, or checkpoint step fails.
    pub fn reconcile_ambiguous_reserved_readback_after_cold_reopen(
        &mut self,
        token: AgentOutcomeRecoveryTokenV1,
        request: &AgentOperationRequestV1,
        evidence: DormantGuestReservedReadbackEvidenceV1,
    ) -> Result<
        DormantGuestReservedReconciliationV1,
        DormantGuestReservedReadbackReconciliationErrorV1,
    > {
        let retained_evidence = evidence.retained_copy();
        if !self.cold_reopened || self.checkpoint_recovery_required {
            return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                DormantProtectedGuestExecutionErrorV1::ColdReopenRequired,
                retained_evidence,
                Some(token),
            ));
        }
        let DormantGuestReservedReadbackEvidenceV1::Resolved { outcome, signature } = evidence
        else {
            return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                DormantProtectedGuestExecutionErrorV1::InvalidObservation,
                retained_evidence,
                Some(token),
            ));
        };
        if request.session() != token.session()
            || request.sequence() != token.sequence()
            || request.operation_id() != token.operation_id()
            || request.request_commitment() != token.request_commitment()
            || outcome.session() != request.session()
            || outcome.sequence() != request.sequence()
            || outcome.operation_id() != request.operation_id()
            || outcome.request_commitment() != request.request_commitment()
            || outcome.outcome_commitment() != token.outcome_commitment()
        {
            return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                DormantProtectedGuestExecutionErrorV1::InvalidObservation,
                retained_evidence,
                Some(token),
            ));
        }
        let reservation = match AgentOperationReservationV1::new(
            token.session(),
            token.sequence(),
            token.operation_id(),
            token.request_commitment(),
            token.store_commitment(),
            AgentReservationDispositionV1::ExactReplay,
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                    AgentReducerError::from(error).into(),
                    retained_evidence,
                    Some(token),
                ));
            }
        };
        let public_key = self.owner.agent_peer().public_key();
        let authority_binding = self.owner.agent_peer().authority_binding();
        let authenticated = match verify_signed_recovered_agent_outcome_v1(
            request,
            &public_key,
            authority_binding,
            SignedRecoveredAgentOutcomeV1::new(outcome.clone(), signature),
        ) {
            Ok(authenticated) => authenticated,
            Err(error) => {
                return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                    AgentReducerError::from(error).into(),
                    retained_evidence,
                    Some(token),
                ));
            }
        };
        let classification =
            match self
                .owner
                .recover_guest_outcome_commit(&token, &reservation, &outcome)
            {
                Ok(classification) => classification,
                Err(error) => {
                    return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                        error.into(),
                        retained_evidence,
                        Some(token),
                    ));
                }
            };
        match classification {
            AgentRecoveredOutcomeCommitV1::Committed(commitment)
                if commitment == outcome.outcome_commitment()
                    && self.reducer.contains_completed_outcome(&outcome) =>
            {
                Ok(DormantGuestReservedReconciliationV1::Resolved(outcome))
            }
            AgentRecoveredOutcomeCommitV1::Absent => {
                let prepared = match self.reducer.checkpointed_outstanding_prepared() {
                    Ok(prepared)
                        if prepared.request() == request
                            && prepared.reservation() == &reservation =>
                    {
                        prepared
                    }
                    Ok(_) | Err(_) => {
                        return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                            DormantProtectedGuestExecutionErrorV1::InvalidObservation,
                            retained_evidence,
                            Some(token),
                        ));
                    }
                };
                drop(prepared);
                let outcome = match self
                    .reducer
                    .resolve_reserved_outstanding(self.owner, authenticated)
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        let recovery_token = match &error {
                            AgentReducerError::OutcomeRecoveryRequired(next) => {
                                self.checkpoint_recovery_required = true;
                                Some(*next)
                            }
                            _ => Some(token),
                        };
                        return Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                            error.into(),
                            retained_evidence,
                            recovery_token,
                        ));
                    }
                };
                self.commit_reducer_checkpoint().map_err(|error| {
                    DormantGuestReservedReadbackReconciliationErrorV1::new(
                        error,
                        retained_evidence,
                        Some(token),
                    )
                })?;
                Ok(DormantGuestReservedReconciliationV1::Resolved(outcome))
            }
            AgentRecoveredOutcomeCommitV1::Committed(_) => {
                Err(DormantGuestReservedReadbackReconciliationErrorV1::new(
                    DormantProtectedGuestExecutionErrorV1::InvalidObservation,
                    retained_evidence,
                    Some(token),
                ))
            }
        }
    }

    fn commit_reducer_checkpoint(&mut self) -> Result<(), DormantProtectedGuestExecutionErrorV1> {
        let checkpoint_sequence = match self.owner.next_agent_checkpoint_sequence() {
            Ok(sequence) => sequence,
            Err(_) => {
                self.checkpoint_recovery_required = true;
                return Err(DormantProtectedGuestExecutionErrorV1::AgentStore);
            }
        };
        let checkpoint = match self.reducer.checkpoint(checkpoint_sequence) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.checkpoint_recovery_required = true;
                return Err(error.into());
            }
        };
        if self.owner.commit_agent_checkpoint(&checkpoint).is_err() {
            self.checkpoint_recovery_required = true;
            return Err(DormantProtectedGuestExecutionErrorV1::Checkpoint);
        }
        self.checkpoint_recovery_required = false;
        Ok(())
    }

    fn commit_handshake_checkpoint(
        &mut self,
        request: &AgentHandshakeRequestV1,
        response: &AgentHandshakeResponseV1,
    ) -> Result<(), DormantProtectedGuestExecutionErrorV1> {
        let checkpoint_sequence = match self.owner.next_agent_handshake_checkpoint_sequence() {
            Ok(sequence) => sequence,
            Err(_) => {
                self.checkpoint_recovery_required = true;
                return Err(DormantProtectedGuestExecutionErrorV1::AgentStore);
            }
        };
        let checkpoint = match self.reducer.checkpoint(checkpoint_sequence) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.checkpoint_recovery_required = true;
                return Err(error.into());
            }
        };
        if self
            .owner
            .commit_agent_handshake_checkpoint(request, response, &checkpoint)
            .is_err()
        {
            self.checkpoint_recovery_required = true;
            return Err(DormantProtectedGuestExecutionErrorV1::Checkpoint);
        }
        self.checkpoint_recovery_required = false;
        Ok(())
    }

    fn require_current_checkpoint(&self) -> Result<(), DormantProtectedGuestExecutionErrorV1> {
        if self.checkpoint_recovery_required {
            return Err(DormantProtectedGuestExecutionErrorV1::ColdReopenRequired);
        }
        Ok(())
    }

    fn commit_reservation_checkpoint(
        &mut self,
        handoff: &GuestLocalExecutionHandoffV1,
    ) -> Result<(), DormantProtectedGuestExecutionErrorV1> {
        self.commit_reducer_checkpoint().map_err(|_| {
            DormantProtectedGuestExecutionErrorV1::CheckpointRecoveryRequired(
                DormantGuestCheckpointRecoveryTokenV1::reservation(handoff),
            )
        })
    }

    fn heal_operation_ahead_checkpoint(
        &mut self,
    ) -> Result<Option<GuestLocalExecutionHandoffV1>, DormantProtectedGuestExecutionErrorV1> {
        let outstanding = self
            .reducer
            .outstanding_for_reopen()
            .map(|(reservation, request)| (*reservation, request.clone()));
        let (healed, recovered_handoff) = if let Some((reservation, request)) = outstanding {
            match self
                .owner
                .recover_operation(&reservation, &request)
                .map_err(AgentReducerError::from)?
            {
                AgentRecoveredOperationV1::Completed(_) => {
                    self.reducer.reconcile_outstanding(self.owner)?;
                    (true, None)
                }
                AgentRecoveredOperationV1::Reserved => (false, None),
                AgentRecoveredOperationV1::Absent => {
                    return Err(AgentReducerError::CasReceiptMismatch.into());
                }
            }
        } else {
            match self.owner.load_uncheckpointed_guest_reservation()? {
                Some((request, reservation)) => {
                    let (expected_session, expected_sequence) = self.reducer.recovery_cursor()?;
                    if request.session() != expected_session
                        || request.sequence() != expected_sequence
                        || reservation.session() != expected_session
                        || reservation.sequence() != expected_sequence
                    {
                        return Err(AgentReducerError::CasReceiptMismatch.into());
                    }
                    let prepared = self
                        .reducer
                        .install_cold_recovered_reservation(request, reservation)?;
                    (true, Some(self.adapter.compile_reserved(prepared)?))
                }
                None => (false, None),
            }
        };
        if healed {
            self.commit_reducer_checkpoint()?;
        }
        Ok(recovered_handoff)
    }
}

fn verify_reserved_readback_signature(
    request: &AgentOperationRequestV1,
    handoff_binding: aos_sandbox_core::ObjectDigest,
    disposition: DormantGuestReservedReadbackDispositionV1,
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), DormantProtectedGuestExecutionErrorV1> {
    let message =
        dormant_guest_reserved_readback_signing_message_v1(request, handoff_binding, disposition);
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| DormantProtectedGuestExecutionErrorV1::InvalidObservation)?;
    verifying_key
        .verify_strict(&message, &Signature::from_bytes(signature))
        .map_err(|_| DormantProtectedGuestExecutionErrorV1::InvalidObservation)
}

/// Proves the fixed runtime owner authenticated one exact process effect.
#[must_use = "protected guest effect authority must be executed or retained"]
pub struct ProtectedDormantGuestProcessEffectV1<'effect, 'claim, 'owner> {
    effect: PreparedDormantGuestProcessEffectV1,
    controller: &'effect mut DormantProtectedGuestExecutionControllerV1<'claim, 'owner>,
}

impl<'effect, 'claim, 'owner> ProtectedDormantGuestProcessEffectV1<'effect, 'claim, 'owner> {
    /// Borrows the exact process, PTY, signal, or credential effect.
    #[must_use]
    pub const fn effect(&self) -> &DormantGuestProcessEffectV1 {
        self.effect.effect()
    }

    /// Returns the owner-authenticated handoff binding.
    #[must_use]
    pub const fn handoff_binding(&self) -> aos_sandbox_core::ObjectDigest {
        self.effect.handoff_binding()
    }

    /// Crosses the injected guest process boundary and mints one observation.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuestProcessSupervisorErrorV1`] before any observation
    /// exists when a credential, PTY, process, resize, signal, or inspect effect
    /// fails.
    pub fn execute<Effects>(
        self,
        supervisor: &mut DormantGuestProcessSupervisorV1<Effects>,
    ) -> Result<
        ObservedGuestLocalExecutionV1,
        DormantGuestProcessExecutionFailureV1<'effect, 'claim, 'owner>,
    >
    where
        Effects: DormantGuestProcessEffectsV1,
    {
        if let Err(error) = self.controller.require_current_checkpoint() {
            return Err(DormantGuestProcessExecutionFailureV1::BeforeEffect {
                authority: self,
                error: DormantGuestProcessSupervisorErrorV1::ProtectedCurrentness(
                    error.to_string(),
                ),
            });
        }
        if let Err(error) = self
            .controller
            .owner
            .authenticate_guest_reservation(self.effect.prepared())
        {
            return Err(DormantGuestProcessExecutionFailureV1::BeforeEffect {
                authority: self,
                error: DormantGuestProcessSupervisorErrorV1::ProtectedCurrentness(
                    error.to_string(),
                ),
            });
        }

        let ProtectedDormantGuestProcessEffectV1 { effect, controller } = self;
        match supervisor.execute(effect, |prepared| {
            controller.require_current_checkpoint().map_err(|error| {
                DormantGuestProcessSupervisorErrorV1::ProtectedCurrentness(error.to_string())
            })?;
            controller
                .owner
                .authenticate_guest_reservation(prepared)
                .map_err(|error| {
                    DormantGuestProcessSupervisorErrorV1::ProtectedCurrentness(error.to_string())
                })
        }) {
            Ok(observed) => Ok(observed),
            Err(failure) => {
                let (disposition, error, effect) = failure.into_parts();
                let authority = ProtectedDormantGuestProcessEffectV1 { effect, controller };
                match disposition {
                    DormantGuestProcessAttemptDispositionV1::BeforeEffect => {
                        Err(DormantGuestProcessExecutionFailureV1::BeforeEffect {
                            authority,
                            error,
                        })
                    }
                    DormantGuestProcessAttemptDispositionV1::OutcomeUnknown => {
                        Err(DormantGuestProcessExecutionFailureV1::OutcomeUnknown(
                            DormantGuestProcessOutcomeUnknownV1 { authority, error },
                        ))
                    }
                }
            }
        }
    }
}

/// Retains a handoff when protected process-effect preparation fails.
#[must_use = "the exact guest handoff must be retried or reconciled"]
pub struct DormantGuestProcessPreparationErrorV1 {
    error: DormantProtectedGuestExecutionErrorV1,
    handoff: GuestLocalExecutionHandoffV1,
}

impl DormantGuestProcessPreparationErrorV1 {
    /// Returns the preparation failure.
    #[must_use]
    pub const fn error(&self) -> &DormantProtectedGuestExecutionErrorV1 {
        &self.error
    }

    /// Consumes the failure without discarding the move-only reducer handoff.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        DormantProtectedGuestExecutionErrorV1,
        GuestLocalExecutionHandoffV1,
    ) {
        (self.error, self.handoff)
    }
}

impl std::fmt::Debug for DormantGuestProcessPreparationErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DormantGuestProcessPreparationErrorV1")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for DormantGuestProcessPreparationErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for DormantGuestProcessPreparationErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Classifies an attempted process effect while retaining its exact authority.
#[must_use = "process-effect custody must be retried or physically reconciled"]
pub enum DormantGuestProcessExecutionFailureV1<'effect, 'claim, 'owner> {
    /// Protected evidence proves the principal effect was not attempted.
    BeforeEffect {
        /// Current-owner-bound authority that may be retried.
        authority: ProtectedDormantGuestProcessEffectV1<'effect, 'claim, 'owner>,
        /// Exact pre-effect failure.
        error: DormantGuestProcessSupervisorErrorV1,
    },
    /// The principal effect may have crossed and must be physically read back.
    OutcomeUnknown(DormantGuestProcessOutcomeUnknownV1<'effect, 'claim, 'owner>),
}

/// Retains current-owner and readback custody for one ambiguous process effect.
#[must_use = "ambiguous process effects must be resolved from physical readback"]
pub struct DormantGuestProcessOutcomeUnknownV1<'effect, 'claim, 'owner> {
    authority: ProtectedDormantGuestProcessEffectV1<'effect, 'claim, 'owner>,
    error: DormantGuestProcessSupervisorErrorV1,
}

impl<'effect, 'claim, 'owner> DormantGuestProcessOutcomeUnknownV1<'effect, 'claim, 'owner> {
    /// Returns the last attempt or readback failure.
    #[must_use]
    pub const fn error(&self) -> &DormantGuestProcessSupervisorErrorV1 {
        &self.error
    }

    /// Releases the live owner borrow into exact cold-readback custody.
    ///
    /// The returned handoff cannot mint an observation. It can only be
    /// authenticated again by a freshly opened protected controller, whose
    /// signed Reserved-readback path performs physical reconciliation.
    #[must_use]
    pub fn into_cold_recovery_parts(
        self,
    ) -> (
        GuestLocalExecutionHandoffV1,
        DormantGuestProcessSupervisorErrorV1,
    ) {
        let DormantGuestProcessOutcomeUnknownV1 { authority, error } = self;
        (authority.effect.into_handoff(), error)
    }
}

/// Retains signed Reserved readback when protected reconciliation cannot finish.
pub struct DormantGuestReservedReadbackReconciliationErrorV1 {
    error: DormantProtectedGuestExecutionErrorV1,
    evidence: DormantGuestReservedReadbackEvidenceV1,
    recovery_token: Option<AgentOutcomeRecoveryTokenV1>,
}

impl DormantGuestReservedReadbackReconciliationErrorV1 {
    fn new(
        error: DormantProtectedGuestExecutionErrorV1,
        evidence: DormantGuestReservedReadbackEvidenceV1,
        recovery_token: Option<AgentOutcomeRecoveryTokenV1>,
    ) -> Self {
        Self {
            error,
            evidence,
            recovery_token,
        }
    }

    /// Returns the closed reconciliation failure.
    #[must_use]
    pub const fn error(&self) -> &DormantProtectedGuestExecutionErrorV1 {
        &self.error
    }

    /// Returns the exact ambiguous terminal-append token, when present.
    #[must_use]
    pub const fn recovery_token(&self) -> Option<AgentOutcomeRecoveryTokenV1> {
        self.recovery_token
    }

    /// Consumes the failure without discarding signed evidence or recovery authority.
    #[must_use]
    pub fn into_recovery_parts(
        self,
    ) -> (
        DormantProtectedGuestExecutionErrorV1,
        DormantGuestReservedReadbackEvidenceV1,
        Option<AgentOutcomeRecoveryTokenV1>,
    ) {
        (self.error, self.evidence, self.recovery_token)
    }
}

/// Retains an adapter-minted observation after terminal durability failure.
pub struct DormantProtectedGuestCompletionErrorV1 {
    error: DormantProtectedGuestExecutionErrorV1,
    observed: ObservedGuestLocalExecutionV1,
    recovery_token: Option<AgentOutcomeRecoveryTokenV1>,
}

impl DormantProtectedGuestCompletionErrorV1 {
    /// Returns the closed completion failure.
    #[must_use]
    pub const fn error(&self) -> &DormantProtectedGuestExecutionErrorV1 {
        &self.error
    }

    /// Recovers the intact opaque observation for protected recovery.
    #[must_use]
    pub fn into_observation(self) -> ObservedGuestLocalExecutionV1 {
        self.observed
    }

    /// Consumes the failure without discarding either recovery authority.
    #[must_use]
    pub fn into_recovery_parts(
        self,
    ) -> (
        DormantProtectedGuestExecutionErrorV1,
        ObservedGuestLocalExecutionV1,
        Option<AgentOutcomeRecoveryTokenV1>,
    ) {
        (self.error, self.observed, self.recovery_token)
    }

    /// Returns the exact ambiguous terminal-append token, when present.
    #[must_use]
    pub const fn recovery_token(&self) -> Option<AgentOutcomeRecoveryTokenV1> {
        self.recovery_token
    }
}

/// Reports dormant protected guest execution failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantProtectedGuestExecutionErrorV1 {
    /// The observation did not originate from this exact effect adapter.
    #[error("guest execution observation is not authenticated by the dormant adapter")]
    InvalidObservation,
    /// Cold reopen found no authenticated pre-effect reducer checkpoint.
    #[error("guest execution protected checkpoint is absent")]
    MissingCheckpoint,
    /// Durable state exists and must be reconstructed instead of reset.
    #[error("guest execution durable state requires cold reopen")]
    ColdReopenRequired,
    /// Protected checkpoint replay or commit failed.
    #[error("guest execution protected checkpoint failed")]
    Checkpoint,
    /// An operation won but its matching checkpoint append is ambiguous.
    #[error("guest execution checkpoint ambiguity requires cold reopen")]
    CheckpointRecoveryRequired(DormantGuestCheckpointRecoveryTokenV1),
    /// The dedicated protected agent store failed.
    #[error("guest execution protected agent store failed")]
    AgentStore,
    /// The portable reducer rejected the request or outcome.
    #[error("guest execution reducer rejected the operation: {0}")]
    Reducer(#[from] AgentReducerError),
    /// The closed guest-local projection rejected the reserved operation.
    #[error("guest execution effect projection failed: {0}")]
    Adapter(#[from] GuestExecutionAdapterErrorV1),
    /// The dormant process/PTY/signal projection rejected the handoff.
    #[error("guest process-effect projection failed: {0}")]
    ProcessEffect(#[from] DormantGuestProcessEffectErrorV1),
    /// The fixed protected runtime owner rejected reservation authority.
    #[error("guest execution protected owner rejected the operation: {0}")]
    Owner(#[from] super::DormantRuntimeExecutionOwnerErrorV1),
}
