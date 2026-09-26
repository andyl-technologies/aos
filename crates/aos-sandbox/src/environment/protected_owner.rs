//! Dormant environment protected-journal ownership and cold replay.

use aos_sandbox_core::{
    ExecutionAdmissionDraftV1, ExecutionId, ObjectDigest, ProjectId, SandboxId,
};
use sha2::{Digest as _, Sha256};

use crate::journal::Journal;
use crate::lifecycle::protected_journal_adapter::{
    ProtectedDomainJournalErrorV1, decode_reducer_payload_with_validator,
    protected_current_record_candidates_v1,
};

use super::EnvironmentProtectedEvidenceOwnerV1;
use super::execution::{
    NixBuildJournalRecordV1, NixBuildObservationV1, decode_nix_build_journal_record_v1,
};
use super::protected_evidence::EnvironmentProtectedClaimEvidenceV1;
use super::protected_journal::{
    EnvironmentJournalCommitOutcomeV1, EnvironmentJournalOutcomeUnknownV1,
    EnvironmentJournalRecoveryV1, EnvironmentProtectedJournalProjectionV1,
    EnvironmentProtectedJournalSchemaV1, EnvironmentProtectedJournalV1,
    EnvironmentProtectedRecordKindV1, EnvironmentReducerRecordV1,
    claim_environment_protected_journal_v1, environment_protected_key_v1,
    environment_reducer_envelope_v1,
};
use super::{
    DormantEnvironmentRuntimeAdmissionConsumerV1, EnvironmentActivationPhaseV1,
    EnvironmentActivationTransactionV1, EnvironmentExecutionAdmissionV1,
    EnvironmentExecutionErrorV1, EnvironmentExecutionSourceV1, EnvironmentGenerationHistoryV1,
    EnvironmentJournalVerifierV1, EnvironmentModelError, EnvironmentRuntimeAdmissionOutcomeV1,
    NixBuildEffectHandoffV1, NixBuildPrepareOutcomeV1, NixBuildPrepareRecoveryV1,
    NixBuildProtectedCapabilityOwnerV1, NixBuildProtectedObservationOwnerV1, NixBuildRequestV1,
    NixBuildSettlementOutcomeV1, NixBuildSettlementRecoveryV1, NixBuildSettlementRetryV1,
    NixBuildSettlementUnknownV1, NixBuildStateV1, ReadOnlyNixStorePresentationV1,
    decode_environment_activation_v1, decode_environment_generation_v1,
};

/// Owns a cold-replayed, dormant environment adapter and its custody verifier.
pub struct EnvironmentProtectedJournalOwnerV1<'journal, 'evidence> {
    journal: EnvironmentProtectedJournalV1<'journal>,
    verifier: EnvironmentJournalVerifierV1,
    evidence_owner: &'evidence mut EnvironmentProtectedEvidenceOwnerV1,
}

impl<'journal, 'evidence> EnvironmentProtectedJournalOwnerV1<'journal, 'evidence> {
    /// Cold-replays actual current records and claims the environment adapter.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed protected records, invalid generation
    /// lineage, invalid trusted clock input, or absent protected provenance.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        evidence: EnvironmentProtectedClaimEvidenceV1,
        evidence_owner: &'evidence mut EnvironmentProtectedEvidenceOwnerV1,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        let history = recover_environment_generation_history_v1(journal)?;
        let verifier = recover_environment_journal_verifier_v1(journal, evidence)?;

        let claimed = claim_environment_protected_journal_v1(journal, history.clone())?;
        let projection = claimed.replay()?;
        let authenticated_manifests = projection
            .records()
            .iter()
            .filter(|record| record.key().kind() == EnvironmentProtectedRecordKindV1::Generation)
            .map(|record| {
                let payload = decode_reducer_payload_with_validator::<
                    EnvironmentProtectedJournalSchemaV1,
                >(record.key(), record.payload(), &history)?;
                decode_environment_generation_v1(payload.body())
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authenticated_history =
            EnvironmentGenerationHistoryV1::from_protected_manifests(authenticated_manifests)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        if authenticated_history != history {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;

        Ok(Self {
            journal: claimed,
            verifier,
            evidence_owner,
        })
    }

    /// Replays the current environment projection under fresh evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained fixed evidence is no longer current.
    #[must_use]
    pub fn replay(
        &mut self,
    ) -> Result<EnvironmentProtectedJournalProjectionV1, ProtectedDomainJournalErrorV1> {
        self.revalidate_evidence()?;
        let projection = self.journal.replay()?;
        self.revalidate_evidence()?;
        Ok(projection)
    }

    /// Prepares one constrained Nix build under a freshly replayed generation.
    ///
    /// This method does not call Nix. The returned value mutably borrows this
    /// owner, so currentness cannot be refreshed or replaced while a future
    /// effect implementation holds the handoff.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] when protected replay fails or
    /// the request and presentation do not reproduce one protected generation.
    pub fn prepare_nix_build<'current>(
        &'current mut self,
        request: NixBuildRequestV1,
        capability_owner: &'current mut NixBuildProtectedCapabilityOwnerV1,
    ) -> Result<NixBuildPrepareOutcomeV1<'current>, EnvironmentExecutionErrorV1> {
        let capability = capability_owner
            .claim(request.selector())
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let (policy, policy_commitment, authority_fence, client_boundary, presentation) =
            capability.into_parts();
        let projection = self.current_projection()?;
        let history = authenticated_generation_history(&projection)?;
        let selector = request.selector();
        let mut matching_generation = 0_usize;
        for record in projection
            .records()
            .iter()
            .filter(|record| record.key().kind() == EnvironmentProtectedRecordKindV1::Generation)
        {
            let payload = decode_reducer_payload_with_validator::<
                EnvironmentProtectedJournalSchemaV1,
            >(record.key(), record.payload(), &history)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
            let manifest = decode_environment_generation_v1(payload.body())
                .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
            if manifest == *selector.manifest_record() {
                matching_generation = matching_generation
                    .checked_add(1)
                    .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
            }
        }
        if !super::execution::selector_matches_presentation(selector, &presentation)
            || matching_generation != 1
        {
            return Err(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch);
        }
        self.revalidate_execution_evidence()?;
        capability_owner
            .revalidate()
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let record = NixBuildJournalRecordV1::prepared(
            request,
            presentation.commitment(),
            policy_commitment,
        );
        let selector = record.state().request().selector();
        let key = environment_protected_key_v1(
            EnvironmentProtectedRecordKindV1::BuildEffect,
            selector.manifest_record().project(),
            selector.manifest_record().sandbox(),
            record.state().request().operation(),
        )
        .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let envelope = environment_reducer_envelope_v1(
            key,
            1,
            None,
            EnvironmentReducerRecordV1::Build(&record),
            &history,
        )
        .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let prepared = self
            .journal
            .plan(
                *record.state().request().operation().as_bytes(),
                vec![envelope],
            )
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        match self
            .journal
            .commit(prepared)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
        {
            EnvironmentJournalCommitOutcomeV1::Applied(mut applied) => {
                self.revalidate_execution_evidence()?;
                capability_owner
                    .revalidate()
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                validate_nix_effect_authority(&authority, &record, &history)?;
                Ok(NixBuildPrepareOutcomeV1::Prepared(
                    NixBuildEffectHandoffV1::new(
                        record.state().clone(),
                        policy,
                        authority_fence,
                        client_boundary,
                        presentation,
                        authority,
                    ),
                ))
            }
            EnvironmentJournalCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                Ok(NixBuildPrepareOutcomeV1::OutcomeUnknown(pending))
            }
        }
    }

    /// Recovers one ambiguous pre-effect build commit without minting a blind retry.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] when protected replay or the
    /// fixed capability is unavailable.
    pub fn recover_nix_build_prepare<'current>(
        &'current mut self,
        pending: EnvironmentJournalOutcomeUnknownV1,
        request: NixBuildRequestV1,
        capability_owner: &'current mut NixBuildProtectedCapabilityOwnerV1,
    ) -> Result<NixBuildPrepareRecoveryV1<'current>, EnvironmentExecutionErrorV1> {
        let capability = capability_owner
            .claim(request.selector())
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let (policy, policy_commitment, authority_fence, client_boundary, presentation) =
            capability.into_parts();
        let projection = self.current_projection()?;
        let history = authenticated_generation_history(&projection)?;
        let expected = NixBuildJournalRecordV1::prepared(
            request.clone(),
            presentation.commitment(),
            policy_commitment,
        );
        match self
            .journal
            .recover(pending)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
        {
            EnvironmentJournalRecoveryV1::Applied(mut applied) => {
                self.revalidate_execution_evidence()?;
                capability_owner
                    .revalidate()
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                validate_nix_effect_authority(&authority, &expected, &history)?;
                Ok(NixBuildPrepareRecoveryV1::Prepared(
                    NixBuildEffectHandoffV1::new(
                        expected.state().clone(),
                        policy,
                        authority_fence,
                        client_boundary,
                        presentation,
                        authority,
                    ),
                ))
            }
            EnvironmentJournalRecoveryV1::Retry(prepared) => {
                Ok(NixBuildPrepareRecoveryV1::Retry(prepared))
            }
            EnvironmentJournalRecoveryV1::Diverged(unknown) => {
                Ok(NixBuildPrepareRecoveryV1::Diverged(unknown))
            }
        }
    }

    /// Commits the sole exact retry returned by pre-effect recovery.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] when the fixed capability or
    /// current protected environment no longer reproduces the request.
    pub fn retry_nix_build_prepare<'current>(
        &'current mut self,
        prepared: super::protected_journal::PreparedEnvironmentJournalTransactionV1,
        request: NixBuildRequestV1,
        capability_owner: &'current mut NixBuildProtectedCapabilityOwnerV1,
    ) -> Result<NixBuildPrepareOutcomeV1<'current>, EnvironmentExecutionErrorV1> {
        let capability = capability_owner
            .claim(request.selector())
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let (policy, policy_commitment, authority_fence, client_boundary, presentation) =
            capability.into_parts();
        let history = authenticated_generation_history(&self.current_projection()?)?;
        let expected = NixBuildJournalRecordV1::prepared(
            request,
            presentation.commitment(),
            policy_commitment,
        );
        match self
            .journal
            .commit(prepared)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
        {
            EnvironmentJournalCommitOutcomeV1::Applied(mut applied) => {
                self.revalidate_execution_evidence()?;
                capability_owner
                    .revalidate()
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                validate_nix_effect_authority(&authority, &expected, &history)?;
                Ok(NixBuildPrepareOutcomeV1::Prepared(
                    NixBuildEffectHandoffV1::new(
                        expected.state().clone(),
                        policy,
                        authority_fence,
                        client_boundary,
                        presentation,
                        authority,
                    ),
                ))
            }
            EnvironmentJournalCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                Ok(NixBuildPrepareOutcomeV1::OutcomeUnknown(pending))
            }
        }
    }

    /// Reads canonical environment input from the current protected activation.
    ///
    /// This owned snapshot does not authorize an effect after the owner borrow
    /// ends. An execution producer must coordinate other protected owners and
    /// revalidate this input before committing a canonical specification.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] if protected replay, current
    /// selection, execution lease, closure roots, or evidence revalidation fails.
    pub fn current_execution_source(
        &mut self,
        project: ProjectId,
        sandbox: SandboxId,
        execution: ExecutionId,
    ) -> Result<EnvironmentExecutionSourceV1, EnvironmentExecutionErrorV1> {
        let activation = self.current_activation(project, sandbox)?;
        let source = EnvironmentExecutionSourceV1::from_activation(&activation, execution)?;
        self.revalidate_execution_evidence()?;
        Ok(source)
    }

    /// Replays and compares an exact previously observed execution source.
    ///
    /// Any activation revision or lease change invalidates the snapshot;
    /// this check alone is not an atomic cross-owner admission barrier.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] for stale or unavailable
    /// protected activation and retention evidence.
    pub fn revalidate_execution_source(
        &mut self,
        source: &EnvironmentExecutionSourceV1,
    ) -> Result<(), EnvironmentExecutionErrorV1> {
        let current =
            self.current_execution_source(source.project(), source.sandbox(), source.execution())?;
        if current != *source {
            return Err(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch);
        }
        Ok(())
    }

    /// Gates one runtime admission draft on current activation and retention.
    ///
    /// The resulting capability remains nonauthorizing for runtime resources;
    /// it proves only that the execution's environment was current, rooted,
    /// leased, and presented read-only during this fixed-owner borrow.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] for unavailable protected
    /// evidence, ambiguous current activation, or an exact binding mismatch.
    pub(crate) fn authorize_execution<'current>(
        &'current mut self,
        project: ProjectId,
        sandbox: SandboxId,
        draft: ExecutionAdmissionDraftV1,
        presentation: ReadOnlyNixStorePresentationV1,
    ) -> Result<EnvironmentExecutionAdmissionV1<'current>, EnvironmentExecutionErrorV1> {
        let activation = self.current_activation(project, sandbox)?;
        let admission = EnvironmentExecutionAdmissionV1::new(draft, activation, presentation)?;
        self.revalidate_execution_evidence()?;
        Ok(admission)
    }

    /// Validates and consumes runtime admission within one fixed-owner session.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] before invoking `consumer` when
    /// current activation, retention, or protected presentation evidence fails.
    pub fn consume_execution_admission<C>(
        &mut self,
        project: ProjectId,
        sandbox: SandboxId,
        draft: ExecutionAdmissionDraftV1,
        capability_owner: &mut NixBuildProtectedCapabilityOwnerV1,
        consumer: &mut C,
    ) -> Result<
        EnvironmentRuntimeAdmissionOutcomeV1<C::Output, C::Error>,
        EnvironmentExecutionErrorV1,
    >
    where
        C: DormantEnvironmentRuntimeAdmissionConsumerV1,
    {
        let activation = self.current_activation(project, sandbox)?;
        let selector = activation
            .current()
            .filter(|selector| activation.observed() == Some(*selector))
            .ok_or(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch)?;
        let protected = capability_owner
            .claim(selector)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let (_, _, _, _, presentation) = protected.into_parts();
        let admission = EnvironmentExecutionAdmissionV1::new(draft, activation, presentation)?;
        self.revalidate_execution_evidence()?;
        capability_owner
            .revalidate()
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let effect_result = consumer.consume(admission);

        // Both post-effect reads are attempted even when the first fails. Once
        // the consumer ran, rollover or expiry is outcome ambiguity, never a
        // retryable pre-effect rejection.
        let environment_current = self.revalidate_execution_evidence();
        let capability_current = capability_owner
            .revalidate()
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable);
        match (environment_current, capability_current) {
            (Ok(()), Ok(())) => Ok(EnvironmentRuntimeAdmissionOutcomeV1::Completed(
                effect_result,
            )),
            (Err(error), _) | (Ok(()), Err(error)) => {
                Ok(EnvironmentRuntimeAdmissionOutcomeV1::OutcomeUnknown {
                    effect_result,
                    currentness_error: error,
                })
            }
        }
    }

    /// Publishes one sealed protected Nix observation as terminal build state.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] unless the pre-effect member is
    /// current and the fixed observation exactly resolves it.
    pub fn settle_nix_build(
        &mut self,
        state: NixBuildStateV1,
        capability_owner: &mut NixBuildProtectedCapabilityOwnerV1,
        observation_owner: &mut NixBuildProtectedObservationOwnerV1,
    ) -> Result<NixBuildSettlementOutcomeV1, EnvironmentExecutionErrorV1> {
        if !matches!(
            state.phase(),
            super::NixBuildPhaseV1::Prepared | super::NixBuildPhaseV1::Indeterminate
        ) {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        let projection = self.current_projection()?;
        let history = authenticated_generation_history(&projection)?;
        let capability = capability_owner
            .claim(state.request().selector())
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let (policy, policy_commitment, _, _, presentation) = capability.into_parts();
        if policy_commitment != state.policy_commitment()
            || presentation.commitment() != state.presentation_commitment()
        {
            return Err(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch);
        }
        let protected = observation_owner
            .claim(state.request().operation(), state.request().commitment())
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let observation = NixBuildObservationV1::from_protected(
            protected.request(),
            protected.accepted(),
            protected.outputs().to_vec(),
            protected.receipt(),
        )?;
        if protected.outputs().len() > policy.maximum_output_objects() as usize {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        if protected.operation() != state.request().operation() {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        let prepared_record = NixBuildJournalRecordV1::prepared(
            state.request().clone(),
            state.presentation_commitment(),
            state.policy_commitment(),
        );
        let mut matching_prepared = 0_usize;
        for record in projection
            .records()
            .iter()
            .filter(|record| record.key().kind() == EnvironmentProtectedRecordKindV1::BuildEffect)
        {
            let payload = decode_reducer_payload_with_validator::<
                EnvironmentProtectedJournalSchemaV1,
            >(record.key(), record.payload(), &history)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
            if decode_nix_build_journal_record_v1(payload.body(), state.request().selector())
                .is_ok_and(|candidate| candidate == prepared_record)
            {
                matching_prepared = matching_prepared
                    .checked_add(1)
                    .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
            }
        }
        if matching_prepared != 1 {
            return Err(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch);
        }
        let terminal = NixBuildJournalRecordV1::terminal(
            &prepared_record,
            observation,
            protected.commitment(),
        )?;
        let selector = state.request().selector();
        let key = environment_protected_key_v1(
            EnvironmentProtectedRecordKindV1::BuildTerminal,
            selector.manifest_record().project(),
            selector.manifest_record().sandbox(),
            state.request().operation(),
        )
        .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let envelope = environment_reducer_envelope_v1(
            key,
            1,
            None,
            EnvironmentReducerRecordV1::Build(&terminal),
            &history,
        )
        .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        let prepared = self
            .journal
            .plan(
                build_terminal_transaction_id(state.request().operation()),
                vec![envelope],
            )
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        match self
            .journal
            .commit(prepared)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
        {
            EnvironmentJournalCommitOutcomeV1::Applied(_) => {
                self.revalidate_execution_evidence()?;
                capability_owner
                    .revalidate()
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                Ok(NixBuildSettlementOutcomeV1::Applied(
                    terminal.state().clone(),
                ))
            }
            EnvironmentJournalCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                Ok(NixBuildSettlementOutcomeV1::OutcomeUnknown(
                    NixBuildSettlementUnknownV1::new(terminal, pending),
                ))
            }
        }
    }

    /// Recovers one ambiguous terminal build publication exactly.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] when protected replay fails.
    pub fn recover_nix_build_settlement(
        &mut self,
        unknown: NixBuildSettlementUnknownV1,
    ) -> Result<NixBuildSettlementRecoveryV1, EnvironmentExecutionErrorV1> {
        let (terminal, pending) = unknown.into_parts();
        match self
            .journal
            .recover(pending)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
        {
            EnvironmentJournalRecoveryV1::Applied(mut applied) => {
                self.revalidate_execution_evidence()?;
                let history = authenticated_generation_history(&self.current_projection()?)?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                validate_nix_terminal_authority(&authority, &terminal, &history)?;
                Ok(NixBuildSettlementRecoveryV1::Applied(
                    terminal.state().clone(),
                ))
            }
            EnvironmentJournalRecoveryV1::Retry(prepared) => {
                Ok(NixBuildSettlementRecoveryV1::Retry(
                    NixBuildSettlementRetryV1::new(terminal, prepared),
                ))
            }
            EnvironmentJournalRecoveryV1::Diverged(pending) => {
                Ok(NixBuildSettlementRecoveryV1::Diverged(
                    NixBuildSettlementUnknownV1::new(terminal, pending),
                ))
            }
        }
    }

    /// Commits the sole exact retry returned by terminal recovery.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] when protected currentness or
    /// exact terminal readback fails.
    pub fn retry_nix_build_settlement(
        &mut self,
        retry: NixBuildSettlementRetryV1,
    ) -> Result<NixBuildSettlementOutcomeV1, EnvironmentExecutionErrorV1> {
        let (terminal, prepared) = retry.into_parts();
        let history = authenticated_generation_history(&self.current_projection()?)?;
        match self
            .journal
            .commit(prepared)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
        {
            EnvironmentJournalCommitOutcomeV1::Applied(mut applied) => {
                self.revalidate_execution_evidence()?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
                validate_nix_terminal_authority(&authority, &terminal, &history)?;
                Ok(NixBuildSettlementOutcomeV1::Applied(
                    terminal.state().clone(),
                ))
            }
            EnvironmentJournalCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                Ok(NixBuildSettlementOutcomeV1::OutcomeUnknown(
                    NixBuildSettlementUnknownV1::new(terminal, pending),
                ))
            }
        }
    }

    fn revalidate_evidence(&mut self) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
    }

    fn current_projection(
        &mut self,
    ) -> Result<EnvironmentProtectedJournalProjectionV1, EnvironmentExecutionErrorV1> {
        self.revalidate_execution_evidence()?;
        let projection = self
            .journal
            .replay()
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        self.revalidate_execution_evidence()?;
        Ok(projection)
    }

    fn current_activation(
        &mut self,
        project: ProjectId,
        sandbox: SandboxId,
    ) -> Result<EnvironmentActivationTransactionV1, EnvironmentExecutionErrorV1> {
        if project.as_bytes() == &[0; 16] || sandbox.as_bytes() == &[0; 16] {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        let projection = self.current_projection()?;
        let history = authenticated_generation_history(&projection)?;
        let mut candidates = Vec::new();
        for record in projection
            .records()
            .iter()
            .filter(|record| record.key().kind() == EnvironmentProtectedRecordKindV1::Current)
        {
            let payload = decode_reducer_payload_with_validator::<
                EnvironmentProtectedJournalSchemaV1,
            >(record.key(), record.payload(), &history)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
            let activation = decode_environment_activation_v1(payload.body(), &history)
                .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
            if activation.project() == project
                && activation.sandbox() == sandbox
                && matches!(
                    activation.phase(),
                    EnvironmentActivationPhaseV1::Observed | EnvironmentActivationPhaseV1::Released
                )
            {
                candidates.push(activation);
            }
        }
        candidates.sort_unstable_by_key(EnvironmentActivationTransactionV1::revision);
        let current = candidates
            .pop()
            .ok_or(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch)?;
        if candidates
            .last()
            .is_some_and(|prior| prior.revision() == current.revision())
        {
            return Err(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch);
        }
        let protected_horizon = self
            .evidence_owner
            .revalidate_pinned_horizon()
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        current
            .validate_current_leases_with_rollover(
                &protected_horizon,
                self.verifier.boot_rollover(),
            )
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
        Ok(current)
    }

    fn revalidate_execution_evidence(&mut self) -> Result<(), EnvironmentExecutionErrorV1> {
        self.revalidate_evidence()
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)
    }
}

fn authenticated_generation_history(
    projection: &EnvironmentProtectedJournalProjectionV1,
) -> Result<EnvironmentGenerationHistoryV1, EnvironmentExecutionErrorV1> {
    let manifests = projection
        .records()
        .iter()
        .filter(|record| record.key().kind() == EnvironmentProtectedRecordKindV1::Generation)
        .map(|record| {
            let payload =
                decode_reducer_payload_with_validator::<EnvironmentProtectedJournalSchemaV1>(
                    record.key(),
                    record.payload(),
                    &EnvironmentGenerationHistoryV1::default(),
                )
                .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
            decode_environment_generation_v1(payload.body())
                .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    EnvironmentGenerationHistoryV1::from_protected_manifests(manifests)
        .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)
}

fn validate_nix_effect_authority(
    authority: &super::protected_journal::ValidatedEnvironmentPostcommitV1<'_>,
    expected: &NixBuildJournalRecordV1,
    history: &EnvironmentGenerationHistoryV1,
) -> Result<(), EnvironmentExecutionErrorV1> {
    let records = authority.records();
    let record = records
        .first()
        .filter(|_| records.len() == 1)
        .filter(|record| record.is_effect())
        .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
    let envelope = record.envelope();
    let payload = decode_reducer_payload_with_validator::<EnvironmentProtectedJournalSchemaV1>(
        envelope.key(),
        envelope.payload(),
        history,
    )
    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
    let decoded =
        decode_nix_build_journal_record_v1(payload.body(), expected.state().request().selector())?;
    if super::execution::encode_nix_build_journal_record_v1(&decoded)
        != super::execution::encode_nix_build_journal_record_v1(expected)
    {
        return Err(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable);
    }
    Ok(())
}

fn validate_nix_terminal_authority(
    authority: &super::protected_journal::ValidatedEnvironmentPostcommitV1<'_>,
    expected: &NixBuildJournalRecordV1,
    history: &EnvironmentGenerationHistoryV1,
) -> Result<(), EnvironmentExecutionErrorV1> {
    let records = authority.records();
    let record = records
        .first()
        .filter(|_| records.len() == 1)
        .filter(|record| record.is_publication())
        .ok_or(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
    let envelope = record.envelope();
    let payload = decode_reducer_payload_with_validator::<EnvironmentProtectedJournalSchemaV1>(
        envelope.key(),
        envelope.payload(),
        history,
    )
    .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;
    let decoded =
        decode_nix_build_journal_record_v1(payload.body(), expected.state().request().selector())?;
    if super::execution::encode_nix_build_journal_record_v1(&decoded)
        != super::execution::encode_nix_build_journal_record_v1(expected)
    {
        return Err(EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable);
    }
    Ok(())
}

pub(crate) fn recover_environment_generation_history_v1(
    journal: &Journal,
) -> Result<EnvironmentGenerationHistoryV1, ProtectedDomainJournalErrorV1> {
    let manifests =
        protected_current_record_candidates_v1::<EnvironmentProtectedJournalSchemaV1>(journal)?
            .into_iter()
            .filter(|candidate| {
                candidate.key().kind() == EnvironmentProtectedRecordKindV1::Generation
            })
            .map(|candidate| {
                decode_environment_generation_v1(candidate.body())
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
            })
            .collect::<Result<Vec<_>, _>>()?;
    EnvironmentGenerationHistoryV1::from_protected_manifests(manifests)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
}

pub(crate) fn recover_environment_journal_verifier_v1(
    journal: &Journal,
    evidence: EnvironmentProtectedClaimEvidenceV1,
) -> Result<EnvironmentJournalVerifierV1, ProtectedDomainJournalErrorV1> {
    let (current_boot, current_time, boot_attestation, mut authenticated_predecessor_boots) =
        evidence.into_parts();
    let candidates =
        protected_current_record_candidates_v1::<EnvironmentProtectedJournalSchemaV1>(journal)?;
    authenticated_predecessor_boots.sort_unstable();
    if authenticated_predecessor_boots
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let mut accepted_records = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() != EnvironmentProtectedRecordKindV1::Checkpoint)
        .map(|candidate| candidate.envelope_digest())
        .collect::<Vec<_>>();
    let mut accepted_checkpoints = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() == EnvironmentProtectedRecordKindV1::Checkpoint)
        .map(|candidate| candidate.envelope_digest())
        .collect::<Vec<_>>();
    accepted_records.sort_unstable();
    accepted_checkpoints.sort_unstable();
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.environment.protected-owner.v1\0")
        .chain_update((candidates.len() as u64).to_be_bytes());
    for candidate in &candidates {
        hasher = hasher
            .chain_update((candidate.key().as_bytes().len() as u32).to_be_bytes())
            .chain_update(candidate.key().as_bytes())
            .chain_update(candidate.envelope_digest().as_bytes());
    }
    let authority = ObjectDigest::from_bytes(hasher.finalize().into());
    EnvironmentJournalVerifierV1::from_verified_state(
        authority,
        current_boot,
        current_time,
        boot_attestation,
        authenticated_predecessor_boots,
        accepted_records,
        accepted_checkpoints,
    )
    .map_err(map_environment_error)
}

fn map_environment_error(_error: EnvironmentModelError) -> ProtectedDomainJournalErrorV1 {
    ProtectedDomainJournalErrorV1::NonCanonicalRecord
}

fn build_terminal_transaction_id(operation: aos_sandbox_core::ResourceId) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.environment.nix-build-terminal-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .finalize();
    let mut transaction = [0_u8; 16];
    transaction.copy_from_slice(&digest[..16]);
    transaction
}
