//! Dormant protected publication for compiled policy artifacts.
//!
//! Compilation remains inert until the crate-sealed protected verifier authenticates the
//! normalized input and ancestry/currentness joins. This adapter then commits
//! the complete portable output, complete diagnostics, immediate-successor
//! publication head, and effect handoff in one exact CAS transaction.
//!
//! Candidate V3 retains the complete existing compiler-commitment preimage.
//! Its byte consistency is not an authenticated input or runtime-read proof;
//! Earlier Candidate versions are refused without rewriting retained state.

use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;

use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use aos_sandbox_model::{
    DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId,
    SandboxId,
    format::{
        decode_optimization, decode_policy, descriptor_for_bytes, encode_optimization,
        encode_policy,
    },
};
use sha2::{Digest as _, Sha256};

use super::PolicyNativeJournalErrorV1 as JournalError;
use super::append::PolicyMutationGateV1 as CacheMutationGateV1;
use super::journal::RootPolicyJournalV1 as Journal;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedDomainEnvelopeV1, ProtectedDomainKeyV1, ProtectedDomainProjectionV1,
    ProtectedDomainSchemaV1, ProtectedRecordRoleV1, ProtectedReducerPhaseV1,
    decode_reducer_payload_with_validator, encode_reducer_payload_with_validator,
};

use super::protected_transaction::{
    AppliedDomainTransactionV1, DomainCommitOutcomeV1, DomainOutcomeUnknownV1,
    DomainPostcommitCapabilityV1, DomainRecoveryV1, DomainRetainedCommitFailureV1,
    PreparedDomainTransactionV1, ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1,
    ProtectedDomainSnapshotV1, ReplayedDomainPostcommitV1, RetainedCommitFailureV1,
    ValidatedDomainPostcommitV1,
};

use crate::{
    CandidateAuthorityV1, CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyModelError,
};
use aos_sandbox_protocol::policy_data::compiled_policy_candidate_digest_v1;

mod model_receiving;
pub(in crate::native) use model_receiving::{schema_replay_model_receiving_bytes_v1, schema_replay_model_metadata_entries_v1};
use crate::normalized_policy_input_digest_v1;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod resolved_policy_fixture;
mod state_readback;
pub use state_readback::{CurrentNixPolicyOpeningV1, HeldResolvedRuntimePolicyV1,
    PolicyCompilerStateReadbackOwnerV1};

pub(crate) use crate::publication::*;
use crate::publication::{canonical_output, geometry};
use crate::publication::geometry::{candidate_payload_bytes_v1, CURRENT_BODY_BYTES,
    DIAGNOSTICS_BODY_FIXED_BYTES, EFFECT_BODY_BYTES};
use crate::publication::records::*;
use crate::publication::PublicationBodyFieldsV1;

mod custody;
pub(crate) use custody::PolicyPublicationVerifierV1;
mod records;

pub(in crate::native) use geometry::{Q04PublicationByteShapeV1, q04_publication_byte_shape_v1};

use custody::*;
use records::*;

pub(in crate::native) use custody::{
    AppliedPolicyPublicationV1, PolicyCheckpointCommitOutcomeV1, PolicyCheckpointOutcomeUnknownV1,
    PolicyCheckpointRecoveryV1, PolicyCompilerColdObservationV1, PolicyCompilerEffectHandoffV1,
    PolicyCompilerJournalSnapshotV1,
    PolicyCompilerPostcommitCapabilityV1, PolicyEffectObservationCommitOutcomeV1,
    PolicyEffectObservationOutcomeUnknownV1, PolicyEffectObservationRecoveryV1,
    PolicyEffectObservationRequestV1, PolicyPublicationColdRecoveryV1,
    PolicyPublicationCommitOutcomeV1, PolicyPublicationOutcomeUnknownV1,
    PolicyPublicationRecoveryV1,
    PreparedPolicyCheckpointV1, PreparedPolicyEffectObservationV1, PreparedPolicyPublicationV1,
    Q04PolicyPublicationAttemptV1,
    Q04PolicyPublicationReadbackV1, Q04PublicationCapacityV1, VerifiedPolicyEffectObservationV1,
    VerifiedPolicyPublicationV1,
};

pub(in crate::native) use crate::publication::records::{
    DecodedCurrentPolicyHeadV1, candidate_output_bytes,
    decode_current_payload, policy_current_key,
    policy_key, validate_candidate_payload, validate_state_candidate_body,
};

/// Owns dormant policy compilation and publication durability.
pub struct PolicyCompilerProtectedJournalV1<'journal> {
    inner: ProtectedDomainJournalV1<'journal, PolicyCompilerJournalSchemaV1>,
    validator: PolicyCompilerReplayValidatorV1,
}

impl<'journal> PolicyCompilerProtectedJournalV1<'journal> {
    /// Claims the adapter over a protected-open journal.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] unless protected provenance and
    /// a healthy replay boundary are available.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        validator: PolicyCompilerReplayValidatorV1,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        Ok(Self {
            inner: ProtectedDomainJournalV1::claim_with_validator(journal, validator.clone())?,
            validator,
        })
    }

    /// Replays and validates every retained policy head and artifact join.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for malformed or substituted
    /// current-head state.
    pub fn replay(
        &self,
    ) -> Result<PolicyCompilerJournalProjectionV1, PolicyCompilerJournalErrorV1> {
        let projection = self.inner.replay()?;
        validate_policy_projection(&projection, &self.validator)?;
        Ok(projection)
    }

    /// Captures exact policy-publication currentness.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when replay fails.
    pub fn snapshot(
        &self,
    ) -> Result<PolicyCompilerJournalSnapshotV1, PolicyCompilerJournalErrorV1> {
        self.replay()?;
        Ok(self.inner.snapshot()?)
    }

    // Q04 alone requests Current before Effect. Legacy plan_publication keeps
    // its original dependent encoder/allocation/error order below.
    pub(super) fn q04_independent_recipe(
        &self,
        input: &PolicyCompilerInputV1,
        candidate: &CompiledPolicyCandidateV1,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> Result<Q04IndependentPublicationRecipeV1, PolicyCompilerJournalErrorV1> {
        let project = input.project().project();
        let sandbox = input.sandbox();
        let normalized_input = normalized_policy_input_digest_v1(input)
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let canonical_diagnostics = aos_sandbox_protocol::policy_data::canonical_bytes(
            DIAGNOSTICS_DOMAIN,
            candidate.explanation(),
        )
        .map_err(crate::PolicyModelError::from)?;
        if candidate.authority_status() != CandidateAuthorityV1::NonAuthoritativeAncestry
            || !self.validator.contains(prerequisites)
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let projection = self.replay()?;
        if current_policy_head(&projection, project, sandbox, &self.validator)?.is_some() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let candidate_digest = candidate.commitment().digest();
        let candidate_key = policy_key(
            PolicyCompilerJournalRecordKindV1::Candidate,
            project,
            sandbox,
            candidate_digest,
        )?;
        let diagnostics_key = policy_key(
            PolicyCompilerJournalRecordKindV1::Diagnostics,
            project,
            sandbox,
            candidate_digest,
        )?;
        if projection
            .records()
            .iter()
            .any(|record| record.key() == &candidate_key || record.key() == &diagnostics_key)
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }

        Q04IndependentPublicationRecipeV1::encode(
            PublicationBodyFieldsV1 {
                project,
                sandbox,
                normalized_input,
                candidate,
                prerequisites,
            },
            &canonical_diagnostics,
            candidate_key,
            diagnostics_key,
        )
    }

    pub(super) fn q04_capacity_plan(
        &self,
        transaction_id: [u8; 16],
        recipe: Q04IndependentPublicationRecipeV1,
        input: &PolicyCompilerInputV1,
        candidate: &CompiledPolicyCandidateV1,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> Result<Q04PublicationCapacityV1, PolicyCompilerJournalErrorV1> {
        let project = input.project().project();
        let sandbox = input.sandbox();
        let normalized_input = normalized_policy_input_digest_v1(input)
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if !self.validator.contains(prerequisites)
            || recipe.project != project
            || recipe.sandbox != sandbox
            || recipe.normalized_input != normalized_input
            || recipe.candidate_digest != candidate.commitment().digest()
            || &recipe.prerequisites != prerequisites
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let effect = encode_effect_payload(
            transaction_id,
            1,
            PublicationBodyFieldsV1 {
                project,
                sandbox,
                normalized_input,
                candidate,
                prerequisites,
            },
            recipe.diagnostics_digest,
        )?;
        let mut successors = vec![
            policy_reducer_envelope(
                recipe.candidate_key,
                1,
                None,
                &recipe.candidate_body,
                &self.validator,
            )?,
            policy_reducer_envelope(
                recipe.diagnostics_key,
                1,
                None,
                &recipe.diagnostics_body,
                &self.validator,
            )?,
            policy_reducer_envelope(
                policy_effect_key(project, sandbox, transaction_id)?,
                1,
                None,
                &effect,
                &self.validator,
            )?,
        ];
        let current = policy_reducer_envelope(
            recipe.current_key,
            1,
            None,
            &recipe.current_body,
            &self.validator,
        )?;
        // This is the exact existing Current envelope digest, not a hash of
        // its body or the adapter's durable-member wrapper.
        let current_envelope = current.digest();
        successors.push(current);
        Ok(Q04PublicationCapacityV1 {
            inner: self.inner.plan(transaction_id, successors)?,
            current_envelope,
        })
    }

    pub(super) fn q04_current_plan(
        &self,
        transaction_id: [u8; 16],
        verified: VerifiedPolicyPublicationV1,
        capacity: &Q04PublicationCapacityV1,
    ) -> Result<PreparedPolicyPublicationV1, PolicyCompilerJournalErrorV1> {
        let prepared = self.plan_publication(transaction_id, 1, verified)?;
        if prepared.inner.transaction_id() != capacity.inner.transaction_id()
            || prepared.inner.journal_records() != capacity.inner.journal_records()
            || prepared.inner.transaction_digest() != capacity.inner.transaction_digest()
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        Ok(prepared)
    }

    // The strict donor retains Prepared/Pending/Applied before classification.
    // Its finite gate rechecks this genuine held verifier after slow native
    // preparation, so an earlier successful model check cannot authorize append.
    pub(super) fn q04_commit_original(
        &mut self,
        attempt: &mut Q04PolicyPublicationAttemptV1,
        verifier: &crate::native::target::RootCurrentInputVerifierV1<'_, '_, '_, '_, '_>,
    ) -> Result<(), PolicyCompilerJournalErrorV1> {
        if attempt.prepared.is_none()
            || attempt.returned.is_some()
            || attempt.applied.is_some()
            || attempt.pending.is_some()
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let Q04PolicyPublicationAttemptV1 {
            prerequisites,
            prepared,
            returned,
            ..
        } = attempt;
        let invoked = verifier.while_prerequisites_current(prerequisites, || {
            let Some(original) = prepared.take() else {
                return false;
            };
            *returned = Some(self.inner.commit_strict_with_original_cache_gate_v1(
                original,
                CacheMutationGateV1::Publication(verifier),
            ));
            true
        });
        if invoked != Some(true) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        // The full actual result was parked before classification. Moving its
        // typed cause out never discards Prepared/Pending or substitutes a
        // synthetic readback error for the original durability failure.
        attempt.classify_returned()
    }

    pub(super) fn q04_observe_original_publication(
        &self,
        attempt: &Q04PolicyPublicationAttemptV1,
        capacity: &Q04PublicationCapacityV1,
    ) -> Result<Q04PolicyPublicationReadbackV1, PolicyCompilerJournalErrorV1> {
        let applied = attempt
            .applied()
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let projection = self.replay()?;
        let snapshot = self.inner.snapshot()?;
        let transaction = projection
            .transactions()
            .iter()
            .find(|transaction| transaction.transaction_id() == capacity.transaction_id())
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let current = transaction
            .records()
            .iter()
            .find(|record| record.key().kind() == PolicyCompilerJournalRecordKindV1::Current)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        // The old applied snapshot's scalars are comparison DATA here. This
        // newly borrowed adapter does not adopt its old instance brand. Root
        // separately retains that real outcome and proves the same original
        // Journal/native file before and after this fresh complete replay.
        if transaction.records().len() != 4
            || transaction.transaction_digest() != capacity.transaction_digest()
            || applied.transaction_digest() != capacity.transaction_digest()
            || snapshot.journal_sequence() != applied.snapshot().journal_sequence()
            || snapshot.projection_root() != applied.snapshot().projection_root()
            || current.digest() != capacity.current_envelope_digest()
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        self.inner.revalidate_snapshot(&snapshot)?;
        Ok(Q04PolicyPublicationReadbackV1 {
            sequence: snapshot.journal_sequence(),
            transaction: transaction.transaction_digest(),
            current: current.digest(),
        })
    }

    /// Plans one complete immediate-successor policy publication.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for candidate reuse, skipped
    /// generation, stale CAS, malformed outputs, or failed journal preflight.
    pub(crate) fn plan_publication(
        &self,
        transaction_id: [u8; 16],
        generation: u64,
        verified: VerifiedPolicyPublicationV1,
    ) -> Result<PreparedPolicyPublicationV1, PolicyCompilerJournalErrorV1> {
        if generation == 0 || transaction_id == [0; 16] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let projection = self.replay()?;
        let current = current_policy_head(
            &projection,
            verified.project,
            verified.sandbox,
            &self.validator,
        )?;
        let expected_generation = current
            .as_ref()
            .map_or(Some(1), |head| head.generation.checked_add(1))
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if generation != expected_generation {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }

        let candidate_digest = verified.candidate.commitment().digest();
        let candidate_key = policy_key(
            PolicyCompilerJournalRecordKindV1::Candidate,
            verified.project,
            verified.sandbox,
            candidate_digest,
        )?;
        let diagnostic_key = policy_key(
            PolicyCompilerJournalRecordKindV1::Diagnostics,
            verified.project,
            verified.sandbox,
            candidate_digest,
        )?;
        if projection
            .records()
            .iter()
            .any(|record| record.key() == &candidate_key || record.key() == &diagnostic_key)
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }

        let diagnostics_payload = encode_diagnostics_payload(
            verified.project,
            verified.sandbox,
            candidate_digest,
            &verified.diagnostics,
        )?;
        let diagnostics_digest = digest_bytes(DIAGNOSTICS_DOMAIN, &diagnostics_payload);
        let candidate_payload =
            encode_candidate_payload(generation, verified.body_fields(), diagnostics_digest)?;
        let effect_payload = encode_effect_payload(
            transaction_id,
            generation,
            verified.body_fields(),
            diagnostics_digest,
        )?;
        let mut successors = vec![
            policy_reducer_envelope(candidate_key, 1, None, &candidate_payload, &self.validator)?,
            policy_reducer_envelope(
                diagnostic_key,
                1,
                None,
                &diagnostics_payload,
                &self.validator,
            )?,
        ];
        successors.push(policy_reducer_envelope(
            policy_effect_key(verified.project, verified.sandbox, transaction_id)?,
            1,
            None,
            &effect_payload,
            &self.validator,
        )?);
        let (revision, predecessor) = match current.as_ref() {
            Some(head) => (
                head.envelope_revision
                    .checked_add(1)
                    .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
                Some(head.envelope_digest),
            ),
            None => (1, None),
        };
        successors.push(policy_reducer_envelope(
            policy_current_key(verified.project, verified.sandbox)?,
            revision,
            predecessor,
            &encode_current_payload(
                verified.project,
                verified.sandbox,
                generation,
                candidate_digest,
                verified.normalized_input,
                diagnostics_digest,
                &verified.prerequisites,
            ),
            &self.validator,
        )?);
        let inner = self.inner.plan(transaction_id, successors)?;
        Ok(PreparedPolicyPublicationV1 {
            inner,
            prerequisites: verified.prerequisites,
        })
    }

    /// Commits one policy publication and performs exact readback.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for stale authority or an
    /// invalid protected-journal operation.
    pub(crate) fn commit(
        &mut self,
        prepared: PreparedPolicyPublicationV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PolicyPublicationCommitOutcomeV1, PolicyCompilerJournalErrorV1> {
        let prerequisites = prepared.prerequisites;
        let outcome = verifier
            .while_prerequisites_current(&prerequisites, || self.inner.commit(prepared.inner))
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)??;
        match outcome {
            DomainCommitOutcomeV1::Applied(inner) => Ok(PolicyPublicationCommitOutcomeV1::Applied(
                AppliedPolicyPublicationV1 {
                    inner,
                    prerequisites: Some(prerequisites),
                },
            )),
            DomainCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                Ok(PolicyPublicationCommitOutcomeV1::OutcomeUnknown {
                    pending: PolicyPublicationOutcomeUnknownV1 {
                        inner: pending,
                        prerequisites,
                    },
                    cause,
                })
            }
        }
    }

    /// Resolves one ambiguous policy publication after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when replay is malformed.
    pub(crate) fn recover(
        &self,
        pending: PolicyPublicationOutcomeUnknownV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PolicyPublicationRecoveryV1, PolicyCompilerJournalErrorV1> {
        self.replay()?;
        let prerequisites = pending.prerequisites;
        let recovery = verifier
            .while_prerequisites_current(&prerequisites, || self.inner.recover(pending.inner))
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)??;
        match recovery {
            DomainRecoveryV1::Applied(inner) => Ok(PolicyPublicationRecoveryV1::Applied(
                AppliedPolicyPublicationV1 {
                    inner,
                    prerequisites: Some(prerequisites),
                },
            )),
            DomainRecoveryV1::Retry(inner) => Ok(PolicyPublicationRecoveryV1::Retry(
                PreparedPolicyPublicationV1 {
                    inner,
                    prerequisites,
                },
            )),
            DomainRecoveryV1::Diverged(inner) => Ok(PolicyPublicationRecoveryV1::Diverged(
                PolicyPublicationOutcomeUnknownV1 {
                    inner,
                    prerequisites,
                },
            )),
        }
    }

    /// Reconstructs one complete policy transaction after cold reopen.
    ///
    /// Pending installation records authorize observation only until their
    /// composite capability passes exact current readback.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when semantic replay or durable
    /// transaction grouping fails closed.
    pub fn recover_current_transaction(
        &self,
        transaction_id: [u8; 16],
    ) -> Result<PolicyPublicationColdRecoveryV1, PolicyCompilerJournalErrorV1> {
        let projection = self.replay()?;
        let prerequisites = projection
            .transactions()
            .iter()
            .find(|transaction| transaction.transaction_id() == transaction_id)
            .map(|transaction| transaction_prerequisites(transaction.records(), &self.validator))
            .transpose()?
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        Ok(
            match self.inner.recover_current_postcommit(transaction_id)? {
                Some(ReplayedDomainPostcommitV1::Prepared(capability)) => {
                    PolicyPublicationColdRecoveryV1::ObservePending(
                        PolicyCompilerColdObservationV1 {
                            inner: capability,
                            prerequisites: prerequisites.clone(),
                        },
                    )
                }
                Some(ReplayedDomainPostcommitV1::Terminal(capability)) => {
                    PolicyPublicationColdRecoveryV1::Terminal(PolicyCompilerColdObservationV1 {
                        inner: capability,
                        prerequisites,
                    })
                }
                None => PolicyPublicationColdRecoveryV1::StateOnly,
            },
        )
    }

    /// Plans one durable observed successor for a cold pending effect.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] unless the cold transaction,
    /// prerequisite heads, effect predecessor, and observation are exact.
    pub(crate) fn plan_cold_observation(
        &self,
        transaction_id: [u8; 16],
        cold: PolicyCompilerColdObservationV1,
        observation: ObjectDigest,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PreparedPolicyEffectObservationV1, PolicyCompilerJournalErrorV1> {
        let prerequisites = cold.prerequisites;
        let validated = cold.inner.consume(&self.inner)?;
        let retained = validated_postcommit_prerequisites(&validated, &self.validator)?;
        if retained != prerequisites {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let effect = validated
            .records()
            .iter()
            .find(|record| {
                record.envelope().key().kind() == PolicyCompilerJournalRecordKindV1::Effect
            })
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
            .envelope();
        if effect.key().identity().get(32..48) == Some(transaction_id.as_slice()) {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let key = effect.key().clone();
        let revision = effect
            .revision()
            .checked_add(1)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let predecessor = Some(effect.digest());
        let effect_body = policy_body(effect, &self.validator)?.to_vec();
        let request = policy_effect_observation_request(
            effect,
            &effect_body,
            transaction_id,
            observation,
            prerequisites.digest(),
        )?;
        drop(validated);

        verifier
            .while_effect_observation_current(&prerequisites, &request, |verified| {
                let body = encode_observed_effect_payload(&effect_body, verified.result())?;
                let envelope =
                    policy_reducer_envelope(key, revision, predecessor, &body, &self.validator)?;
                Ok(PreparedPolicyEffectObservationV1 {
                    inner: self.inner.plan(transaction_id, vec![envelope])?,
                    prerequisites: prerequisites.clone(),
                    observation: verified,
                })
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?
    }

    /// Commits one observation successor without minting effect authority.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when prerequisite currentness,
    /// CAS, durability, or exact readback fails.
    pub(crate) fn commit_observation(
        &mut self,
        prepared: PreparedPolicyEffectObservationV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PolicyEffectObservationCommitOutcomeV1, PolicyCompilerJournalErrorV1> {
        let prerequisites = prepared.prerequisites;
        let observation = prepared.observation;
        let request = observation.request().clone();
        let outcome = verifier
            .while_effect_observation_current(&prerequisites, &request, |current| {
                if current != observation {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                self.inner.commit(prepared.inner).map_err(Into::into)
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)??;
        Ok(match outcome {
            DomainCommitOutcomeV1::Applied(_) => {
                self.replay()?;
                PolicyEffectObservationCommitOutcomeV1::Applied
            }
            DomainCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                PolicyEffectObservationCommitOutcomeV1::OutcomeUnknown {
                    pending: PolicyEffectObservationOutcomeUnknownV1 {
                        inner: pending,
                        prerequisites,
                        observation,
                    },
                    cause,
                }
            }
        })
    }

    /// Recovers one ambiguous observation successor without minting authority.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for unauthenticated currentness
    /// or malformed durable recovery state.
    pub(crate) fn recover_observation(
        &self,
        pending: PolicyEffectObservationOutcomeUnknownV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PolicyEffectObservationRecoveryV1, PolicyCompilerJournalErrorV1> {
        let prerequisites = pending.prerequisites;
        let observation = pending.observation;
        let request = observation.request().clone();
        let recovery = verifier
            .while_effect_observation_current(&prerequisites, &request, |current| {
                if current != observation {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                self.inner.recover(pending.inner).map_err(Into::into)
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)??;
        Ok(match recovery {
            DomainRecoveryV1::Applied(_) => {
                self.replay()?;
                PolicyEffectObservationRecoveryV1::Applied
            }
            DomainRecoveryV1::Retry(inner) => {
                self.replay()?;
                PolicyEffectObservationRecoveryV1::Retry(PreparedPolicyEffectObservationV1 {
                    inner,
                    prerequisites,
                    observation,
                })
            }
            DomainRecoveryV1::Diverged(inner) => PolicyEffectObservationRecoveryV1::Diverged(
                PolicyEffectObservationOutcomeUnknownV1 {
                    inner,
                    prerequisites,
                    observation,
                },
            ),
        })
    }

    /// Plans an immutable replay join without granting compaction authority.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for a sentinel checkpoint,
    /// stale projection, or failed preflight.
    pub fn plan_checkpoint(
        &self,
        transaction_id: [u8; 16],
        checkpoint: ObjectDigest,
    ) -> Result<PreparedPolicyCheckpointV1, PolicyCompilerJournalErrorV1> {
        if checkpoint.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        self.replay()?;
        let key = PolicyCompilerJournalKeyV1::new(
            PolicyCompilerJournalRecordKindV1::Checkpoint,
            checkpoint.as_bytes().to_vec(),
        )?;
        let envelope = self.inner.checkpoint_successor(key, 1, None)?;
        Ok(PreparedPolicyCheckpointV1 {
            inner: self.inner.plan(transaction_id, vec![envelope])?,
        })
    }

    /// Commits one checkpoint without minting publication or effect authority.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when precommit replay, CAS, or
    /// protected-journal preflight fails before durable mutation.
    pub fn commit_checkpoint(
        &mut self,
        prepared: PreparedPolicyCheckpointV1,
    ) -> Result<PolicyCheckpointCommitOutcomeV1, PolicyCompilerJournalErrorV1> {
        self.replay()?;
        Ok(match self.inner.commit(prepared.inner)? {
            DomainCommitOutcomeV1::Applied(inner) => {
                if let Err(cause) = self.replay() {
                    PolicyCheckpointCommitOutcomeV1::ValidationUnknown {
                        pending: PolicyCheckpointOutcomeUnknownV1 {
                            inner: PolicyCheckpointOutcomeUnknownStateV1::PostcommitValidation(
                                inner,
                            ),
                        },
                        cause,
                    }
                } else {
                    PolicyCheckpointCommitOutcomeV1::Applied
                }
            }
            DomainCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                PolicyCheckpointCommitOutcomeV1::OutcomeUnknown {
                    pending: PolicyCheckpointOutcomeUnknownV1 {
                        inner: PolicyCheckpointOutcomeUnknownStateV1::Commit(pending),
                    },
                    cause,
                }
            }
        })
    }

    /// Recovers one exact ambiguous checkpoint after full protected replay.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] if generic protected recovery
    /// cannot decode or authenticate its exact retained transaction.
    pub fn recover_checkpoint(
        &self,
        pending: PolicyCheckpointOutcomeUnknownV1,
    ) -> Result<PolicyCheckpointRecoveryV1, PolicyCompilerJournalErrorV1> {
        if let Err(cause) = self.replay() {
            return Ok(PolicyCheckpointRecoveryV1::Indeterminate { pending, cause });
        }
        let inner = match pending.inner {
            PolicyCheckpointOutcomeUnknownStateV1::PostcommitValidation(applied) => {
                let _transaction_digest = applied.transaction_digest();
                return Ok(PolicyCheckpointRecoveryV1::Applied);
            }
            PolicyCheckpointOutcomeUnknownStateV1::Commit(inner) => inner,
        };
        Ok(match self.inner.recover(inner)? {
            DomainRecoveryV1::Applied(applied) => {
                if let Err(cause) = self.replay() {
                    PolicyCheckpointRecoveryV1::Indeterminate {
                        pending: PolicyCheckpointOutcomeUnknownV1 {
                            inner: PolicyCheckpointOutcomeUnknownStateV1::PostcommitValidation(
                                applied,
                            ),
                        },
                        cause,
                    }
                } else {
                    PolicyCheckpointRecoveryV1::Applied
                }
            }
            DomainRecoveryV1::Retry(inner) => {
                PolicyCheckpointRecoveryV1::Retry(PreparedPolicyCheckpointV1 { inner })
            }
            DomainRecoveryV1::Diverged(inner) => {
                PolicyCheckpointRecoveryV1::Diverged(PolicyCheckpointOutcomeUnknownV1 {
                    inner: PolicyCheckpointOutcomeUnknownStateV1::Commit(inner),
                })
            }
        })
    }
}

impl PolicyCompilerPostcommitCapabilityV1 {
    /// Consumes one policy transaction after revalidating all prerequisite heads.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when any prerequisite changed,
    /// the journal advanced, or the exact transaction bodies disagree.
    pub(crate) fn consume_with<R>(
        self,
        authority: &PolicyCompilerProtectedJournalV1<'_>,
        verifier: &impl PolicyPublicationVerifierV1,
        handoff: impl for<'guard> FnOnce(PolicyCompilerEffectHandoffV1<'guard>) -> R,
    ) -> Result<R, PolicyCompilerJournalErrorV1> {
        verifier
            .while_prerequisites_current(&self.prerequisites, || {
                let validated = self.inner.consume(&authority.inner)?;
                let retained =
                    validated_postcommit_prerequisites(&validated, &authority.validator)?;
                if retained != self.prerequisites {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                Ok::<_, PolicyCompilerJournalErrorV1>(handoff(PolicyCompilerEffectHandoffV1 {
                    transaction_digest: validated.transaction_digest(),
                    marker: PhantomData,
                }))
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?
    }
}

impl PolicyCompilerColdObservationV1 {
    /// Consumes cold terminal authority while protected prerequisites are held.
    ///
    /// # Errors
    ///
    /// Returns an error when prerequisites, replay, or transaction currentness
    /// changed after cold recovery.
    pub(crate) fn consume_with<R>(
        self,
        authority: &PolicyCompilerProtectedJournalV1<'_>,
        verifier: &impl PolicyPublicationVerifierV1,
        handoff: impl for<'guard> FnOnce(PolicyCompilerEffectHandoffV1<'guard>) -> R,
    ) -> Result<R, PolicyCompilerJournalErrorV1> {
        verifier
            .while_prerequisites_current(&self.prerequisites, || {
                let validated = self.inner.consume(&authority.inner)?;
                let retained =
                    validated_postcommit_prerequisites(&validated, &authority.validator)?;
                if retained != self.prerequisites {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                Ok::<_, PolicyCompilerJournalErrorV1>(handoff(PolicyCompilerEffectHandoffV1 {
                    transaction_digest: validated.transaction_digest(),
                    marker: PhantomData,
                }))
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?
    }
}

impl PolicyCompilerEffectHandoffV1<'_> {
    /// Returns the exact durable publication transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction_digest
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
#[path = "publication/candidate_tests.rs"]
pub(crate) mod candidate_tests;

#[cfg(test)]
mod canonical_replay_tests;

#[cfg(test)]
mod canonical_diagnostics_tests {
    use super::{DIAGNOSTICS_DOMAIN, PolicyCompilerJournalErrorV1, validate_canonical_diagnostics};

    fn frame(domain: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn diagnostics_require_the_exact_domain_and_canonical_json() {
        let valid = super::candidate_tests::fixture(4096).diagnostics;
        assert!(validate_canonical_diagnostics(&valid).is_ok());

        for invalid in [
            frame(b"wrong", b"{}"),
            frame(DIAGNOSTICS_DOMAIN, b"{ }"),
            frame(DIAGNOSTICS_DOMAIN, b""),
            valid[..valid.len() - 1].to_vec(),
        ] {
            assert!(matches!(
                validate_canonical_diagnostics(&invalid),
                Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication)
            ));
        }
    }
}

/// Preserves the original Policy publication/schema cause.
pub use crate::publication::PolicyCompilerJournalErrorV1;

/// Borrows canonical publication comparison DATA without issuing native authority.
pub use crate::publication::{
    DecodedCandidateHeaderV1, compare_recompiled_candidate_derivation_v1, validated_candidate_body,
};

pub use crate::publication::{
    PolicyPublicationPrerequisitesV1, Q04IndependentPublicationRecipeV1,
    q04_independent_publication_data_v1,
};
