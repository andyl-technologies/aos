//! Dormant protected-journal adapter for publisher admission.
//!
//! Publisher reducer records already form a canonical hash chain. This adapter
//! preserves every entry under its sequence and digest, advances one protected
//! current head in the same transaction, and releases reducer acknowledgement
//! or completion-effect authority only after exact journal readback.

use std::{collections::BTreeSet, marker::PhantomData};

use aos_sandbox_core::{ObjectDigest, OperationId};

use crate::journal::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, Journal, JournalError, RecordNamespace,
};
use crate::lifecycle::protected_journal_adapter::{
    AppliedDomainTransactionV1, DomainCapacityAdmissionCommitOutcomeV1,
    DomainCapacityAdmissionRecoveryV1, DomainCapacityAdmissionUnknownV1,
    DomainCapacityReservationV1, DomainCapacitySettlementCommitOutcomeV1,
    DomainCapacitySettlementRecoveryV1, DomainCapacitySettlementUnknownV1, DomainCommitOutcomeV1,
    DomainOutcomeUnknownV1, DomainPostcommitCapabilityV1, DomainRecoveryV1,
    PreparedCapacityReservedDomainTransactionV1, PreparedCapacitySettlementDomainTransactionV1,
    PreparedDomainTransactionV1, ProtectedCapacitySettlementMemberV1, ProtectedDomainEnvelopeV1,
    ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1, ProtectedDomainKeyV1,
    ProtectedDomainProjectionV1, ProtectedDomainSchemaV1, ProtectedDomainSnapshotV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1, ReplayedDomainPostcommitV1,
    ValidatedDomainPostcommitV1, bind_domain_capacity_request_v1,
    decode_reducer_payload_with_validator, encode_reducer_payload_with_validator,
    validate_domain_capacity_lineage_v1,
};

use super::{
    AdmissionError, AdmissionLimits, AuthorityCheckpointV1, CapacityPolicyV1,
    CompletionPermitStateV1, CompletionPermitV1, DecodedPublisherPayloadV1, LedgerMutation,
    ProtectedLedgerReplayV1, ProtectedMutationBranchV1, ProtectedRecordCodecError,
    ProtectedRecordKindV1, ProtectedStoreCommitToken, decode_protected_record_v1,
};

const HEAD_MAGIC: &[u8; 8] = b"AOSPAH01";
const MUTATION_MAGIC: &[u8; 8] = b"AOSPAM01";
const MAXIMUM_BATCH_RECORDS: usize = 65_536;
const COMPLETION_TERMINAL_RECORDS: u32 = 8;
const COMPLETION_POISON_RECORDS: u32 = 5;
const LEDGER_MEMBER_OVERHEAD_BYTES: u64 = 72 * 1024;
const FIXED_TERMINAL_OVERHEAD_BYTES: u64 = 16 * 1024;
const CHECKPOINT_COMMITMENT_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-admission.capacity-checkpoint.v1\0";

const fn maximum_admission_limits() -> AdmissionLimits {
    AdmissionLimits {
        maximum_records: 1_000_000,
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_materialized_bytes: 512 * 1024 * 1024,
        maximum_outstanding_permits: 65_536,
        maximum_protocol_bytes: 1024 * 1024,
    }
}

/// Selects one closed publisher-admission journal family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PublisherAdmissionJournalRecordKindV1 {
    /// Retains one immutable entry from the reducer's canonical hash chain.
    LedgerEntry = 1,
    /// Retains a pre-effect boundary for an outstanding completion permit.
    CompletionEffect = 2,
    /// Publishes the exact reducer chain and checkpoint head.
    Current = 3,
    /// Publishes a replay join without granting compaction authority.
    Checkpoint = 4,
    /// Retains exact reservation-to-terminal lineage for one settlement.
    CapacitySettlement = 5,
}

/// Defines the publisher-admission protected-journal schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublisherAdmissionJournalSchemaV1;

impl ProtectedDomainSchemaV1 for PublisherAdmissionJournalSchemaV1 {
    type Kind = PublisherAdmissionJournalRecordKindV1;
    type ReplayValidator = AdmissionLimits;

    const MAGIC: [u8; 8] = *b"AOSPAJ01";
    const HASH_DOMAIN: &'static [u8] = b"aos.sandbox.publisher-admission.journal.v1\0";
    const KEY_PREFIX: &'static [u8] = b"\0aos-publisher-admission-v1\0";
    const MAXIMUM_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::LedgerEntry),
            2 => Some(Self::Kind::CompletionEffect),
            3 => Some(Self::Kind::Current),
            4 => Some(Self::Kind::Checkpoint),
            5 => Some(Self::Kind::CapacitySettlement),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::LedgerEntry | Self::Kind::CapacitySettlement => {
                RecordNamespace::PublisherAuthority
            }
            Self::Kind::CompletionEffect => RecordNamespace::Effect,
            Self::Kind::Current => RecordNamespace::AuthorityPublication,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::LedgerEntry | Self::Kind::CapacitySettlement => {
                ProtectedRecordRoleV1::State
            }
            Self::Kind::CompletionEffect => ProtectedRecordRoleV1::Effect,
            Self::Kind::Current | Self::Kind::Checkpoint => ProtectedRecordRoleV1::Publication,
        }
    }

    fn is_checkpoint(kind: Self::Kind) -> bool {
        matches!(kind, Self::Kind::Checkpoint)
    }

    fn family(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn decode_reducer_phase(
        validator: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        match kind {
            Self::Kind::LedgerEntry => {
                let mutation = decode_mutation(body, *validator).ok()?;
                let record = decode_protected_record_v1(&mutation.value, *validator).ok()?;
                (identity.len() == 40
                    && identity[..8] == record.sequence.to_be_bytes()
                    && identity[8..] == *record.digest.as_bytes())
                .then_some(ProtectedReducerPhaseV1::Terminal)
            }
            Self::Kind::CompletionEffect => {
                let effect = decode_effect_permit(body).ok()?;
                (identity == effect.transaction && encode_effect_binding(&effect) == body)
                    .then_some(ProtectedReducerPhaseV1::Prepared)
            }
            Self::Kind::Current => decode_current_head(body)
                .ok()
                .map(|_| ProtectedReducerPhaseV1::Terminal),
            Self::Kind::Checkpoint => None,
            Self::Kind::CapacitySettlement => {
                let settlement = decode_capacity_settlement(body).ok()?;
                (identity == settlement.admission_transaction_id
                    && encode_capacity_settlement(&settlement) == body)
                    .then_some(ProtectedReducerPhaseV1::Terminal)
            }
        }
    }

    fn validates_identity(kind: Self::Kind, identity: &[u8]) -> bool {
        match kind {
            Self::Kind::LedgerEntry => {
                identity.len() == 40 && identity[..8] != [0; 8] && identity[8..] != [0; 32]
            }
            Self::Kind::CompletionEffect => identity.len() == 16 && identity != [0; 16],
            Self::Kind::Current => identity == b"authority",
            Self::Kind::Checkpoint => identity.len() == 32 && identity != [0; 32],
            Self::Kind::CapacitySettlement => identity.len() == 16 && identity != [0; 16],
        }
    }

    fn validates_capacity_settlement(
        request: &GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
        members: &[ProtectedCapacitySettlementMemberV1<'_, Self::Kind>],
    ) -> bool {
        validate_capacity_settlement_members(request, admission_transaction_id, members).is_ok()
    }
}

/// Canonical publisher-admission key.
pub type PublisherAdmissionJournalKeyV1 = ProtectedDomainKeyV1<PublisherAdmissionJournalSchemaV1>;
/// Canonical publisher-admission envelope.
pub type PublisherAdmissionJournalEnvelopeV1 =
    ProtectedDomainEnvelopeV1<PublisherAdmissionJournalSchemaV1>;
/// Exact publisher-admission currentness snapshot.
pub type PublisherAdmissionJournalSnapshotV1 =
    ProtectedDomainSnapshotV1<PublisherAdmissionJournalSchemaV1>;
/// Replayed publisher-admission projection.
pub type PublisherAdmissionJournalProjectionV1 =
    ProtectedDomainProjectionV1<PublisherAdmissionJournalSchemaV1>;
type RawPublisherAdmissionPostcommitCapabilityV1 =
    DomainPostcommitCapabilityV1<PublisherAdmissionJournalSchemaV1>;

/// Composite publisher authority released after exact transaction readback.
#[must_use = "publisher authority must be revalidated against its exact journal"]
pub(crate) struct PublisherAdmissionPostcommitCapabilityV1 {
    inner: RawPublisherAdmissionPostcommitCapabilityV1,
    capacity: Option<PublisherCompletionCapacityV1>,
}

/// Carries one fully revalidated publisher transaction.
#[must_use = "validated publisher authority must be handed to one dormant consumer"]
pub(crate) struct ValidatedPublisherAdmissionPostcommitV1<'current> {
    inner: ValidatedDomainPostcommitV1<'current, PublisherAdmissionJournalSchemaV1>,
    capacity: Option<PublisherCompletionCapacityV1>,
}

/// Seals one live permit observation to the exact cold-replayed projection.
#[must_use = "cold publisher observation authority must be revalidated exactly once"]
pub(crate) struct PublisherAdmissionColdObservationV1 {
    snapshot: PublisherAdmissionJournalSnapshotV1,
    transaction_id: [u8; 16],
    transaction_digest: ObjectDigest,
    effect_digest: ObjectDigest,
    permit_record_digest: ObjectDigest,
    current_digest: ObjectDigest,
    binding: CompletionEffectBindingV1,
    capacity: Option<PublisherCompletionCapacityV1>,
}

/// Carries a revalidated cold permit observation and its settlement capacity.
#[must_use = "validated cold publisher authority must be handed to one observer"]
pub(crate) struct ValidatedPublisherAdmissionColdObservationV1<'current> {
    transaction_digest: ObjectDigest,
    capacity: Option<PublisherCompletionCapacityV1>,
    current: PhantomData<&'current Journal>,
}
/// Exact publisher replay-checkpoint transaction.
pub(crate) type PreparedPublisherAdmissionCheckpointV1 =
    PreparedDomainTransactionV1<PublisherAdmissionJournalSchemaV1>;
/// Publisher replay-checkpoint commit outcome.
pub(crate) type PublisherAdmissionCheckpointCommitOutcomeV1 =
    DomainCommitOutcomeV1<PublisherAdmissionJournalSchemaV1>;
/// Publisher replay-checkpoint recovery classification.
pub(crate) type PublisherAdmissionCheckpointRecoveryV1 =
    DomainRecoveryV1<PublisherAdmissionJournalSchemaV1>;

/// Reports semantic-chain, codec, reducer, or journal failures.
#[derive(Debug, thiserror::Error)]
pub enum PublisherAdmissionJournalErrorV1 {
    /// A mutation batch is empty, noncontiguous, reused, or not checkpointed.
    #[error("publisher admission mutation batch is not a canonical successor")]
    InvalidMutationBatch,
    /// A protected reducer record is malformed or exceeds its limit.
    #[error(transparent)]
    Codec(#[from] ProtectedRecordCodecError),
    /// The publisher reducer rejected its own protected projection.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// The protected-domain adapter rejected currentness or durability.
    #[error(transparent)]
    Journal(#[from] ProtectedDomainJournalErrorV1),
}

/// Holds one exact reducer branch before durable mutation.
#[must_use = "a publisher admission transaction must be committed or deliberately discarded"]
pub(crate) struct PreparedPublisherAdmissionTransactionV1 {
    inner: PreparedDomainTransactionV1<PublisherAdmissionJournalSchemaV1>,
    checkpoint: AuthorityCheckpointV1,
    chain_head: ObjectDigest,
}

/// Holds an effect-bearing permit admission and its durable capacity reservation.
#[must_use = "a capacity-reserved publisher admission must be committed or discarded"]
pub(crate) struct PreparedPublisherCapacityAdmissionV1 {
    inner: PreparedCapacityReservedDomainTransactionV1<PublisherAdmissionJournalSchemaV1>,
    checkpoint: AuthorityCheckpointV1,
    chain_head: ObjectDigest,
    binding: CompletionCapacityBindingV1,
}

/// Retains an effect-bearing admission after ambiguous durability.
#[must_use = "ambiguous publisher capacity admission must be resolved after reopen"]
pub(crate) struct PublisherCapacityAdmissionOutcomeUnknownV1 {
    inner: DomainCapacityAdmissionUnknownV1<PublisherAdmissionJournalSchemaV1>,
    checkpoint: AuthorityCheckpointV1,
    chain_head: ObjectDigest,
    binding: CompletionCapacityBindingV1,
}

/// Authorizes exactly one terminal or poison successor for an issued permit.
#[must_use = "publisher completion capacity must settle its exact retained obligation"]
pub(crate) struct PublisherCompletionCapacityV1 {
    inner: DomainCapacityReservationV1<PublisherAdmissionJournalSchemaV1>,
    binding: CompletionCapacityBindingV1,
}

impl PublisherCompletionCapacityV1 {
    /// Returns the exact operation bound by the authenticated reservation.
    pub(super) const fn operation_id(&self) -> [u8; 16] {
        self.binding.operation
    }
}

/// Holds one terminal publisher branch joined to reservation deletion.
#[must_use = "a publisher capacity settlement must be committed or discarded"]
pub(crate) struct PreparedPublisherCapacitySettlementV1 {
    inner: PreparedCapacitySettlementDomainTransactionV1<PublisherAdmissionJournalSchemaV1>,
    checkpoint: AuthorityCheckpointV1,
    chain_head: ObjectDigest,
}

/// Retains one exact terminal settlement after ambiguous durability.
#[must_use = "ambiguous publisher capacity settlement must be resolved after reopen"]
pub(crate) struct PublisherCapacitySettlementOutcomeUnknownV1 {
    inner: DomainCapacitySettlementUnknownV1<PublisherAdmissionJournalSchemaV1>,
    checkpoint: AuthorityCheckpointV1,
    chain_head: ObjectDigest,
}

/// Retains an exact publisher branch after ambiguous append or synchronization.
#[must_use = "an ambiguous publisher commit must be resolved after protected reopen"]
pub(crate) struct PublisherAdmissionOutcomeUnknownV1 {
    inner: DomainOutcomeUnknownV1<PublisherAdmissionJournalSchemaV1>,
    checkpoint: AuthorityCheckpointV1,
    chain_head: ObjectDigest,
}

/// Proves a publisher reducer branch was committed and read back exactly.
#[must_use = "publisher postcommit authority must be consumed or deliberately discarded"]
pub(crate) struct AppliedPublisherAdmissionTransactionV1 {
    inner: AppliedDomainTransactionV1<PublisherAdmissionJournalSchemaV1>,
    acknowledgement: Option<ProtectedStoreCommitToken>,
    capacity: Option<PublisherCompletionCapacityV1>,
}

impl AppliedPublisherAdmissionTransactionV1 {
    /// Takes the reducer acknowledgement for this exact checkpoint and head.
    #[must_use]
    pub(crate) fn take_acknowledgement(&mut self) -> Option<ProtectedStoreCommitToken> {
        self.acknowledgement.take()
    }

    /// Takes composite authority for exact current revalidation.
    #[must_use]
    pub(crate) fn take_postcommit(&mut self) -> Option<PublisherAdmissionPostcommitCapabilityV1> {
        Some(PublisherAdmissionPostcommitCapabilityV1 {
            inner: self.inner.take_postcommit()?,
            capacity: self.capacity.take(),
        })
    }
}

/// Distinguishes exact capacity-admission success from mandatory reopen recovery.
#[must_use = "ambiguous publisher capacity admissions retain mandatory recovery state"]
pub(crate) enum PublisherCapacityAdmissionCommitOutcomeV1 {
    /// The permit, effect, current head, and reservation are durable together.
    Applied(AppliedPublisherAdmissionTransactionV1),
    /// Durable outcome is unknown and no publisher authority may escape.
    OutcomeUnknown {
        /// Retains the exact admission and reservation transaction.
        pending: PublisherCapacityAdmissionOutcomeUnknownV1,
        /// Reports the underlying durability failure.
        cause: JournalError,
    },
}

/// Classifies protected recovery of an effect-bearing capacity admission.
#[must_use = "publisher capacity admission recovery must be applied, retried, or quarantined"]
pub(crate) enum PublisherCapacityAdmissionRecoveryV1 {
    /// Reopen found the complete exact admission and retained reservation.
    Applied(AppliedPublisherAdmissionTransactionV1),
    /// Reopen found every predecessor and no admission member.
    Retry(PreparedPublisherCapacityAdmissionV1),
    /// Reopen found mixed, substituted, or incomplete state.
    Diverged(PublisherCapacityAdmissionOutcomeUnknownV1),
}

/// Distinguishes exact terminal settlement from ambiguous durability.
#[must_use = "ambiguous publisher capacity settlements retain mandatory recovery state"]
pub(crate) enum PublisherCapacitySettlementCommitOutcomeV1 {
    /// The terminal branch is durable and its reservation is absent.
    Applied(AppliedPublisherAdmissionTransactionV1),
    /// Durable outcome is unknown and no publisher authority may escape.
    OutcomeUnknown {
        /// Retains the exact terminal branch and reservation deletion.
        pending: PublisherCapacitySettlementOutcomeUnknownV1,
        /// Reports the underlying durability failure.
        cause: JournalError,
    },
}

/// Classifies protected recovery of one terminal capacity settlement.
#[must_use = "publisher capacity settlement recovery must be applied, retried, or quarantined"]
pub(crate) enum PublisherCapacitySettlementRecoveryV1 {
    /// Reopen found the terminal branch and no reservation.
    Applied(AppliedPublisherAdmissionTransactionV1),
    /// Reopen found every predecessor and the exact retained reservation.
    Retry(PreparedPublisherCapacitySettlementV1),
    /// Reopen found mixed, substituted, or incomplete state.
    Diverged(PublisherCapacitySettlementOutcomeUnknownV1),
}

/// Distinguishes exact publisher commit success from mandatory reopen recovery.
#[must_use = "ambiguous publisher commits retain mandatory recovery state"]
pub(crate) enum PublisherAdmissionCommitOutcomeV1 {
    /// The exact reducer branch is durable and was read back.
    Applied(AppliedPublisherAdmissionTransactionV1),
    /// Durable outcome is unknown and no reducer authority may escape.
    OutcomeUnknown {
        /// Retains the complete exact branch.
        pending: PublisherAdmissionOutcomeUnknownV1,
        /// Reports the underlying durability failure.
        cause: JournalError,
    },
}

/// Classifies protected recovery of one exact publisher branch.
#[must_use = "publisher recovery must be applied, retried, or quarantined"]
pub(crate) enum PublisherAdmissionJournalRecoveryV1 {
    /// Every exact successor was present after reopen.
    Applied(AppliedPublisherAdmissionTransactionV1),
    /// Every predecessor was present and only the retained retry is legal.
    Retry(PreparedPublisherAdmissionTransactionV1),
    /// Mixed or substituted state denies authority.
    Diverged(PublisherAdmissionOutcomeUnknownV1),
}

/// Classifies a complete publisher transaction reconstructed after cold reopen.
#[must_use = "pending publisher effects permit observation only"]
pub(crate) enum PublisherAdmissionColdRecoveryV1 {
    /// No current effect or publication authority exists for the transaction.
    StateOnly,
    /// An outstanding permit requires physical observation before settlement.
    ObservePending(PublisherAdmissionColdObservationV1),
    /// A terminal branch may be revalidated as one exact transaction.
    Terminal(PublisherAdmissionPostcommitCapabilityV1),
}

/// Owns dormant publisher-admission durability.
pub(crate) struct PublisherAdmissionProtectedJournalV1<'journal> {
    inner: ProtectedDomainJournalV1<'journal, PublisherAdmissionJournalSchemaV1>,
    limits: AdmissionLimits,
    capacity: CapacityPolicyV1,
    maximum_source_releases: usize,
    maximum_root_records: usize,
}

impl<'journal> PublisherAdmissionProtectedJournalV1<'journal> {
    /// Claims the adapter over a protected-open journal.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] for invalid limits or a
    /// journal without healthy protected provenance.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        limits: AdmissionLimits,
        capacity: CapacityPolicyV1,
        maximum_source_releases: usize,
        maximum_root_records: usize,
    ) -> Result<Self, PublisherAdmissionJournalErrorV1> {
        if maximum_source_releases == 0 || maximum_root_records == 0 {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        let limits = limits.validate()?;
        Ok(Self {
            inner: ProtectedDomainJournalV1::claim_with_validator(journal, limits)?,
            limits,
            capacity: capacity.validate().map_err(AdmissionError::from)?,
            maximum_source_releases,
            maximum_root_records,
        })
    }

    /// Replays every retained publisher entry and exact current head.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] for malformed projection
    /// bytes, broken chain continuity, or a substituted head.
    pub(crate) fn replay(
        &self,
    ) -> Result<PublisherAdmissionJournalProjectionV1, PublisherAdmissionJournalErrorV1> {
        let projection = self.inner.replay()?;
        validate_projection(&projection, self.limits)?;
        validate_semantic_projection(
            &projection,
            self.limits,
            self.capacity,
            self.maximum_source_releases,
            self.maximum_root_records,
        )?;
        Ok(projection)
    }

    /// Reconstructs the complete typed publisher authority after protected replay.
    ///
    /// An empty journal returns `None`; once the first reducer branch is
    /// committed, every reopen must reconstruct the exact terminal checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] for any semantic reducer,
    /// accounting, registry, chain, checkpoint, or head mismatch.
    pub(crate) fn replay_authority(
        &self,
    ) -> Result<Option<ProtectedLedgerReplayV1>, PublisherAdmissionJournalErrorV1> {
        let projection = self.inner.replay()?;
        validate_projection(&projection, self.limits)?;
        reconstruct_semantic_projection(
            &projection,
            self.limits,
            self.capacity,
            self.maximum_source_releases,
            self.maximum_root_records,
        )
    }

    /// Seals exact publisher currentness.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] when replay fails.
    pub(crate) fn snapshot(
        &self,
    ) -> Result<PublisherAdmissionJournalSnapshotV1, PublisherAdmissionJournalErrorV1> {
        self.replay()?;
        Ok(self.inner.snapshot()?)
    }

    /// Plans one already-sealed reducer branch and terminal checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] unless the mutations are
    /// contiguous from the protected current head, end in the exact branch
    /// checkpoint, and do not reuse an immutable sequence/digest identity.
    pub(crate) fn plan_branch(
        &self,
        transaction_id: [u8; 16],
        branch: &ProtectedMutationBranchV1,
    ) -> Result<PreparedPublisherAdmissionTransactionV1, PublisherAdmissionJournalErrorV1> {
        let checkpoint = branch.ledger.checkpoint()?;
        let planned = self.plan_mutations(transaction_id, &branch.mutations, checkpoint, None)?;
        if planned.issued.is_some()
            || planned.settlement.is_some()
            || (planned.poisoned && planned.active_capacity)
        {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        Ok(planned.prepared)
    }

    /// Plans absent-to-outstanding permit issuance with durable global capacity.
    ///
    /// The permit mutation, completion effect, current authority head, and
    /// capacity reservation are one closed protected transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] unless the branch issues
    /// exactly one previously unseen outstanding permit and the journal can
    /// retain the worst-case terminal and poison budgets.
    pub(crate) fn plan_capacity_reserved_branch(
        &mut self,
        transaction_id: [u8; 16],
        branch: &ProtectedMutationBranchV1,
    ) -> Result<PreparedPublisherCapacityAdmissionV1, PublisherAdmissionJournalErrorV1> {
        let checkpoint = branch.ledger.checkpoint()?;
        let planned = self.plan_mutations(transaction_id, &branch.mutations, checkpoint, None)?;
        let permit = planned
            .issued
            .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
        if planned.settlement.is_some() || planned.poisoned || planned.active_capacity {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }

        let request = completion_capacity_request(
            &planned.prepared.inner,
            &permit,
            &planned.prepared.checkpoint,
            planned.prepared.chain_head,
            self.limits,
        )?;
        let binding = CompletionCapacityBindingV1::from_permit(
            planned.prepared.inner.transaction_id(),
            &permit,
        );
        let inner = self
            .inner
            .prepare_capacity_reserved_admission(planned.prepared.inner, request)?;
        Ok(PreparedPublisherCapacityAdmissionV1 {
            inner,
            checkpoint: planned.prepared.checkpoint,
            chain_head: planned.prepared.chain_head,
            binding,
        })
    }

    /// Plans one permit terminal or poison branch with atomic capacity release.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] unless the branch spends or
    /// retires the exact retained permit, or latches the canonical poison
    /// alternative, and the complete branch fits its reserved budget.
    pub(crate) fn plan_capacity_settlement(
        &mut self,
        transaction_id: [u8; 16],
        branch: &ProtectedMutationBranchV1,
        capacity: PublisherCompletionCapacityV1,
    ) -> Result<PreparedPublisherCapacitySettlementV1, PublisherAdmissionJournalErrorV1> {
        let checkpoint = branch.ledger.checkpoint()?;
        let (capacity_request, capacity_admission) = capacity.inner.authenticated_binding();
        if !capacity
            .binding
            .matches_reservation(&capacity_request, capacity_admission)
        {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        let planned = self.plan_mutations(
            transaction_id,
            &branch.mutations,
            checkpoint,
            Some(&capacity),
        )?;
        if planned.issued.is_some()
            || (planned.poisoned && !planned.active_capacity)
            || (!planned.poisoned
                && planned
                    .settlement
                    .as_ref()
                    .is_none_or(|permit| !capacity.binding.matches_terminal(permit)))
        {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        let inner = self
            .inner
            .prepare_capacity_settlement(planned.prepared.inner, capacity.inner)?;
        Ok(PreparedPublisherCapacitySettlementV1 {
            inner,
            checkpoint: planned.prepared.checkpoint,
            chain_head: planned.prepared.chain_head,
        })
    }

    /// Commits a publisher branch and releases authority only after readback.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] for stale authority or an
    /// invalid protected-journal operation.
    pub(crate) fn commit(
        &mut self,
        prepared: PreparedPublisherAdmissionTransactionV1,
    ) -> Result<PublisherAdmissionCommitOutcomeV1, PublisherAdmissionJournalErrorV1> {
        let checkpoint = prepared.checkpoint;
        let chain_head = prepared.chain_head;
        match self.inner.commit(prepared.inner)? {
            DomainCommitOutcomeV1::Applied(inner) => {
                Ok(PublisherAdmissionCommitOutcomeV1::Applied(
                    applied_publisher(inner, checkpoint, chain_head, None),
                ))
            }
            DomainCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                Ok(PublisherAdmissionCommitOutcomeV1::OutcomeUnknown {
                    pending: PublisherAdmissionOutcomeUnknownV1 {
                        inner: pending,
                        checkpoint,
                        chain_head,
                    },
                    cause,
                })
            }
        }
    }

    /// Commits one effect-bearing permit admission and its reservation.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] for stale authority or an
    /// invalid protected-capacity transaction.
    pub(crate) fn commit_capacity_reserved_branch(
        &mut self,
        prepared: PreparedPublisherCapacityAdmissionV1,
    ) -> Result<PublisherCapacityAdmissionCommitOutcomeV1, PublisherAdmissionJournalErrorV1> {
        let PreparedPublisherCapacityAdmissionV1 {
            inner,
            checkpoint,
            chain_head,
            binding,
        } = prepared;
        match self.inner.commit_capacity_reserved_admission(inner)? {
            DomainCapacityAdmissionCommitOutcomeV1::Applied {
                domain,
                reservation,
            } => Ok(PublisherCapacityAdmissionCommitOutcomeV1::Applied(
                applied_publisher(
                    domain,
                    checkpoint,
                    chain_head,
                    Some(PublisherCompletionCapacityV1 {
                        inner: reservation,
                        binding,
                    }),
                ),
            )),
            DomainCapacityAdmissionCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                Ok(PublisherCapacityAdmissionCommitOutcomeV1::OutcomeUnknown {
                    pending: PublisherCapacityAdmissionOutcomeUnknownV1 {
                        inner: pending,
                        checkpoint,
                        chain_head,
                        binding,
                    },
                    cause,
                })
            }
        }
    }

    /// Commits one terminal branch and releases its reservation atomically.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] for stale authority or an
    /// invalid protected-capacity transaction.
    pub(crate) fn commit_capacity_settlement(
        &mut self,
        prepared: PreparedPublisherCapacitySettlementV1,
    ) -> Result<PublisherCapacitySettlementCommitOutcomeV1, PublisherAdmissionJournalErrorV1> {
        let PreparedPublisherCapacitySettlementV1 {
            inner,
            checkpoint,
            chain_head,
        } = prepared;
        match self.inner.commit_capacity_settlement(inner)? {
            DomainCapacitySettlementCommitOutcomeV1::Applied(domain) => {
                Ok(PublisherCapacitySettlementCommitOutcomeV1::Applied(
                    applied_publisher(domain, checkpoint, chain_head, None),
                ))
            }
            DomainCapacitySettlementCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                Ok(PublisherCapacitySettlementCommitOutcomeV1::OutcomeUnknown {
                    pending: PublisherCapacitySettlementOutcomeUnknownV1 {
                        inner: pending,
                        checkpoint,
                        chain_head,
                    },
                    cause,
                })
            }
        }
    }

    /// Resolves one ambiguous publisher branch after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] when complete replay is
    /// malformed or poisoned.
    pub(crate) fn recover(
        &self,
        pending: PublisherAdmissionOutcomeUnknownV1,
    ) -> Result<PublisherAdmissionJournalRecoveryV1, PublisherAdmissionJournalErrorV1> {
        self.replay()?;
        let checkpoint = pending.checkpoint;
        let chain_head = pending.chain_head;
        match self.inner.recover(pending.inner)? {
            DomainRecoveryV1::Applied(inner) => Ok(PublisherAdmissionJournalRecoveryV1::Applied(
                applied_publisher(inner, checkpoint, chain_head, None),
            )),
            DomainRecoveryV1::Retry(inner) => Ok(PublisherAdmissionJournalRecoveryV1::Retry(
                PreparedPublisherAdmissionTransactionV1 {
                    inner,
                    checkpoint,
                    chain_head,
                },
            )),
            DomainRecoveryV1::Diverged(inner) => Ok(PublisherAdmissionJournalRecoveryV1::Diverged(
                PublisherAdmissionOutcomeUnknownV1 {
                    inner,
                    checkpoint,
                    chain_head,
                },
            )),
        }
    }

    /// Resolves one ambiguous capacity admission after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] when replay or reservation
    /// validation fails closed.
    pub(crate) fn recover_capacity_reserved_branch(
        &mut self,
        pending: PublisherCapacityAdmissionOutcomeUnknownV1,
    ) -> Result<PublisherCapacityAdmissionRecoveryV1, PublisherAdmissionJournalErrorV1> {
        self.replay()?;
        let PublisherCapacityAdmissionOutcomeUnknownV1 {
            inner,
            checkpoint,
            chain_head,
            binding,
        } = pending;
        match self.inner.recover_capacity_reserved_admission(inner)? {
            DomainCapacityAdmissionRecoveryV1::Applied {
                domain,
                reservation,
            } => Ok(PublisherCapacityAdmissionRecoveryV1::Applied(
                applied_publisher(
                    domain,
                    checkpoint,
                    chain_head,
                    Some(PublisherCompletionCapacityV1 {
                        inner: reservation,
                        binding,
                    }),
                ),
            )),
            DomainCapacityAdmissionRecoveryV1::Retry(inner) => Ok(
                PublisherCapacityAdmissionRecoveryV1::Retry(PreparedPublisherCapacityAdmissionV1 {
                    inner,
                    checkpoint,
                    chain_head,
                    binding,
                }),
            ),
            DomainCapacityAdmissionRecoveryV1::Diverged(inner) => {
                Ok(PublisherCapacityAdmissionRecoveryV1::Diverged(
                    PublisherCapacityAdmissionOutcomeUnknownV1 {
                        inner,
                        checkpoint,
                        chain_head,
                        binding,
                    },
                ))
            }
        }
    }

    /// Resolves one ambiguous terminal capacity settlement after reopen.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] when replay or reservation
    /// validation fails closed.
    pub(crate) fn recover_capacity_settlement(
        &mut self,
        pending: PublisherCapacitySettlementOutcomeUnknownV1,
    ) -> Result<PublisherCapacitySettlementRecoveryV1, PublisherAdmissionJournalErrorV1> {
        self.replay()?;
        let PublisherCapacitySettlementOutcomeUnknownV1 {
            inner,
            checkpoint,
            chain_head,
        } = pending;
        match self.inner.recover_capacity_settlement(inner)? {
            DomainCapacitySettlementRecoveryV1::Applied(domain) => {
                Ok(PublisherCapacitySettlementRecoveryV1::Applied(
                    applied_publisher(domain, checkpoint, chain_head, None),
                ))
            }
            DomainCapacitySettlementRecoveryV1::Retry(inner) => {
                Ok(PublisherCapacitySettlementRecoveryV1::Retry(
                    PreparedPublisherCapacitySettlementV1 {
                        inner,
                        checkpoint,
                        chain_head,
                    },
                ))
            }
            DomainCapacitySettlementRecoveryV1::Diverged(inner) => {
                Ok(PublisherCapacitySettlementRecoveryV1::Diverged(
                    PublisherCapacitySettlementOutcomeUnknownV1 {
                        inner,
                        checkpoint,
                        chain_head,
                    },
                ))
            }
        }
    }

    /// Reconstructs a complete durable branch without repeating an effect.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] when semantic replay or
    /// durable transaction grouping fails closed.
    pub(crate) fn recover_current_transaction(
        &mut self,
        transaction_id: [u8; 16],
    ) -> Result<PublisherAdmissionColdRecoveryV1, PublisherAdmissionJournalErrorV1> {
        let projection = self.replay()?;
        Ok(
            match self.inner.recover_current_postcommit(transaction_id)? {
                Some(ReplayedDomainPostcommitV1::Prepared(capability)) => {
                    let transaction = projection
                        .transactions()
                        .iter()
                        .find(|transaction| transaction.transaction_id() == transaction_id)
                        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
                    let effect = transaction
                        .records()
                        .iter()
                        .find(|record| {
                            record.key().kind()
                                == PublisherAdmissionJournalRecordKindV1::CompletionEffect
                        })
                        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
                    let effect = decode_effect_permit(publisher_body(effect)?)?;
                    let replay = reconstruct_semantic_projection(
                        &projection,
                        self.limits,
                        self.capacity,
                        self.maximum_source_releases,
                        self.maximum_root_records,
                    )?
                    .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
                    let current = current_permit_for_effect(&replay, &effect)?;
                    if replay.checkpoint.poisoned
                        || matches!(
                            current.state,
                            CompletionPermitStateV1::Spent
                                | CompletionPermitStateV1::RetiredWithoutEffect
                        )
                    {
                        return Ok(PublisherAdmissionColdRecoveryV1::StateOnly);
                    }
                    let effect_digest = effect_record_digest(&projection, transaction_id, &effect)?;
                    let permit_record_digest =
                        current_permit_record_digest(&projection, &effect, self.limits)?;
                    let current_digest = current_publication_digest(&projection)?;
                    let transaction_digest = capability.transaction_digest();
                    let request =
                        capacity_request_from_effect(transaction_digest, &effect, self.limits)?;
                    let reservation = self
                        .inner
                        .recover_domain_capacity_reservation_for_request(request, transaction_id)?;
                    PublisherAdmissionColdRecoveryV1::ObservePending(
                        PublisherAdmissionColdObservationV1 {
                            snapshot: self.inner.snapshot()?,
                            transaction_id,
                            transaction_digest,
                            effect_digest,
                            permit_record_digest,
                            current_digest,
                            binding: effect,
                            capacity: Some(PublisherCompletionCapacityV1 {
                                inner: reservation,
                                binding: CompletionCapacityBindingV1::from_effect(&effect),
                            }),
                        },
                    )
                }
                Some(ReplayedDomainPostcommitV1::Terminal(capability)) => {
                    PublisherAdmissionColdRecoveryV1::Terminal(
                        PublisherAdmissionPostcommitCapabilityV1 {
                            inner: capability,
                            capacity: None,
                        },
                    )
                }
                None => {
                    let effect = retained_completion_effect(&projection, transaction_id)?;
                    let Some(effect) = effect else {
                        return Ok(PublisherAdmissionColdRecoveryV1::StateOnly);
                    };
                    let replay = reconstruct_semantic_projection(
                        &projection,
                        self.limits,
                        self.capacity,
                        self.maximum_source_releases,
                        self.maximum_root_records,
                    )?
                    .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
                    let current = current_permit_for_effect(&replay, &effect)?;
                    if replay.checkpoint.poisoned
                        || matches!(
                            current.state,
                            CompletionPermitStateV1::Spent
                                | CompletionPermitStateV1::RetiredWithoutEffect
                        )
                    {
                        return Ok(PublisherAdmissionColdRecoveryV1::StateOnly);
                    }
                    let recovery_binding =
                        capacity_recovery_binding_from_effect(&effect, self.limits)?;
                    let reservation = self
                        .inner
                        .recover_unique_domain_capacity_reservation_by_binding(recovery_binding)?;
                    if reservation.admission_transaction_id() != effect.transaction {
                        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
                    }
                    let transaction_digest = reservation.owner_digest();
                    let effect_digest = effect_record_digest(&projection, transaction_id, &effect)?;
                    let permit_record_digest =
                        current_permit_record_digest(&projection, &effect, self.limits)?;
                    let current_digest = current_publication_digest(&projection)?;
                    PublisherAdmissionColdRecoveryV1::ObservePending(
                        PublisherAdmissionColdObservationV1 {
                            snapshot: self.inner.snapshot()?,
                            transaction_id,
                            transaction_digest,
                            effect_digest,
                            permit_record_digest,
                            current_digest,
                            binding: effect,
                            capacity: Some(PublisherCompletionCapacityV1 {
                                inner: reservation,
                                binding: CompletionCapacityBindingV1::from_effect(&effect),
                            }),
                        },
                    )
                }
            },
        )
    }

    /// Recovers the unique active completion capacity for one operation.
    ///
    /// This operation-keyed path is used by a distinct recovery request whose
    /// transaction identity cannot equal the earlier permit-issuance request.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] unless exactly one retained
    /// completion effect and protected reservation match the active permit.
    pub(crate) fn recover_current_operation(
        &mut self,
        operation: OperationId,
    ) -> Result<PublisherAdmissionColdRecoveryV1, PublisherAdmissionJournalErrorV1> {
        let projection = self.replay()?;
        let mut retained = None;
        for envelope in projection.records().iter().filter(|record| {
            record.key().kind() == PublisherAdmissionJournalRecordKindV1::CompletionEffect
        }) {
            let effect = decode_effect_permit(publisher_body(envelope)?)?;
            if effect.operation != *operation.as_bytes() {
                continue;
            }
            if retained.replace(effect).is_some() {
                return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
            }
        }
        let effect = retained.ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
        let replay = reconstruct_semantic_projection(
            &projection,
            self.limits,
            self.capacity,
            self.maximum_source_releases,
            self.maximum_root_records,
        )?
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
        let current = current_permit_for_effect(&replay, &effect)?;
        if replay.checkpoint.poisoned
            || matches!(
                current.state,
                CompletionPermitStateV1::Spent | CompletionPermitStateV1::RetiredWithoutEffect
            )
        {
            return Ok(PublisherAdmissionColdRecoveryV1::StateOnly);
        }
        let recovery_binding = capacity_recovery_binding_from_effect(&effect, self.limits)?;
        let reservation = self
            .inner
            .recover_unique_domain_capacity_reservation_by_binding(recovery_binding)?;
        if reservation.admission_transaction_id() != effect.transaction {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        let transaction_digest = reservation.owner_digest();
        let effect_digest = effect_record_digest(&projection, effect.transaction, &effect)?;
        let permit_record_digest = current_permit_record_digest(&projection, &effect, self.limits)?;
        let current_digest = current_publication_digest(&projection)?;
        Ok(PublisherAdmissionColdRecoveryV1::ObservePending(
            PublisherAdmissionColdObservationV1 {
                snapshot: self.inner.snapshot()?,
                transaction_id: effect.transaction,
                transaction_digest,
                effect_digest,
                permit_record_digest,
                current_digest,
                binding: effect,
                capacity: Some(PublisherCompletionCapacityV1 {
                    inner: reservation,
                    binding: CompletionCapacityBindingV1::from_effect(&effect),
                }),
            },
        ))
    }

    /// Plans an immutable replay join without granting compaction authority.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] for a sentinel checkpoint,
    /// stale projection, or failed preflight.
    pub(crate) fn plan_checkpoint(
        &self,
        transaction_id: [u8; 16],
        checkpoint: ObjectDigest,
    ) -> Result<PreparedPublisherAdmissionCheckpointV1, PublisherAdmissionJournalErrorV1> {
        self.replay()?;
        let envelope = self.inner.checkpoint_successor(
            publisher_admission_checkpoint_key_v1(checkpoint)?,
            1,
            None,
        )?;
        Ok(self.inner.plan(transaction_id, vec![envelope])?)
    }

    /// Commits a publisher replay join and performs exact readback.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] for stale authority or an
    /// invalid protected-journal operation.
    pub(crate) fn commit_checkpoint(
        &mut self,
        prepared: PreparedPublisherAdmissionCheckpointV1,
    ) -> Result<PublisherAdmissionCheckpointCommitOutcomeV1, PublisherAdmissionJournalErrorV1> {
        Ok(self.inner.commit(prepared)?)
    }

    /// Resolves an ambiguous publisher replay-join commit after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] when replay is malformed.
    pub(crate) fn recover_checkpoint(
        &self,
        pending: DomainOutcomeUnknownV1<PublisherAdmissionJournalSchemaV1>,
    ) -> Result<PublisherAdmissionCheckpointRecoveryV1, PublisherAdmissionJournalErrorV1> {
        self.replay()?;
        Ok(self.inner.recover(pending)?)
    }

    fn plan_mutations(
        &self,
        transaction_id: [u8; 16],
        mutations: &[LedgerMutation],
        checkpoint: AuthorityCheckpointV1,
        capacity: Option<&PublisherCompletionCapacityV1>,
    ) -> Result<PlannedPublisherBranchV1, PublisherAdmissionJournalErrorV1> {
        if mutations.is_empty() || mutations.len() > MAXIMUM_BATCH_RECORDS {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        let projection = self.replay()?;
        let active_capacity = projection_has_active_capacity(&projection, self.limits)?;
        let current = current_head(&projection)?;
        let decoded = decode_mutation_batch(mutations, self.limits)?;
        validate_batch_successor(current.as_ref(), &decoded, &checkpoint)?;

        let mut successors = Vec::with_capacity(decoded.len() + 2);
        for (mutation, record) in mutations.iter().zip(&decoded) {
            let key = ledger_entry_key(record.sequence, record.digest)?;
            if projection
                .records()
                .iter()
                .any(|retained| retained.key() == &key)
            {
                return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
            }
            successors.push(publisher_reducer_envelope(
                key,
                1,
                None,
                &encode_mutation(mutation)?,
                self.limits,
            )?);
        }

        let chain_head = decoded
            .last()
            .map(|record| record.digest)
            .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
        let issued = newly_outstanding_permit(&projection, &decoded, self.limits)?;
        if let Some(permit) = issued.as_ref() {
            successors.push(publisher_reducer_envelope(
                completion_effect_key(transaction_id)?,
                1,
                None,
                &encode_effect_permit(transaction_id, &permit, &checkpoint, chain_head),
                self.limits,
            )?);
        }
        let (revision, predecessor) = match current.as_ref() {
            Some(head) => (
                head.envelope_revision
                    .checked_add(1)
                    .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
                Some(head.envelope_digest),
            ),
            None => (1, None),
        };
        successors.push(publisher_reducer_envelope(
            current_key()?,
            revision,
            predecessor,
            &encode_current_head(&checkpoint, chain_head),
            self.limits,
        )?);
        let settlement = terminal_permit(&decoded)?;
        let poisoned = decoded
            .iter()
            .any(|record| record.kind == ProtectedRecordKindV1::Poison);
        if let Some(capacity) = capacity {
            let disposition = match (settlement.as_ref(), poisoned) {
                (Some(permit), false) => {
                    CapacitySettlementDispositionV1::from_permit_state(permit.state)?
                }
                (None, true) => CapacitySettlementDispositionV1::Poison,
                _ => return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch),
            };
            let lineage = CompletionSettlementLineageV1::from_capacity(capacity, disposition)?;
            successors.push(publisher_reducer_envelope(
                capacity_settlement_key(lineage.admission_transaction_id)?,
                1,
                None,
                &encode_capacity_settlement(&lineage),
                self.limits,
            )?);
        }
        let inner = self.inner.plan(transaction_id, successors)?;
        Ok(PlannedPublisherBranchV1 {
            prepared: PreparedPublisherAdmissionTransactionV1 {
                inner,
                checkpoint,
                chain_head,
            },
            issued,
            settlement,
            poisoned,
            active_capacity,
        })
    }
}

impl PublisherAdmissionPostcommitCapabilityV1 {
    /// Consumes this capability against the exact issuing publisher journal.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] when the journal or any
    /// durable branch member changed after readback.
    pub(crate) fn consume<'current>(
        self,
        authority: &'current PublisherAdmissionProtectedJournalV1<'_>,
    ) -> Result<ValidatedPublisherAdmissionPostcommitV1<'current>, PublisherAdmissionJournalErrorV1>
    {
        let inner = self.inner.consume(&authority.inner)?;
        Ok(ValidatedPublisherAdmissionPostcommitV1 {
            inner,
            capacity: self.capacity,
        })
    }
}

impl ValidatedPublisherAdmissionPostcommitV1<'_> {
    /// Returns the exact durable transaction commitment.
    #[must_use]
    pub(crate) const fn transaction_digest(&self) -> ObjectDigest {
        self.inner.transaction_digest()
    }

    /// Takes capacity for the exact effect-bearing permit after revalidation.
    #[must_use]
    pub(crate) fn take_completion_capacity(&mut self) -> Option<PublisherCompletionCapacityV1> {
        self.capacity.take()
    }
}

impl PublisherAdmissionColdObservationV1 {
    /// Consumes cold observation authority after exact snapshot revalidation.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAdmissionJournalErrorV1`] if the shared journal,
    /// effect, latest permit state, publication head, or reservation changed.
    pub(crate) fn consume<'current>(
        self,
        authority: &'current PublisherAdmissionProtectedJournalV1<'_>,
    ) -> Result<
        ValidatedPublisherAdmissionColdObservationV1<'current>,
        PublisherAdmissionJournalErrorV1,
    > {
        authority.inner.revalidate_snapshot(&self.snapshot)?;
        let projection = authority.replay()?;
        if effect_record_digest(&projection, self.transaction_id, &self.binding)?
            != self.effect_digest
            || current_permit_record_digest(&projection, &self.binding, authority.limits)?
                != self.permit_record_digest
            || current_publication_digest(&projection)? != self.current_digest
        {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        authority.inner.revalidate_snapshot(&self.snapshot)?;
        Ok(ValidatedPublisherAdmissionColdObservationV1 {
            transaction_digest: self.transaction_digest,
            capacity: self.capacity,
            current: PhantomData,
        })
    }
}

impl ValidatedPublisherAdmissionColdObservationV1<'_> {
    /// Returns the original permit-admission transaction commitment.
    #[must_use]
    pub(crate) const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction_digest
    }

    /// Takes exact terminal capacity after the observation decision.
    #[must_use]
    pub(crate) fn take_completion_capacity(&mut self) -> Option<PublisherCompletionCapacityV1> {
        self.capacity.take()
    }
}

#[derive(Clone, Copy)]
struct CurrentPublisherHeadV1 {
    sequence: u64,
    chain_head: ObjectDigest,
    envelope_revision: u64,
    envelope_digest: ObjectDigest,
}

struct PlannedPublisherBranchV1 {
    prepared: PreparedPublisherAdmissionTransactionV1,
    issued: Option<CompletionPermitV1>,
    settlement: Option<CompletionPermitV1>,
    poisoned: bool,
    active_capacity: bool,
}

#[derive(Clone, Copy)]
struct CompletionCapacityBindingV1 {
    admission_transaction_id: [u8; 16],
    permit: [u8; 16],
    operation: [u8; 16],
    artifact: ObjectDigest,
    permit_digest: ObjectDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum CapacitySettlementDispositionV1 {
    Spent = 1,
    RetiredWithoutEffect = 2,
    Poison = 3,
}

impl CapacitySettlementDispositionV1 {
    fn from_permit_state(
        state: CompletionPermitStateV1,
    ) -> Result<Self, PublisherAdmissionJournalErrorV1> {
        match state {
            CompletionPermitStateV1::Spent => Ok(Self::Spent),
            CompletionPermitStateV1::RetiredWithoutEffect => Ok(Self::RetiredWithoutEffect),
            _ => Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch),
        }
    }

    fn from_byte(value: u8) -> Result<Self, PublisherAdmissionJournalErrorV1> {
        match value {
            1 => Ok(Self::Spent),
            2 => Ok(Self::RetiredWithoutEffect),
            3 => Ok(Self::Poison),
            _ => Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch),
        }
    }
}

#[derive(Clone, Copy)]
struct CompletionSettlementLineageV1 {
    disposition: CapacitySettlementDispositionV1,
    admission_transaction_id: [u8; 16],
    owner_id: [u8; 32],
    owner_digest: ObjectDigest,
    reservation_id: [u8; 32],
    permit: [u8; 16],
    operation: [u8; 16],
    artifact: ObjectDigest,
    permit_digest: ObjectDigest,
    checkpoint: ObjectDigest,
    chain_head: ObjectDigest,
    terminal_records: u32,
    terminal_bytes: u64,
    poison_records: u32,
    poison_bytes: u64,
}

impl CompletionSettlementLineageV1 {
    fn from_capacity(
        capacity: &PublisherCompletionCapacityV1,
        disposition: CapacitySettlementDispositionV1,
    ) -> Result<Self, PublisherAdmissionJournalErrorV1> {
        let (request, admission_transaction_id) = capacity.inner.authenticated_binding();
        if !capacity
            .binding
            .matches_reservation(&request, admission_transaction_id)
        {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        Ok(Self {
            disposition,
            admission_transaction_id,
            owner_id: request.owner_id,
            owner_digest: ObjectDigest::from_bytes(request.owner_digest),
            reservation_id: capacity.inner.reservation_id(),
            permit: capacity.binding.permit,
            operation: capacity.binding.operation,
            artifact: capacity.binding.artifact,
            permit_digest: capacity.binding.permit_digest,
            checkpoint: ObjectDigest::from_bytes(request.checkpoint_digest),
            chain_head: ObjectDigest::from_bytes(request.chain_head_digest),
            terminal_records: request.terminal_records,
            terminal_bytes: request.terminal_bytes,
            poison_records: request.poison_records,
            poison_bytes: request.poison_bytes,
        })
    }

    fn matches_request(
        &self,
        request: &GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> bool {
        self.admission_transaction_id == admission_transaction_id && self.request() == *request
    }

    fn request(&self) -> GlobalCapacityReservationRequestV1 {
        GlobalCapacityReservationRequestV1 {
            purpose: GlobalCapacityReservationPurposeV1::PublisherCompletion,
            owner_namespace: RecordNamespace::PublisherAuthority,
            owner_id: self.owner_id,
            owner_digest: *self.owner_digest.as_bytes(),
            operation_id: self.operation,
            artifact_digest: *self.artifact.as_bytes(),
            checkpoint_digest: *self.checkpoint.as_bytes(),
            chain_head_digest: *self.chain_head.as_bytes(),
            terminal_records: self.terminal_records,
            terminal_bytes: self.terminal_bytes,
            poison_records: self.poison_records,
            poison_bytes: self.poison_bytes,
        }
    }
}

impl CompletionCapacityBindingV1 {
    fn from_permit(admission_transaction_id: [u8; 16], permit: &CompletionPermitV1) -> Self {
        Self {
            admission_transaction_id,
            permit: *permit.permit.as_bytes(),
            operation: *permit.operation.as_bytes(),
            artifact: permit.artifact_digest,
            permit_digest: permit.permit_digest,
        }
    }

    fn from_effect(effect: &CompletionEffectBindingV1) -> Self {
        Self {
            admission_transaction_id: effect.transaction,
            permit: effect.permit,
            operation: effect.operation,
            artifact: effect.artifact,
            permit_digest: effect.permit_digest,
        }
    }

    fn matches_terminal(&self, permit: &CompletionPermitV1) -> bool {
        self.admission_transaction_id != [0; 16]
            && self.permit == *permit.permit.as_bytes()
            && self.operation == *permit.operation.as_bytes()
            && self.artifact == permit.artifact_digest
            && self.permit_digest == permit.permit_digest
            && matches!(
                permit.state,
                CompletionPermitStateV1::Spent | CompletionPermitStateV1::RetiredWithoutEffect
            )
    }

    fn matches_reservation(
        &self,
        request: &GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> bool {
        self.admission_transaction_id == admission_transaction_id
            && request.purpose == GlobalCapacityReservationPurposeV1::PublisherCompletion
            && request.owner_namespace == RecordNamespace::PublisherAuthority
            && self.operation == request.operation_id
            && self.artifact.as_bytes() == &request.artifact_digest
    }
}

fn applied_publisher(
    inner: AppliedDomainTransactionV1<PublisherAdmissionJournalSchemaV1>,
    checkpoint: AuthorityCheckpointV1,
    chain_head: ObjectDigest,
    capacity: Option<PublisherCompletionCapacityV1>,
) -> AppliedPublisherAdmissionTransactionV1 {
    AppliedPublisherAdmissionTransactionV1 {
        inner,
        acknowledgement: Some(ProtectedStoreCommitToken::from_durable_adapter(
            checkpoint, chain_head,
        )),
        capacity,
    }
}

fn validate_projection(
    projection: &PublisherAdmissionJournalProjectionV1,
    limits: AdmissionLimits,
) -> Result<(), PublisherAdmissionJournalErrorV1> {
    let mut entries = Vec::new();
    let mut entry_digests = BTreeSet::new();
    let mut effect_heads = Vec::new();
    let mut current_count = 0_usize;
    for envelope in projection.records() {
        match envelope.key().kind() {
            PublisherAdmissionJournalRecordKindV1::LedgerEntry => {
                let mutation = decode_mutation(publisher_body(envelope)?, limits)?;
                let decoded = decode_protected_record_v1(&mutation.value, limits)?;
                let expected_key = ledger_entry_key(decoded.sequence, decoded.digest)?;
                if envelope.revision() != 1
                    || envelope.predecessor().is_some()
                    || &expected_key != envelope.key()
                {
                    return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
                }
                entry_digests.insert(decoded.digest);
                entries.push(decoded);
            }
            PublisherAdmissionJournalRecordKindV1::Current => {
                if envelope.key().identity() != b"authority"
                    || publisher_body(envelope)?.len() != 127
                {
                    return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
                }
                current_count = current_count
                    .checked_add(1)
                    .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
            }
            PublisherAdmissionJournalRecordKindV1::CompletionEffect => {
                if envelope.key().identity().len() != 16
                    || envelope.key().identity().iter().all(|byte| *byte == 0)
                    || envelope.revision() != 1
                    || envelope.predecessor().is_some()
                {
                    return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
                }
                effect_heads.push(decode_effect_permit(publisher_body(envelope)?)?.chain_head);
            }
            PublisherAdmissionJournalRecordKindV1::CapacitySettlement => {
                let lineage = decode_capacity_settlement(publisher_body(envelope)?)?;
                if envelope.key().identity() != lineage.admission_transaction_id
                    || envelope.revision() != 1
                    || envelope.predecessor().is_some()
                {
                    return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
                }
            }
            PublisherAdmissionJournalRecordKindV1::Checkpoint => {
                if envelope.key().identity().len() != 32
                    || envelope.key().identity().iter().all(|byte| *byte == 0)
                    || envelope.revision() != 1
                    || envelope.predecessor().is_some()
                {
                    return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
                }
            }
        }
    }
    entries.sort_by_key(|record| record.sequence);
    if entries
        .first()
        .is_some_and(|first| first.sequence != 1 || first.predecessor.is_some())
        || entries.windows(2).any(|pair| {
            pair[0].sequence.checked_add(1) != Some(pair[1].sequence)
                || pair[1].predecessor != Some(pair[0].digest)
        })
        || current_count > 1
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    if let Some(head) = current_head(projection)? {
        let last = entries
            .last()
            .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
        if head.sequence != last.sequence || head.chain_head != last.digest {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
    } else if !entries.is_empty() {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    if effect_heads
        .iter()
        .any(|effect_head| !entry_digests.contains(effect_head))
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    for transaction in projection.transactions() {
        validate_publisher_transaction(
            transaction.transaction_id(),
            transaction.records(),
            limits,
        )?;
    }
    Ok(())
}

fn validate_publisher_transaction(
    transaction_id: [u8; 16],
    records: &[PublisherAdmissionJournalEnvelopeV1],
    limits: AdmissionLimits,
) -> Result<(), PublisherAdmissionJournalErrorV1> {
    use PublisherAdmissionJournalRecordKindV1 as Kind;
    if records.len() == 1 && records[0].key().kind() == Kind::Checkpoint {
        return Ok(());
    }
    let current = records
        .iter()
        .filter(|record| record.key().kind() == Kind::Current)
        .collect::<Vec<_>>();
    let effects = records
        .iter()
        .filter(|record| record.key().kind() == Kind::CompletionEffect)
        .collect::<Vec<_>>();
    let settlements = records
        .iter()
        .filter(|record| record.key().kind() == Kind::CapacitySettlement)
        .collect::<Vec<_>>();
    let entries = records
        .iter()
        .filter(|record| record.key().kind() == Kind::LedgerEntry)
        .collect::<Vec<_>>();
    if current.len() > 1 || effects.len() > 1 || settlements.len() > 1 || entries.is_empty() {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let mut outstanding = Vec::new();
    for entry in &entries {
        let mutation = decode_mutation(publisher_body(entry)?, limits)?;
        let decoded = decode_protected_record_v1(&mutation.value, limits)?;
        if decoded.kind == ProtectedRecordKindV1::CompletionPermit {
            let permit = super::payload_decode::decode_permit(&decoded.payload)?;
            if permit.state == CompletionPermitStateV1::Outstanding {
                outstanding.push(permit);
            }
        }
    }
    let last = entries
        .iter()
        .map(|entry| {
            decode_mutation(publisher_body(entry)?, limits)
                .and_then(|mutation| Ok(decode_protected_record_v1(&mutation.value, limits)?))
        })
        .collect::<Result<Vec<_>, PublisherAdmissionJournalErrorV1>>()?
        .into_iter()
        .max_by_key(|record| record.sequence)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let derived_current;
    let current_body = if let Some(current) = current.first() {
        publisher_body(current)?
    } else {
        if last.kind != ProtectedRecordKindV1::AuthorityCheckpoint {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        let checkpoint = super::payload_decode::decode_checkpoint(&last.payload)?;
        derived_current = encode_current_head(&checkpoint, last.digest);
        &derived_current
    };
    let (current_sequence, current_head) = decode_current_head(current_body)?;
    if current_sequence != last.sequence || current_head != last.digest {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    match (effects.as_slice(), settlements.as_slice()) {
        ([], []) => Ok(()),
        ([effect], []) if outstanding.len() == 1 => {
            let binding = decode_effect_permit(publisher_body(effect)?)?;
            let permit = &outstanding[0];
            if binding.transaction != transaction_id
                || permit.permit.as_bytes() != &binding.permit
                || permit.operation.as_bytes() != &binding.operation
                || permit.artifact_digest != binding.artifact
                || permit.permit_digest != binding.permit_digest
                || binding.checkpoint_sequence != current_sequence
                || current_body[58..90] != *binding.checkpoint_state.as_bytes()
                || super::model::digest_parts(CHECKPOINT_COMMITMENT_DOMAIN, &[current_body])
                    != binding.checkpoint_commitment
                || binding.chain_head != last.digest
            {
                return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
            }
            Ok(())
        }
        ([], [settlement]) => {
            let lineage = decode_capacity_settlement(publisher_body(settlement)?)?;
            validate_settlement_lineage_against_records(&lineage, &entries, limits)
        }
        _ => Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch),
    }
}

fn validate_settlement_lineage_against_records(
    lineage: &CompletionSettlementLineageV1,
    entries: &[&PublisherAdmissionJournalEnvelopeV1],
    limits: AdmissionLimits,
) -> Result<(), PublisherAdmissionJournalErrorV1> {
    let mut decoded = Vec::with_capacity(entries.len());
    for entry in entries {
        let mutation = decode_mutation(publisher_body(entry)?, limits)?;
        decoded.push(decode_protected_record_v1(&mutation.value, limits)?);
    }
    validate_settlement_lineage_against_decoded(lineage, &decoded)
}

fn validate_settlement_lineage_against_decoded(
    lineage: &CompletionSettlementLineageV1,
    entries: &[super::DecodedProtectedRecordV1],
) -> Result<(), PublisherAdmissionJournalErrorV1> {
    let count = |kind| entries.iter().filter(|record| record.kind == kind).count();
    let poisoned = count(ProtectedRecordKindV1::Poison) == 1;
    let kinds = entries.iter().map(|record| record.kind).collect::<Vec<_>>();
    let expected_shape = match lineage.disposition {
        CapacitySettlementDispositionV1::Poison => {
            poisoned
                && kinds
                    == [
                        ProtectedRecordKindV1::Poison,
                        ProtectedRecordKindV1::AuthorityCheckpoint,
                    ]
        }
        CapacitySettlementDispositionV1::Spent => {
            !poisoned
                && (kinds
                    == [
                        ProtectedRecordKindV1::CompletionPermit,
                        ProtectedRecordKindV1::Accounting,
                        ProtectedRecordKindV1::CompletionReceipt,
                        ProtectedRecordKindV1::AuthorityCheckpoint,
                    ]
                    || kinds
                        == [
                            ProtectedRecordKindV1::RecoveryObservation,
                            ProtectedRecordKindV1::CompletionPermit,
                            ProtectedRecordKindV1::Accounting,
                            ProtectedRecordKindV1::CompletionReceipt,
                            ProtectedRecordKindV1::AuthorityCheckpoint,
                        ])
        }
        CapacitySettlementDispositionV1::RetiredWithoutEffect => {
            !poisoned
                && kinds
                    == [
                        ProtectedRecordKindV1::RecoveryObservation,
                        ProtectedRecordKindV1::CompletionPermit,
                        ProtectedRecordKindV1::Accounting,
                        ProtectedRecordKindV1::AuthorityCheckpoint,
                    ]
        }
    };
    if !expected_shape {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let terminal = entries
        .iter()
        .find(|record| record.kind == ProtectedRecordKindV1::CompletionPermit)
        .map(|record| super::payload_decode::decode_permit(&record.payload))
        .transpose()?;
    let recovery = entries
        .iter()
        .find(|record| record.kind == ProtectedRecordKindV1::RecoveryObservation)
        .map(|record| super::payload_decode::decode_recovery_observation(&record.payload))
        .transpose()?;
    let receipt = entries
        .iter()
        .find(|record| record.kind == ProtectedRecordKindV1::CompletionReceipt)
        .map(|record| super::payload_decode::decode_receipt(&record.payload))
        .transpose()?;
    match (lineage.disposition, terminal, poisoned, recovery, receipt) {
        (CapacitySettlementDispositionV1::Poison, None, true, None, None) => Ok(()),
        (CapacitySettlementDispositionV1::Spent, Some(permit), false, recovery, Some(receipt))
            if permit.state == CompletionPermitStateV1::Spent
                && permit.permit.as_bytes() == &lineage.permit
                && permit.operation.as_bytes() == &lineage.operation
                && permit.artifact_digest == lineage.artifact
                && permit.permit_digest == lineage.permit_digest
                && receipt.permit == permit.permit
                && receipt.operation == permit.operation
                && receipt.artifact_digest == permit.artifact_digest
                && recovery.as_ref().is_none_or(|observation| {
                    observation.outcome == super::RecoveryObservationKindCodeV1::Committed
                        && observation.operation == permit.operation
                        && observation.artifact_digest == Some(permit.artifact_digest)
                        && observation.catalog_entry_digest == Some(receipt.catalog_entry_digest)
                }) =>
        {
            Ok(())
        }
        (
            CapacitySettlementDispositionV1::RetiredWithoutEffect,
            Some(permit),
            false,
            Some(recovery),
            None,
        ) if permit.state == CompletionPermitStateV1::RetiredWithoutEffect
            && permit.permit.as_bytes() == &lineage.permit
            && permit.operation.as_bytes() == &lineage.operation
            && permit.artifact_digest == lineage.artifact
            && permit.permit_digest == lineage.permit_digest
            && recovery.outcome == super::RecoveryObservationKindCodeV1::AbsentAfterFence
            && recovery.operation == permit.operation
            && recovery.artifact_digest == Some(permit.artifact_digest) =>
        {
            Ok(())
        }
        _ => Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch),
    }
}

fn validate_capacity_settlement_members(
    request: &GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    members: &[ProtectedCapacitySettlementMemberV1<'_, PublisherAdmissionJournalRecordKindV1>],
) -> Result<(), PublisherAdmissionJournalErrorV1> {
    if request.purpose != GlobalCapacityReservationPurposeV1::PublisherCompletion
        || request.owner_namespace != RecordNamespace::PublisherAuthority
        || admission_transaction_id == [0; 16]
        || members.is_empty()
        || members
            .iter()
            .any(|member| member.kind == PublisherAdmissionJournalRecordKindV1::CompletionEffect)
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let mut current = None;
    let mut settlement = None;
    let mut entries = Vec::new();
    let codec_limits = maximum_admission_limits();
    for member in members {
        match member.kind {
            PublisherAdmissionJournalRecordKindV1::LedgerEntry => {
                let mutation = decode_mutation(member.body, codec_limits)?;
                entries.push(decode_protected_record_v1(&mutation.value, codec_limits)?);
            }
            PublisherAdmissionJournalRecordKindV1::Current => {
                if member.identity != b"authority" || current.replace(member.body).is_some() {
                    return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
                }
            }
            PublisherAdmissionJournalRecordKindV1::CapacitySettlement => {
                let decoded = decode_capacity_settlement(member.body)?;
                if member.identity != decoded.admission_transaction_id
                    || settlement.replace(decoded).is_some()
                {
                    return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
                }
            }
            PublisherAdmissionJournalRecordKindV1::Checkpoint
            | PublisherAdmissionJournalRecordKindV1::CompletionEffect => {
                return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
            }
        }
    }
    let current = current.ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let settlement = settlement.ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    if !settlement.matches_request(request, admission_transaction_id) {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let last = entries
        .iter()
        .max_by_key(|record| record.sequence)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let (current_sequence, current_head) = decode_current_head(current)?;
    if current_sequence != last.sequence || current_head != last.digest {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    validate_settlement_lineage_against_decoded(&settlement, &entries)
}

fn validate_semantic_projection(
    projection: &PublisherAdmissionJournalProjectionV1,
    limits: AdmissionLimits,
    capacity: CapacityPolicyV1,
    maximum_source_releases: usize,
    maximum_root_records: usize,
) -> Result<(), PublisherAdmissionJournalErrorV1> {
    validate_retained_settlement_effects(projection)?;
    let replay = reconstruct_semantic_projection(
        projection,
        limits,
        capacity,
        maximum_source_releases,
        maximum_root_records,
    )?;
    if let Some(replay) = replay {
        for effect in projection.records().iter().filter(|record| {
            record.key().kind() == PublisherAdmissionJournalRecordKindV1::CompletionEffect
        }) {
            let binding = decode_effect_permit(publisher_body(effect)?)?;
            let permit = replay
                .records
                .iter()
                .find_map(|record| match &record.payload {
                    DecodedPublisherPayloadV1::Permit(permit)
                        if permit.permit.as_bytes() == &binding.permit =>
                    {
                        Some(permit)
                    }
                    _ => None,
                });
            let Some(permit) = permit else {
                return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
            };
            if permit.operation.as_bytes() != &binding.operation
                || permit.artifact_digest != binding.artifact
                || permit.permit_digest != binding.permit_digest
            {
                return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
            }
            let issuance_checkpoint = replay
                .records
                .iter()
                .find_map(|record| {
                    (record.envelope.digest == binding.chain_head).then_some(&record.payload)
                })
                .and_then(|payload| match payload {
                    DecodedPublisherPayloadV1::Checkpoint(checkpoint) => Some(checkpoint),
                    _ => None,
                })
                .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
            if issuance_checkpoint.sequence != binding.checkpoint_sequence
                || issuance_checkpoint.state_digest != binding.checkpoint_state
                || checkpoint_commitment(issuance_checkpoint, binding.chain_head)
                    != binding.checkpoint_commitment
            {
                return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
            }
        }
    }
    Ok(())
}

fn validate_retained_settlement_effects(
    projection: &PublisherAdmissionJournalProjectionV1,
) -> Result<(), PublisherAdmissionJournalErrorV1> {
    for envelope in projection.records().iter().filter(|record| {
        record.key().kind() == PublisherAdmissionJournalRecordKindV1::CapacitySettlement
    }) {
        let settlement = decode_capacity_settlement(publisher_body(envelope)?)?;
        let effect = retained_completion_effect(projection, settlement.admission_transaction_id)?
            .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
        if effect.permit != settlement.permit
            || effect.operation != settlement.operation
            || effect.artifact != settlement.artifact
            || effect.permit_digest != settlement.permit_digest
            || effect.checkpoint_commitment != settlement.checkpoint
            || effect.chain_head != settlement.chain_head
        {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
    }
    Ok(())
}

fn newly_outstanding_permit(
    projection: &PublisherAdmissionJournalProjectionV1,
    records: &[super::DecodedProtectedRecordV1],
    limits: AdmissionLimits,
) -> Result<Option<CompletionPermitV1>, PublisherAdmissionJournalErrorV1> {
    let mut issued = None;
    for record in records
        .iter()
        .filter(|record| record.kind == ProtectedRecordKindV1::CompletionPermit)
    {
        let permit = super::payload_decode::decode_permit(&record.payload)?;
        if permit.state != CompletionPermitStateV1::Outstanding {
            continue;
        }
        if issued.replace(permit).is_some() {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
    }
    let Some(permit) = issued else {
        return Ok(None);
    };
    for envelope in projection
        .records()
        .iter()
        .filter(|record| record.key().kind() == PublisherAdmissionJournalRecordKindV1::LedgerEntry)
    {
        let mutation = decode_mutation(publisher_body(envelope)?, limits)?;
        let record = decode_protected_record_v1(&mutation.value, limits)?;
        if record.kind == ProtectedRecordKindV1::CompletionPermit
            && super::payload_decode::decode_permit(&record.payload)?.permit == permit.permit
        {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
    }
    Ok(Some(permit))
}

fn projection_has_active_capacity(
    projection: &PublisherAdmissionJournalProjectionV1,
    limits: AdmissionLimits,
) -> Result<bool, PublisherAdmissionJournalErrorV1> {
    for effect in projection.records().iter().filter(|record| {
        record.key().kind() == PublisherAdmissionJournalRecordKindV1::CompletionEffect
    }) {
        let binding = decode_effect_permit(publisher_body(effect)?)?;
        let mut current = None;
        for entry in projection.records().iter().filter(|record| {
            record.key().kind() == PublisherAdmissionJournalRecordKindV1::LedgerEntry
        }) {
            let mutation = decode_mutation(publisher_body(entry)?, limits)?;
            let record = decode_protected_record_v1(&mutation.value, limits)?;
            if record.kind != ProtectedRecordKindV1::CompletionPermit {
                continue;
            }
            let permit = super::payload_decode::decode_permit(&record.payload)?;
            if permit.permit.as_bytes() == &binding.permit
                && current
                    .as_ref()
                    .is_none_or(|(sequence, _): &(u64, CompletionPermitV1)| {
                        *sequence < record.sequence
                    })
            {
                current = Some((record.sequence, permit));
            }
        }
        if current.is_some_and(|(_, permit)| {
            matches!(
                permit.state,
                CompletionPermitStateV1::Outstanding
                    | CompletionPermitStateV1::RevocationPending
                    | CompletionPermitStateV1::Uncertain
            )
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn retained_completion_effect(
    projection: &PublisherAdmissionJournalProjectionV1,
    transaction_id: [u8; 16],
) -> Result<Option<CompletionEffectBindingV1>, PublisherAdmissionJournalErrorV1> {
    let mut retained = None;
    for envelope in projection.records().iter().filter(|record| {
        record.key().kind() == PublisherAdmissionJournalRecordKindV1::CompletionEffect
    }) {
        let effect = decode_effect_permit(publisher_body(envelope)?)?;
        if effect.transaction != transaction_id {
            continue;
        }
        if retained.replace(effect).is_some() {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
    }
    Ok(retained)
}

fn current_permit_for_effect<'replay>(
    replay: &'replay ProtectedLedgerReplayV1,
    effect: &CompletionEffectBindingV1,
) -> Result<&'replay CompletionPermitV1, PublisherAdmissionJournalErrorV1> {
    let permit = replay
        .records
        .iter()
        .rev()
        .find_map(|record| match &record.payload {
            DecodedPublisherPayloadV1::Permit(permit)
                if permit.permit.as_bytes() == &effect.permit =>
            {
                Some(permit)
            }
            _ => None,
        })
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    if permit.operation.as_bytes() != &effect.operation
        || permit.artifact_digest != effect.artifact
        || permit.permit_digest != effect.permit_digest
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(permit)
}

fn effect_record_digest(
    projection: &PublisherAdmissionJournalProjectionV1,
    transaction_id: [u8; 16],
    binding: &CompletionEffectBindingV1,
) -> Result<ObjectDigest, PublisherAdmissionJournalErrorV1> {
    let mut retained = None;
    for effect in projection.records().iter().filter(|record| {
        record.key().kind() == PublisherAdmissionJournalRecordKindV1::CompletionEffect
    }) {
        let decoded = decode_effect_permit(publisher_body(effect)?)?;
        if decoded.transaction != transaction_id
            || encode_effect_binding(&decoded) != encode_effect_binding(binding)
        {
            continue;
        }
        if retained.replace(effect.digest()).is_some() {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
    }
    retained.ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)
}

fn current_permit_record_digest(
    projection: &PublisherAdmissionJournalProjectionV1,
    binding: &CompletionEffectBindingV1,
    limits: AdmissionLimits,
) -> Result<ObjectDigest, PublisherAdmissionJournalErrorV1> {
    let mut retained = None;
    for envelope in projection
        .records()
        .iter()
        .filter(|record| record.key().kind() == PublisherAdmissionJournalRecordKindV1::LedgerEntry)
    {
        let mutation = decode_mutation(publisher_body(envelope)?, limits)?;
        let record = decode_protected_record_v1(&mutation.value, limits)?;
        if record.kind != ProtectedRecordKindV1::CompletionPermit {
            continue;
        }
        let permit = super::payload_decode::decode_permit(&record.payload)?;
        if permit.permit.as_bytes() != &binding.permit {
            continue;
        }
        if permit.operation.as_bytes() != &binding.operation
            || permit.artifact_digest != binding.artifact
            || permit.permit_digest != binding.permit_digest
        {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        if retained
            .as_ref()
            .is_none_or(|(sequence, _): &(u64, ObjectDigest)| *sequence < record.sequence)
        {
            retained = Some((record.sequence, envelope.digest()));
        }
    }
    retained
        .map(|(_, digest)| digest)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)
}

fn current_publication_digest(
    projection: &PublisherAdmissionJournalProjectionV1,
) -> Result<ObjectDigest, PublisherAdmissionJournalErrorV1> {
    let current = projection
        .records()
        .iter()
        .find(|record| record.key().kind() == PublisherAdmissionJournalRecordKindV1::Current)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    Ok(current.digest())
}

fn terminal_permit(
    records: &[super::DecodedProtectedRecordV1],
) -> Result<Option<CompletionPermitV1>, PublisherAdmissionJournalErrorV1> {
    let mut terminal = None;
    for record in records
        .iter()
        .filter(|record| record.kind == ProtectedRecordKindV1::CompletionPermit)
    {
        let permit = super::payload_decode::decode_permit(&record.payload)?;
        if !matches!(
            permit.state,
            CompletionPermitStateV1::Spent | CompletionPermitStateV1::RetiredWithoutEffect
        ) {
            continue;
        }
        if terminal.replace(permit).is_some() {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
    }
    Ok(terminal)
}

fn completion_capacity_request(
    prepared: &PreparedDomainTransactionV1<PublisherAdmissionJournalSchemaV1>,
    permit: &CompletionPermitV1,
    checkpoint: &AuthorityCheckpointV1,
    chain_head: ObjectDigest,
    limits: AdmissionLimits,
) -> Result<GlobalCapacityReservationRequestV1, PublisherAdmissionJournalErrorV1> {
    let (terminal_bytes, poison_bytes) = completion_capacity_budgets(limits)?;
    Ok(bind_domain_capacity_request_v1::<
        PublisherAdmissionJournalSchemaV1,
    >(GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::PublisherCompletion,
        owner_namespace: RecordNamespace::PublisherAuthority,
        owner_id: [0; 32],
        owner_digest: *prepared.transaction_digest().as_bytes(),
        operation_id: *permit.operation.as_bytes(),
        artifact_digest: *permit.artifact_digest.as_bytes(),
        checkpoint_digest: *checkpoint_commitment(checkpoint, chain_head).as_bytes(),
        chain_head_digest: *chain_head.as_bytes(),
        terminal_records: COMPLETION_TERMINAL_RECORDS,
        terminal_bytes,
        poison_records: COMPLETION_POISON_RECORDS,
        poison_bytes,
    }))
}

fn capacity_request_from_effect(
    transaction_digest: ObjectDigest,
    effect: &CompletionEffectBindingV1,
    limits: AdmissionLimits,
) -> Result<GlobalCapacityReservationRequestV1, PublisherAdmissionJournalErrorV1> {
    let (terminal_bytes, poison_bytes) = completion_capacity_budgets(limits)?;
    Ok(bind_domain_capacity_request_v1::<
        PublisherAdmissionJournalSchemaV1,
    >(GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::PublisherCompletion,
        owner_namespace: RecordNamespace::PublisherAuthority,
        owner_id: [0; 32],
        owner_digest: *transaction_digest.as_bytes(),
        operation_id: effect.operation,
        artifact_digest: *effect.artifact.as_bytes(),
        checkpoint_digest: *effect.checkpoint_commitment.as_bytes(),
        chain_head_digest: *effect.chain_head.as_bytes(),
        terminal_records: COMPLETION_TERMINAL_RECORDS,
        terminal_bytes,
        poison_records: COMPLETION_POISON_RECORDS,
        poison_bytes,
    }))
}

fn capacity_recovery_binding_from_effect(
    effect: &CompletionEffectBindingV1,
    limits: AdmissionLimits,
) -> Result<GlobalCapacityReservationRecoveryBindingV1, PublisherAdmissionJournalErrorV1> {
    let (terminal_bytes, poison_bytes) = completion_capacity_budgets(limits)?;
    Ok(GlobalCapacityReservationRecoveryBindingV1 {
        purpose: GlobalCapacityReservationPurposeV1::PublisherCompletion,
        operation_id: effect.operation,
        artifact_digest: *effect.artifact.as_bytes(),
        checkpoint_digest: *effect.checkpoint_commitment.as_bytes(),
        chain_head_digest: *effect.chain_head.as_bytes(),
        terminal_records: COMPLETION_TERMINAL_RECORDS,
        terminal_bytes,
        poison_records: COMPLETION_POISON_RECORDS,
        poison_bytes,
    })
}

fn completion_capacity_budgets(
    limits: AdmissionLimits,
) -> Result<(u64, u64), PublisherAdmissionJournalErrorV1> {
    // The largest successful/recovery terminal writes at least five ledger
    // members plus capacity lineage, current, and reservation deletion. Poison
    // writes poison, checkpoint, capacity lineage, current, and deletion. This includes
    // the largest legal protected record plus key, envelope, transaction, and
    // frame overhead per ledger member.
    let maximum_record = u64::try_from(limits.maximum_record_bytes)
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let ledger_member = maximum_record
        .checked_add(LEDGER_MEMBER_OVERHEAD_BYTES)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let terminal = ledger_member
        .checked_mul(5)
        .and_then(|bytes| bytes.checked_add(FIXED_TERMINAL_OVERHEAD_BYTES))
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let poison = ledger_member
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(FIXED_TERMINAL_OVERHEAD_BYTES))
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    Ok((terminal, poison))
}

fn checkpoint_commitment(
    checkpoint: &AuthorityCheckpointV1,
    chain_head: ObjectDigest,
) -> ObjectDigest {
    let current = encode_current_head(checkpoint, chain_head);
    super::model::digest_parts(CHECKPOINT_COMMITMENT_DOMAIN, &[&current])
}

fn reconstruct_semantic_projection(
    projection: &PublisherAdmissionJournalProjectionV1,
    limits: AdmissionLimits,
    capacity: CapacityPolicyV1,
    maximum_source_releases: usize,
    maximum_root_records: usize,
) -> Result<Option<ProtectedLedgerReplayV1>, PublisherAdmissionJournalErrorV1> {
    let mut entries = Vec::new();
    for envelope in projection
        .records()
        .iter()
        .filter(|record| record.key().kind() == PublisherAdmissionJournalRecordKindV1::LedgerEntry)
    {
        let mutation = decode_mutation(publisher_body(envelope)?, limits)?;
        let decoded = decode_protected_record_v1(&mutation.value, limits)?;
        entries.push((decoded.sequence, mutation.value));
    }
    entries.sort_by_key(|(sequence, _)| *sequence);
    if entries.is_empty() {
        return Ok(None);
    }
    let replay = ProtectedLedgerReplayV1::reconstruct(
        entries.into_iter().map(|(_, value)| value),
        limits,
        capacity,
        maximum_source_releases,
        maximum_root_records,
    )?;
    let current = projection
        .records()
        .iter()
        .find(|record| record.key().kind() == PublisherAdmissionJournalRecordKindV1::Current)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let chain_head = replay
        .records
        .last()
        .map(|record| record.envelope.digest)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    if publisher_body(current)? != encode_current_head(&replay.checkpoint, chain_head) {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(Some(replay))
}

fn decode_mutation_batch(
    mutations: &[LedgerMutation],
    limits: AdmissionLimits,
) -> Result<Vec<super::DecodedProtectedRecordV1>, PublisherAdmissionJournalErrorV1> {
    mutations
        .iter()
        .map(|mutation| {
            let decoded = decode_protected_record_v1(&mutation.value, limits)?;
            if decoded.kind != mutation.kind || decoded.key != mutation.key {
                return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
            }
            Ok(decoded)
        })
        .collect()
}

fn validate_batch_successor(
    current: Option<&CurrentPublisherHeadV1>,
    records: &[super::DecodedProtectedRecordV1],
    checkpoint: &AuthorityCheckpointV1,
) -> Result<(), PublisherAdmissionJournalErrorV1> {
    let first = records
        .first()
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let last = records
        .last()
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let (expected_sequence, expected_predecessor) = match current {
        Some(head) => (
            head.sequence
                .checked_add(1)
                .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
            Some(head.chain_head),
        ),
        None => (1, None),
    };
    if first.sequence != expected_sequence
        || first.predecessor != expected_predecessor
        || records.windows(2).any(|pair| {
            pair[0].sequence.checked_add(1) != Some(pair[1].sequence)
                || pair[1].predecessor != Some(pair[0].digest)
        })
        || last.kind != ProtectedRecordKindV1::AuthorityCheckpoint
        || last.sequence != checkpoint.sequence
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(())
}

fn ledger_entry_key(
    sequence: u64,
    digest: ObjectDigest,
) -> Result<PublisherAdmissionJournalKeyV1, PublisherAdmissionJournalErrorV1> {
    if sequence == 0 || digest.as_bytes() == &[0; 32] {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let mut identity = Vec::with_capacity(40);
    identity.extend_from_slice(&sequence.to_be_bytes());
    identity.extend_from_slice(digest.as_bytes());
    Ok(PublisherAdmissionJournalKeyV1::new(
        PublisherAdmissionJournalRecordKindV1::LedgerEntry,
        identity,
    )?)
}

fn completion_effect_key(
    transaction: [u8; 16],
) -> Result<PublisherAdmissionJournalKeyV1, PublisherAdmissionJournalErrorV1> {
    if transaction == [0; 16] {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(PublisherAdmissionJournalKeyV1::new(
        PublisherAdmissionJournalRecordKindV1::CompletionEffect,
        transaction.to_vec(),
    )?)
}

fn capacity_settlement_key(
    admission_transaction: [u8; 16],
) -> Result<PublisherAdmissionJournalKeyV1, PublisherAdmissionJournalErrorV1> {
    if admission_transaction == [0; 16] {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(PublisherAdmissionJournalKeyV1::new(
        PublisherAdmissionJournalRecordKindV1::CapacitySettlement,
        admission_transaction.to_vec(),
    )?)
}

fn current_key() -> Result<PublisherAdmissionJournalKeyV1, PublisherAdmissionJournalErrorV1> {
    Ok(PublisherAdmissionJournalKeyV1::new(
        PublisherAdmissionJournalRecordKindV1::Current,
        b"authority".to_vec(),
    )?)
}

fn current_head(
    projection: &PublisherAdmissionJournalProjectionV1,
) -> Result<Option<CurrentPublisherHeadV1>, PublisherAdmissionJournalErrorV1> {
    projection
        .records()
        .iter()
        .find(|record| record.key().kind() == PublisherAdmissionJournalRecordKindV1::Current)
        .map(|envelope| {
            let (sequence, chain_head) = decode_current_head(publisher_body(envelope)?)?;
            Ok(CurrentPublisherHeadV1 {
                sequence,
                chain_head,
                envelope_revision: envelope.revision(),
                envelope_digest: envelope.digest(),
            })
        })
        .transpose()
}

fn encode_mutation(mutation: &LedgerMutation) -> Result<Vec<u8>, PublisherAdmissionJournalErrorV1> {
    let key_length = u16::try_from(mutation.key.len())
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let value_length = u32::try_from(mutation.value.len())
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let mut bytes = Vec::with_capacity(19 + mutation.key.len() + mutation.value.len());
    bytes.extend_from_slice(MUTATION_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(mutation.kind as u8);
    bytes.extend_from_slice(&key_length.to_be_bytes());
    bytes.extend_from_slice(&value_length.to_be_bytes());
    bytes.extend_from_slice(&mutation.key);
    bytes.extend_from_slice(&mutation.value);
    Ok(bytes)
}

fn decode_mutation(
    bytes: &[u8],
    limits: AdmissionLimits,
) -> Result<LedgerMutation, PublisherAdmissionJournalErrorV1> {
    if bytes.len() < 17 || &bytes[..8] != MUTATION_MAGIC || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let key_length = usize::from(u16::from_be_bytes([bytes[11], bytes[12]]));
    let value_length = usize::try_from(u32::from_be_bytes([
        bytes[13], bytes[14], bytes[15], bytes[16],
    ]))
    .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let key_end = 17_usize
        .checked_add(key_length)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let value_end = key_end
        .checked_add(value_length)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    if value_end != bytes.len() {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let value = bytes[key_end..].to_vec();
    let decoded = decode_protected_record_v1(&value, limits)?;
    if decoded.kind as u8 != bytes[10] || decoded.key != bytes[17..key_end] {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let mutation = LedgerMutation {
        kind: decoded.kind,
        key: bytes[17..key_end].to_vec(),
        value,
    };
    if encode_mutation(&mutation)? != bytes {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(mutation)
}

fn encode_current_head(checkpoint: &AuthorityCheckpointV1, chain_head: ObjectDigest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(123);
    bytes.extend_from_slice(HEAD_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&checkpoint.sequence.to_be_bytes());
    bytes.extend_from_slice(chain_head.as_bytes());
    bytes.extend_from_slice(&checkpoint.epoch.get().to_be_bytes());
    bytes.extend_from_slice(checkpoint.state_digest.as_bytes());
    bytes.extend_from_slice(checkpoint.outstanding_digest.as_bytes());
    bytes.extend_from_slice(&checkpoint.outstanding_count.to_be_bytes());
    bytes.push(u8::from(checkpoint.poisoned));
    bytes
}

fn decode_current_head(
    bytes: &[u8],
) -> Result<(u64, ObjectDigest), PublisherAdmissionJournalErrorV1> {
    if bytes.len() != 127
        || &bytes[..8] != HEAD_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[126] > 1
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let sequence = u64::from_be_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let chain_head = ObjectDigest::from_bytes(
        bytes[18..50]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let epoch = u64::from_be_bytes(
        bytes[50..58]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let state_digest = &bytes[58..90];
    let outstanding_digest = &bytes[90..122];
    if sequence == 0
        || epoch == 0
        || chain_head.as_bytes() == &[0; 32]
        || state_digest == [0; 32]
        || outstanding_digest == [0; 32]
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok((sequence, chain_head))
}

fn encode_effect_permit(
    transaction: [u8; 16],
    permit: &CompletionPermitV1,
    checkpoint: &AuthorityCheckpointV1,
    chain_head: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(226);
    bytes.extend_from_slice(b"AOSPAE01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&transaction);
    bytes.extend_from_slice(permit.permit.as_bytes());
    bytes.extend_from_slice(permit.operation.as_bytes());
    bytes.extend_from_slice(permit.artifact_digest.as_bytes());
    bytes.extend_from_slice(permit.permit_digest.as_bytes());
    bytes.extend_from_slice(&checkpoint.sequence.to_be_bytes());
    bytes.extend_from_slice(checkpoint.state_digest.as_bytes());
    bytes.extend_from_slice(checkpoint_commitment(checkpoint, chain_head).as_bytes());
    bytes.extend_from_slice(chain_head.as_bytes());
    bytes
}

#[derive(Clone, Copy)]
struct CompletionEffectBindingV1 {
    transaction: [u8; 16],
    permit: [u8; 16],
    operation: [u8; 16],
    artifact: ObjectDigest,
    permit_digest: ObjectDigest,
    checkpoint_sequence: u64,
    checkpoint_state: ObjectDigest,
    checkpoint_commitment: ObjectDigest,
    chain_head: ObjectDigest,
}

fn encode_effect_binding(binding: &CompletionEffectBindingV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(226);
    bytes.extend_from_slice(b"AOSPAE01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&binding.transaction);
    bytes.extend_from_slice(&binding.permit);
    bytes.extend_from_slice(&binding.operation);
    bytes.extend_from_slice(binding.artifact.as_bytes());
    bytes.extend_from_slice(binding.permit_digest.as_bytes());
    bytes.extend_from_slice(&binding.checkpoint_sequence.to_be_bytes());
    bytes.extend_from_slice(binding.checkpoint_state.as_bytes());
    bytes.extend_from_slice(binding.checkpoint_commitment.as_bytes());
    bytes.extend_from_slice(binding.chain_head.as_bytes());
    bytes
}

fn decode_effect_permit(
    bytes: &[u8],
) -> Result<CompletionEffectBindingV1, PublisherAdmissionJournalErrorV1> {
    if bytes.len() != 226 || &bytes[..8] != b"AOSPAE01" || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let transaction = bytes[10..26]
        .try_into()
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let permit = bytes[26..42]
        .try_into()
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let operation = bytes[42..58]
        .try_into()
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let artifact = ObjectDigest::from_bytes(
        bytes[58..90]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let permit_digest = ObjectDigest::from_bytes(
        bytes[90..122]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let checkpoint_sequence = u64::from_be_bytes(
        bytes[122..130]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let checkpoint_state = ObjectDigest::from_bytes(
        bytes[130..162]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let checkpoint_commitment = ObjectDigest::from_bytes(
        bytes[162..194]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let chain_head = ObjectDigest::from_bytes(
        bytes[194..226]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    if transaction == [0; 16]
        || permit == [0; 16]
        || operation == [0; 16]
        || checkpoint_sequence == 0
        || [
            artifact,
            permit_digest,
            checkpoint_state,
            checkpoint_commitment,
            chain_head,
        ]
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(CompletionEffectBindingV1 {
        transaction,
        permit,
        operation,
        artifact,
        permit_digest,
        checkpoint_sequence,
        checkpoint_state,
        checkpoint_commitment,
        chain_head,
    })
}

fn encode_capacity_settlement(lineage: &CompletionSettlementLineageV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(308);
    bytes.extend_from_slice(b"AOSPAS01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(lineage.disposition as u8);
    bytes.push(0);
    bytes.extend_from_slice(&lineage.admission_transaction_id);
    bytes.extend_from_slice(&lineage.owner_id);
    bytes.extend_from_slice(lineage.owner_digest.as_bytes());
    bytes.extend_from_slice(&lineage.reservation_id);
    bytes.extend_from_slice(&lineage.permit);
    bytes.extend_from_slice(&lineage.operation);
    bytes.extend_from_slice(lineage.artifact.as_bytes());
    bytes.extend_from_slice(lineage.permit_digest.as_bytes());
    bytes.extend_from_slice(lineage.checkpoint.as_bytes());
    bytes.extend_from_slice(lineage.chain_head.as_bytes());
    bytes.extend_from_slice(&lineage.terminal_records.to_be_bytes());
    bytes.extend_from_slice(&lineage.terminal_bytes.to_be_bytes());
    bytes.extend_from_slice(&lineage.poison_records.to_be_bytes());
    bytes.extend_from_slice(&lineage.poison_bytes.to_be_bytes());
    bytes
}

fn decode_capacity_settlement(
    bytes: &[u8],
) -> Result<CompletionSettlementLineageV1, PublisherAdmissionJournalErrorV1> {
    if bytes.len() != 308
        || &bytes[..8] != b"AOSPAS01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[11] != 0
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let digest = |start: usize| -> Result<ObjectDigest, PublisherAdmissionJournalErrorV1> {
        let value = ObjectDigest::from_bytes(capacity_settlement_array(bytes, start)?);
        if value.as_bytes() == &[0; 32] {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        Ok(value)
    };
    let lineage = CompletionSettlementLineageV1 {
        disposition: CapacitySettlementDispositionV1::from_byte(bytes[10])?,
        admission_transaction_id: capacity_settlement_array(bytes, 12)?,
        owner_id: capacity_settlement_array(bytes, 28)?,
        owner_digest: digest(60)?,
        reservation_id: capacity_settlement_array(bytes, 92)?,
        permit: capacity_settlement_array(bytes, 124)?,
        operation: capacity_settlement_array(bytes, 140)?,
        artifact: digest(156)?,
        permit_digest: digest(188)?,
        checkpoint: digest(220)?,
        chain_head: digest(252)?,
        terminal_records: u32::from_be_bytes(capacity_settlement_array(bytes, 284)?),
        terminal_bytes: u64::from_be_bytes(capacity_settlement_array(bytes, 288)?),
        poison_records: u32::from_be_bytes(capacity_settlement_array(bytes, 296)?),
        poison_bytes: u64::from_be_bytes(capacity_settlement_array(bytes, 300)?),
    };
    if lineage.admission_transaction_id == [0; 16]
        || lineage.owner_id == [0; 32]
        || lineage.reservation_id == [0; 32]
        || lineage.permit == [0; 16]
        || lineage.operation == [0; 16]
        || lineage.terminal_records == 0
        || lineage.terminal_bytes == 0
        || lineage.poison_records == 0
        || lineage.poison_bytes == 0
        || bind_domain_capacity_request_v1::<PublisherAdmissionJournalSchemaV1>(lineage.request())
            != lineage.request()
        || !validate_domain_capacity_lineage_v1::<PublisherAdmissionJournalSchemaV1>(
            &lineage.request(),
            lineage.admission_transaction_id,
            lineage.reservation_id,
        )
        || encode_capacity_settlement(&lineage) != bytes
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(lineage)
}

fn capacity_settlement_array<const LENGTH: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; LENGTH], PublisherAdmissionJournalErrorV1> {
    bytes
        .get(start..start + LENGTH)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?
        .try_into()
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)
}

fn publisher_reducer_envelope(
    key: PublisherAdmissionJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    canonical_body: &[u8],
    validator: AdmissionLimits,
) -> Result<PublisherAdmissionJournalEnvelopeV1, PublisherAdmissionJournalErrorV1> {
    let payload = encode_reducer_payload_with_validator::<PublisherAdmissionJournalSchemaV1>(
        &key,
        canonical_body,
        &validator,
    )?;
    Ok(PublisherAdmissionJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        &validator,
    )?)
}

fn publisher_body(
    envelope: &PublisherAdmissionJournalEnvelopeV1,
) -> Result<&[u8], PublisherAdmissionJournalErrorV1> {
    let validator = maximum_admission_limits();
    Ok(
        decode_reducer_payload_with_validator::<PublisherAdmissionJournalSchemaV1>(
            envelope.key(),
            envelope.payload(),
            &validator,
        )?
        .body(),
    )
}

/// Constructs an immutable checkpoint key for a publisher replay join.
///
/// # Errors
///
/// Returns [`PublisherAdmissionJournalErrorV1`] for a sentinel checkpoint.
pub(crate) fn publisher_admission_checkpoint_key_v1(
    checkpoint: ObjectDigest,
) -> Result<PublisherAdmissionJournalKeyV1, PublisherAdmissionJournalErrorV1> {
    if checkpoint.as_bytes() == &[0; 32] {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(PublisherAdmissionJournalKeyV1::new(
        PublisherAdmissionJournalRecordKindV1::Checkpoint,
        checkpoint.as_bytes().to_vec(),
    )?)
}

/// Derives a diagnostic-only operation key for controller handler correlation.
pub(crate) fn publisher_admission_operation_key_v1(operation: OperationId) -> Vec<u8> {
    operation.as_bytes().to_vec()
}
