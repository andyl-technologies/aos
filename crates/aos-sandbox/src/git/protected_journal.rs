//! Dormant protected-journal adapter for Git repository projections.
//!
//! The adapter persists canonical Git control-plane bytes only. It neither
//! invokes Git nor grants filesystem, quarantine, pack, or network authority.

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId};

use crate::journal::{Journal, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::{
    AppliedDomainTransactionV1, DomainCommitOutcomeV1, DomainOutcomeUnknownV1,
    DomainPostcommitCapabilityV1, DomainRecoveryV1, PreparedDomainTransactionV1,
    ProtectedDomainEnvelopeV1, ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1,
    ProtectedDomainKeyV1, ProtectedDomainProjectionV1, ProtectedDomainReplayPhaseV1,
    ProtectedDomainReplayTransactionV1, ProtectedDomainSchemaV1, ProtectedDomainSnapshotV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1, ReplayedDomainPostcommitV1,
    ValidatedDomainPostcommitV1, encode_reducer_payload_with_validator,
};

use super::{
    GitDurablePayloadV1, GitDurableRecordKindV1, GitDurableRecordV1, GitReceivePhaseV1,
    GitTrustedValidatorV1, decode_git_durable_record_v1, encode_git_durable_record_v1,
};

/// Selects one closed Git protected-journal family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GitProtectedRecordKindV1 {
    /// Stores repository, immutable-pack, lease, and fork projection state.
    State = 1,
    /// Stores a receive/quarantine or export effect boundary.
    ExchangeEffect = 2,
    /// Publishes an atomic ref/ODB or immutable-pack successor.
    Publication = 3,
    /// Publishes a validator-bound replay checkpoint without compaction authority.
    Checkpoint = 4,
}

/// Defines the closed Git adapter schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitProtectedJournalSchemaV1;

impl ProtectedDomainSchemaV1 for GitProtectedJournalSchemaV1 {
    type Kind = GitProtectedRecordKindV1;
    type ReplayValidator = GitTrustedValidatorV1;

    const MAGIC: [u8; 8] = *b"AOSGPJ01";
    const HASH_DOMAIN: &'static [u8] = b"aos.sandbox.git.protected-journal.v1\0";
    const KEY_PREFIX: &'static [u8] = b"\0aos-git-v1\0";
    const MAXIMUM_PAYLOAD_BYTES: usize = 160 * 1024 * 1024;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::State),
            2 => Some(Self::Kind::ExchangeEffect),
            3 => Some(Self::Kind::Publication),
            4 => Some(Self::Kind::Checkpoint),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::State | Self::Kind::Publication => RecordNamespace::DesiredState,
            Self::Kind::ExchangeEffect => RecordNamespace::Effect,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        match kind {
            Self::Kind::State => 1,
            Self::Kind::ExchangeEffect => 2,
            Self::Kind::Publication => 3,
            Self::Kind::Checkpoint => 4,
        }
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::State => ProtectedRecordRoleV1::State,
            Self::Kind::ExchangeEffect => ProtectedRecordRoleV1::Effect,
            Self::Kind::Publication | Self::Kind::Checkpoint => ProtectedRecordRoleV1::Publication,
        }
    }

    fn is_checkpoint(kind: Self::Kind) -> bool {
        matches!(kind, Self::Kind::Checkpoint)
    }

    fn family(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn decode_reducer_phase(
        trusted_validator: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        if identity.len() != 48 {
            return None;
        }
        let record = decode_git_durable_record_v1(body, trusted_validator).ok()?;
        if encode_git_durable_record_v1(&record).ok()?.as_slice() != body
            || record.project().as_bytes() != &identity[..16]
            || record.repository().as_bytes() != &identity[16..32]
            || record.lineage().as_bytes() != &identity[32..48]
        {
            return None;
        }
        match (kind, record.payload()) {
            (
                Self::Kind::State,
                GitDurablePayloadV1::Repository(_)
                | GitDurablePayloadV1::Export(_)
                | GitDurablePayloadV1::Pack(_)
                | GitDurablePayloadV1::PackLease(_)
                | GitDurablePayloadV1::CheapFork(_),
            ) => Some(ProtectedReducerPhaseV1::Observed),
            (Self::Kind::Publication, GitDurablePayloadV1::Publication(_)) => {
                Some(ProtectedReducerPhaseV1::Terminal)
            }
            (Self::Kind::ExchangeEffect, GitDurablePayloadV1::Receive(receive)) => {
                match receive.phase() {
                    GitReceivePhaseV1::Admitted
                    | GitReceivePhaseV1::Quarantined
                    | GitReceivePhaseV1::Validated => Some(ProtectedReducerPhaseV1::Prepared),
                    GitReceivePhaseV1::Published | GitReceivePhaseV1::Rejected => {
                        Some(ProtectedReducerPhaseV1::Terminal)
                    }
                }
            }
            _ => None,
        }
    }

    fn semantic_tuple(_kind: Self::Kind, identity: &[u8], _body: &[u8]) -> Option<[u8; 32]> {
        identity.get(..32)?.try_into().ok()
    }

    fn validates_identity(_kind: Self::Kind, identity: &[u8]) -> bool {
        identity.len() == 48
            && identity
                .chunks_exact(16)
                .all(|component| component != [0; 16])
    }
}

/// Canonical Git shared-journal key.
pub type GitProtectedJournalKeyV1 = ProtectedDomainKeyV1<GitProtectedJournalSchemaV1>;
/// Canonical Git value and predecessor CAS.
pub type GitProtectedJournalEnvelopeV1 = ProtectedDomainEnvelopeV1<GitProtectedJournalSchemaV1>;
/// Sealed Git journal currentness snapshot.
pub type GitProtectedJournalSnapshotV1 = ProtectedDomainSnapshotV1<GitProtectedJournalSchemaV1>;
/// Replayed materialized Git projection.
pub type GitProtectedJournalProjectionV1 = ProtectedDomainProjectionV1<GitProtectedJournalSchemaV1>;
/// Git transaction group reconstructed during bounded cold replay.
pub type GitJournalReplayTransactionV1 =
    ProtectedDomainReplayTransactionV1<GitProtectedJournalSchemaV1>;
/// Fail-closed Git cold-replay phase.
pub type GitJournalReplayPhaseV1 = ProtectedDomainReplayPhaseV1;
/// Semantic phase decoded from one Git reducer body.
pub type GitReducerPhaseV1 = ProtectedReducerPhaseV1;
/// Exact prepared Git transaction.
pub type PreparedGitJournalTransactionV1 = PreparedDomainTransactionV1<GitProtectedJournalSchemaV1>;
/// Exact ambiguous Git transaction recovery token.
pub type GitJournalOutcomeUnknownV1 = DomainOutcomeUnknownV1<GitProtectedJournalSchemaV1>;
/// Git transaction commit outcome.
pub type GitJournalCommitOutcomeV1 = DomainCommitOutcomeV1<GitProtectedJournalSchemaV1>;
/// Git outcome-unknown recovery classification.
pub type GitJournalRecoveryV1 = DomainRecoveryV1<GitProtectedJournalSchemaV1>;
/// Exact-readback Git transaction result.
pub type AppliedGitJournalTransactionV1 = AppliedDomainTransactionV1<GitProtectedJournalSchemaV1>;
/// Composite postcommit Git transaction authority.
pub type GitPostcommitCapabilityV1 = DomainPostcommitCapabilityV1<GitProtectedJournalSchemaV1>;
/// Current, consumed Git transaction authority.
pub type ValidatedGitPostcommitV1<'current> =
    ValidatedDomainPostcommitV1<'current, GitProtectedJournalSchemaV1>;
/// Current Git postcommit authority reconstructed during cold replay.
pub type ReplayedGitPostcommitV1 = ReplayedDomainPostcommitV1<GitProtectedJournalSchemaV1>;
/// Protected Git journal owner.
pub type GitProtectedJournalV1<'journal> =
    ProtectedDomainJournalV1<'journal, GitProtectedJournalSchemaV1>;
/// Git adapter validation or durability failure.
pub type GitProtectedJournalErrorV1 = ProtectedDomainJournalErrorV1;

/// Constructs the canonical key for one project repository subject.
///
/// # Errors
///
/// Returns [`GitProtectedJournalErrorV1`] only if the fixed typed identity
/// cannot be represented by the bounded key schema.
pub fn git_protected_key_v1(
    kind: GitProtectedRecordKindV1,
    project: ProjectId,
    repository: ResourceId,
    subject: ResourceId,
) -> Result<GitProtectedJournalKeyV1, GitProtectedJournalErrorV1> {
    if project.as_bytes() == &[0; 16]
        || repository.as_bytes() == &[0; 16]
        || subject.as_bytes() == &[0; 16]
    {
        return Err(GitProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let mut identity = Vec::with_capacity(48);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(repository.as_bytes());
    identity.extend_from_slice(subject.as_bytes());
    GitProtectedJournalKeyV1::new(kind, identity)
}

/// Claims the dormant Git adapter over an already protected-open journal.
pub(crate) fn claim_git_protected_journal_v1(
    journal: &mut Journal,
    trusted_validator: GitTrustedValidatorV1,
) -> Result<GitProtectedJournalV1<'_>, GitProtectedJournalErrorV1> {
    GitProtectedJournalV1::claim_with_validator(journal, trusted_validator)
}

/// Wraps one reducer-issued canonical Git body for journal admission.
pub(crate) fn git_reducer_envelope_v1(
    key: GitProtectedJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    record: &GitDurableRecordV1,
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitProtectedJournalEnvelopeV1, GitProtectedJournalErrorV1> {
    let kind_matches = match (key.kind(), record.kind()) {
        (
            GitProtectedRecordKindV1::State,
            GitDurableRecordKindV1::Repository
            | GitDurableRecordKindV1::Export
            | GitDurableRecordKindV1::Pack
            | GitDurableRecordKindV1::PackLease
            | GitDurableRecordKindV1::CheapFork,
        )
        | (GitProtectedRecordKindV1::ExchangeEffect, GitDurableRecordKindV1::Receive)
        | (GitProtectedRecordKindV1::Publication, GitDurableRecordKindV1::Publication) => true,
        _ => false,
    };
    if !kind_matches
        || record.project().as_bytes() != &key.identity()[..16]
        || record.repository().as_bytes() != &key.identity()[16..32]
        || record.lineage().as_bytes() != &key.identity()[32..48]
    {
        return Err(GitProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let body = encode_git_durable_record_v1(record)
        .map_err(|_| GitProtectedJournalErrorV1::NonCanonicalRecord)?;
    let payload = encode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
        &key,
        &body,
        trusted_validator,
    )?;
    GitProtectedJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        trusted_validator,
    )
}
