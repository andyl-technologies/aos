//! Dormant protected-journal adapter for lifecycle transactions.
//!
//! Canonical ordering is intent, operation, effect, idempotency, auxiliary
//! join, then checkpoint. A transaction is entirely durable before any
//! postcommit effect capability can leave this module.

mod receiving;
pub use receiving::LifecycleReplayReceivingV1;

mod schema_capture;
pub use schema_capture::LifecycleSchemaReplayCaptureV1;
use schema_capture::{decode_reducer_phase_with_original, operation_tuple};

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, ResourceId};

use crate::journal::{Journal, RecordNamespace};

use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedDomainEnvelopeV1, ProtectedDomainKeyV1, ProtectedDomainProjectionV1,
    ProtectedDomainReplayPhaseV1, ProtectedDomainReplayTransactionV1, ProtectedDomainSchemaV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1, encode_reducer_payload_with_validator,
};

use crate::protected_domain_journal::{
    AppliedDomainTransactionV1, DomainCommitOutcomeV1, DomainOutcomeUnknownV1,
    DomainPostcommitCapabilityV1, DomainRecoveryV1, PreparedDomainTransactionV1,
    ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1, ProtectedDomainSnapshotV1,
    ReplayedDomainPostcommitV1, ValidatedDomainPostcommitV1,
};

use super::{
    LifecycleAuxiliaryKindV1, LifecycleAuxiliaryRecordV1, LifecycleIntentV1,
    LifecycleJournalOwnershipRecordV1, LifecycleJournalRecordKindV1, LifecycleJournalVerifierV1,
    LifecycleOperationV1, decode_lifecycle_auxiliary_record_v1, decode_lifecycle_journal_record_v1,
    decode_operation_record_v1, encode_lifecycle_auxiliary_record_v1,
    encode_lifecycle_journal_record_v1,
};

pub(super) const LIFECYCLE_PROTECTED_IDENTITY_BYTES: usize = 48;

// This is the same immutable operation selector used by the full retained
// latest/history engine. Keys have already passed this schema's identity-width
// check; this comparison is DATA and creates no CurrentLifecycle capability.
pub(crate) fn lifecycle_key_selects_operation_v2(
    key: &LifecycleProtectedJournalKeyV1, operation: OperationId,
) -> bool {
    matches!(key.kind(), LifecycleProtectedRecordKindV1::Intent
        | LifecycleProtectedRecordKindV1::Operation | LifecycleProtectedRecordKindV1::Effect)
        && key.identity()[32..48] == operation.as_bytes()[..]
}

/// Selects one closed lifecycle protected-journal family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleProtectedRecordKindV1 {
    /// Stores normalized lifecycle desired intent and preconditions.
    Intent = 1,
    /// Stores the complete lifecycle operation projection.
    Operation = 2,
    /// Stores a pending, observed, or terminal effect attempt.
    Effect = 3,
    /// Stores a caller/project/method idempotency decision.
    Idempotency = 4,
    /// Stores one closed auxiliary atomic-join projection.
    Auxiliary = 5,
    /// Publishes a verified lifecycle replay checkpoint without compaction authority.
    Checkpoint = 6,
}

/// Defines the closed lifecycle adapter schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleProtectedJournalSchemaV1;

impl ProtectedDomainSchemaV1 for LifecycleProtectedJournalSchemaV1 {
    type Kind = LifecycleProtectedRecordKindV1;
    type ReplayValidator = LifecycleJournalVerifierV1;

    const MAGIC: [u8; 8] = aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::LIFECYCLE_PROTECTED_MAGIC_V1;
    const HASH_DOMAIN: &'static [u8] = aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::LIFECYCLE_PROTECTED_DOMAIN_V1;
    const KEY_PREFIX: &'static [u8] = aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::LIFECYCLE_PROTECTED_KEY_PREFIX_V1;
    const MAXIMUM_PAYLOAD_BYTES: usize = aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::Intent),
            2 => Some(Self::Kind::Operation),
            3 => Some(Self::Kind::Effect),
            4 => Some(Self::Kind::Idempotency),
            5 => Some(Self::Kind::Auxiliary),
            6 => Some(Self::Kind::Checkpoint),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::Intent | Self::Kind::Idempotency | Self::Kind::Auxiliary => {
                RecordNamespace::DesiredState
            }
            Self::Kind::Operation => RecordNamespace::Operation,
            Self::Kind::Effect => RecordNamespace::Effect,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        match kind {
            Self::Kind::Intent => 1,
            Self::Kind::Operation => 2,
            Self::Kind::Effect => 3,
            Self::Kind::Idempotency => 4,
            Self::Kind::Auxiliary => 5,
            Self::Kind::Checkpoint => 6,
        }
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::Effect => ProtectedRecordRoleV1::Effect,
            Self::Kind::Checkpoint => ProtectedRecordRoleV1::Publication,
            Self::Kind::Intent
            | Self::Kind::Operation
            | Self::Kind::Idempotency
            | Self::Kind::Auxiliary => ProtectedRecordRoleV1::State,
        }
    }

    fn is_checkpoint(kind: Self::Kind) -> bool {
        matches!(kind, Self::Kind::Checkpoint)
    }

    fn family(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn decode_reducer_phase(
        verifier: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        decode_reducer_phase_with_original(verifier, kind, identity, body, None)
    }

    fn semantic_tuple(kind: Self::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        if !matches!(
            kind,
            Self::Kind::Intent | Self::Kind::Operation | Self::Kind::Effect
        ) {
            return None;
        }
        let operation = canonical_operation(body)?;
        operation_tuple(&operation, identity)
    }

    fn validates_identity(_kind: Self::Kind, identity: &[u8]) -> bool {
        identity.len() == LIFECYCLE_PROTECTED_IDENTITY_BYTES
            && identity
                .chunks_exact(16)
                .all(|component| component != [0; 16])
    }
}

fn canonical_operation(body: &[u8]) -> Option<LifecycleOperationV1> {
    let operation = decode_operation_record_v1(body).ok()?;
    super::format::operation_record_matches_canonical_encoding(&operation, body)
        .ok()
        .filter(|matches| *matches)
        .map(|_| operation)
}

pub(super) fn lifecycle_journal_subject(intent: &LifecycleIntentV1) -> [u8; 16] {
    match intent {
        LifecycleIntentV1::Create { sandbox }
        | LifecycleIntentV1::UpdateEnvironment { sandbox, .. }
        | LifecycleIntentV1::UpdatePolicy { sandbox, .. }
        | LifecycleIntentV1::Start { sandbox, .. }
        | LifecycleIntentV1::Stop { sandbox, .. }
        | LifecycleIntentV1::SuspendMemory { sandbox, .. }
        | LifecycleIntentV1::Resume { sandbox, .. }
        | LifecycleIntentV1::Hibernate { sandbox, .. }
        | LifecycleIntentV1::Snapshot { sandbox, .. }
        | LifecycleIntentV1::DeleteSandbox { sandbox, .. }
        | LifecycleIntentV1::CreateExecution { sandbox, .. }
        | LifecycleIntentV1::AttachView { sandbox, .. } => *sandbox.as_bytes(),
        LifecycleIntentV1::Fork { source, .. }
        | LifecycleIntentV1::Restore {
            snapshot: source, ..
        }
        | LifecycleIntentV1::DeleteSnapshot {
            snapshot: source, ..
        } => *source.as_bytes(),
        LifecycleIntentV1::CancelExecution { execution, .. } => *execution.as_bytes(),
        LifecycleIntentV1::CreateView { view } | LifecycleIntentV1::ReleaseView { view, .. } => {
            *view.as_bytes()
        }
        LifecycleIntentV1::ReplaceAttachment { attachment, .. }
        | LifecycleIntentV1::DetachView { attachment, .. } => *attachment.as_bytes(),
        LifecycleIntentV1::AttenuateCapability { parent, .. }
        | LifecycleIntentV1::RenewCapability {
            capability: parent, ..
        }
        | LifecycleIntentV1::RevokeCapability {
            capability: parent, ..
        } => *parent.as_bytes(),
    }
}

fn operation_phase(
    kind: LifecycleProtectedRecordKindV1,
    phase: u8,
) -> Option<ProtectedReducerPhaseV1> {
    match (kind, phase) {
        (LifecycleProtectedRecordKindV1::Intent, 1) => Some(ProtectedReducerPhaseV1::Observed),
        (LifecycleProtectedRecordKindV1::Effect, 2 | 3 | 6 | 7 | 9 | 10) => {
            Some(ProtectedReducerPhaseV1::Prepared)
        }
        (LifecycleProtectedRecordKindV1::Operation, 4 | 5) => {
            Some(ProtectedReducerPhaseV1::Observed)
        }
        (LifecycleProtectedRecordKindV1::Operation, 8 | 11) => {
            Some(ProtectedReducerPhaseV1::Terminal)
        }
        _ => None,
    }
}

/// Selects one typed canonical lifecycle reducer record.
pub(crate) enum LifecycleReducerRecordV1<'record> {
    /// Encodes one operation snapshot into its phase-selected family.
    Operation(&'record LifecycleOperationV1),
    /// Encodes one idempotency custody record.
    Idempotency(LifecycleJournalOwnershipRecordV1),
    /// Encodes one closed auxiliary join record.
    Auxiliary(&'record LifecycleAuxiliaryRecordV1),
}

/// Canonical lifecycle shared-journal key.
pub type LifecycleProtectedJournalKeyV1 = ProtectedDomainKeyV1<LifecycleProtectedJournalSchemaV1>;
/// Canonical lifecycle value and predecessor CAS.
pub type LifecycleProtectedJournalEnvelopeV1 =
    ProtectedDomainEnvelopeV1<LifecycleProtectedJournalSchemaV1>;
/// Sealed lifecycle journal currentness snapshot.
pub type LifecycleProtectedJournalSnapshotV1 =
    ProtectedDomainSnapshotV1<LifecycleProtectedJournalSchemaV1>;
/// Replayed materialized lifecycle projection.
pub type LifecycleProtectedJournalProjectionV1 =
    ProtectedDomainProjectionV1<LifecycleProtectedJournalSchemaV1>;
/// Lifecycle transaction group reconstructed during bounded cold replay.
pub type LifecycleJournalReplayTransactionV1 =
    ProtectedDomainReplayTransactionV1<LifecycleProtectedJournalSchemaV1>;
/// Fail-closed lifecycle cold-replay phase.
pub type LifecycleJournalReplayPhaseV1 = ProtectedDomainReplayPhaseV1;
/// Semantic phase decoded from one lifecycle reducer body.
pub type LifecycleReducerPhaseV1 = ProtectedReducerPhaseV1;
/// Exact prepared lifecycle transaction.
pub type PreparedLifecycleJournalTransactionV1 =
    PreparedDomainTransactionV1<LifecycleProtectedJournalSchemaV1>;
/// Exact ambiguous lifecycle transaction recovery token.
pub type LifecycleJournalOutcomeUnknownV1 =
    DomainOutcomeUnknownV1<LifecycleProtectedJournalSchemaV1>;
/// Lifecycle transaction commit outcome.
pub type LifecycleJournalCommitOutcomeV1 = DomainCommitOutcomeV1<LifecycleProtectedJournalSchemaV1>;
/// Lifecycle outcome-unknown recovery classification.
pub type LifecycleJournalRecoveryV1 = DomainRecoveryV1<LifecycleProtectedJournalSchemaV1>;
/// Exact-readback lifecycle transaction result.
pub type AppliedLifecycleJournalTransactionV1 =
    AppliedDomainTransactionV1<LifecycleProtectedJournalSchemaV1>;
/// Composite postcommit lifecycle transaction authority.
pub type LifecyclePostcommitCapabilityV1 =
    DomainPostcommitCapabilityV1<LifecycleProtectedJournalSchemaV1>;
/// Current, consumed lifecycle transaction authority.
pub type ValidatedLifecyclePostcommitV1<'current> =
    ValidatedDomainPostcommitV1<'current, LifecycleProtectedJournalSchemaV1>;
/// Current lifecycle postcommit authority reconstructed during cold replay.
pub type ReplayedLifecyclePostcommitV1 =
    ReplayedDomainPostcommitV1<LifecycleProtectedJournalSchemaV1>;
/// Protected lifecycle journal owner.
pub type LifecycleProtectedJournalV1<'journal> =
    ProtectedDomainJournalV1<'journal, LifecycleProtectedJournalSchemaV1>;
/// Lifecycle adapter validation or durability failure.
pub type LifecycleProtectedJournalErrorV1 = ProtectedDomainJournalErrorV1;

/// Constructs the canonical key for one lifecycle operation subject.
///
/// # Errors
///
/// Returns [`LifecycleProtectedJournalErrorV1`] only if the fixed typed
/// identity cannot be represented by the bounded key schema.
pub fn lifecycle_protected_key_v1(
    kind: LifecycleProtectedRecordKindV1,
    project: ProjectId,
    namespace: ResourceId,
    operation: OperationId,
) -> Result<LifecycleProtectedJournalKeyV1, LifecycleProtectedJournalErrorV1> {
    if project.as_bytes() == &[0; 16]
        || namespace.as_bytes() == &[0; 16]
        || operation.as_bytes() == &[0; 16]
    {
        return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let mut identity = Vec::with_capacity(LIFECYCLE_PROTECTED_IDENTITY_BYTES);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(namespace.as_bytes());
    identity.extend_from_slice(operation.as_bytes());
    LifecycleProtectedJournalKeyV1::new(kind, identity).map_err(ProtectedDomainJournalErrorV1::from)
}

/// Claims the dormant lifecycle adapter over an already protected-open journal.
pub(crate) fn claim_lifecycle_protected_journal_v1(
    journal: &mut Journal,
    verifier: LifecycleJournalVerifierV1,
) -> Result<LifecycleProtectedJournalV1<'_>, LifecycleProtectedJournalErrorV1> {
    LifecycleProtectedJournalV1::claim_with_validator(journal, verifier)
}

/// Wraps one reducer-issued canonical lifecycle body for journal admission.
pub(crate) fn lifecycle_reducer_envelope_v1(
    key: LifecycleProtectedJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    record: LifecycleReducerRecordV1<'_>,
    verifier: &LifecycleJournalVerifierV1,
) -> Result<LifecycleProtectedJournalEnvelopeV1, LifecycleProtectedJournalErrorV1> {
    lifecycle_reducer_envelope_with_record_digest_v2(key, revision, predecessor, record, verifier, None)
}

// The same encoder lends only its exact canonical operation digest. This DATA
// becomes completion evidence only after the caller's actual commit/readback
// and independently owed native posts have completed.
pub(crate) fn lifecycle_reducer_envelope_with_record_digest_v2(
    key: LifecycleProtectedJournalKeyV1, revision: u64, predecessor: Option<ObjectDigest>,
    record: LifecycleReducerRecordV1<'_>, verifier: &LifecycleJournalVerifierV1,
    digest: Option<&mut Option<super::LifecycleRecordDigestV1>>,
) -> Result<LifecycleProtectedJournalEnvelopeV1, LifecycleProtectedJournalErrorV1> {
    let is_operation = matches!(&record, LifecycleReducerRecordV1::Operation(_));
    let body = match record {
        LifecycleReducerRecordV1::Operation(operation)
            if operation.project().as_bytes() == &key.identity()[..16]
                && lifecycle_journal_subject(operation.intent()).as_slice()
                    == &key.identity()[16..32]
                && operation.operation_id().as_bytes() == &key.identity()[32..48]
                && operation_phase(key.kind(), operation.phase() as u8).is_some() =>
        {
            super::format::encode_retained_operation_record(operation)
        }
        LifecycleReducerRecordV1::Idempotency(record)
            if key.kind() == LifecycleProtectedRecordKindV1::Idempotency
                && record.kind() == LifecycleJournalRecordKindV1::Idempotency
                && record.project().as_bytes() == &key.identity()[..16]
                && record.namespace().as_bytes() == &key.identity()[16..32]
                && record
                    .operation()
                    .is_some_and(|operation| operation.as_bytes() == &key.identity()[32..48]) =>
        {
            encode_lifecycle_journal_record_v1(record)
        }
        LifecycleReducerRecordV1::Auxiliary(record)
            if key.kind() == LifecycleProtectedRecordKindV1::Auxiliary
                && record.project().as_bytes() == &key.identity()[..16]
                && record.lineage().as_bytes() == &key.identity()[16..32]
                && record.operation().as_bytes() == &key.identity()[32..48] =>
        {
            encode_lifecycle_auxiliary_record_v1(record)
        }
        LifecycleReducerRecordV1::Operation(_)
        | LifecycleReducerRecordV1::Idempotency(_)
        | LifecycleReducerRecordV1::Auxiliary(_) => {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
    }
    .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
    if let Some(digest) = digest {
        if !is_operation || digest.is_some() {
            return Err(LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        *digest = Some(super::format::record_digest(&body)
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?);
    }
    let payload = encode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
        &key, &body, verifier,
    )?;
    LifecycleProtectedJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        verifier,
    ).map_err(ProtectedDomainJournalErrorV1::from)
}
