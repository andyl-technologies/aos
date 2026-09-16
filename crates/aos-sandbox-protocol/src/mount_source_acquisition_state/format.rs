//! Exact `AOSMSA02` namespace-40 framing, keys, and digest domains.
//!
//! ```text
//! {"schema":"AOSMSA02","version":2,"record":{"record_kind":...}}
//! ```
//!
//! Values and record bodies must be canonical serde JSON. Arbitrary byte
//! strings are lowercase hexadecimal JSON strings, never decimal arrays; this
//! fixes their maximum materialized expansion at exactly two characters per
//! byte. Keys select exactly one of the five v2 record kinds; a v1 prefix is
//! never recognized. Every value is independently limited to 4 MiB, including
//! its envelope, field names, arrays, and retained signed bytes. Signed
//! protocol objects retain their tighter 1 MiB ceiling. A valid table has at
//! most 1,024 acquisitions and holder-sequence floors, 256 heads, 4,096
//! immutable sessions, and 65,536 immutable attempts, with at most 64 attempts
//! in one intent lineage.
//!
//! ```text
//! keys:
//!   aos.mount.source-acquisition.v2\0 || acquisition_id[32]                 (64 bytes)
//!   aos.mount.source-provider-head.v2\0 || holder_id[16] || provider_id[16] (66 bytes)
//!   aos.mount.source-holder-sequence.v2\0 || holder_id[16]                  (52 bytes)
//!   aos.mount.source-provider-session.v2\0 || session_id[32]                (69 bytes)
//!   aos.mount.source-provider-query-attempt.v2\0 || attempt_id[32]          (75 bytes)
//! record digest domains:
//!   aos.sandbox.mount.source-acquisition-record.v2\0
//!   aos.sandbox.mount.source-provider-head-record.v2\0
//!   aos.sandbox.mount.source-holder-sequence-record.v2\0
//!   aos.sandbox.mount.source-provider-session-record.v2\0
//!   aos.sandbox.mount.source-provider-query-attempt-record.v2\0
//! ```
//!
//! ```text
//! Acquisition (<=4 MiB): distinct Mount/provider identities, revision/phase/
//!   scope, exact Mount bodies, immutable intents and lineages,
//!   assignment/template/binding/plan facts,
//!   provider/lease/resource/descriptor evidence, custody/consumption, closed
//!   Release proof, fault/recovery state, and record digest.
//! ProviderHead (<=4 MiB): scope/current authority/session, direction heads,
//!   pending attempt, Inventory floor/ordinal, projection/reconciliation,
//!   recovery barrier, and record digest.
//! HolderSequence (<=4 MiB): stable holder ID, exact last allocated and next
//!   never-reused acquisition sequence, revision, and record digest.
//! ProviderSession (<=4 MiB): immutable scope/node/boot, authority/route,
//!   capabilities, exact hellos, authority/four-signer trust, trusted clock,
//!   actual Root writer/provider execution, and record digest.
//! ProviderQueryAttempt (<=4 MiB): identity/scope/method/owner/intent/lineage,
//!   immutable session/currentness snapshots, authority-scoped provider
//!   acquisition identity, AOSNPI01 version-2 normalization, sequence/exact signed
//!   request, compact pre-reservation owner-record witness, closed outcome/
//!   recovery state, and digest. Only the initial Acquire omits that witness.
//! ```
//!
//! A Reserved attempt body is at most 2,616,320 bytes. Its terminal state can
//! add at most 1,576,960 bytes: two hexadecimal characters for each byte in
//! the 768 KiB aggregate signed-object allowance, plus 4 KiB for fixed JSON
//! structure. The fixed envelope allowance is 1,024 bytes, so
//! `2,616,320 + 1,576,960 + 1,024 == 4,194,304`. Reservation must satisfy this
//! bound before provider I/O; every canonical terminal value therefore fits
//! the 4 MiB record limit.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use super::model::{
    ManagerCustodyEvidenceV2, ManagerCustodyLossEvidenceV2, ManagerCustodyLossKindV2,
    ManagerCustodyOriginV2, ProviderIntentV2, SourceProviderQueryAttemptV2,
    SourceProviderSessionV2, StoredEnvelopeV2, StoredRecordV2,
};
use super::{MountSourceAcquisitionStateError, Result};

pub const SCHEMA: &str = "AOSMSA02";
pub const FORMAT_VERSION: u16 = 2;
pub const MAXIMUM_VALUE_BYTES: usize = 4 * 1024 * 1024;
pub const MAXIMUM_ACQUISITION_VALUE_BYTES: usize = MAXIMUM_VALUE_BYTES;
pub const MAXIMUM_PROVIDER_HEAD_VALUE_BYTES: usize = MAXIMUM_VALUE_BYTES;
pub const MAXIMUM_HOLDER_SEQUENCE_VALUE_BYTES: usize = MAXIMUM_VALUE_BYTES;
pub const MAXIMUM_PROVIDER_SESSION_VALUE_BYTES: usize = MAXIMUM_VALUE_BYTES;
pub const MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES: usize = MAXIMUM_VALUE_BYTES;
pub const MAXIMUM_SIGNED_PROVIDER_BYTES: usize = 1024 * 1024;
const COMPANION_RECORD_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-acquisition-companion.v2\0";
/// Bounds the simultaneous exact request, status, and result retained by an attempt.
///
/// SourceProvider's method-specific decoders impose tighter individual shapes:
/// the largest Inventory result is 704,944 bytes, while its fixed request and
/// status fit in the remaining allowance. Acquire and Release have smaller
/// bounded results, including Acquire's separately bounded nested lease. Hex
/// encoding leaves the rest of the record for intent and predecessor evidence.
pub const MAXIMUM_PROVIDER_ATTEMPT_SIGNED_BYTES: usize = 768 * 1024;
/// Bounds one compact canonical owner-predecessor witness.
pub const MAXIMUM_OWNER_PREDECESSOR_WITNESS_BYTES: usize = 256 * 1024;
/// Reserves enough materialization space for every valid terminal disposition.
///
/// A terminal state adds at most two hexadecimal characters per retained
/// signed byte plus a fixed 4 KiB of JSON names, punctuation, scalar values,
/// and enum tags. A Reserved attempt must fit below the complementary bound
/// before provider I/O begins.
pub const MAXIMUM_PROVIDER_OUTCOME_MATERIALIZATION_BYTES: usize =
    2 * MAXIMUM_PROVIDER_ATTEMPT_SIGNED_BYTES + 4 * 1024;
pub const MAXIMUM_AOSMSA02_ENVELOPE_BYTES: usize = 1024;
pub const MAXIMUM_RESERVED_PROVIDER_ATTEMPT_BYTES: usize = MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES
    - MAXIMUM_PROVIDER_OUTCOME_MATERIALIZATION_BYTES
    - MAXIMUM_AOSMSA02_ENVELOPE_BYTES;
pub const MAXIMUM_LINEAGE_ATTEMPTS: usize = 64;

const MAXIMUM_SIGNED_INVENTORY_RESULT_BYTES: usize =
    432 + 344 * aos_sandbox_source_provider_protocol::MAXIMUM_INVENTORY_ENTRIES;

/// Commits one exact companion record used by the atomic consumption edge.
///
/// The namespace is the stable journal namespace number. `value` is `None`
/// only for callers validating a forbidden deletion; the consumption journal
/// authority itself accepts PUT records exclusively.
#[must_use]
pub fn mount_source_consumption_companion_digest_v2(
    namespace: u16,
    key: &[u8],
    value: Option<&[u8]>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(COMPANION_RECORD_DIGEST_DOMAIN);
    digest.update(namespace.to_be_bytes());
    digest.update((key.len() as u64).to_be_bytes());
    digest.update(key);
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        None => digest.update([0]),
    }
    digest.finalize().into()
}

pub const MAXIMUM_SOURCE_ACQUISITIONS: usize = 1_024;
pub const MAXIMUM_SOURCE_PROVIDER_HEADS: usize = 256;
pub const MAXIMUM_SOURCE_HOLDER_SEQUENCES: usize = MAXIMUM_SOURCE_ACQUISITIONS;
pub const MAXIMUM_SOURCE_PROVIDER_SESSIONS: usize = 4_096;
pub const MAXIMUM_SOURCE_PROVIDER_ATTEMPTS: usize = 65_536;

pub mod canonical_bytes {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        decode_hex(&encoded).map_err(serde::de::Error::custom)
    }
}

pub mod canonical_optional_bytes {
    use super::*;

    pub fn serialize<S>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(value) => serializer.serialize_some(&encode_hex(value)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|encoded| decode_hex(&encoded).map_err(serde::de::Error::custom))
            .transpose()
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(encoded: &str) -> std::result::Result<Vec<u8>, &'static str> {
    if encoded.len() % 2 != 0 {
        return Err("canonical byte string has odd hexadecimal length");
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks_exact(2) {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

const fn decode_nibble(value: u8) -> std::result::Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("canonical byte string is not lowercase hexadecimal"),
    }
}

const ACQUISITION_KEY_PREFIX: &[u8] = b"aos.mount.source-acquisition.v2\0";
const PROVIDER_HEAD_KEY_PREFIX: &[u8] = b"aos.mount.source-provider-head.v2\0";
const HOLDER_SEQUENCE_KEY_PREFIX: &[u8] = b"aos.mount.source-holder-sequence.v2\0";
const PROVIDER_SESSION_KEY_PREFIX: &[u8] = b"aos.mount.source-provider-session.v2\0";
const PROVIDER_ATTEMPT_KEY_PREFIX: &[u8] = b"aos.mount.source-provider-query-attempt.v2\0";

const ACQUISITION_RECORD_DOMAIN: &[u8] = b"aos.sandbox.mount.source-acquisition-record.v2\0";
const PROVIDER_HEAD_RECORD_DOMAIN: &[u8] = b"aos.sandbox.mount.source-provider-head-record.v2\0";
const HOLDER_SEQUENCE_RECORD_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-holder-sequence-record.v2\0";
const PROVIDER_SESSION_RECORD_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-provider-session-record.v2\0";
const PROVIDER_ATTEMPT_RECORD_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-provider-query-attempt-record.v2\0";
const SESSION_ID_DOMAIN: &[u8] = b"aos.sandbox.mount.source-provider-session-id.v2\0";
const ATTEMPT_ID_DOMAIN: &[u8] = b"aos.sandbox.mount.source-provider-query-attempt-id.v2\0";
const REQUEST_ID_DOMAIN: &[u8] = b"aos.sandbox.mount.source-provider-request-id.v2\0";
const ACQUIRE_INTENT_DOMAIN: &[u8] = b"aos.sandbox.mount.source-acquire-intent.v2\0";
const RELEASE_INTENT_DOMAIN: &[u8] = b"aos.sandbox.mount.source-release-intent.v2\0";
const INVENTORY_INTENT_DOMAIN: &[u8] = b"aos.sandbox.mount.source-inventory-intent.v2\0";
const EXECUTION_DOMAIN: &[u8] = b"aos.sandbox.mount.source-provider-execution.v2\0";
const DEATH_DOMAIN: &[u8] = b"aos.sandbox.mount.dead-provider-execution.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.mount.source-acquisition-transaction.v2\0";
const INVENTORY_CORRELATION_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-provider-inventory-correlation.v2\0";
const MANAGER_CUSTODY_EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.mount-manager.custody-evidence.v2\0";
const MANAGER_CUSTODY_LOSS_EVIDENCE_DOMAIN: &[u8] =
    b"aos.sandbox.mount-manager.custody-loss-evidence.v2\0";

/// Reproduces the compact manager-custody evidence digest persisted in a row.
#[must_use]
pub fn manager_custody_evidence_digest_v2(evidence: &ManagerCustodyEvidenceV2) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MANAGER_CUSTODY_EVIDENCE_DOMAIN);
    hasher.update([match evidence.origin {
        ManagerCustodyOriginV2::FreshControlReadback => 1,
        ManagerCustodyOriginV2::StartupCapture => 2,
    }]);
    update_record_ref(&mut hasher, evidence.admission_predecessor);
    update_record_ref(&mut hasher, evidence.owner_attempt);
    hasher.update(evidence.owner_session_id);
    hasher.update(evidence.owner_session_record_digest);
    hasher.update(evidence.manager_kernel_boot_id);
    hasher.update(evidence.manager_execution_commitment);
    hasher.update(evidence.capture_sequence.to_be_bytes());
    hasher.update(evidence.capture_id);
    hasher.update(evidence.capture_record_digest);
    hasher.update(evidence.descriptor_count.to_be_bytes());
    hasher.update(evidence.activation_count.to_be_bytes());
    hasher.update(evidence.expected_descriptor_count.to_be_bytes());
    hasher.update(evidence.source_subject_count.to_be_bytes());
    hasher.update(evidence.cleanup_subject_count.to_be_bytes());
    hasher.update(evidence.terminal_subject_count.to_be_bytes());
    hasher.update(evidence.source_entry_commitment);
    hasher.update(evidence.presence_commitment);
    hasher.finalize().into()
}

/// Reproduces the compact manager-custody loss digest persisted in a row.
#[must_use]
pub fn manager_custody_loss_evidence_digest_v2(
    evidence: &ManagerCustodyLossEvidenceV2,
) -> [u8; 32] {
    use crate::mount_manager_startup::StartupCleanupPhaseV1;

    let mut hasher = Sha256::new();
    hasher.update(MANAGER_CUSTODY_LOSS_EVIDENCE_DOMAIN);
    let subject = evidence.subject;
    hasher.update(subject.acquisition_id);
    hasher.update(subject.acquisition_revision.to_be_bytes());
    hasher.update(subject.acquisition_record_digest);
    hasher.update([match subject.phase {
        StartupCleanupPhaseV1::PendingQuery => 1,
        StartupCleanupPhaseV1::DescriptorCustodied => 2,
        StartupCleanupPhaseV1::Active => 3,
        StartupCleanupPhaseV1::Consumed => 4,
    }]);
    hasher.update(subject.acquire_attempt_id);
    hasher.update(subject.acquire_attempt_revision.to_be_bytes());
    hasher.update(subject.acquire_attempt_record_digest);
    match subject.evidence {
        Some(source) => {
            hasher.update([1]);
            hasher.update(source.source_realization_handle);
            hasher.update(source.descriptor_commitment);
            hasher.update(source.source_kernel_boot_id);
            hasher.update(source.source_device.to_be_bytes());
            hasher.update(source.source_inode.to_be_bytes());
            hasher.update(source.source_unique_mount_id.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    match subject.last_custody_owner {
        Some(owner) => {
            hasher.update([1]);
            hasher.update(owner.attempt_id);
            hasher.update(owner.attempt_revision.to_be_bytes());
            hasher.update(owner.attempt_record_digest);
            hasher.update(owner.session_id);
            hasher.update(owner.session_record_digest);
            hasher.update(owner.kernel_boot_id);
            hasher.update(owner.tgid.to_be_bytes());
            hasher.update(owner.start_time_ticks.to_be_bytes());
            hasher.update(owner.cgroup_digest);
        }
        None => hasher.update([0]),
    }
    hasher.update(evidence.capture_id);
    hasher.update(evidence.capture_record_digest);
    hasher.update([match evidence.kind {
        ManagerCustodyLossKindV2::NoPriorCustody => 1,
        ManagerCustodyLossKindV2::BootReplaced => 2,
        ManagerCustodyLossKindV2::PidfdExited => 3,
        ManagerCustodyLossKindV2::ProcessReplaced => 4,
    }]);
    hasher.update(evidence.death_commitment);
    hasher.finalize().into()
}

fn update_record_ref(hasher: &mut Sha256, reference: super::model::RecordRefV2) {
    hasher.update(reference.id);
    hasher.update(reference.revision.to_be_bytes());
    hasher.update(reference.record_digest);
}

/// Identifies the record kind selected by one exact namespace-40 key.
#[derive(Clone, Copy)]
pub enum RecordKindV2 {
    Acquisition,
    ProviderHead,
    HolderSequence,
    ProviderSession,
    ProviderQueryAttempt,
}

/// Names each bounded five-record-or-smaller AOSMSA02 transaction shape.
#[derive(Clone, Copy)]
pub enum MutationTagV2 {
    InitialAdmission = 1,
    ReserveRetry = 2,
    ConsumeOutcome = 3,
    CompleteInventory = 4,
    IdleReplacement = 5,
    DeadReplacement = 6,
    RecoveryCompletion = 7,
    Custody = 8,
    Activation = 9,
    Consumption = 10,
    BeginRelease = 11,
    FinishRelease = 12,
    Fault = 13,
    StartupCustodyRebind = 14,
    BackendRecoveryReplacement = 15,
}

pub(crate) fn state_error(message: &'static str) -> MountSourceAcquisitionStateError {
    MountSourceAcquisitionStateError::Invalid(message)
}

pub fn acquisition_key(id: [u8; 32]) -> Vec<u8> {
    key(ACQUISITION_KEY_PREFIX, &[&id])
}

pub fn provider_head_key(holder: [u8; 16], provider: [u8; 16]) -> Vec<u8> {
    key(PROVIDER_HEAD_KEY_PREFIX, &[&holder, &provider])
}

pub fn holder_sequence_key(holder: [u8; 16]) -> Vec<u8> {
    key(HOLDER_SEQUENCE_KEY_PREFIX, &[&holder])
}

pub fn provider_session_key(id: [u8; 32]) -> Vec<u8> {
    key(PROVIDER_SESSION_KEY_PREFIX, &[&id])
}

pub fn provider_attempt_key(id: [u8; 32]) -> Vec<u8> {
    key(PROVIDER_ATTEMPT_KEY_PREFIX, &[&id])
}

/// Classifies one exact v2 key before materializing its bounded value.
pub fn key_kind(key: &[u8]) -> Result<RecordKindV2> {
    match key {
        value if value.len() == 64 && value.starts_with(ACQUISITION_KEY_PREFIX) => {
            Ok(RecordKindV2::Acquisition)
        }
        value if value.len() == 66 && value.starts_with(PROVIDER_HEAD_KEY_PREFIX) => {
            Ok(RecordKindV2::ProviderHead)
        }
        value
            if value.len() == HOLDER_SEQUENCE_KEY_PREFIX.len() + 16
                && value.starts_with(HOLDER_SEQUENCE_KEY_PREFIX) =>
        {
            Ok(RecordKindV2::HolderSequence)
        }
        value if value.len() == 69 && value.starts_with(PROVIDER_SESSION_KEY_PREFIX) => {
            Ok(RecordKindV2::ProviderSession)
        }
        value if value.len() == 75 && value.starts_with(PROVIDER_ATTEMPT_KEY_PREFIX) => {
            Ok(RecordKindV2::ProviderQueryAttempt)
        }
        _ => Err(state_error("unsupported AOSMSA02 namespace-40 key")),
    }
}

fn key(prefix: &[u8], suffixes: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        prefix.len() + suffixes.iter().map(|suffix| suffix.len()).sum::<usize>(),
    );
    bytes.extend_from_slice(prefix);
    for suffix in suffixes {
        bytes.extend_from_slice(suffix);
    }
    bytes
}

/// Decodes and authenticates one exact canonical v2 envelope.
pub(crate) fn decode_value(key_bytes: &[u8], value: &[u8]) -> Result<StoredRecordV2> {
    let maximum = match key_kind(key_bytes)? {
        RecordKindV2::Acquisition => MAXIMUM_ACQUISITION_VALUE_BYTES,
        RecordKindV2::ProviderHead => MAXIMUM_PROVIDER_HEAD_VALUE_BYTES,
        RecordKindV2::HolderSequence => MAXIMUM_HOLDER_SEQUENCE_VALUE_BYTES,
        RecordKindV2::ProviderSession => MAXIMUM_PROVIDER_SESSION_VALUE_BYTES,
        RecordKindV2::ProviderQueryAttempt => MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES,
    };
    if value.len() > maximum {
        return Err(state_error("AOSMSA02 value exceeds its fixed bound"));
    }
    let envelope: StoredEnvelopeV2 =
        serde_json::from_slice(value).map_err(|_| state_error("invalid AOSMSA02 JSON envelope"))?;
    if envelope.schema != SCHEMA || envelope.version != FORMAT_VERSION {
        return Err(state_error("unsupported Mount source acquisition format"));
    }
    if serde_json::to_vec(&envelope).map_err(|_| state_error("cannot encode AOSMSA02"))? != value {
        return Err(state_error("noncanonical AOSMSA02 JSON encoding"));
    }
    if key_bytes != record_key(&envelope.record)
        || record_digest(&envelope.record)? != stored_digest(&envelope.record)
    {
        return Err(state_error("AOSMSA02 key or record digest mismatch"));
    }
    Ok(envelope.record)
}

/// Seals one private record with its exact kind-specific digest.
pub fn seal_record(mut record: StoredRecordV2) -> Result<StoredRecordV2> {
    let digest = record_digest(&record)?;
    match &mut record {
        StoredRecordV2::Acquisition { value } => value.record_digest = digest,
        StoredRecordV2::ProviderHead { value } => value.record_digest = digest,
        StoredRecordV2::HolderSequence { value } => value.record_digest = digest,
        StoredRecordV2::ProviderSession { value } => value.record_digest = digest,
        StoredRecordV2::ProviderQueryAttempt { value } => value.record_digest = digest,
    }
    Ok(record)
}

/// Encodes one sealed canonical namespace-40 key and value.
pub fn encode_mount_source_state_record_v2(record: &StoredRecordV2) -> Result<(Vec<u8>, Vec<u8>)> {
    if record_digest(record)? != stored_digest(record) {
        return Err(state_error("cannot encode an unsealed AOSMSA02 record"));
    }
    let key = record_key(record);
    let envelope = StoredEnvelopeV2 {
        schema: SCHEMA.to_owned(),
        version: FORMAT_VERSION,
        record: record.clone(),
    };
    let value = serde_json::to_vec(&envelope)
        .map_err(|_| state_error("cannot encode canonical AOSMSA02 record"))?;
    let maximum = match record {
        StoredRecordV2::Acquisition { .. } => MAXIMUM_ACQUISITION_VALUE_BYTES,
        StoredRecordV2::ProviderHead { .. } => MAXIMUM_PROVIDER_HEAD_VALUE_BYTES,
        StoredRecordV2::HolderSequence { .. } => MAXIMUM_HOLDER_SEQUENCE_VALUE_BYTES,
        StoredRecordV2::ProviderSession { .. } => MAXIMUM_PROVIDER_SESSION_VALUE_BYTES,
        StoredRecordV2::ProviderQueryAttempt { .. } => MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES,
    };
    if value.len() > maximum {
        return Err(state_error(
            "canonical AOSMSA02 record exceeds its kind bound",
        ));
    }
    Ok((key, value))
}

fn record_key(record: &StoredRecordV2) -> Vec<u8> {
    match record {
        StoredRecordV2::Acquisition { value } => acquisition_key(value.acquisition_id),
        StoredRecordV2::ProviderHead { value } => provider_head_key(
            value.scope.holder_authority_id,
            value.scope.provider_authority_id,
        ),
        StoredRecordV2::HolderSequence { value } => holder_sequence_key(value.holder_authority_id),
        StoredRecordV2::ProviderSession { value } => provider_session_key(value.session_id),
        StoredRecordV2::ProviderQueryAttempt { value } => provider_attempt_key(value.attempt_id),
    }
}

fn stored_digest(record: &StoredRecordV2) -> [u8; 32] {
    match record {
        StoredRecordV2::Acquisition { value } => value.record_digest,
        StoredRecordV2::ProviderHead { value } => value.record_digest,
        StoredRecordV2::HolderSequence { value } => value.record_digest,
        StoredRecordV2::ProviderSession { value } => value.record_digest,
        StoredRecordV2::ProviderQueryAttempt { value } => value.record_digest,
    }
}

pub fn record_digest(record: &StoredRecordV2) -> Result<[u8; 32]> {
    match record {
        StoredRecordV2::Acquisition { value } => {
            let mut zeroed = value.clone();
            zeroed.record_digest = [0; 32];
            hash_serialized(ACQUISITION_RECORD_DOMAIN, &zeroed)
        }
        StoredRecordV2::ProviderHead { value } => {
            let mut zeroed = value.clone();
            zeroed.record_digest = [0; 32];
            hash_serialized(PROVIDER_HEAD_RECORD_DOMAIN, &zeroed)
        }
        StoredRecordV2::HolderSequence { value } => {
            let mut zeroed = value.clone();
            zeroed.record_digest = [0; 32];
            hash_serialized(HOLDER_SEQUENCE_RECORD_DOMAIN, &zeroed)
        }
        StoredRecordV2::ProviderSession { value } => {
            let mut zeroed = value.clone();
            zeroed.record_digest = [0; 32];
            hash_serialized(PROVIDER_SESSION_RECORD_DOMAIN, &zeroed)
        }
        StoredRecordV2::ProviderQueryAttempt { value } => {
            let mut zeroed = value.clone();
            zeroed.record_digest = [0; 32];
            hash_serialized(PROVIDER_ATTEMPT_RECORD_DOMAIN, &zeroed)
        }
    }
}

pub fn intent_digest(intent: &ProviderIntentV2) -> Result<[u8; 32]> {
    let (domain, bytes) = match intent {
        ProviderIntentV2::Acquire { value } => {
            let mut bytes = scope_bytes(value.scope);
            bytes.extend_from_slice(&value.acquisition_id);
            push_bytes(&mut bytes, &value.mount_request)?;
            bytes.extend_from_slice(&value.mount_request_digest);
            push_assignment(&mut bytes, value.assignment);
            bytes.extend_from_slice(&value.mount_plan_digest);
            bytes.extend_from_slice(&value.ownership_lease_digest);
            push_bytes(&mut bytes, &value.prospective_mount_template)?;
            bytes.extend_from_slice(&value.prospective_mount_template_digest);
            push_bytes(&mut bytes, &value.source_binding)?;
            bytes.extend_from_slice(&value.source_binding_digest);
            bytes.extend_from_slice(&value.requested_lease_seconds.to_be_bytes());
            bytes.extend_from_slice(&value.requested_maximum_submounts.to_be_bytes());
            bytes.push(u8::from(value.recursive));
            bytes.push(u8::from(value.kernel_coupled));
            (ACQUIRE_INTENT_DOMAIN, bytes)
        }
        ProviderIntentV2::Release { value } => {
            let mut bytes = scope_bytes(value.scope);
            bytes.extend_from_slice(&value.acquisition_id);
            push_provider_acquisition(&mut bytes, value.provider_acquisition);
            push_bytes(&mut bytes, &value.mount_request)?;
            bytes.extend_from_slice(&value.mount_operation.operation_id);
            bytes.extend_from_slice(&value.mount_operation.request_digest);
            bytes.extend_from_slice(&value.authority.sandbox_id);
            bytes.extend_from_slice(&value.authority.incarnation_id);
            bytes.extend_from_slice(&value.authority.assignment_epoch.to_be_bytes());
            bytes.extend_from_slice(&value.authority.desired_generation.to_be_bytes());
            bytes.extend_from_slice(&value.authority.assignment_digest);
            bytes.extend_from_slice(&value.authority.expected_revision.to_be_bytes());
            bytes.extend_from_slice(&value.authority.expected_record_digest);
            bytes.extend_from_slice(&value.lease_id);
            bytes.extend_from_slice(&value.signed_lease_digest);
            bytes.extend_from_slice(&value.provider_resource_id);
            bytes.extend_from_slice(&value.provider_resource_digest);
            bytes.extend_from_slice(&value.provider_proof_digest);
            bytes.extend_from_slice(&value.descriptor_commitment);
            (RELEASE_INTENT_DOMAIN, bytes)
        }
        ProviderIntentV2::Inventory { value } => {
            let mut bytes = scope_bytes(value.scope);
            push_optional_u64(&mut bytes, value.known_inventory_generation);
            push_optional_digest(&mut bytes, value.known_inventory_digest);
            push_optional_u64(&mut bytes, value.known_catalog_generation);
            push_optional_digest(&mut bytes, value.known_catalog_digest);
            bytes.extend_from_slice(&value.known_observation_ordinal.to_be_bytes());
            push_optional_digest(&mut bytes, value.recovery_root_attempt_id);
            bytes.extend_from_slice(&value.correlation_digest);
            (INVENTORY_INTENT_DOMAIN, bytes)
        }
    };
    Ok(hash_parts(domain, &[&bytes]))
}

fn push_provider_acquisition(
    bytes: &mut Vec<u8>,
    value: super::model::ProviderAcquisitionIdentityV2,
) {
    bytes.extend_from_slice(&value.holder_authority_id);
    bytes.extend_from_slice(&value.holder_authority_generation.to_be_bytes());
    bytes.extend_from_slice(&value.holder_authority_digest);
    bytes.extend_from_slice(&value.acquisition_sequence.to_be_bytes());
    bytes.extend_from_slice(&value.acquisition_id);
}

fn hash_serialized<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| state_error("cannot encode canonical AOSMSA02 digest input"))?;
    Ok(hash_parts(domain, &[&bytes]))
}

pub fn session_id(session: &SourceProviderSessionV2) -> [u8; 32] {
    hash_parts(
        SESSION_ID_DOMAIN,
        &[
            &session.scope.holder_authority_id,
            &session.scope.provider_authority_id,
            &session.scope.route_id,
            &session.node_id,
            &session.kernel_boot_id,
            &session.session_binding,
            &session.signer_set_commitment,
            &session.actual_writer_root_mount_process.uid.to_be_bytes(),
            &session.actual_writer_root_mount_process.gid.to_be_bytes(),
            &session.actual_writer_root_mount_process.tgid.to_be_bytes(),
            &session
                .actual_writer_root_mount_process
                .start_time_ticks
                .to_be_bytes(),
            &session.actual_writer_root_mount_process.cgroup_digest,
            &session.provider_process_instance,
            &session.provider_execution.process_execution_digest,
            &session.current_valid_until_seconds.to_be_bytes(),
        ],
    )
}

pub fn attempt_id(attempt: &SourceProviderQueryAttemptV2) -> [u8; 32] {
    let zero = [0; 32];
    let previous = attempt.previous_attempt_id.as_ref().unwrap_or(&zero);
    let owner = attempt.owner.owner_id();
    let owner_tag = [attempt.owner.tag()];
    let number = attempt.attempt_number.to_be_bytes();
    let sequence = attempt.request_sequence.to_be_bytes();
    hash_parts(
        ATTEMPT_ID_DOMAIN,
        &[
            &owner_tag,
            &owner,
            &attempt.immutable_intent_digest,
            previous,
            &number,
            &attempt.session_id,
            &sequence,
        ],
    )
}

pub fn request_id(attempt_id: [u8; 32]) -> [u8; 16] {
    let digest = hash_parts(REQUEST_ID_DOMAIN, &[&attempt_id]);
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

pub fn execution_digest(session: &SourceProviderSessionV2) -> Result<[u8; 32]> {
    let value = session.provider_execution;
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&value.pid.to_be_bytes());
    bytes.extend_from_slice(&value.tgid.to_be_bytes());
    bytes.extend_from_slice(&value.ppid.to_be_bytes());
    bytes.extend_from_slice(&value.start_time_ticks.to_be_bytes());
    bytes.extend_from_slice(&value.cgroup_id.to_be_bytes());
    for credential in [
        value.real_uid,
        value.effective_uid,
        value.saved_uid,
        value.filesystem_uid,
        value.real_gid,
        value.effective_gid,
        value.saved_gid,
        value.filesystem_gid,
    ] {
        bytes.extend_from_slice(&credential.to_be_bytes());
    }
    Ok(hash_parts(EXECUTION_DOMAIN, &[&bytes]))
}

pub fn death_digest(value: &super::model::DeadProviderExecutionProjectionV2) -> Result<[u8; 32]> {
    let proof = [match value.proof_kind {
        super::model::DeadProviderExecutionProofKindV2::PidfdExited => 1,
        super::model::DeadProviderExecutionProofKindV2::BootReplaced => 2,
    }];
    Ok(hash_parts(
        DEATH_DOMAIN,
        &[
            &proof,
            &value.old_session_id,
            &value.old_session_record_digest,
            &value.node_id,
            &value.old_kernel_boot_id,
            &value.provider_process_instance,
            &value.process_execution_digest,
            &value.observed_kernel_boot_id,
        ],
    ))
}

fn scope_bytes(scope: super::model::ProviderScopeV2) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(&scope.holder_authority_id);
    bytes.extend_from_slice(&scope.provider_authority_id);
    bytes.extend_from_slice(&scope.route_id);
    bytes.extend_from_slice(&scope.resource_namespace_digest);
    bytes
}

fn push_assignment(bytes: &mut Vec<u8>, value: super::model::AssignmentV2) {
    bytes.extend_from_slice(&value.sandbox_id);
    bytes.extend_from_slice(&value.incarnation_id);
    bytes.extend_from_slice(&value.assignment_epoch.to_be_bytes());
    bytes.extend_from_slice(&value.desired_generation.to_be_bytes());
    bytes.extend_from_slice(&value.assignment_digest);
    bytes.extend_from_slice(&value.namespace_generation.to_be_bytes());
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length =
        u32::try_from(value.len()).map_err(|_| state_error("AOSMSA02 intent field exceeds u32"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn push_optional_u64(target: &mut Vec<u8>, value: Option<u64>) {
    target.push(u8::from(value.is_some()));
    target.extend_from_slice(&value.unwrap_or_default().to_be_bytes());
}

fn push_optional_digest(target: &mut Vec<u8>, value: Option<[u8; 32]>) {
    target.push(u8::from(value.is_some()));
    target.extend_from_slice(&value.unwrap_or([0; 32]));
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

/// Derives the fixed transaction identity used by the sealed transition layer.
#[allow(clippy::too_many_arguments)]
pub fn transaction_id(
    tag: MutationTagV2,
    holder_id: [u8; 16],
    provider_id: [u8; 16],
    next_holder_sequence_revision: u64,
    next_head_revision: u64,
    acquisition_id: Option<[u8; 32]>,
    next_row_revision: Option<u64>,
    attempt_id: Option<[u8; 32]>,
    next_attempt_revision: Option<u64>,
    session_id: Option<[u8; 32]>,
) -> [u8; 16] {
    let tag = [tag as u8];
    let holder_sequence = next_holder_sequence_revision.to_be_bytes();
    let head = next_head_revision.to_be_bytes();
    let row = next_row_revision.unwrap_or_default().to_be_bytes();
    let attempt_revision = next_attempt_revision.unwrap_or_default().to_be_bytes();
    let digest = hash_parts(
        TRANSACTION_DOMAIN,
        &[
            &tag,
            &holder_id,
            &provider_id,
            &holder_sequence,
            &head,
            &acquisition_id.unwrap_or([0; 32]),
            &row,
            &attempt_id.unwrap_or([0; 32]),
            &attempt_revision,
            &session_id.unwrap_or([0; 32]),
        ],
    );
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// Seals one exact ordered Inventory correlation preimage.
///
/// # Errors
///
/// Returns an error for an empty or oversized set, noncanonical ordering,
/// duplicate identities, sentinel fields, or a mismatched acquisition record.
pub fn inventory_correlation_set_v2(
    entries: Vec<super::model::InventoryCorrelationV2>,
) -> Result<super::model::InventoryCorrelationSetV2> {
    use std::collections::BTreeSet;

    if entries.len() > aos_sandbox_source_provider_protocol::MAXIMUM_INVENTORY_ENTRIES
        || entries.windows(2).any(|pair| {
            pair[0].provider_acquisition.acquisition_id
                >= pair[1].provider_acquisition.acquisition_id
        })
    {
        return Err(state_error(
            "Inventory correlations are oversized or unordered",
        ));
    }
    let mut mount_ids = BTreeSet::new();
    let mut lease_ids = BTreeSet::new();
    for entry in &entries {
        if entry.mount_acquisition_id == [0; 32]
            || entry.provider_acquisition.acquisition_id == [0; 32]
            || entry.provider_acquisition.acquisition_sequence == 0
            || entry.lease_id.is_some() != entry.signed_lease_digest.is_some()
            || entry.lease_id == Some([0; 16])
            || entry.signed_lease_digest == Some([0; 32])
            || (entry.expectation
                == super::model::InventoryCorrelationExpectationV2::AbsentOrMatchingActive)
                != entry.lease_id.is_none()
            || entry.acquisition_record.id != entry.mount_acquisition_id
            || entry.acquisition_record.revision == 0
            || entry.acquisition_record.record_digest == [0; 32]
            || !mount_ids.insert(entry.mount_acquisition_id)
            || entry
                .lease_id
                .is_some_and(|lease_id| !lease_ids.insert(lease_id))
        {
            return Err(state_error("Inventory correlation identity is invalid"));
        }
    }
    let canonical = serde_json::to_vec(&entries)
        .map_err(|_| state_error("cannot encode Inventory correlations"))?;
    let digest = hash_parts(INVENTORY_CORRELATION_DOMAIN, &[&canonical]);
    Ok(super::model::InventoryCorrelationSetV2 { entries, digest })
}

/// Validates and recomputes an exact persisted Inventory correlation set.
///
/// # Errors
///
/// Returns an error unless the stored entries and digest are canonical.
pub fn validate_inventory_correlation_set_v2(
    value: &super::model::InventoryCorrelationSetV2,
) -> Result<()> {
    let rebuilt = inventory_correlation_set_v2(value.entries.clone())?;
    if &rebuilt != value {
        return Err(state_error("Inventory correlation digest differs"));
    }
    Ok(())
}

const _: () = assert!(ACQUISITION_KEY_PREFIX.len() + 32 == 64);
const _: () = assert!(PROVIDER_HEAD_KEY_PREFIX.len() + 32 == 66);
const _: () = assert!(HOLDER_SEQUENCE_KEY_PREFIX.len() + 16 == 52);
const _: () = assert!(PROVIDER_SESSION_KEY_PREFIX.len() + 32 == 69);
const _: () = assert!(PROVIDER_ATTEMPT_KEY_PREFIX.len() + 32 == 75);
const _: () = assert!(7 + 75 + MAXIMUM_VALUE_BYTES <= 4_194_386);
const _: () = assert!(5 * (7 + 75 + MAXIMUM_VALUE_BYTES) < 64 * 1024 * 1024);
const _: () = assert!(MAXIMUM_SIGNED_INVENTORY_RESULT_BYTES == 704_944);
const _: () = assert!(
    MAXIMUM_SIGNED_INVENTORY_RESULT_BYTES + 64 * 1024 <= MAXIMUM_PROVIDER_ATTEMPT_SIGNED_BYTES
);
const _: () = assert!(
    MAXIMUM_RESERVED_PROVIDER_ATTEMPT_BYTES
        + MAXIMUM_PROVIDER_OUTCOME_MATERIALIZATION_BYTES
        + MAXIMUM_AOSMSA02_ENVELOPE_BYTES
        == MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES
);
