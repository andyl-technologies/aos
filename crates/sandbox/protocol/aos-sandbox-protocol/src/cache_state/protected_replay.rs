//! Canonical Cache protected-envelope and historical family DATA validation.
//!
//! These codecs, schema labels and comparisons establish historical grammar
//! only. Native currentness, capabilities and effect admission remain upper.
//! Existing format-schema generics preserve the actual supplied typed records;
//! they do not construct an authority, effect owner or success token.
//!
//! ```text
//! AOSCRJ01 envelope -> reducer header -> closed Cache body -> AOSCOR01 event
//! ```

use std::collections::BTreeMap;
use aos_sandbox_model::{ObjectDigest, ProjectId, RecordNamespace};
use sha2::{Digest as _, Sha256};
use crate::domain_ledger::DomainLedgerDataError;
use crate::domain_ledger::records::{ProtectedDomainSchemaV1, ProtectedDomainKeyV1,
    ProtectedDomainEnvelopeV1, ProtectedDomainProjectionV1, ProtectedDomainReplayPhaseV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1, decode_reducer_payload_with_validator};
use super::{PhysicalPartitionId, recovery::{CacheRecoveryLimitsV1,
    decode_typed_checkpoint, encode_typed_checkpoint, decode_atomic_object_record,
    encode_atomic_object_record}, durable_format::{CacheDurableRecordV1, CacheRecordKindV1}};
use super::replay_envelope::{encode_partition_descriptor, decode_partition_descriptor};

const PARTITION_DESCRIPTOR_BYTES: usize = 241;
/// Canonical historical effect-observation authority-record key prefix.
pub const EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX: &[u8] = b"\0aos-cache-effect-observation-authority-v1\0";
const EFFECT_OBSERVATION_AUTHORITY_BYTES: usize = 192;

/// Selects one closed historical Cache envelope family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CacheResidencyProtectedRecordKindV1 {
    /// Stores the exact current capability and isolation-policy authority.
    Authority = 1,
    /// Stores node-global physical accounting.
    GlobalAccounting = 2,
    /// Stores project-attributed accounting under the global total.
    ProjectAccounting = 3,
    /// Stores disclosure-domain accounting under the project total.
    DomainAccounting = 4,
    /// Stores one capacity reservation generation.
    Reservation = 5,
    /// Stores one logical, source, kernel, or backing pin generation.
    Pin = 6,
    /// Stores a trusted scrub observation or quarantine decision.
    Scrub = 7,
    /// Stores a frozen eviction decision or reclamation observation.
    Eviction = 8,
    /// Stores immutable catalog reachability and backing identity.
    Catalog = 9,
    /// Stores a pre-effect admission, scrub, or unlink boundary.
    Effect = 10,
    /// Publishes the exact current cache projection.
    Current = 11,
    /// Publishes a replay join without granting compaction authority.
    Checkpoint = 12,
    /// Suppresses one cold effect after a trusted physical observation.
    EffectObservation = 13,
}

/// Classifies one historical Cache transaction without granting an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheResidencyTransactionKindV1 {
    /// Reserves capacity before any immutable destination work can escape.
    Admission,
    /// Changes a pin while updating all three accounting scopes atomically.
    PinChange,
    /// Commits a scrub or quarantine result after rechecking current pins.
    Scrub,
    /// Commits an eviction decision before releasing unlink authority.
    EvictionPrepare,
    /// Credits reclaimed bytes only after durable reclamation evidence.
    EvictionFinalize,
    /// Reconstructs an exact interrupted transition without broadening it.
    Recovery,
    /// Publishes a replay join for a future globally validated floor.
    Checkpoint,
}

/// Carries historical effect-observation fields without current authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheEffectObservationDataV1 {
    /// Historical transaction identity.
    pub transaction_id: [u8; 16],
    /// Historical transaction commitment.
    pub transaction_digest: ObjectDigest,
    /// Historical native observation commitment.
    pub evidence: ObjectDigest,
    /// Historical physical partition commitment.
    pub partition: ObjectDigest,
}

/// Defines the canonical historical Cache envelope grammar without Native authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CacheResidencyHistoricalSchemaDataV1;

impl ProtectedDomainSchemaV1 for CacheResidencyHistoricalSchemaDataV1 {
    type Kind = CacheResidencyProtectedRecordKindV1;
    type ReplayValidator = CacheRecoveryLimitsV1;

    const MAGIC: [u8; 8] = *b"AOSCRJ01";
    const HASH_DOMAIN: &'static [u8] = b"aos.sandbox.cache-residency.protected-journal.v1\0";
    const KEY_PREFIX: &'static [u8] = b"\0aos-cache-residency-v1\0";
    const MAXIMUM_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::Authority),
            2 => Some(Self::Kind::GlobalAccounting),
            3 => Some(Self::Kind::ProjectAccounting),
            4 => Some(Self::Kind::DomainAccounting),
            5 => Some(Self::Kind::Reservation),
            6 => Some(Self::Kind::Pin),
            7 => Some(Self::Kind::Scrub),
            8 => Some(Self::Kind::Eviction),
            9 => Some(Self::Kind::Catalog),
            10 => Some(Self::Kind::Effect),
            11 => Some(Self::Kind::Current),
            12 => Some(Self::Kind::Checkpoint),
            13 => Some(Self::Kind::EffectObservation),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::Effect => RecordNamespace::Effect,
            Self::Kind::Current => RecordNamespace::AuthorityPublication,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
            Self::Kind::EffectObservation => RecordNamespace::DesiredState,
            _ => RecordNamespace::DesiredState,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::Effect => ProtectedRecordRoleV1::Effect,
            Self::Kind::Current | Self::Kind::Checkpoint => ProtectedRecordRoleV1::Publication,
            Self::Kind::EffectObservation => ProtectedRecordRoleV1::State,
            _ => ProtectedRecordRoleV1::State,
        }
    }

    fn is_checkpoint(_kind: Self::Kind) -> bool {
        false
    }

    fn family(kind: Self::Kind) -> u8 {
        match kind {
            Self::Kind::Authority => 1,
            Self::Kind::GlobalAccounting
            | Self::Kind::ProjectAccounting
            | Self::Kind::DomainAccounting => 2,
            Self::Kind::Reservation => 3,
            Self::Kind::Pin => 4,
            Self::Kind::Scrub => 5,
            Self::Kind::Eviction => 6,
            Self::Kind::Catalog => 7,
            Self::Kind::Effect => 8,
            Self::Kind::Current => 9,
            Self::Kind::Checkpoint => 10,
            Self::Kind::EffectObservation => 11,
        }
    }

    fn decode_reducer_phase(
        validator: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        if kind == Self::Kind::EffectObservation {
            return decode_cache_effect_observation(identity, body)
                .map(|_| ProtectedReducerPhaseV1::Observed);
        }
        decode_cache_body(kind, identity, body, *validator).map(|_| match kind {
            Self::Kind::Effect => ProtectedReducerPhaseV1::Prepared,
            Self::Kind::Scrub | Self::Kind::Eviction => ProtectedReducerPhaseV1::Observed,
            Self::Kind::EffectObservation => ProtectedReducerPhaseV1::Observed,
            _ => ProtectedReducerPhaseV1::Terminal,
        })
    }

    fn validates_identity(kind: Self::Kind, identity: &[u8]) -> bool {
        let expected_length = if kind == Self::Kind::EffectObservation {
            16
        } else if kind == Self::Kind::Checkpoint {
            81
        } else {
            121
        };
        if identity.len() != expected_length
            || (kind == Self::Kind::EffectObservation && identity == [0; 16])
        {
            return false;
        }
        if kind == Self::Kind::EffectObservation {
            return true;
        }
        if identity[..32] == [0; 32]
            || identity[49..81] == [0; 32]
            || (expected_length == 121
                && (identity[81..89] == [0; 8] || identity[89..121] == [0; 32]))
        {
            return false;
        }
        match kind {
            Self::Kind::ProjectAccounting => identity[32] == 1 && identity[33..49] != [0; 16],
            Self::Kind::DomainAccounting => identity[32] == 2 && identity[33..49] != [0; 16],
            _ => identity[32] == 0 && identity[33..49] == [0; 16],
        }
    }

    fn semantic_tuple(kind: Self::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        if kind == Self::Kind::EffectObservation {
            return None;
        }
        let _ = (kind, body);
        if identity.len() < 81 {
            return None;
        }
        Some(
            Sha256::new()
                .chain_update(b"aos.sandbox.cache-residency.semantic-tuple.v1\0")
                .chain_update(&identity[..49])
                .finalize()
                .into(),
        )
    }
}

/// Applies the sole canonical historical encode cache effect observation recipe.
pub fn encode_cache_effect_observation(observation: CacheEffectObservationDataV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(122);
    bytes.extend_from_slice(b"AOSCRY01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&observation.transaction_id);
    bytes.extend_from_slice(observation.transaction_digest.as_bytes());
    bytes.extend_from_slice(observation.evidence.as_bytes());
    bytes.extend_from_slice(observation.partition.as_bytes());
    bytes
}

/// Applies the sole canonical historical decode cache effect observation recipe.
pub fn decode_cache_effect_observation(
    identity: &[u8],
    bytes: &[u8],
) -> Option<CacheEffectObservationDataV1> {
    if identity.len() != 16
        || bytes.len() != 122
        || &bytes[..8] != b"AOSCRY01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || identity != &bytes[10..26]
    {
        return None;
    }
    let observation = CacheEffectObservationDataV1 {
        transaction_id: bytes[10..26].try_into().ok()?,
        transaction_digest: ObjectDigest::from_bytes(bytes[26..58].try_into().ok()?),
        evidence: ObjectDigest::from_bytes(bytes[58..90].try_into().ok()?),
        partition: ObjectDigest::from_bytes(bytes[90..122].try_into().ok()?),
    };
    if observation.transaction_id == [0; 16]
        || observation.transaction_digest.as_bytes() == &[0; 32]
        || observation.evidence.as_bytes() == &[0; 32]
        || observation.partition.as_bytes() == &[0; 32]
        || encode_cache_effect_observation(observation) != bytes
    {
        return None;
    }
    Some(observation)
}

/// Applies the sole canonical historical cache effect observation authority key recipe.
pub fn cache_effect_observation_authority_key(transaction_id: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX.len() + 16);
    key.extend_from_slice(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX);
    key.extend_from_slice(&transaction_id);
    key
}

/// Applies the sole canonical historical encode cache effect observation authority recipe.
pub fn encode_cache_effect_observation_authority(
    owner_scope: ObjectDigest,
    transaction_id: [u8; 16],
    transaction_digest: ObjectDigest,
    partition: ObjectDigest,
    evidence: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; EFFECT_OBSERVATION_AUTHORITY_BYTES];
    bytes[..8].copy_from_slice(b"AOSCOA01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..48].copy_from_slice(owner_scope.as_bytes());
    bytes[48..64].copy_from_slice(&transaction_id);
    bytes[64..96].copy_from_slice(transaction_digest.as_bytes());
    bytes[96..128].copy_from_slice(partition.as_bytes());
    bytes[128..160].copy_from_slice(evidence.as_bytes());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.cache.effect-observation-authority.v1\0")
        .chain_update(&bytes[..160])
        .finalize();
    bytes[160..192].copy_from_slice(&digest);
    bytes
}

/// Applies the sole canonical historical cache body magic recipe.
pub const fn cache_body_magic(kind: CacheResidencyProtectedRecordKindV1) -> [u8; 8] {
    match kind {
        CacheResidencyProtectedRecordKindV1::Authority => *b"AOSCRA01",
        CacheResidencyProtectedRecordKindV1::GlobalAccounting => *b"AOSCRG01",
        CacheResidencyProtectedRecordKindV1::ProjectAccounting => *b"AOSCRP01",
        CacheResidencyProtectedRecordKindV1::DomainAccounting => *b"AOSCRD01",
        CacheResidencyProtectedRecordKindV1::Reservation => *b"AOSCRR01",
        CacheResidencyProtectedRecordKindV1::Pin => *b"AOSCRN01",
        CacheResidencyProtectedRecordKindV1::Scrub => *b"AOSCRS01",
        CacheResidencyProtectedRecordKindV1::Eviction => *b"AOSCRE01",
        CacheResidencyProtectedRecordKindV1::Catalog => *b"AOSCRC01",
        CacheResidencyProtectedRecordKindV1::Effect => *b"AOSCRX01",
        CacheResidencyProtectedRecordKindV1::Current => *b"AOSCRU01",
        CacheResidencyProtectedRecordKindV1::Checkpoint => *b"AOSCRT01",
        CacheResidencyProtectedRecordKindV1::EffectObservation => *b"AOSCRY01",
    }
}

/// Applies the sole canonical historical cache identity length matches recipe.
pub const fn cache_identity_length_matches(
    kind: CacheResidencyProtectedRecordKindV1,
    length: usize,
) -> bool {
    match kind {
        CacheResidencyProtectedRecordKindV1::EffectObservation => length == 16,
        CacheResidencyProtectedRecordKindV1::Checkpoint => length == 81,
        _ => length == 121,
    }
}

/// Applies the sole canonical historical decode cache body recipe.
pub fn decode_cache_body(
    kind: CacheResidencyProtectedRecordKindV1,
    identity: &[u8],
    body: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Option<Option<CacheDurableRecordV1>> {
    if body.len() <= 8 + PARTITION_DESCRIPTOR_BYTES
        || body[..8] != cache_body_magic(kind)
        || !cache_identity_length_matches(kind, identity.len())
    {
        return None;
    }
    let descriptor_end = 8 + PARTITION_DESCRIPTOR_BYTES;
    let partition = decode_partition_descriptor(&body[8..descriptor_end])?;
    if kind == CacheResidencyProtectedRecordKindV1::Checkpoint {
        let checkpoint =
            decode_typed_checkpoint(partition, &body[descriptor_end..], limits).ok()?;
        if encode_typed_checkpoint(&checkpoint, partition, limits)
            .ok()?
            .as_slice()
            != &body[descriptor_end..]
            || identity[..32] != *partition.digest().as_bytes()
            || identity[49..81] != *checkpoint.digest.as_bytes()
        {
            return None;
        }
        return Some(None);
    }
    let payload = decode_atomic_object_record(partition, &body[descriptor_end..], limits).ok()?;
    if encode_atomic_object_record(&payload, limits)
        .ok()?
        .as_slice()
        != &body[descriptor_end..]
        || encode_partition_descriptor(partition).as_slice() != &body[8..descriptor_end]
        || identity[..32] != *partition.digest().as_bytes()
        || payload.record.partition != partition.digest()
        || !cache_record_kind_matches(kind, payload.record.kind)
        || identity[49..81] != *payload.record.subject.as_bytes()
        || (identity.len() == 121
            && (identity[81..89] != payload.record.sequence.to_be_bytes()
                || identity[89..121] != *payload.record.digest.as_bytes()))
        || (kind == CacheResidencyProtectedRecordKindV1::ProjectAccounting
            && identity[33..49] != *payload.plan.project.as_bytes())
        || (kind == CacheResidencyProtectedRecordKindV1::DomainAccounting
            && identity[33..49] != *partition.disclosure().domain_id().as_bytes())
    {
        return None;
    }
    Some(Some(payload.record))
}

/// Applies the sole canonical historical cache record kind matches recipe.
pub fn cache_record_kind_matches(
    protected: CacheResidencyProtectedRecordKindV1,
    durable: CacheRecordKindV1,
) -> bool {
    match protected {
        CacheResidencyProtectedRecordKindV1::Authority => matches!(
            durable,
            CacheRecordKindV1::Domain | CacheRecordKindV1::ReadHandoff
        ),
        CacheResidencyProtectedRecordKindV1::GlobalAccounting
        | CacheResidencyProtectedRecordKindV1::ProjectAccounting
        | CacheResidencyProtectedRecordKindV1::DomainAccounting => {
            matches!(durable, CacheRecordKindV1::Quota | CacheRecordKindV1::Pin)
        }
        CacheResidencyProtectedRecordKindV1::Reservation => {
            durable == CacheRecordKindV1::Reservation
        }
        CacheResidencyProtectedRecordKindV1::Pin => durable == CacheRecordKindV1::Pin,
        CacheResidencyProtectedRecordKindV1::Scrub => durable == CacheRecordKindV1::Scrub,
        CacheResidencyProtectedRecordKindV1::Eviction => matches!(
            durable,
            CacheRecordKindV1::EvictionPlan | CacheRecordKindV1::EvictionProgress
        ),
        CacheResidencyProtectedRecordKindV1::Catalog => durable == CacheRecordKindV1::Catalog,
        CacheResidencyProtectedRecordKindV1::Effect => matches!(
            durable,
            CacheRecordKindV1::Admission
                | CacheRecordKindV1::EvictionPlan
                | CacheRecordKindV1::ReadHandoff
        ),
        CacheResidencyProtectedRecordKindV1::Current => {
            !matches!(durable, CacheRecordKindV1::Poison)
        }
        CacheResidencyProtectedRecordKindV1::Checkpoint => false,
        CacheResidencyProtectedRecordKindV1::EffectObservation => false,
    }
}

/// Applies the sole canonical historical validate cache key recipe.
///
/// # Errors
/// Returns [`DomainLedgerDataError`] for noncanonical historical fields.
pub fn validate_cache_key<S: ProtectedDomainSchemaV1<Kind = CacheResidencyProtectedRecordKindV1>>(
    key: &ProtectedDomainKeyV1<S>,
) -> Result<(), DomainLedgerDataError> {
    let identity = key.identity();
    if key.kind() == CacheResidencyProtectedRecordKindV1::EffectObservation {
        return if identity.len() == 16 && identity != [0; 16] {
            Ok(())
        } else {
            Err(DomainLedgerDataError::NonCanonicalRecord)
        };
    }
    if !cache_identity_length_matches(key.kind(), identity.len())
        || identity[..32] == [0; 32]
        || identity[49..81] == [0; 32]
        || (identity.len() == 121 && (identity[81..89] == [0; 8] || identity[89..121] == [0; 32]))
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let valid_scope = match key.kind() {
        CacheResidencyProtectedRecordKindV1::ProjectAccounting => {
            identity[32] == 1 && identity[33..49] != [0; 16]
        }
        CacheResidencyProtectedRecordKindV1::DomainAccounting => {
            identity[32] == 2 && identity[33..49] != [0; 16]
        }
        _ => identity[32] == 0 && identity[33..49] == [0; 16],
    };
    if !valid_scope {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    Ok(())
}

/// Applies the sole canonical historical cache transaction partition recipe.
///
/// # Errors
/// Returns [`DomainLedgerDataError`] for noncanonical historical fields.
pub fn cache_transaction_partition<S: ProtectedDomainSchemaV1<Kind = CacheResidencyProtectedRecordKindV1>>(
    records: &[ProtectedDomainEnvelopeV1<S>],
) -> Result<Option<ObjectDigest>, DomainLedgerDataError> {
    let mut partition = None;
    for record in records {
        if matches!(
            record.key().kind(),
            CacheResidencyProtectedRecordKindV1::Checkpoint
                | CacheResidencyProtectedRecordKindV1::EffectObservation
        ) {
            continue;
        }
        let candidate = ObjectDigest::from_bytes(
            record.key().identity()[..32]
                .try_into()
                .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?,
        );
        if partition.is_some_and(|retained| retained != candidate) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        partition = Some(candidate);
    }
    Ok(partition)
}

mod transition;
pub use transition::{validate_cache_transition, classify_replayed_cache_transaction};
mod history;
pub use history::{CachePartitionHistoryDataV1, group_cache_history_data_v1, validate_projection_transaction_groups_data_v1, partition_history_inline_bytes_v1, validate_partition_history_tail_data_v1};

#[cfg(test)]
mod tests;
