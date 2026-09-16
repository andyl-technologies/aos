//! Pure canonical storage and graph validation for `AOSMSA02`.
//!
//! This module owns the only decoder and encoder for the Mount source
//! acquisition namespace. Decoded records and validated snapshots are plain,
//! nonauthorizing data. Runtime crates must separately prove that the exact
//! bytes came from a current protected journal before granting authority.

use std::collections::BTreeMap;

use format::decode_value;

#[doc(hidden)]
pub mod checkpoint;
#[doc(hidden)]
pub mod floor;
#[doc(hidden)]
pub mod format;
#[doc(hidden)]
pub mod history;
mod migration;
mod migration_v1;
#[doc(hidden)]
pub mod model;
#[doc(hidden)]
pub mod projection;
mod validation;

pub use checkpoint::outcome_verification_anchor_digest_v2;
pub use floor::{
    acquire_verification_floor_v2, protocol_acquire_verification_floor_v2,
    protocol_selection_floor_v2, selection_floor_snapshot_v2,
};
pub use format::{
    MAXIMUM_SOURCE_ACQUISITIONS, MAXIMUM_SOURCE_HOLDER_SEQUENCES, MAXIMUM_SOURCE_PROVIDER_ATTEMPTS,
    MAXIMUM_SOURCE_PROVIDER_HEADS, MAXIMUM_SOURCE_PROVIDER_SESSIONS, MutationTagV2, RecordKindV2,
    acquisition_key, attempt_id, encode_mount_source_state_record_v2, holder_sequence_key,
    intent_digest, inventory_correlation_set_v2, key_kind, manager_custody_evidence_digest_v2,
    manager_custody_loss_evidence_digest_v2, mount_source_consumption_companion_digest_v2,
    provider_attempt_key, provider_head_key, provider_session_key, record_digest, request_id,
    seal_record, session_id, transaction_id, validate_inventory_correlation_set_v2,
};
pub use migration::{
    LegacyMountSourceStateV1, MountSourceStateMigrationDispositionV2,
    MountSourceStateMigrationPlanV2, decode_mount_source_state_graph_v1,
    plan_mount_source_state_migration_v2,
};
pub use model::*;
pub use projection::{
    ProjectionV2, inventory_correlation_for_row_v2, inventory_entry_matches_evidence, project_row,
    project_scope, projection_entries, projection_from_entries, reconciliation_commitment,
    reproduce_reconciliation,
};
pub use validation::validate_recovered_table;

/// Maximum aggregate key and value bytes accepted for one recovered snapshot.
pub const MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES: usize = 512 * 1024 * 1024;

/// Reports invalid canonical `AOSMSA02` storage or object-graph state.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountSourceAcquisitionStateError {
    /// A bounded field, record, reference, or graph invariant failed.
    #[error("invalid AOSMSA02 state: {0}")]
    Invalid(&'static str),
}

/// Result returned by pure `AOSMSA02` storage validation.
pub type Result<T> = std::result::Result<T, MountSourceAcquisitionStateError>;

/// Holds one fully validated, nonauthorizing `AOSMSA02` object graph.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct MountSourceAcquisitionStateV2 {
    pub acquisitions: BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    pub holder_sequences: BTreeMap<[u8; 16], HolderSequenceV2>,
    pub provider_heads: BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV2>,
    pub provider_sessions: BTreeMap<[u8; 32], SourceProviderSessionV2>,
    pub provider_attempts: BTreeMap<[u8; 32], SourceProviderQueryAttemptV2>,
}

/// Compatibility name used by the pure graph validators.
#[doc(hidden)]
pub type SourceAcquisitionTableV2 = MountSourceAcquisitionStateV2;

/// Decodes one canonical record after checking its exact key and self-digest.
///
/// # Errors
///
/// Returns an error for an unknown key, unsupported or noncanonical envelope,
/// oversized value, mismatched key, or mismatched record digest.
pub fn decode_mount_source_state_record_v2(key: &[u8], value: &[u8]) -> Result<StoredRecordV2> {
    decode_value(key, value)
}

/// Materializes and validates one complete canonical `AOSMSA02` snapshot.
///
/// Count and aggregate byte limits are enforced before decoding each value.
/// The returned data is historical evidence only and grants no live authority.
///
/// # Errors
///
/// Returns an error for any count, aggregate-size, canonical-record, identity,
/// reference, ordering, signature, or whole-graph invariant failure.
pub fn validate_mount_source_state_graph_v2<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<MountSourceAcquisitionStateV2> {
    let mut state = MountSourceAcquisitionStateV2 {
        acquisitions: BTreeMap::new(),
        holder_sequences: BTreeMap::new(),
        provider_heads: BTreeMap::new(),
        provider_sessions: BTreeMap::new(),
        provider_attempts: BTreeMap::new(),
    };
    let mut materialized_bytes = 0usize;

    for (key, value) in records {
        materialized_bytes = materialized_bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| format::state_error("AOSMSA02 materialized byte count overflow"))?;
        if materialized_bytes > MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES {
            return Err(format::state_error(
                "AOSMSA02 snapshot exceeds its aggregate materialized bound",
            ));
        }

        let kind = key_kind(key)?;
        let count = match kind {
            RecordKindV2::Acquisition => state.acquisitions.len(),
            RecordKindV2::ProviderHead => state.provider_heads.len(),
            RecordKindV2::HolderSequence => state.holder_sequences.len(),
            RecordKindV2::ProviderSession => state.provider_sessions.len(),
            RecordKindV2::ProviderQueryAttempt => state.provider_attempts.len(),
        };
        let maximum = match kind {
            RecordKindV2::Acquisition => MAXIMUM_SOURCE_ACQUISITIONS,
            RecordKindV2::ProviderHead => MAXIMUM_SOURCE_PROVIDER_HEADS,
            RecordKindV2::HolderSequence => MAXIMUM_SOURCE_HOLDER_SEQUENCES,
            RecordKindV2::ProviderSession => MAXIMUM_SOURCE_PROVIDER_SESSIONS,
            RecordKindV2::ProviderQueryAttempt => MAXIMUM_SOURCE_PROVIDER_ATTEMPTS,
        };
        if count >= maximum {
            return Err(format::state_error(
                "AOSMSA02 record kind exceeds its fixed bound",
            ));
        }

        match decode_value(key, value)? {
            StoredRecordV2::Acquisition { value } => {
                if state
                    .acquisitions
                    .insert(value.acquisition_id, value)
                    .is_some()
                {
                    return Err(format::state_error(
                        "duplicate AOSMSA02 acquisition identity",
                    ));
                }
            }
            StoredRecordV2::ProviderHead { value } => {
                let identity = (
                    value.scope.holder_authority_id,
                    value.scope.provider_authority_id,
                );
                if state.provider_heads.insert(identity, value).is_some() {
                    return Err(format::state_error(
                        "duplicate AOSMSA02 provider-head identity",
                    ));
                }
            }
            StoredRecordV2::HolderSequence { value } => {
                if state
                    .holder_sequences
                    .insert(value.holder_authority_id, value)
                    .is_some()
                {
                    return Err(format::state_error(
                        "duplicate AOSMSA02 holder-sequence identity",
                    ));
                }
            }
            StoredRecordV2::ProviderSession { value } => {
                if state
                    .provider_sessions
                    .insert(value.session_id, value)
                    .is_some()
                {
                    return Err(format::state_error(
                        "duplicate AOSMSA02 provider-session identity",
                    ));
                }
            }
            StoredRecordV2::ProviderQueryAttempt { value } => {
                if state
                    .provider_attempts
                    .insert(value.attempt_id, value)
                    .is_some()
                {
                    return Err(format::state_error(
                        "duplicate AOSMSA02 provider-attempt identity",
                    ));
                }
            }
        }
    }

    validate_recovered_table(&state)?;
    Ok(state)
}
