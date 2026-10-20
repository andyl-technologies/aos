//! Delegates original Root historical comparisons to the canonical DATA owner.
//!
//! Mount owns the live native issuer and same-writer readback. These remaining
//! comparisons preserve Domain replay, compaction and generic mutation fences;
//! they cannot issue a Mount authority or reconstruct live custody.

use aos_sandbox_protocol::domain_ledger::capacity_family::family::{
    CanonicalCapacityFamily, canonical_reservations,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::OriginalRootCapacityRecordV5;
use aos_sandbox_protocol::domain_ledger::capacity_family::ordinary::{
    OrdinaryCapacityKindV4, OrdinaryCapacityProfileV4, OrdinaryCapacityRecordV4,
};

use crate::journal::PreflightTransactionViewV1;
use crate::journal::semantic_append::PreflightScope;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeCutKindV1, RootNativeCutV1, RootNativeHeldGraphV2, RootNativeHeldSidecarV2,
    RootNativeTransitionKindV2 as Kind, has_original_pending_closed_cut_v5,
    native_root_sidecar_key_v2, original_root_remaining_v5,
    validate_native_root_graph_v2, validate_original_root_transition_v5,
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1, NativeHeldOwnerV1,
    frame::{PreparedNativeHeldControlV1, SignedNativeHeldControlV1},
    suffix::NativeHeldCompletionSuffixV1,
};
use sha2::{Digest as _, Sha256};

use super::{
    CacheMutationGateV1, CommitResult, Journal, JournalError, JournalLimits, JournalRecord,
    JournalTransaction, ProtectedAuthorityScope, ProtectedJournalAuthority,
    ProtectedJournalSnapshot, RecordNamespace, RootOwnerEdge, authority_preflight_digest,
    validate_transaction,
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

fn invalid() -> JournalError {
    aos_sandbox_ledger_replay::replay::root_original_native::invalid().into()
}

fn graph(state: &State) -> Result<RootNativeHeldGraphV2, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::graph(state)
        .map_err(JournalError::from)
}

fn require_named_funding(state: &State, limits: JournalLimits) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_named_funding(state, limits)
        .map_err(JournalError::from)
}

fn is_original_release_floor(family: &CanonicalCapacityFamily) -> bool {
    aos_sandbox_ledger_replay::replay::root_original_native::is_original_release_floor(family)
}

fn validate_original_release_floors(
    state: &State,
    families: &[CanonicalCapacityFamily],
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_original_release_floors(
        state,
        families,
    )
        .map_err(JournalError::from)
}

fn original_release_current_puts(
    checked: &RootNativeHeldGraphV2,
    release: [u8; 32],
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::original_release_current_puts(
        checked,
        release,
    )
        .map_err(JournalError::from)
}

fn derive_original_release(
    state: &State,
    owners: &JournalTransaction,
    root: [u8; 32],
    release: [u8; 32],
    limits: JournalLimits,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::derive_original_release(
        state,
        owners,
        root,
        release,
        limits,
    )
        .map_err(JournalError::from)
}

fn validate_original_release_edge(
    state: &State,
    transaction: &JournalTransaction,
    root: [u8; 32],
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_original_release_edge(
        state,
        transaction,
        root,
        limits,
    )
        .map_err(JournalError::from)
}

fn derive_original_release_status(
    state: &State,
    owners: &JournalTransaction,
    root: [u8; 32],
    release: [u8; 32],
    limits: JournalLimits,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::derive_original_release_status(
        state,
        owners,
        root,
        release,
        limits,
    )
        .map_err(JournalError::from)
}

/// Shares only the closed family policy after complete canonical traversal.
///
/// # Errors
/// Rejects unsupported Source5, Mount Native3 and non-kind2/kind5 Ordinary4.
pub(super) fn require_supported_funding_families(
    families: &[CanonicalCapacityFamily],
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_supported_funding_families(families)
        .map_err(JournalError::from)
}

/// Rejoins unchanged native5 originals after the caller's exact ordinary reducer.
pub(super) fn preserve_local_owner(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::preserve_local_owner(state, transaction)
        .map_err(JournalError::from)
}

pub(super) fn require_funded_original_owner(
    state: &State,
    checked: &RootNativeHeldGraphV2,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_funded_original_owner(state, checked)
        .map_err(JournalError::from)
}

/// Rejoins every selected original floor only after validating ALL families.
pub(super) fn pending(
    state: &State,
    limits: JournalLimits,
) -> Result<Vec<OriginalRootCapacityRecordV5>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::pending(state, limits)
        .map_err(JournalError::from)
}

pub(super) fn require_generic_transaction(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_generic_transaction(
        state,
        transaction,
    )
        .map_err(JournalError::from)
}

fn apply(state: &State, records: &[JournalRecord]) -> Result<State, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::apply(state, records)
        .map_err(JournalError::from)
}

fn require_exact_owner_puts(
    owners: &JournalTransaction,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
    generated: Option<(&[u8], &[u8])>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_exact_owner_puts(
        owners,
        puts,
        generated,
    )
        .map_err(JournalError::from)
}

fn admission(
    state: &State,
    owners: &JournalTransaction,
    prepared: PreparedNativeHeldControlV1,
    limits: JournalLimits,
) -> Result<(JournalTransaction, OriginalRootCapacityRecordV5), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::admission(state, owners, prepared, limits)
        .map_err(JournalError::from)
}

fn derive_admission(
    state: &State,
    owners: &JournalTransaction,
    prepared: PreparedNativeHeldControlV1,
    limits: JournalLimits,
) -> Result<(JournalTransaction, OriginalRootCapacityRecordV5), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::derive_admission(
        state,
        owners,
        prepared,
        limits,
    )
        .map_err(JournalError::from)
}

fn continuation(
    state: &State,
    owners: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<
    (
        JournalTransaction,
        Option<OriginalRootCapacityRecordV5>,
        [u8; 32],
    ),
    JournalError,
> {
    aos_sandbox_ledger_replay::replay::root_original_native::continuation(state, owners, attempt, limits)
        .map_err(JournalError::from)
}

fn derive_continuation(
    state: &State,
    owners: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<
    (
        JournalTransaction,
        Option<OriginalRootCapacityRecordV5>,
        OriginalRootCapacityRecordV5,
    ),
    JournalError,
> {
    aos_sandbox_ledger_replay::replay::root_original_native::derive_continuation(
        state,
        owners,
        attempt,
        limits,
    )
        .map_err(JournalError::from)
}

fn validate_transfer(
    transaction: &JournalTransaction,
    old: &OriginalRootCapacityRecordV5,
    next: Option<&OriginalRootCapacityRecordV5>,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_transfer(
        transaction,
        old,
        next,
        limits,
    )
        .map_err(JournalError::from)
}

pub(super) fn validate_edge(
    state: &State,
    transaction: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_edge(
        state,
        transaction,
        attempt,
        limits,
    )
        .map_err(JournalError::from)
}

pub(super) fn validate_replayed_transaction(
    state: &State,
    transaction: &JournalTransaction,
    limits: JournalLimits,
    successor_sequence: u64,
) -> Result<bool, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_replayed_transaction(
        state,
        transaction,
        limits,
        successor_sequence,
    )
        .map_err(JournalError::from)
}
