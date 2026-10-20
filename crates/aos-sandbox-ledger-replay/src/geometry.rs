//! Shares the actual per-row and per-family semantic replay geometry.
//!
//! These DATA functions inspect actual borrowed rows and proposed records
//! without cloning, decoding a second journal, or selecting a receiving payer.
//! Source, Root and Cache retain their separate genuine financial owners.

/// Prices the matching hierarchy decoder frontiers.
pub mod hierarchy;
/// Prices the original closed all-family representation planes.
pub mod semantic_rows;
/// Prices actual current and proposed Source semantic rows.
pub mod reached;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_core::ResourceVector;
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError, transaction::JournalTransaction};
use crate::genesis::SourceGenesisReceiptDataErrorV1;
use crate::replay::source_tree_successor::{self, State};

/// Bounds the same complete reached semantic families before their growth.
///
/// # Errors
/// Rejects checked representation overflow in either original supplier.
pub fn complete_replay_demand_v1(
    state: &State,
    transaction: Option<&JournalTransaction>,
) -> Result<ResourceVector, CanonicalJournalMechanicalErrorV1> {
    reached::semantic_demand_v1(state, transaction)?
        .checked_add(source_tree_successor::source_member_dynamic_demand_v1::<
            CanonicalJournalMechanicalErrorV1,
            DomainLedgerDataError,
            SourceGenesisReceiptDataErrorV1,
        >(state, transaction)?)
        .map_err(|_| CanonicalJournalMechanicalErrorV1::JournalTooLarge)
}

/// Bounds cumulative committed challenge checkpoints from their real prefix.
///
/// Unlike a final materialized map, this vector retains replaced historical
/// rows. Every checkpoint comes from a complete framed mutation, and its two
/// byte strings come from that same prefix. Three carrier/backing lanes cover
/// the retained allocation and geometric growth overlap. No live challenge
/// view, witness, nonce or role is constructed by this byte/cardinality bound.
///
/// # Errors
/// Refuses native-prefix conversion or checked representation overflow.
pub fn retained_challenge_history_demand_v1(
    captured_native_bytes: u64,
) -> Result<ResourceVector, CanonicalJournalMechanicalErrorV1> {
    let invalid = || CanonicalJournalMechanicalErrorV1::JournalTooLarge;
    let encoded = usize::try_from(captured_native_bytes).map_err(|_| invalid())?;
    let checkpoints = encoded / aos_sandbox_journal::framing::HEADER_BYTES;
    let bytes = checkpoints.checked_mul(std::mem::size_of::<
        crate::replay::challenge::SourceOriginalChallengeCheckpointV5,
    >()).and_then(|bytes| bytes.checked_mul(3))
        .and_then(|bytes| bytes.checked_add(encoded.checked_mul(3)?))
        .ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO
        .with(aos_sandbox_core::ResourceDimension::MemoryBytes,
            u64::try_from(bytes).map_err(|_| invalid())?)
        .with(aos_sandbox_core::ResourceDimension::MetadataEntries,
            u64::try_from(checkpoints).map_err(|_| invalid())?))
}
