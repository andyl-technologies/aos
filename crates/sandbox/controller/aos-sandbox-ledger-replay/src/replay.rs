//! Validates saved Source and related Root historical DATA with canonical engines.
//!
//! These comparisons consume saved maps, transactions, limits and exact typed
//! records. They create no live writer, received subject, signing input, floor
//! grant or semantic readiness. Actual Source construction runs these same
//! engines on its sealed indexed native replay before publishing its owner.

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_journal::materialized::RecordMutationRef;
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalRecord, JournalTransaction, encoded_transaction_append_bytes,
    validate_transaction,
};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use sha2::{Digest as _, Sha256};

/// Checks the exact saved native-capacity transfer envelope.
pub mod native_transfer;
/// Rejoins historical local replacement floors and postimages.
pub mod root_local_recovery;
/// Validates historical original Inventory owner edges.
pub mod root_original_inventory;
/// Validates historical native Root floors and transitions.
pub mod root_original_native;

/// Identifies a historical owner edge without issuing any live authority.
#[derive(Clone, Copy)]
pub enum RootReplayOwnerEdgeV1 {
    /// Names the exact saved original Inventory transition.
    OriginalInventory {
        /// Retains the saved Root owner identifier.
        root: [u8; 32],
        /// Retains the saved query identifier.
        query: [u8; 32],
        /// Retains the saved transition class.
        kind: aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::OriginalInventoryTransitionKindV6,
    },
}

/// Hashes the same canonical capacity record bytes without a role grant.
#[doc(hidden)]
pub fn digest_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

/// Owns saved challenge checkpoints and pure replay identity comparisons.
pub mod challenge;

/// Owns canonical native suffix and original Source continuation geometry DATA.
pub mod native_held;

/// Owns complete original Source owner/floor union saved-state comparisons.
pub mod source_original;

/// Owns the canonical fixed Source, Controller and Root phase DATA codecs.
pub mod phase_records;

/// Owns canonical genesis saved rows and the complete receipt/ACK/pending fold.
pub mod source_tree_genesis;

/// Owns canonical saved Controller genesis rows and mutation comparisons.
pub mod controller_source_genesis;

/// Owns the complete canonical seven-family hierarchy historical DATA schema.
pub mod hierarchy_records;

/// Owns exact saved Source successor selectors, rows and capacity DATA.
pub mod source_tree_successor;

/// Owns saved Controller successor issuance and immutable family comparisons.
pub mod controller_source_successor_issuance;

/// Owns canonical saved structural Tree/Lineage grouping and replay work.
pub mod tree_lineage;

/// Owns canonical saved Root genesis instance, intent and floor DATA codecs.
pub mod root_genesis_records;

/// Owns canonical saved Root verifier tuple framing and signature checks.
pub mod root_genesis_pins;

/// Owns the complete saved Root successor archive and phase comparisons.
pub mod root_successor;

/// Checks complete saved NoApply floor history as nonauthorizing DATA.
pub mod execution_no_apply_history;

/// Checks ordinary Root genesis capacity DATA at its original boundaries.
pub mod root_genesis_capacity;

/// Compares the complete retained Root/Source floor and lineage DATA.
pub mod root_saved_floor;
