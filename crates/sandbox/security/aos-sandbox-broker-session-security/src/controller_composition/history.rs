//! Exposes historical outcome DATA without exporting verified recovery states.
//!
//! These views never authorize replay, currentness, a request, or an effect.
//! Only the original protected history reader can construct the opaque owner.

use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

/// Retains the original fully reauthenticated historical classification.
///
/// This private-field owner has no public constructor. Its projections are
/// historical DATA only; no protected admission API accepts those projections.
pub struct HistoricalAtomicStorageHistoryV1(pub(crate) HistoricalAtomicStorageHistoryDataV1);

/// Transfers historical outcome DATA, never a protected continuation permit.
///
/// Callers may construct these variants, but no protected admission API accepts
/// them as historical custody or currentness evidence.
pub enum HistoricalAtomicStorageHistoryDataV1 {
    /// The exact protected history contains no matching request.
    Absent,
    /// The exact request or adjacent successor is not terminal.
    Incomplete,
    /// The group completed without an adjacent original successor.
    GroupCommitted {
        /// The original authenticated predecessor inventory.
        predecessor: AuthenticatedBrokerMethodOutcomeV1,
        /// The original authenticated group result.
        group: AuthenticatedBrokerMethodOutcomeV1,
    },
    /// The original three adjacent exchanges completed.
    Complete {
        /// The original authenticated predecessor inventory.
        predecessor: AuthenticatedBrokerMethodOutcomeV1,
        /// The original authenticated group result.
        group: AuthenticatedBrokerMethodOutcomeV1,
        /// The original authenticated successor inventory.
        successor: AuthenticatedBrokerMethodOutcomeV1,
    },
}

impl HistoricalAtomicStorageHistoryV1 {
    /// Borrows historical DATA without issuing accepted evidence or currentness.
    pub fn view(&self) -> &HistoricalAtomicStorageHistoryDataV1 {
        &self.0
    }

    /// Moves the original historical outcomes once into inert DATA parts.
    pub fn into_data(self) -> HistoricalAtomicStorageHistoryDataV1 {
        self.0
    }
}

/// Owns the original archived inventory bytes as non-authorizing recovery DATA.
///
/// This decomposition is never accepted as a protected archive or admission
/// witness. It retains all original buffers while Controller inspects history.
pub struct ArchivedStorageInventoryHeadDataV1 {
    /// The original read-only inventory request identifier.
    pub inventory_request_id: [u8; 16],
    /// The original canonical request commitment.
    pub inventory_request_digest: [u8; 32],
    /// The original canonical request packet.
    pub inventory_request_packet: Vec<u8>,
    /// The protected client head retained by the original archive.
    pub original_head: [u8; 32],
    /// The original archive commitment.
    pub archive_digest: [u8; 32],
    /// The original terminal packet, when present.
    pub terminal_packet: Option<Vec<u8>>,
    /// The existing classification of a fresh status rather than original readback.
    pub fresh: bool,
}
