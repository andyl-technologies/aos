//! Exposes historical outcome DATA without exporting verified recovery states.
//!
//! These views never authorize replay, currentness, a request, or an effect.
//! Only the original protected history reader can construct the opaque owner.

use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

use crate::recovery::ProtectedVerifiedAtomicStorageHistoryV1;

/// Retains the original fully reauthenticated historical classification.
///
/// This private-field owner has no public constructor. Its projections are
/// historical DATA only; no protected admission API accepts those projections.
pub struct HistoricalAtomicStorageHistoryV1(pub(crate) ProtectedVerifiedAtomicStorageHistoryV1);

/// Borrows the historical outcomes without releasing their owning classification.
pub enum HistoricalAtomicStorageHistoryViewV1<'history> {
    /// The exact protected history contains no matching request.
    Absent,
    /// The exact request or adjacent successor is not terminal.
    Incomplete,
    /// The group completed without an adjacent original successor.
    GroupCommitted {
        /// The original authenticated predecessor inventory.
        predecessor: &'history AuthenticatedBrokerMethodOutcomeV1,
        /// The original authenticated group result.
        group: &'history AuthenticatedBrokerMethodOutcomeV1,
    },
    /// The original three adjacent exchanges completed.
    Complete {
        /// The original authenticated predecessor inventory.
        predecessor: &'history AuthenticatedBrokerMethodOutcomeV1,
        /// The original authenticated group result.
        group: &'history AuthenticatedBrokerMethodOutcomeV1,
        /// The original authenticated successor inventory.
        successor: &'history AuthenticatedBrokerMethodOutcomeV1,
    },
}

/// Transfers historical outcome DATA, never a protected continuation permit.
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
    pub fn view(&self) -> HistoricalAtomicStorageHistoryViewV1<'_> {
        match &self.0 {
            ProtectedVerifiedAtomicStorageHistoryV1::Absent => {
                HistoricalAtomicStorageHistoryViewV1::Absent
            }
            ProtectedVerifiedAtomicStorageHistoryV1::Incomplete => {
                HistoricalAtomicStorageHistoryViewV1::Incomplete
            }
            ProtectedVerifiedAtomicStorageHistoryV1::GroupCommitted { predecessor, group } => {
                HistoricalAtomicStorageHistoryViewV1::GroupCommitted { predecessor, group }
            }
            ProtectedVerifiedAtomicStorageHistoryV1::Complete {
                predecessor,
                group,
                successor,
            } => HistoricalAtomicStorageHistoryViewV1::Complete {
                predecessor,
                group,
                successor,
            },
        }
    }

    /// Moves the original historical outcomes once into inert DATA parts.
    pub fn into_data(self) -> HistoricalAtomicStorageHistoryDataV1 {
        match self.0 {
            ProtectedVerifiedAtomicStorageHistoryV1::Absent => {
                HistoricalAtomicStorageHistoryDataV1::Absent
            }
            ProtectedVerifiedAtomicStorageHistoryV1::Incomplete => {
                HistoricalAtomicStorageHistoryDataV1::Incomplete
            }
            ProtectedVerifiedAtomicStorageHistoryV1::GroupCommitted { predecessor, group } => {
                HistoricalAtomicStorageHistoryDataV1::GroupCommitted { predecessor, group }
            }
            ProtectedVerifiedAtomicStorageHistoryV1::Complete {
                predecessor,
                group,
                successor,
            } => HistoricalAtomicStorageHistoryDataV1::Complete {
                predecessor,
                group,
                successor,
            },
        }
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
