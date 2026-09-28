//! Retained generation-one ancestry floor from the actual independent Root owner.
//!
//! The selected local profile trusts protected Root state and kernel/PID1. It
//! does not resist whole-host disk rollback or use Storage's method46 TPM floor.
//! The borrow retains the real Root writer and the exact nonce-bound Source
//! observation joined to Controller completion. It grants neither ContentRead
//! nor a later Tree mutation; other owners must remain held in canonical order.

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::source_genesis::SourceTreeGenesisStateV1;

use super::super::source_genesis_readback::{
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, VerifiedSourceTreeGenesisReadbackV1,
};
use super::{RootSourceGenesisAuthorityV1, SourceHierarchyFloorRecordV1};

/// Borrows the actual Root's current settled generation-one Source floor.
///
/// This server-local value cannot be cloned, serialized or adopted from a
/// decoded floor. Its owner remains locked, and every recheck repeats the
/// original independently pinned observation and completed Controller join.
/// The original Controller and Source writers must remain held through its
/// consumer; a signature does not establish that cross-owner lifetime.
///
/// This is only the Source-floor component of a future Root-last read barrier.
/// It does not authenticate a client peer/image, Publisher, Cache, assignment,
/// connected worker, either ContentRead grant, or future administrative append.
#[must_use = "retain the actual Root writer and original cross-owner flight"]
pub struct CurrentRootSourceGenesisFloorV1<'root> {
    owner: &'root RootSourceGenesisAuthorityV1,
    floor: SourceHierarchyFloorRecordV1,
    source_packet: [u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1],
}

impl CurrentRootSourceGenesisFloorV1<'_> {
    /// Borrows the exact semantic floor read from the retained Root writer.
    ///
    /// The returned record's bytes alone remain data, not detachable authority.
    #[must_use]
    pub const fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        &self.floor
    }

    /// Rechecks exact Root custody, pinned roles and the original settled join.
    ///
    /// # Errors
    /// Rejects changed Root names/state/pins, a missing or different stored
    /// floor, noncompleted Controller custody, or a foreign Source observation.
    /// The enclosing original flight separately checks its process, stream,
    /// selected image/policy and unchanged deadline before every crossing.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.owner
            .confirm_source_ack(&self.source_packet, &self.floor)
    }
}

impl RootSourceGenesisAuthorityV1 {
    /// Borrows its actual current floor after the original settled owner join.
    ///
    /// Selection comes from the verified completed Controller input under this
    /// actual Root owner, not a caller-proposed project or raw floor. The Source
    /// packet must be the fresh separately pinned observation obtained by the
    /// original Root-last flight while Controller and Source remain held.
    /// Empty, Prepared and signature-only historical observations cannot select
    /// a floor. Repeated exact observation never appends or renews authority.
    ///
    /// # Errors
    /// Rejects missing completion or stored floor, wrong packet width, stale
    /// nonce/role/Source cut, non-Anchored state, changed ACK, or unsafe Root.
    pub fn current_anchored_floor(
        &self,
        source_packet: &[u8],
    ) -> Result<CurrentRootSourceGenesisFloorV1<'_>, SourceGenesisErrorV1> {
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        if !accepted.completed {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let floor = self
            .floor(accepted.acceptance.project())?
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        self.confirm_source_ack(source_packet, &floor)?;
        let source_packet = source_packet
            .try_into()
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let current = CurrentRootSourceGenesisFloorV1 {
            owner: self,
            floor,
            source_packet,
        };
        current.recheck()?;
        Ok(current)
    }
}

// Shared by the actual owner confirmation and tests of genuine Source rows.
// Matching these data alone never constructs the retained owner above.
pub(super) fn require_anchored_observation(
    observed: &VerifiedSourceTreeGenesisReadbackV1,
    floor: &SourceHierarchyFloorRecordV1,
) -> Result<(), SourceGenesisErrorV1> {
    if floor.semantic_revision() != 1
        || floor.predecessor().is_some()
        || observed.state() != SourceTreeGenesisStateV1::Anchored
        || observed.receipt() != Some(floor.receipt())
        || observed.ack_floor_digest() != Some(floor.digest())
        || observed.ack_record_digest().is_none()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
