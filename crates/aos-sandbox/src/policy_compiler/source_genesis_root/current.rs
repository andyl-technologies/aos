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

/// Borrows the actual completed populated floor and its full immutable archive.
///
/// This protected-local profile is not whole-host disk anti-rollback. Only the
/// genuine Root owner constructs the loan after fresh Controller/Source joins.
#[must_use = "retain the actual Root writer through the original Finish"]
pub struct CurrentRootFirstSourceSuccessorFloorV2<'root> {
    owner: &'root RootSourceGenesisAuthorityV1,
    archive: super::successor_owner::RootFirstSourceSuccessorArchiveV2,
    completion: [u8; 96],
}

impl<'root> CurrentRootFirstSourceSuccessorFloorV2<'root> {
    pub(super) fn from_completed_owner(
        owner: &'root RootSourceGenesisAuthorityV1,
        archive: super::successor_owner::RootFirstSourceSuccessorArchiveV2,
        completion: [u8; 96],
    ) -> Result<Self, SourceGenesisErrorV1> {
        let current = Self { owner, archive, completion };
        current.recheck()?;
        Ok(current)
    }

    /// Borrows the logical floor without releasing its physical archive owner.
    pub fn floor(&self) -> &super::RootFirstSourceSuccessorFloorV2 { &self.archive.floor }

    /// Borrows the full original immutable intent retained beside that floor.
    pub fn original_intent(&self) -> &super::RootFirstSourceSuccessorIntentV2 { &self.archive.original }

    /// Borrows the joined final floor/Controller Complete/Source ACK DATA.
    pub const fn completion(&self) -> &[u8; 96] { &self.completion }

    /// Rechecks the same named Root writer, full archive and independent pins.
    ///
    /// # Errors
    /// Rejects changed protected custody or any stored archive byte or join.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.owner.require_current_first_successor_archive_v2(&self.archive)
    }
}

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

/// Retains the actual selected populated floor and complete mixed Root family.
///
/// This loan is constructed only by the held Root after its fresh independent
/// Controller and Source completion join; it has no strict-v2 conversion.
#[must_use = "retain the real mixed Root owner through Finish"]
pub struct CurrentRootProjectSuccessorFloorV3<'root> {
    owner: &'root RootSourceGenesisAuthorityV1,
    archive: super::successor_owner::RootFirstSourceSuccessorArchiveV2,
    completion: [u8; 96],
}

impl<'root> CurrentRootProjectSuccessorFloorV3<'root> {
    pub(super) fn from_completed_owner(
        owner: &'root RootSourceGenesisAuthorityV1,
        archive: super::successor_owner::RootFirstSourceSuccessorArchiveV2,
        completion: [u8; 96],
    ) -> Result<Self, SourceGenesisErrorV1> {
        let current = Self { owner, archive, completion };
        current.recheck()?;
        Ok(current)
    }

    /// Borrows the selected logical floor DATA without releasing its owner.
    pub fn floor(&self) -> &super::RootFirstSourceSuccessorFloorV2 { &self.archive.floor }

    /// Borrows the persisted admission DATA without renewing its original D.
    pub fn original_intent(&self) -> &super::RootFirstSourceSuccessorIntentV2 { &self.archive.original }

    /// Borrows the exact final floor, Controller Complete and Source ACK tuple.
    pub const fn completion(&self) -> &[u8; 96] { &self.completion }

    /// Rechecks the same owner and every retained mixed-family archive.
    ///
    /// # Errors
    /// Rejects changed protected names, original custody or family joins.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.owner.require_current_project_successor_archive_v3(&self.archive)
    }
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
    /// Borrows a completed initial-project floor under the distinct mixed owner.
    ///
    /// # Errors
    /// Rejects missing actual Complete/ACK, changed role/cut or selected floor.
    pub fn current_project_genesis_floor_v3(
        &self, source_packet: &[u8],
    ) -> Result<CurrentRootSourceProjectGenesisFloorV3<'_>, SourceGenesisErrorV1> {
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let floor = self.floor(accepted.acceptance.project())?.ok_or(SourceGenesisErrorV1::Conflict)?;
        self.confirm_project_genesis_ack_v3(source_packet, &floor)?;
        let current = CurrentRootSourceProjectGenesisFloorV3 {
            owner: self, floor,
            source_packet: source_packet.try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
        };
        current.recheck()?;
        Ok(current)
    }
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

/// Borrows the actual completed mixed initial-project Root owner and fixed cut.
///
/// This purpose cannot be exported as a strict V1 proof or public Create loan.
pub struct CurrentRootSourceProjectGenesisFloorV3<'root> {
    owner: &'root RootSourceGenesisAuthorityV1,
    floor: SourceHierarchyFloorRecordV1,
    source_packet: [u8; crate::policy_compiler::SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3],
}

impl CurrentRootSourceProjectGenesisFloorV3<'_> {
    /// Borrows logical floor DATA while the genuine Root owner remains held.
    pub const fn floor(&self) -> &SourceHierarchyFloorRecordV1 { &self.floor }

    /// Rechecks the same named Root, final Controller cut and Source ACK.
    ///
    /// # Errors
    /// Rejects changed owner state or independent Source signature/current cut.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.owner.confirm_project_genesis_ack_v3(&self.source_packet, &self.floor)
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
