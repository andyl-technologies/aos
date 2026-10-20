//! Shares the five current Cache replay extents and their receiving peaks.
//!
//! The order is Bootstrap, post-Held HOLD, State, Authority and Clock. These
//! values are comparison DATA. They contain no original, financial borrower,
//! native descriptor, signature approval or permission to enter an audit.

use super::*;
use crate::journal::{
    ProtectedJournalPreopenReplayExtentV1, protected_journal_preopen_replay_extent_for_prefix_v1,
};
use aos_sandbox_core::ResourceDimension as D;

/// Describes the five compiled Cache recipes at supplied, bounded prefix ends.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateStorageCacheCurrentExtentsDataV1 {
    extents: [ProtectedJournalPreopenReplayExtentV1; 5],
}

impl CreateStorageCacheCurrentExtentsDataV1 {
    /// Derives replay bounds from a canonical Held receipt's returned positions.
    ///
    /// HOLD uses the returned after-Held end, rather than the body predecessor.
    /// Parsing this receipt authenticates neither its signer nor a live Cache.
    ///
    /// # Errors
    /// Rejects malformed or differently associated receipt DATA, a prefix beyond
    /// its compiled role limit, or checked receiving arithmetic overflow.
    pub fn from_held_receipt_v1(
        bytes: &[u8],
        lane: [u8; 16],
    ) -> Result<Self, ResourceReservationErrorV1> {
        let receipt = CacheHeldReceiptDataV1::decode(bytes, lane)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut snapshot = receipt
            .body(lane)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        snapshot.hold.end = receipt.hold_after_end;
        Self::from_current_snapshot_v1(&snapshot)
    }

    /// Derives replay bounds from the current snapshot inside a verified body.
    ///
    /// The caller retains responsibility for signature, original and freshness
    /// checks. This method uses only the supplied five physical prefix ends.
    ///
    /// # Errors
    /// Rejects a prefix beyond its compiled role limit or checked overflow.
    pub fn from_current_snapshot_v1(
        snapshot: &CacheHeldBodyDataV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        Self::from_ends_v1([
            snapshot.bootstrap.end,
            snapshot.hold.end,
            snapshot.state.end,
            snapshot.authority.end,
            snapshot.clock.end,
        ])
    }

    fn from_ends_v1(ends: [u64; 5]) -> Result<Self, ResourceReservationErrorV1> {
        let roles = [
            InitializerJournal::Source,
            InitializerJournal::Hold,
            InitializerJournal::State,
            InitializerJournal::Authority,
            InitializerJournal::Clock,
        ];
        // Every element retains its own compiled limits; a common default or
        // the maximum of five file lengths would erase real role differences.
        let extent = |index: usize| -> Result<_, ResourceReservationErrorV1> {
            Ok(protected_journal_preopen_replay_extent_for_prefix_v1(
                roles[index].recipe().2,
                ends[index],
            )?)
        };
        Ok(Self {
            extents: [extent(0)?, extent(1)?, extent(2)?, extent(3)?, extent(4)?],
        })
    }

    pub(super) fn from_captured_extents_v1(
        extents: [ProtectedJournalPreopenReplayExtentV1; 5],
    ) -> Self {
        Self { extents }
    }

    /// Borrows the exact five stored extents in the documented role order.
    pub fn extents_v1(&self) -> &[ProtectedJournalPreopenReplayExtentV1; 5] {
        &self.extents
    }

    /// Borrows the same array for a receiving recipe accepting captured DATA.
    pub fn captured_extents_v1(&self) -> &[ProtectedJournalPreopenReplayExtentV1; 5] {
        self.extents_v1()
    }

    /// Returns the five bounded physical ends in the documented role order.
    pub fn native_bytes_v1(&self) -> [u64; 5] {
        self.extents.map(|extent| extent.native_bytes)
    }

    /// Returns the shared sequential native and semantic receiving peaks.
    ///
    /// # Errors
    /// Rejects checked overflow or inconsistent extent DATA.
    pub fn dynamic_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        create_storage_cache_current_dynamic_receiving_demand_v1(&self.extents)
    }

    pub(super) fn semantic_peak_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        semantic_peak(&self.extents)
    }
}

/// Prices the same five sequential native audits from exact captured extents.
///
/// A completed positive reader and its local posts are physically disposed
/// before the next reader. A negative reader remains resident and stops the
/// sequence. Native and semantic peaks are added because they coexist.
///
/// # Errors
/// Rejects inconsistent extent DATA or checked arithmetic overflow.
#[doc(hidden)]
pub fn create_storage_cache_current_dynamic_receiving_demand_v1(
    extents: &[ProtectedJournalPreopenReplayExtentV1; 5],
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let mut native = ResourceVector::ZERO;
    for extent in extents {
        native = native.componentwise_max(extent.dominant_native_receiving_demand_v1()?);
    }
    Ok(native.checked_add(semantic_peak(extents)?)?)
}

fn semantic_peak(
    extents: &[ProtectedJournalPreopenReplayExtentV1; 5],
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let mut semantic = ResourceVector::ZERO;
    for extent in extents {
        semantic = semantic.componentwise_max(extent.dominant_semantic_receiving_demand_v1()?);
    }
    Ok(semantic)
}

pub(crate) fn current_cache_fixed_receiving_demand_v1()
-> Result<ResourceVector, ResourceReservationErrorV1> {
    let clock_bytes =
        crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
    let construction = std::mem::size_of::<CreateStorageCacheCurrentExtentsDataV1>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<ResourceVector>()))
        .and_then(|bytes| bytes.checked_add(clock_bytes))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let clock = ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(construction).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .with(D::OpenFiles, u64::try_from(
            crate::policy_compiler::RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1,
        ).map_err(|_| ResourceReservationErrorV1::Conflict)?);
    // Rust control fields and native metadata samples are not namespace rows.
    let fixed = receiving::current_fixed_demand()
        .map_err(|_| ResourceReservationErrorV1::Conflict)?
        .with(D::MetadataEntries, 0);
    Ok(fixed.checked_add(clock)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        association::AcceptedAssociationDataV1,
        cache_held::{CACHE_HELD_RECORD_BYTES_V1, CachePhysicalDataV1},
    };
    use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

    fn snapshot() -> CacheHeldBodyDataV1 {
        let coordinate = CacheJournalDataV1 {
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            next: 1,
            end: 0,
        };
        CacheHeldBodyDataV1 {
            association: AcceptedAssociationDataV1 {
                operation: [1; 16],
                project: [2; 16],
                sandbox: [3; 16],
                accepted_request: [4; 32],
                coissuance_binding: [5; 32],
                seed: [6; 32],
                controller_nonce: [7; 16],
                boot: [8; 16],
                started: 9,
                cutoff: 10,
            },
            source_held: [11; 32],
            bootstrap: coordinate,
            hold: coordinate,
            state: coordinate,
            authority: coordinate,
            clock: coordinate,
            physical: CachePhysicalDataV1 {
                root: (12, 13),
                uid: 1000,
                mode: 0o700,
                lock: (12, 14),
                manifest: (0, 0),
                generation: 0,
                digest: [0; 32],
                limits: [15; 32],
            },
            selected_partition: [16; 32],
            selected_head: [17; 32],
            quota: [18; 32],
            disk_count: 0,
            negative_count: 0,
            pin_count: 0,
            clock_floor: 19,
        }
    }

    #[test]
    fn receipt_and_current_snapshot_share_the_actual_post_held_extent() {
        let lane = [22; 16];
        let original = snapshot();
        let mut record = [0; CACHE_HELD_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(
            RecordCoordinatesV1 {
                key: KeyV1::new(lane, OwnerV1::Cache, 1).unwrap(),
                phase: PhaseV1::new(OwnerV1::Cache, 1).unwrap(),
                predecessor: [0; 32],
                correlation: original.association.seed,
            },
            &original.encode().unwrap(),
            &mut record,
        )
        .unwrap();
        let receipt = CacheHeldReceiptDataV1 {
            record: &record,
            latest_head: LatestHeadV1::new(1, checksum).unwrap().encode(),
            hold_names: original.hold.names,
            hold_after_next: original.hold.next + 4,
            hold_after_end: 4096,
        }
        .encode(lane)
        .unwrap();

        let held =
            CreateStorageCacheCurrentExtentsDataV1::from_held_receipt_v1(&receipt, lane).unwrap();
        let mut current = original;
        current.hold.end = 4096;
        let signed =
            CreateStorageCacheCurrentExtentsDataV1::from_current_snapshot_v1(&current).unwrap();

        assert_eq!(held, signed);
        assert_eq!(held.native_bytes_v1(), [0, 4096, 0, 0, 0]);
        assert_ne!(
            held,
            CreateStorageCacheCurrentExtentsDataV1::from_current_snapshot_v1(&original).unwrap()
        );
        assert!(
            CreateStorageCacheCurrentExtentsDataV1::from_held_receipt_v1(&receipt, [23; 16])
                .is_err()
        );
    }

    #[test]
    fn five_role_dynamic_peak_is_shared_without_summing_sequential_readers() {
        let mut body = snapshot();
        body.bootstrap.end = 8192;
        body.hold.end = 4096;
        body.state.end = 2048;
        body.authority.end = 1024;
        body.clock.end = 512;
        let data = CreateStorageCacheCurrentExtentsDataV1::from_current_snapshot_v1(&body).unwrap();
        let mut native = ResourceVector::ZERO;
        let mut semantic = ResourceVector::ZERO;
        for extent in data.extents_v1() {
            native =
                native.componentwise_max(extent.dominant_native_receiving_demand_v1().unwrap());
            semantic =
                semantic.componentwise_max(extent.dominant_semantic_receiving_demand_v1().unwrap());
        }

        assert_eq!(
            data.dynamic_receiving_demand_v1().unwrap(),
            native.checked_add(semantic).unwrap()
        );
        assert!(std::ptr::eq(data.extents_v1(), data.captured_extents_v1()));
        body.clock.end = data.extents_v1()[4].limits.maximum_journal_bytes + 1;
        assert!(CreateStorageCacheCurrentExtentsDataV1::from_current_snapshot_v1(&body).is_err());
        assert_eq!(
            current_cache_fixed_receiving_demand_v1()
                .unwrap()
                .get(D::MetadataEntries),
            0
        );
    }
}
