//! Shares the five current Cache replay extents and their receiving peaks.
//!
//! The order is Bootstrap, post-Held HOLD, State, Authority and Clock. These
//! values are comparison DATA. They contain no original, financial borrower,
//! native descriptor, signature approval or permission to enter an audit.

use super::*;
use crate::journal::{
    ProtectedJournalPreopenReplayExtentV1, protected_journal_preopen_replay_extent_for_prefix_v1,
};
use aos_sandbox_model::ResourceDimension as D;

/// Describes the five compiled Cache recipes at supplied, bounded prefix ends.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
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
    ) -> Result<Self, CacheHeldErrorV1> {
        let receipt = CacheHeldReceiptDataV1::decode(bytes, lane)
            .map_err(|_| CacheHeldErrorV1::Order)?;
        let mut snapshot = receipt
            .body(lane)
            .map_err(|_| CacheHeldErrorV1::Order)?;
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
    ) -> Result<Self, CacheHeldErrorV1> {
        Self::from_ends_v1([
            snapshot.bootstrap.end,
            snapshot.hold.end,
            snapshot.state.end,
            snapshot.authority.end,
            snapshot.clock.end,
        ])
    }

    fn from_ends_v1(ends: [u64; 5]) -> Result<Self, CacheHeldErrorV1> {
        let roles = [
            InitializerJournal::Source,
            InitializerJournal::Hold,
            InitializerJournal::State,
            InitializerJournal::Authority,
            InitializerJournal::Clock,
        ];
        // Every element retains its own compiled limits; a common default or
        // the maximum of five file lengths would erase real role differences.
        let extent = |index: usize| -> Result<_, CacheHeldErrorV1> {
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
        self.extents.map(|extent| extent.native_bytes())
    }

    /// Returns the shared sequential native and semantic receiving peaks.
    ///
    /// # Errors
    /// Rejects checked overflow or inconsistent extent DATA.
    pub fn dynamic_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, CacheHeldErrorV1> {
        create_storage_cache_current_dynamic_receiving_demand_v1(&self.extents)
    }

    pub(super) fn dynamic_receiving_with_semantic_supplement_v1(
        &self,
        supplement: Option<ResourceVector>,
    ) -> Result<ResourceVector, CacheHeldErrorV1> {
        create_storage_cache_current_dynamic_with_upper_semantic_quote_v1(&self.extents, supplement)
    }

    pub(super) fn semantic_peak_v1(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
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
) -> Result<ResourceVector, CacheHeldErrorV1> {
    let mut native = ResourceVector::ZERO;
    for extent in extents {
        native = native.componentwise_max(extent.dominant_native_receiving_demand_v1()?);
    }
    Ok(native.checked_add(semantic_peak(extents)?)?)
}

fn semantic_peak(
    extents: &[ProtectedJournalPreopenReplayExtentV1; 5],
) -> Result<ResourceVector, CacheHeldErrorV1> {
    let mut semantic = ResourceVector::ZERO;
    for extent in extents {
        semantic = semantic.componentwise_max(crate::journal::readonly_receiving::full_prefix_semantic_demand_v1(extent)?);
    }
    Ok(semantic)
}


impl PartialEq for CreateStorageCacheCurrentExtentsDataV1 {
    fn eq(&self, other: &Self) -> bool {
        self.extents.iter().zip(&other.extents).all(|(left, right)| {
            left.limits() == right.limits() && left.native_bytes() == right.native_bytes()
        })
    }
}

impl Eq for CreateStorageCacheCurrentExtentsDataV1 {}

/// Prices the actual Current five-prefix peak with its retained upper quote.
///
/// Supplied extent/quote DATA admits no native work. Missing upper quote is a
/// refusal only after the first full Ledger prefix forecast succeeds.
///
/// # Errors
/// Rejects native geometry, full semantic geometry, the deferred upper quote
/// or checked composition overflow in the original native-then-semantic order.
#[doc(hidden)]
pub fn create_storage_cache_current_dynamic_with_upper_semantic_quote_v1(
    extents: &[ProtectedJournalPreopenReplayExtentV1; 5],
    supplement: Option<ResourceVector>,
) -> Result<ResourceVector, CacheHeldErrorV1> {
    let mut native = ResourceVector::ZERO;
    for extent in extents {
        native = native.componentwise_max(extent.dominant_native_receiving_demand_v1()?);
    }
    let semantic = crate::journal::readonly_receiving::full_prefix_semantic_peak_with_supplement_v1(
        extents, supplement,
    )?;
    Ok(native.checked_add(semantic)?)
}
