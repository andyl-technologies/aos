//! Separates one known native Observe prefix's persistent and returning work.
//!
//! The original packet quote and builder remain unchanged. The selected native
//! publisher uses this data after authenticating its actual startup purpose and
//! immutable Source, or after the corresponding real incoming Observe. It is not
//! an allocation grant or a purity promise for arbitrary publish callbacks.

use super::*;

/// Keeps all persistent or uncertain prefix owners separate from returning work.
pub(crate) struct NativeObservePrefixLifetimeStorageData {
    /// Includes every plan, guard, canonical bank, cache and containment owner.
    /// The complete terminating open-ACK allowance stays here: a refused reply
    /// can remain in the original record, including arbitrary Error details.
    pub(crate) retained_requested_bytes: usize,
    /// Covers all construction/preparation/iterator work conservatively summed.
    pub(crate) maximum_simultaneous_transient_bytes: usize,
    /// Keeps the original quoted prefix counter window independently named.
    pub(crate) declared_counter_scratch_bytes: usize,
}

impl NativeObservePrefixLifetimeStorageData {
    /// Includes the original prefix counter window in the full returning phase.
    ///
    /// # Errors
    /// Refuses checked storage arithmetic overflow.
    pub(crate) fn work_requested_bytes(&self) -> Result<usize, ProviderError> {
        add(
            self.maximum_simultaneous_transient_bytes,
            self.declared_counter_scratch_bytes,
        )
    }

    fn peak(&self) -> Result<usize, ProviderError> {
        add(self.retained_requested_bytes, self.work_requested_bytes()?)
    }
}

impl OriginalPacketPrefixStorageData {
    /// Partitions the same full prefix quote for the closed native Observe path.
    ///
    /// No component is subtracted from the whole peak. Source-owned input and
    /// report/preparation capsules remain independent enclosing rows. The fixed
    /// publisher invokes frames/prepare_in_place before publish; the entire
    /// originals/canonical/guard/cache/containment population remains retained
    /// through failure. Preparation errors terminate this once-only attempt;
    /// their complete construction phase remains covered even when its original
    /// error/partial owner is retained. No later phase may reclaim that credit.
    ///
    /// The incoming query has already returned before the selected publisher
    /// quotes or constructs its reply. Its actual original and incident owners
    /// remain in the enclosing Source/control rows. Only those two returning
    /// phase windows can be maxed by that caller; peer/member rows remain summed.
    ///
    /// # Errors
    /// Refuses overflow, a partition differing from the original full quote,
    /// or a full peak exceeding the caller's already admitted maximum.
    pub(crate) fn native_observe_lifetime_storage_data(
        &self,
        maximum: usize,
    ) -> Result<NativeObservePrefixLifetimeStorageData, ProviderError> {
        let retained_requested_bytes = sum(&[
            self.original_plan_requested_bytes,
            self.acknowledgement_index_requested_bytes,
            self.canonical_requested_bytes,
            self.record_slots_requested_bytes,
            self.outgoing_guard_requested_bytes,
            self.successful_ack_cache_requested_bytes,
            self.one_open_ack_requested_bytes,
            self.containment_requested_bytes,
        ])?;
        let data = NativeObservePrefixLifetimeStorageData {
            retained_requested_bytes,
            maximum_simultaneous_transient_bytes: sum(&[
                self.construction_transient_requested_bytes,
                self.preparation_transient_requested_bytes,
                self.response_iterator_requested_bytes,
            ])?,
            declared_counter_scratch_bytes: self.declared_quote_scratch_bytes,
        };
        // This is an exact partition of the OLD full quote, not a smaller
        // allocation ceiling or a replacement for actual owning reconciliation.
        let peak = data.peak()?;
        if peak != self.requested_bytes()? || peak > maximum {
            return Err(credit());
        }
        Ok(data)
    }

    /// Covers the restricted returned Observe under the unchanged SDK metric.
    ///
    /// The closed receive predicate requires empty Observe extensions. The
    /// actual SDK field walk still records that empty tree's possible root;
    /// carry it alongside the already quoted typed Box/hash children. This
    /// selected DATA projection does not change the old generic receive quote
    /// or establish any original Source, currentness or allocation authority.
    ///
    /// # Errors
    /// Refuses checked layout/arithmetic overflow.
    pub(crate) fn native_observe_returned_query_storage_data(
        receive: &OriginalReportQueryReceiveStorageData,
    ) -> Result<usize, ProviderError> {
        let empty_extensions_root = crate::retained_metadata::requested_storage::tree_storage_data(
            1,
            0,
            size_of::<(String, Value)>(),
            align_of::<(String, Value)>(),
        )?;
        add(receive.typed_query_requested_bytes, empty_extensions_root)
    }

    /// Names actual nested result/copy, sum-bank and scalar counter headers.
    /// Compiler/recursive frames and allocator overhead remain separate.
    pub(crate) const fn native_observe_lifetime_counter_scratch_data() -> usize {
        3 * size_of::<NativeObservePrefixLifetimeStorageData>()
            + size_of::<[usize; 8]>()
            + size_of::<[usize; 3]>()
            + 6 * size_of::<usize>()
            // Selected returned-query root layout/result beside the caller's
            // receive view. These are explicit data locals, not compiler frames.
            + 2 * size_of::<usize>()
            + size_of::<&OriginalReportQueryReceiveStorageData>()
            + size_of::<std::alloc::Layout>()
            + size_of::<[usize; 5]>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
    }
}
