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

/// Keeps a selected original Observe's independent encoding and ACK phases.
///
/// The original full quote/builder remains authoritative. Both new axes still
/// include every persistent owner from a terminating Error or malformed ACK.
pub(crate) struct NativeOriginalObservePrefixLifetimeStorageData {
    pub(crate) retained_requested_bytes: usize,
    encoding: usize,
    acknowledgement: usize,
    scratch: usize,
}

impl NativeOriginalObservePrefixLifetimeStorageData {
    pub(crate) fn encoding_work_requested_bytes(&self) -> Result<usize, ProviderError> {
        add(self.encoding, self.scratch)
    }

    pub(crate) fn acknowledgement_work_requested_bytes(&self) -> Result<usize, ProviderError> {
        add(self.acknowledgement, self.scratch)
    }
}

impl OriginalPacketPrefixStorageData {
    /// Splits the actual original Observe's terminating ACK validation lifetime.
    ///
    /// The defining native publisher finishes dispatch/transform/prepare before
    /// publish starts reading any ACK. Its actual typed query and all retained
    /// originals/canonical/guard/cache/error banks remain independently live.
    /// The selected caller must therefore add those enclosing owners to both
    /// transient arms, rather than subtracting their allowance or maxing peers.
    ///
    /// # Errors
    /// Refuses overflow, a cap not matching the original complete ACK quote or
    /// an original full quote above the compiled projection maximum.
    pub(crate) fn native_original_observe_lifetime_storage_data(
        &self,
        maximum_frame: usize,
        maximum: usize,
    ) -> Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError> {
        let old = self.native_observe_lifetime_storage_data(maximum)?;
        let (retained_ack, returning_ack) = if self.requests == 0 {
            if self.one_open_ack_requested_bytes != 0 {
                return Err(credit());
            }
            (0, 0)
        } else {
            let ack = acknowledgements::open_ack_lifetime_storage_data(maximum_frame)?;
            if add(ack.retained, ack.returning)? != self.one_open_ack_requested_bytes {
                return Err(credit());
            }
            (ack.retained, ack.returning)
        };
        let retained = old
            .retained_requested_bytes
            .checked_sub(self.one_open_ack_requested_bytes)
            .and_then(|n| n.checked_add(retained_ack))
            .ok_or_else(credit)?;
        let result = NativeOriginalObservePrefixLifetimeStorageData {
            retained_requested_bytes: retained,
            encoding: old.maximum_simultaneous_transient_bytes,
            acknowledgement: returning_ack,
            scratch: old.declared_counter_scratch_bytes,
        };
        let phase = result
            .encoding_work_requested_bytes()?
            .max(result.acknowledgement_work_requested_bytes()?);
        if add(result.retained_requested_bytes, phase)? > self.requested_bytes()? {
            return Err(credit());
        }
        Ok(result)
    }

    pub(crate) const fn native_original_observe_lifetime_counter_scratch_data() -> usize {
        Self::native_observe_lifetime_counter_scratch_data()
            + acknowledgements::open_ack_lifetime_counter_scratch_data()
            + size_of::<Result<NativeObservePrefixLifetimeStorageData, ProviderError>>()
            + size_of::<NativeOriginalObservePrefixLifetimeStorageData>()
            + size_of::<Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError>>()
            + size_of::<(usize, usize)>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<&OriginalPacketPrefixStorageData>()
            + size_of::<&NativeOriginalObservePrefixLifetimeStorageData>()
            + 6 * size_of::<usize>()
    }
}

impl OriginalPacketPrefixStorageData {
    /// Separates the selected preparation loop without releasing retained owners.
    ///
    /// The opaque preparation row must match every field of this complete
    /// original quote. It bounds one returning loop iteration; all completed
    /// canonical banks, plans, guards, partials and terminating ACK owners remain
    /// in the independently derived retained axis. Construction and iteration
    /// work stay summed with the largest preparation iteration.
    ///
    /// # Errors
    /// Refuses another complete quote, an insufficient limit, overflow or a
    /// preparation phase exceeding the original conservative summed allowance.
    pub(crate) fn native_original_observe_prepared_lifetime_storage_data(
        &self,
        preparation: &OriginalNativeObservePreparationStorageData,
        maximum_frame: usize,
        maximum: usize,
    ) -> Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError> {
        let mut lifetime =
            self.native_original_observe_lifetime_storage_data(maximum_frame, maximum)?;
        let preparation = preparation.maximum_simultaneous_transient_bytes_data(self, maximum)?;
        if preparation > self.preparation_transient_requested_bytes {
            return Err(credit());
        }

        lifetime.encoding = sum(&[
            self.construction_transient_requested_bytes,
            preparation,
            self.response_iterator_requested_bytes,
        ])?;
        if self.requests != 0 {
            // The old full cap was authenticated above. Keep every uncertain
            // owner; only the same returning canonical output banks narrow.
            let ack =
                acknowledgements::native_original_open_ack_lifetime_storage_data(maximum_frame)?;
            lifetime.acknowledgement = ack.returning;
        }
        Ok(lifetime)
    }

    /// Names the complete selected producer and nested lifetime return views.
    pub(crate) fn native_original_observe_prepared_lifetime_counter_scratch_data() -> usize {
        Self::native_original_observe_lifetime_counter_scratch_data()
            + crate::connection::original_native_observe_preparation_counter_scratch_data()
            + acknowledgements::native_original_open_ack_counter_scratch_data()
            + size_of::<acknowledgements::OpenAckLifetimeStorageData>()
            + size_of::<Result<acknowledgements::OpenAckLifetimeStorageData, ProviderError>>()
            + size_of::<&OriginalNativeObservePreparationStorageData>()
            + size_of::<NativeOriginalObservePrefixLifetimeStorageData>()
            + size_of::<Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<[usize; 3]>()
            + size_of::<usize>()
            + size_of::<bool>()
    }
}
