//! Separates one known native Observe prefix's persistent and returning work.
//!
//! The original packet quote and builder remain unchanged. The selected native
//! publisher uses this data after authenticating its actual startup purpose and
//! immutable Source, or after the corresponding real incoming Observe. It is not
//! an allocation grant or a purity promise for arbitrary publish callbacks.

use super::*;

use crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::lifetime as shared;
pub(crate) use shared::{
    NativeObservePrefixLifetimeStorageData, NativeOriginalObservePrefixLifetimeStorageData,
};

// These are the additional lower inputs and wrapper returns, independently
// of every original counter term. The base and returned-query calls execute
// sequentially; the numeric records do not contain native or Source owners.
const OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA: usize = size_of::<&OriginalPacketPrefixStorageData>() // new lower prefix input
        + size_of::<usize>() // new lower maximum input
        + size_of::<Result<NativeObservePrefixLifetimeStorageData, ProviderError>>()
        + size_of::<&OriginalReportQueryReceiveStorageData>() // new lower query input
        + size_of::<Result<usize, ProviderError>>(); // additional query wrapper return

// The original raw-ACK partition has its own nested input family. Its real
// const facts loan is infallible; the ACK calculation stays at the old branch.
const ORIGINAL_OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA: usize =
    size_of::<&OriginalPacketPrefixStorageData>()
        + 2 * size_of::<usize>() // new lower frame-cap and maximum inputs
        + 2 * size_of::<&crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::AckFixedLayoutData>() // formed const loan and lower input
        + size_of::<Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError>>();

/// Retains the original upper Observe lifetime and compiled counter producers.
pub(crate) trait OriginalPacketPrefixLifetimeDataExt {
    fn native_observe_lifetime_storage_data(
        &self,
        maximum: usize,
    ) -> Result<NativeObservePrefixLifetimeStorageData, ProviderError>;

    fn native_observe_returned_query_storage_data(
        receive: &OriginalReportQueryReceiveStorageData,
    ) -> Result<usize, ProviderError>;

    fn native_observe_lifetime_counter_scratch_data() -> usize;

    fn native_original_observe_lifetime_storage_data(
        &self,
        maximum_frame: usize,
        maximum: usize,
    ) -> Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError>;

    fn native_original_observe_lifetime_counter_scratch_data() -> usize;

    fn native_original_observe_prepared_lifetime_storage_data(
        &self,
        preparation: &OriginalNativeObservePreparationStorageData,
        maximum_frame: usize,
        maximum: usize,
    ) -> Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError>;

    fn native_original_observe_prepared_lifetime_counter_scratch_data() -> usize;
}

impl OriginalPacketPrefixLifetimeDataExt for OriginalPacketPrefixStorageData {
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
    fn native_observe_lifetime_storage_data(
        &self,
        maximum: usize,
    ) -> Result<NativeObservePrefixLifetimeStorageData, ProviderError> {
        shared::native_observe_lifetime_storage_data(self, maximum)
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
    fn native_observe_returned_query_storage_data(
        receive: &OriginalReportQueryReceiveStorageData,
    ) -> Result<usize, ProviderError> {
        shared::native_observe_returned_query_storage_data(receive)
    }

    /// Names actual nested result/copy, sum-bank and scalar counter headers.
    /// Compiler/recursive frames and allocator overhead remain separate.
    fn native_observe_lifetime_counter_scratch_data() -> usize {
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
            + OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA
    }

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
    fn native_original_observe_lifetime_storage_data(
        &self,
        maximum_frame: usize,
        maximum: usize,
    ) -> Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError> {
        shared::native_original_observe_lifetime_storage_data(
            self,
            maximum_frame,
            maximum,
            &acknowledgements::ACK_FIXED_LAYOUT,
        )
    }

    fn native_original_observe_lifetime_counter_scratch_data() -> usize {
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
            + ORIGINAL_OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA
    }

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
    fn native_original_observe_prepared_lifetime_storage_data(
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
    fn native_original_observe_prepared_lifetime_counter_scratch_data() -> usize {
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

#[cfg(test)]
#[path = "exchange_observe_lifetime/original.rs"]
mod original;

#[cfg(test)]
#[path = "exchange_observe_lifetime/shared_tests.rs"]
mod shared_tests;
