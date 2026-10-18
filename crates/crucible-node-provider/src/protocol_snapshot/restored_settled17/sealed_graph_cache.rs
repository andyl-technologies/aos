//! Retains a native decoder behind one independently funded lazy heap slot.
//!
//! The outer Source decoder moves between partial and sealed owners. Keeping
//! its two large native decoder headers inline makes those ordinary moves use
//! several copies of their full stack layout even while both caches are absent.
//! This spine retains zero or one actual child, including a reserved empty slot
//! or a failed child. It changes no modeled state or historical wire format.

use crate::ProviderError;
use crate::protocol_snapshot::native_wholegraph17::{
    NativeCurrentGraph17DecodeAttempt, NativeCurrentGraph17ReadLimits,
    read_native_current_graph17_with_limits_into_data,
};
use std::alloc::Layout;
use std::mem::size_of;

/// Owns the actual child slot before any child allocation or decode can fail.
pub(in crate::protocol_snapshot::restored_settled17) struct NativeGraph17DecodeCache {
    slots: Vec<Option<NativeCurrentGraph17DecodeAttempt>>,
    started: bool,
}

impl NativeGraph17DecodeCache {
    /// Creates an absent cache without allocating its large child header.
    pub(in crate::protocol_snapshot::restored_settled17) const fn new() -> Self {
        Self {
            slots: Vec::new(),
            started: false,
        }
    }

    /// Borrows only an actually initialized child, including a failed decoder.
    pub(in crate::protocol_snapshot::restored_settled17) fn as_ref(
        &self,
    ) -> Option<&NativeCurrentGraph17DecodeAttempt> {
        self.slots.first().and_then(Option::as_ref)
    }

    /// Debits the concrete slot before reservation and preserves every failure.
    ///
    /// The same independent backing ceiling covers the slot and the child's
    /// raw/typed backing. The caller has already retained this small spine.
    ///
    /// # Errors
    /// Refuses reuse, short header or child backing credit, allocation refusal,
    /// excessive actual capacity or any underlying native decoder failure.
    pub(in crate::protocol_snapshot::restored_settled17) fn read_into_data(
        &mut self,
        input: &[u8],
        limits: NativeCurrentGraph17ReadLimits,
    ) -> Result<(), ProviderError> {
        if std::mem::replace(&mut self.started, true) || !self.slots.is_empty() {
            return Err(refused());
        }
        let header = Layout::array::<Option<NativeCurrentGraph17DecodeAttempt>>(1)
            .map_err(|_| refused())?
            .size();
        if header > limits.maximum_requested {
            return Err(refused());
        }

        // Capacity belongs to the retained spine even if the allocator returns
        // an excessive bank or a subsequent child decoder refuses immediately.
        self.slots.try_reserve_exact(1).map_err(|_| refused())?;
        let retained = self.retained_requested_storage_data(limits.maximum_requested)?;
        if self.slots.capacity() != 1 {
            return Err(refused());
        }
        self.slots.resize_with(1, || None);
        let destination = self.slots.first_mut().ok_or_else(refused)?;
        read_native_current_graph17_with_limits_into_data(
            input,
            destination,
            NativeCurrentGraph17ReadLimits {
                maximum_requested: limits
                    .maximum_requested
                    .checked_sub(retained)
                    .ok_or_else(refused)?,
                ..limits
            },
        )
    }

    /// Includes actual slot capacity and every initialized child's backing.
    ///
    /// # Errors
    /// Refuses requested-layout overflow or cumulative backing above maximum.
    pub(in crate::protocol_snapshot::restored_settled17) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut retained =
            Layout::array::<Option<NativeCurrentGraph17DecodeAttempt>>(self.slots.capacity())
                .map_err(|_| refused())?
                .size();
        if retained > maximum {
            return Err(refused());
        }
        for child in self.slots.iter().flatten() {
            let remaining = maximum.checked_sub(retained).ok_or_else(refused)?;
            retained = retained
                .checked_add(child.retained_requested_storage_data(remaining)?)
                .ok_or_else(refused)?;
        }
        Ok(retained)
    }
}

/// Names the new slot's fixed allocation, reader and census controls.
pub(super) const fn counter_scratch_data() -> usize {
    size_of::<Layout>()
        + size_of::<NativeCurrentGraph17ReadLimits>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<&'static mut Option<NativeCurrentGraph17DecodeAttempt>, ProviderError>>()
        + size_of::<std::slice::Iter<'static, Option<NativeCurrentGraph17DecodeAttempt>>>()
        + size_of::<
            std::iter::Flatten<
                std::slice::Iter<'static, Option<NativeCurrentGraph17DecodeAttempt>>,
            >,
        >()
        + size_of::<std::collections::TryReserveError>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + 3 * size_of::<usize>()
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("retained native17 decoder slot")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(maximum_requested: usize) -> NativeCurrentGraph17ReadLimits {
        NativeCurrentGraph17ReadLimits {
            maximum_requested,
            maximum_target_requested: maximum_requested,
            maximum_nodes: 64,
            maximum_depth: 64,
        }
    }

    #[test]
    fn one_short_slot_refuses_before_allocation_and_cannot_be_retried() {
        let header = size_of::<Option<NativeCurrentGraph17DecodeAttempt>>();
        let mut cache = NativeGraph17DecodeCache::new();

        assert!(cache.read_into_data(b"{}", limits(header - 1)).is_err());
        assert_eq!(cache.slots.capacity(), 0);
        assert!(cache.started);
        assert!(cache.read_into_data(b"{}", limits(usize::MAX)).is_err());
        assert_eq!(cache.slots.capacity(), 0);
    }

    #[test]
    fn exact_slot_retains_the_initialized_child_after_its_raw_credit_refuses() {
        let header = size_of::<Option<NativeCurrentGraph17DecodeAttempt>>();
        let mut cache = NativeGraph17DecodeCache::new();

        assert!(cache.read_into_data(b"{}", limits(header)).is_err());
        assert_eq!(cache.slots.capacity(), 1);
        assert!(cache.as_ref().is_some());
        assert_eq!(
            cache.retained_requested_storage_data(header).unwrap(),
            header
        );
        assert!(cache.read_into_data(b"{}", limits(usize::MAX)).is_err());
        assert!(cache.as_ref().is_some());
    }

    #[test]
    fn a_later_wire_refusal_keeps_both_the_slot_and_copied_raw_prefix() {
        let header = size_of::<Option<NativeCurrentGraph17DecodeAttempt>>();
        let mut cache = NativeGraph17DecodeCache::new();
        let maximum = header + 2;

        assert!(cache.read_into_data(b"{}", limits(maximum)).is_err());
        assert!(cache.as_ref().is_some());
        assert_eq!(
            cache.retained_requested_storage_data(maximum).unwrap(),
            maximum
        );
        assert!(cache.retained_requested_storage_data(maximum - 1).is_err());
        assert_eq!(cache.slots.capacity(), 1);
    }

    #[test]
    fn large_decoder_headers_are_absent_from_the_outer_moving_owner() {
        assert!(size_of::<super::super::RestoredSettledNative17DecodeAttempt>() < 4096);
        assert!(size_of::<NativeGraph17DecodeCache>() < 128);
    }
}
