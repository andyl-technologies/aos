//! Quotes only the actual closed native-five launch decoding layouts.
//!
//! Recognition inspects the immutable encoded launch before any DOM or typed
//! owner is constructed. It authenticates no Source or launch right. Unknown
//! editions, fields or program variants keep the generic issuer quote, and the
//! original duplicate-refusing parser, typed decoder and validators still run.

use super::*;

use crucible_source_birth_data::profile::reference_packet::service::native_startup::launch_decode::element_slot;
pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::launch_decode::{
    counter_scratch_data, recognized,
};

pub(super) fn quote(bytes: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    if recognized(bytes).is_err() {
        return super::super::super::complete_restore::transfer::selected_issuer_decode_storage_data(
            bytes, size_of::<PacketNative5SourceLaunch>(), maximum,
        );
    }
    // Keep the complete conservative DecodedStorage total, including its
    // separate Value/typed backing and work rows. This intentionally covers
    // more than the minimal live decode: all opaque Value/string/map banks,
    // array minimum/spare capacity, borrowed/owned rebuilding, canonical output
    // and collect/sort banks remain; only the unrelated Control per-token tax
    // disappears. This result never includes or replaces launch.validate work.
    decoded::quote(
        bytes,
        size_of::<PacketNative5SourceLaunch>(),
        element_slot(),
        maximum,
    )?
    .total(maximum)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod original;

#[cfg(test)]
mod shared_tests;
