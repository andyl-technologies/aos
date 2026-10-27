//! Checks completed private banks against the same original retained grant.
//!
//! The fixed floor stays conservative. Actual literal and cut backing can only
//! increase it; the two parsed trees and growable canonical bank are separate.
//! The carried typed launch remains independently funded by private transient
//! demand. This check visits completed trees; parser partial custody remains
//! the defining reader's responsibility.

use super::super::{
    boot::{NativeAckBoot, OriginalNativeStartupBootAttempt},
    owned_read::OriginalPrivateBootstrapStream,
};
use super::*;
use crate::reference_packet::service::native_startup::{
    original_native_private_bootstrap_floor_data, original_native_private_invocation_backing_data,
};
use crate::retained_metadata::{
    MetadataObserver, NativeImport18JsonMetadataProfileData, RetainedProtocolMetadataFacts,
    requested_metadata_backing_storage_data,
};
use crate::transport::{OriginalFrameReaderFacts, original_frames::OriginalFrame};
use std::{cell::Ref, mem::size_of};

/// Checks actual completed owners before the next private construction phase.
///
/// # Errors
/// Refuses stale origin, changed custody, a borrowed bank, invalid traversal,
/// overflow, or retained demand above the original private row.
pub(super) fn check<S: AsFd>(owner: &Bootstrap<S>) -> Result<(), ProviderError> {
    let Bootstrap {
        reader,
        literals: bank,
        launch_value,
        launch_bytes,
        launch: _,
        boot_value,
        boot,
        startup_attempt,
        startup,
    } = owner;
    let Some(startup) = startup.as_ref() else {
        return Ok(());
    };
    startup.ensure_original()?;
    if boot.is_some() || startup_attempt.is_some() {
        return Err(ProviderError::Correlation("native private retained window"));
    }

    // This proves the reader and Bootstrap retain this very same allocation.
    // Equal contents or a copied reservation would not justify counting it once.
    reader.original_owned11_facts(bank)?;
    let literals = bank
        .try_borrow()
        .map_err(|_| ProviderError::Conflict("native private retained literals borrowed"))?;
    let cut = reader
        .stream_ref()
        .cut
        .as_ref()
        .ok_or(ProviderError::Correlation(
            "native private retained cut absent",
        ))?;
    cut.ensure_current()?;

    let mut fixed = MetadataObserver::new();
    fixed.shared_value(bank.as_ref())?;
    literals.observe_owned11_metadata(&mut fixed)?;
    cut.observe_original_private_backing_data(&mut fixed)?;
    let invocation = original_native_private_invocation_backing_data()?;
    let fixed = size_of::<Bootstrap<S>>()
        .checked_add(requested_metadata_backing_storage_data(&fixed.finish())?)
        .and_then(|bytes| bytes.checked_add(invocation))
        .ok_or_else(exhausted)?;
    // The owner is still inline here. Its future Box is not an existing heap
    // allocation; its explicit header contribution is already in this floor.
    let floor = original_native_private_bootstrap_floor_data()?.max(fixed);

    let mut dynamic = MetadataObserver::new();
    for (index, value) in [launch_value.as_ref(), boot_value.as_ref()]
        .into_iter()
        .enumerate()
    {
        let Some(value) = value else {
            continue;
        };
        let frame = literals.frame(index).ok_or(ProviderError::Frame(
            "native private retained literal absent",
        ))?;
        if frame.direction != crate::transport::original_frames::FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
        {
            return Err(ProviderError::Frame(
                "native private retained literal incomplete",
            ));
        }
        let body = frame
            .bytes
            .get(4..)
            .ok_or(ProviderError::Frame("native private retained body absent"))?;
        let mut profile = NativeImport18JsonMetadataProfileData::strict_raw_data();
        // Actual strict syntax bounds visits to this completed tree. This is
        // neither the negotiated maximum nor an encoded-byte heap estimate.
        profile.retain_strict_raw_population_data(body.len());
        dynamic
            .with_native_import18_json_profile_data(profile, |observer| observer.observe(value))?;
    }
    dynamic.vector::<u8>(launch_bytes.capacity())?;
    let requested = floor
        .checked_add(requested_metadata_backing_storage_data(&dynamic.finish())?)
        .ok_or_else(exhausted)?;
    let requested = u64::try_from(requested).map_err(|_| exhausted())?;
    if requested > startup.private_bootstrap.retained_requested_bytes.get() {
        return Err(exhausted());
    }

    cut.ensure_current()?;
    startup.ensure_original()
}

/// Spends the same retained scope when its completed-owner check refuses.
///
/// # Errors
/// Returns the original refusal without dropping or reconstructing any bank.
pub(super) fn finish(
    result: Result<(), ProviderError>,
    startup: &mut Option<admitted::OriginalNativeStartupBootstrap>,
) -> Result<(), ProviderError> {
    if result.is_err()
        && let Some(startup) = startup.as_mut()
    {
        startup.failed = true;
    }
    result
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native private retained banks")
}

/// Counts the additional census views beside all earlier construction windows.
pub(in crate::reference_packet::service::ack_emitter::native_boot) fn counter_scratch_data() -> usize
{
    // Price the defining strict profile's own recursive depth. These typed
    // controls are separate from the earlier constructor/observer windows.
    let depth = NativeImport18JsonMetadataProfileData::strict_raw_data().maximum_depth_data();
    depth * MetadataObserver::native_import18_json_metadata_frame_counter_scratch_data()
        + MetadataObserver::native_import18_json_profile_counter_scratch_data()
        + OriginalNative5BirthCut::original_private_backing_counter_scratch_data()
        + 2 * size_of::<MetadataObserver<'static>>()
        + 2 * size_of::<RetainedProtocolMetadataFacts>()
        + 2 * size_of::<NativeImport18JsonMetadataProfileData>()
        + size_of::<OriginalFrameReaderFacts>()
        + size_of::<Result<OriginalFrameReaderFacts, ProviderError>>()
        + size_of::<Ref<'static, OriginalFrameReservation>>()
        + size_of::<Result<Ref<'static, OriginalFrameReservation>, std::cell::BorrowError>>()
        + size_of::<Result<Ref<'static, OriginalFrameReservation>, ProviderError>>()
        + size_of::<&OriginalNative5BirthCut>()
        + size_of::<Option<&OriginalNative5BirthCut>>()
        + size_of::<Result<&OriginalNative5BirthCut, ProviderError>>()
        + size_of::<&admitted::OriginalNativeStartupBootstrap>()
        + 2 * size_of::<&Bootstrap<OriginalPrivateBootstrapInput>>()
        + size_of::<&FrameReader<OriginalPrivateBootstrapStream<OriginalPrivateBootstrapInput>>>()
        + size_of::<&Rc<RefCell<OriginalFrameReservation>>>()
        + 2 * size_of::<&Option<serde_json::Value>>()
        + size_of::<&Vec<u8>>()
        + size_of::<&Option<Rc<RefCell<NativeAckBoot>>>>()
        + size_of::<&Option<OriginalNativeStartupBootAttempt>>()
        + size_of::<&Option<admitted::OriginalNativeStartupBootstrap>>()
        + size_of::<Option<&admitted::OriginalNativeStartupBootstrap>>()
        + size_of::<&mut Option<admitted::OriginalNativeStartupBootstrap>>()
        + size_of::<Option<&mut admitted::OriginalNativeStartupBootstrap>>()
        + size_of::<&mut admitted::OriginalNativeStartupBootstrap>()
        + size_of::<[Option<&serde_json::Value>; 2]>()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<Option<&serde_json::Value>, 2>>>()
        + size_of::<(usize, Option<&serde_json::Value>)>()
        + size_of::<&serde_json::Value>()
        + size_of::<OriginalFrame<'static>>()
        + size_of::<Option<OriginalFrame<'static>>>()
        + size_of::<Result<OriginalFrame<'static>, ProviderError>>()
        + size_of::<Option<&[u8]>>()
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<&[u8]>()
        + size_of::<std::ops::RangeFrom<usize>>()
        + 13 * size_of::<usize>()
        + 3 * size_of::<Option<usize>>()
        + 6 * size_of::<Result<usize, ProviderError>>()
        + size_of::<u64>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + 12 * size_of::<Result<(), ProviderError>>()
        + 8 * size_of::<bool>()
}
