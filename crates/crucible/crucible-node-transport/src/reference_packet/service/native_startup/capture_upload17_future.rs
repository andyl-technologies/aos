//! Prices the complete finite native upload family before child birth.
//!
//! These prospective rows add new primitive, reply, terminal and ordinary
//! transport owners to the native action reservation. Existing imported state,
//! ingress and five output banks remain separate. This DATA constructs no
//! receiver, Source claim, current owning report or native spending permission.

use super::{PacketNativeStartupAllocationRow, PacketRestoredSettledNativeStorageData};
use crate::ProviderError;
use crate::blob::BlobReceiver;
use crate::connection::OriginalPacketPrefixProjectionStorageDataExt;
use crate::connection::{
    ExchangeRecord, OriginalPacketPrefixProjectionInput,
    quote_original_capture17_upload_prefix_startup_storage_data,
};
use crate::envelope::Method;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crucible_node_format::U64;
use std::mem::size_of;

#[path = "capture_upload17_future_projection.rs"]
mod projection;

/// Retains finite per-original upload demand without issuing an allocation.
///
/// Only the actual native startup producer or the genuine completed startup
/// lender constructs this value. It remains ordinary copyable correspondence
/// DATA; Source/Window ownership and the native actual once debit are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRestoredSettledNativeUploadFutureStorageData {
    launch_identity: [u8; 32],
    maximum_originals: usize,
    content_bytes: usize,
    per_original: PacketNativeStartupAllocationRow,
    lifetime: PacketNativeStartupAllocationRow,
}

impl PacketRestoredSettledNativeUploadFutureStorageData {
    /// Returns an independent bound covering each actual Begin/Chunk/Finish phase.
    pub const fn per_original_requested_axes_data(&self) -> PacketNativeStartupAllocationRow {
        self.per_original
    }

    /// Returns separately derived lifetime axes for the native birth producer.
    pub(super) const fn lifetime_axes_data(&self) -> PacketNativeStartupAllocationRow {
        self.lifetime
    }

    /// Checks both future content extents against the unchanged native recipe.
    ///
    /// # Errors
    /// Refuses either prospective object above the native receiver content cap.
    pub fn authenticate_content_bounds_data(
        &self,
        lengths: [usize; 2],
    ) -> Result<(), ProviderError> {
        if lengths
            .iter()
            .any(|length| *length == 0 || *length > self.content_bytes)
        {
            return Err(exhausted());
        }
        Ok(())
    }

    /// Names fixed defining projection and future owner headers before its walk.
    pub fn counter_scratch_data() -> usize {
        counter_scratch_data()
    }
}

impl PacketRestoredSettledNativeStorageData {
    /// Repeats the future upload projection under the actual retained birth row.
    ///
    /// The genuine Source lender independently authenticates the same complete
    /// typed/raw launch before and after this DATA call. This checks its exact
    /// retained raw identity and numeric partition, without creating an owning
    /// report for today's native state or resetting spent lifetime credit.
    ///
    /// # Errors
    /// Refuses changed raw launch identity, frame/count/row geometry or overflow.
    pub fn source_upload_future_storage_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
    ) -> Result<PacketRestoredSettledNativeUploadFutureStorageData, ProviderError> {
        if canonical_launch5.is_empty()
            || canonical_launch5.len() > 1024 * 1024
            || self.carrier.launch_identity != *blake3::hash(canonical_launch5).as_bytes()
            || usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?
                != self.maximum_frame_bytes_data()
        {
            return Err(refused());
        }
        let maximum_originals =
            usize::try_from(self.carrier.maximum_originals.get()).map_err(|_| exhausted())?;
        let result = future_storage_data(
            launch,
            maximum_originals,
            self.carrier.launch_identity,
            self.requested_bytes_data(),
        )?;
        // Outputs and other actions retain their own independent obligation;
        // a matching upper bound does not identify remaining native credit.
        self.carrier
            .actions
            .authenticate_actual_data(&result.lifetime)?;
        Ok(result)
    }
}

pub(super) fn future_storage_data(
    launch: &PacketNative5SourceLaunch,
    maximum_originals: usize,
    launch_identity: [u8; 32],
    maximum: usize,
) -> Result<PacketRestoredSettledNativeUploadFutureStorageData, ProviderError> {
    if !(1..=256).contains(&maximum_originals)
        || u64::try_from(maximum_originals).map_err(|_| exhausted())? > launch.limits.requests.get()
    {
        return Err(exhausted());
    }
    let chunk = usize::try_from(launch.limits.blob_chunk_bytes.get())
        .map_err(|_| exhausted())?
        .min(4096);
    let limits =
        crate::reference_packet::endpoint::original_capture17_upload_receiver_limits_data(chunk);
    let shapes = projection::project_capture17_upload_future_data(launch, maximum)?;
    let mut axes = [0usize; 3];
    for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
        let shape = shapes.phase_data(method)?;
        let primitive = BlobReceiver::capture17_upload_primitive_future_row_data(
            limits,
            method,
            limits.content_bytes,
            shape.reply_data(),
        )?;
        let prefix = quote_original_capture17_upload_prefix_startup_storage_data(
            launch,
            method,
            OriginalPacketPrefixProjectionInput {
                terminal: shape.terminal_data(),
                original: shape.original_data(),
                objects: &[],
                maximum_requested_bytes: maximum,
            },
        )?;
        let transport = prefix.capture17_upload_transport_storage_data()?;
        let row = complete_phase_data(
            primitive,
            transport,
            shape.terminal_data().retained_value_backing_bytes,
            shape.reply_data().retained_value_backing_bytes,
        )?;
        for (maximum_axis, actual) in axes.iter_mut().zip([
            row.retained_requested_bytes,
            row.maximum_simultaneous_transient_bytes,
            row.declared_counter_scratch_bytes,
        ]) {
            *maximum_axis =
                (*maximum_axis).max(usize::try_from(actual.get()).map_err(|_| exhausted())?);
        }
    }
    let per_original = row(axes)?;
    let lifetime = row([
        axes[0]
            .checked_mul(maximum_originals)
            .ok_or_else(exhausted)?,
        axes[1],
        axes[2],
    ])?;
    if usize::try_from(lifetime.requested_peak_data()?).map_err(|_| exhausted())? > maximum {
        return Err(exhausted());
    }
    Ok(PacketRestoredSettledNativeUploadFutureStorageData {
        launch_identity,
        maximum_originals,
        content_bytes: limits.content_bytes,
        per_original,
        lifetime,
    })
}

fn complete_phase_data(
    primitive: PacketNativeStartupAllocationRow,
    transport: PacketNativeStartupAllocationRow,
    terminal: usize,
    reply: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let replacement = crate::reference_packet::endpoint::EXCHANGES
        .checked_mul(size_of::<ExchangeRecord>())
        .ok_or_else(exhausted)?;
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: primitive.retained_requested_bytes
            .checked_add(transport.retained_requested_bytes)?
            .checked_add(quantity(terminal)?)?
            .checked_add(quantity(replacement)?)?,
        maximum_simultaneous_transient_bytes: primitive.maximum_simultaneous_transient_bytes
            .checked_add(transport.maximum_simultaneous_transient_bytes)?
            .checked_add(quantity(reply)?)?,
        declared_counter_scratch_bytes: primitive.declared_counter_scratch_bytes
            .checked_add(transport.declared_counter_scratch_bytes)?
            .checked_add(quantity(crate::reference_packet::service::ack_emitter::native_capture17_upload_scope_counter_scratch_data())?)?,
    })
}

fn row(
    [retained, transient, scratch]: [usize; 3],
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(scratch)?,
    })
}

fn quantity(value: usize) -> Result<U64, ProviderError> {
    u64::try_from(value).map(U64::new).map_err(|_| exhausted())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("Capture17 future upload defining launch differs")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("Capture17 independently funded full future upload phase")
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<PacketRestoredSettledNativeUploadFutureStorageData>()
        + size_of::<Result<PacketRestoredSettledNativeUploadFutureStorageData, ProviderError>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketRestoredSettledNativeStorageData>()
        + size_of::<&[u8]>()
        + size_of::<&mut usize>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Option<&usize>>()
        + size_of::<[u8; 32]>()
        + size_of::<blake3::Hash>()
        + size_of::<crate::blob::BlobLimits>()
        + size_of::<PacketNativeStartupAllocationRow>() * 5
        + size_of::<OriginalPacketPrefixProjectionInput<'static>>()
        + size_of::<crate::connection::OriginalPacketPrefixProjectionStorageData<0>>()
        + size_of::<[Method; 3]>()
        + size_of::<std::array::IntoIter<Method, 3>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<std::iter::Zip<std::slice::IterMut<'static, usize>, std::array::IntoIter<U64, 3>>>(
        )
        + size_of::<Option<(&mut usize, U64)>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + crate::connection::original_packet_prefix_startup_counter_scratch_data()
        + BlobReceiver::capture17_upload_primitive_future_counter_scratch_data()
        + projection::counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::Bytes;
    use serde_json::json;

    fn launch() -> Result<PacketNative5SourceLaunch, ProviderError> {
        let (_, _, selection, coordinator) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        // A closed launch DTO supplies future DATA geometry only. It creates no
        // registered Source, admitted native process, receiver or private grant.
        serde_json::from_value(json!({
            "schema_version":5,"selection":selection,
            "program":{"kind":"producer","program":{
                "schema":"source-owned.packet-program.v1","events":[]}},
            "controller_pid":"1","controller_uid":"0",
            "controller_executable":coordinator.reference,
            "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
            "limits":{"frame_bytes":"65536","nesting":"64","requests":"256",
                "journal_entries":"256","blob_chunk_bytes":"4096"},
            "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192",
                "protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536",
                "frames_per_direction":"256","hello_bytes":"131080",
                "settlement_bytes":"65536"},
            "effects":"/not-opened-by-data-control"
        }))
        .map_err(|_| refused())
    }

    #[test]
    fn whole_future_uses_persistent_original_sum_and_independent_phase_axes()
    -> Result<(), ProviderError> {
        let launch = launch()?;
        let one = future_storage_data(&launch, 1, [7; 32], usize::MAX)?;
        let many = future_storage_data(&launch, 8, [7; 32], usize::MAX)?;
        let one_row = one.per_original_requested_axes_data();
        assert_eq!(many.per_original, one_row);
        assert_eq!(
            many.lifetime.retained_requested_bytes.get(),
            one_row
                .retained_requested_bytes
                .get()
                .checked_mul(8)
                .ok_or_else(exhausted)?
        );
        assert_eq!(
            many.lifetime.maximum_simultaneous_transient_bytes,
            one_row.maximum_simultaneous_transient_bytes
        );
        assert_eq!(
            many.lifetime.declared_counter_scratch_bytes,
            one_row.declared_counter_scratch_bytes
        );
        let exact =
            usize::try_from(many.lifetime.requested_peak_data()?).map_err(|_| exhausted())?;
        assert_eq!(future_storage_data(&launch, 8, [7; 32], exact)?, many);
        assert!(future_storage_data(&launch, 8, [7; 32], exact - 1).is_err());
        assert!(future_storage_data(&launch, 0, [7; 32], usize::MAX).is_err());
        assert!(future_storage_data(&launch, 257, [7; 32], usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn unchanged_receiver_caps_refuse_large_objects_without_renewing_any_row()
    -> Result<(), ProviderError> {
        let launch = launch()?;
        let value = future_storage_data(&launch, 8, [7; 32], usize::MAX)?;
        value.authenticate_content_bounds_data([1, 65_536])?;
        value.authenticate_content_bounds_data([65_536, 1])?;
        for lengths in [[0, 1], [1, 0], [65_537, 1], [1, 65_537]] {
            assert!(value.authenticate_content_bounds_data(lengths).is_err());
        }
        assert_eq!(value, future_storage_data(&launch, 8, [7; 32], usize::MAX)?);
        Ok(())
    }
}
