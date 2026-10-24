//! Bounds fresh upload primitive owners from the receiver's defining limits.
//!
//! This projection names the same concrete owners as the live receiver quote.
//! It borrows no receiver and issues no upload, quota reservation or native
//! permission. The actual same-occurrence quote must still fit every signed
//! axis before any primitive runs; old or reconstructed ledgers supply no credit.

use super::*;
use crate::envelope::Method;

/// Bounds one prospective closed phase without manufacturing receiver state.
///
/// The defining caller supplies the same reply projection used for its complete
/// future terminal. `content_length` is the independently bounded future object
/// extent, not allocated bytes. All actual IDs are at most128 bytes; fullrefs
/// retain their exact fixed algorithm/domain/digest and at most128 media bytes.
///
/// # Errors
/// Refuses unsupported phases, invalid receiver geometry, a content bound above
/// the independently installed quota, arithmetic overflow or malformed rows.
fn primitive_future_row_data(
    limits: BlobLimits,
    method: Method,
    content_length: usize,
    reply: &NativeSerializationStorageData,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    if limits.chunk_bytes == 0
        || limits.chunk_bytes > 1_048_576
        || !(1..=4096).contains(&limits.transfers_per_origin)
        || !(1..=4096).contains(&limits.tombstones_per_origin)
        || limits.chunks_per_transfer == 0
        || limits.operation_pins == 0
        || content_length > limits.content_bytes
        || content_length > limits.reserved_bytes
    {
        return Err(exhausted());
    }
    let key = 3usize.checked_mul(128).ok_or_else(exhausted)?;
    let reference = sum(&["blake3-256".len(), "cnp.blob.v1".len(), 64, 128])?;
    let mut retained = sum(&[
        size_of::<NativeCapture17UploadStorageData>(),
        size_of::<NativeCapture17UploadAttempt>(),
    ])?;
    let mut transient = sum(&[size_of::<TransferKey>(), key, 20])?;
    match method {
        Method::BlobBegin => {
            // Records are never silently removed: each of the two origins has
            // independent active and retired ceilings. A fresh insertion can
            // split every occupied tree level; old nodes remain retained.
            let records = sum(&[limits.transfers_per_origin, limits.tombstones_per_origin])?
                .checked_mul(2)
                .ok_or_else(exhausted)?;
            retained = sum(&[
                retained,
                content_length,
                key,
                reference,
                tree::insertion_data::<TransferKey, TransferRecord>(records)?,
                128,
            ])?;
            transient = sum(&[transient, size_of::<ContentRef>(), reference])?;
        }
        Method::BlobChunk => {
            retained = sum(&[
                retained,
                tree::insertion_data::<usize, usize>(limits.chunks_per_transfer)?,
                128,
            ])?;
        }
        Method::BlobFinish => {
            retained = sum(&[retained, key, reference])?;
            transient = sum(&[
                transient,
                "blake3-256".len() + "cnp.blob.v1".len() + 64,
                "stored byte length disagrees with reference".len(),
                "stored bytes disagree with digest".len(),
            ])?;
        }
        _ => return Err(refused()),
    }
    retained = sum(&[
        retained,
        reply
            .retained_value_backing_bytes
            .checked_mul(3)
            .ok_or_else(exhausted)?,
    ])?;
    transient = sum(&[transient, reply.requested_total()?])?;
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(capture17_upload_counter_scratch_data())?,
    })
}

/// Names the independently priced fixed projection headers before the walk.
fn primitive_future_counter_scratch_data() -> usize {
    size_of::<BlobLimits>()
        + size_of::<Method>()
        + size_of::<&NativeSerializationStorageData>()
        + size_of::<PacketNativeStartupAllocationRow>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 4]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<usize>() * 7
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + tree::counter_scratch_data()
}

impl BlobReceiver {
    /// Quotes independent future primitive backing from the defining recipe.
    ///
    /// # Errors
    /// Refuses unsupported phases, invalid limits, excessive extents or overflow.
    pub(crate) fn capture17_upload_primitive_future_row_data(
        limits: BlobLimits,
        method: Method,
        content_length: usize,
        reply: &NativeSerializationStorageData,
    ) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
        primitive_future_row_data(limits, method, content_length, reply)
    }

    /// Names only the pure primitive projection's fixed borrowed headers.
    pub(crate) fn capture17_upload_primitive_future_counter_scratch_data() -> usize {
        primitive_future_counter_scratch_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;

    struct Supervisor;

    impl BlobSupervisor for Supervisor {
        fn quarantine(&self, _: BlobQuarantine) {}
    }

    fn limits() -> BlobLimits {
        BlobLimits {
            reserved_bytes: 4 * 1024 * 1024,
            content_bytes: 65_536,
            chunk_bytes: 4096,
            transfers_per_origin: 256,
            tombstones_per_origin: 256,
            chunks_per_transfer: 256,
            operation_pins: 256,
        }
    }

    #[test]
    fn defining_future_primitive_bounds_real_begin_chunk_and_finish_quotes()
    -> Result<(), ProviderError> {
        // Ordinary receiver operations establish real immutable prestate. No
        // Source signature, native action, live scope or completion is minted.
        let session = Id::new("s".repeat(128))?;
        let incarnation = Id::new("i".repeat(128))?;
        let transfer = Id::new("t".repeat(128))?;
        let key = TransferKey {
            origin: RequestOrigin::Controller,
            session: session.clone(),
            incarnation: incarnation.clone(),
            transfer: transfer.clone(),
        };
        let mut receiver = BlobReceiver::new(
            session.clone(),
            incarnation.clone(),
            limits(),
            Rc::new(Supervisor),
        )?;
        let bytes = vec![42; 10_000];
        let content = canonical::content_ref(&bytes, &"m".repeat(128))?;
        let key_view = NativeCapture17UploadKey {
            origin: RequestOrigin::Controller,
            session: &session,
            incarnation: &incarnation,
            transfer: &transfer,
        };
        let input = NativeCapture17UploadInput::Begin {
            key: key_view,
            content: &content,
        };
        let actual = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
        let future = primitive_future_row_data(
            limits(),
            Method::BlobBegin,
            bytes.len(),
            actual.reply_storage_data(),
        )?;
        future.authenticate_actual_data(&actual.row_data())?;
        receiver.begin(key.clone(), content)?;
        receiver.chunk(&key, U64::new(0), &Bytes::new(bytes[..4096].to_vec()))?;
        receiver.chunk(
            &key,
            U64::new(4096),
            &Bytes::new(bytes[4096..8192].to_vec()),
        )?;

        let final_bytes = Bytes::new(bytes[8192..].to_vec());
        let input = NativeCapture17UploadInput::Chunk {
            key: key_view,
            offset: U64::new(8192),
            bytes: &final_bytes,
        };
        let actual = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
        primitive_future_row_data(
            limits(),
            Method::BlobChunk,
            bytes.len(),
            actual.reply_storage_data(),
        )?
        .authenticate_actual_data(&actual.row_data())?;
        receiver.chunk(&key, U64::new(8192), &final_bytes)?;

        let input = NativeCapture17UploadInput::Finish { key: key_view };
        let actual = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
        primitive_future_row_data(
            limits(),
            Method::BlobFinish,
            bytes.len(),
            actual.reply_storage_data(),
        )?
        .authenticate_actual_data(&actual.row_data())?;
        assert_eq!(receiver.state.borrow().records[&key].bytes, bytes);
        Ok(())
    }

    #[test]
    fn exact_object_extent_changes_only_begin_retained_bytes_and_quotas_refuse()
    -> Result<(), ProviderError> {
        let session = Id::new("session")?;
        let incarnation = Id::new("incarnation")?;
        let transfer = Id::new("transfer")?;
        let receiver = BlobReceiver::new(
            session.clone(),
            incarnation.clone(),
            limits(),
            Rc::new(Supervisor),
        )?;
        let content = canonical::content_ref(b"actual", "application/json")?;
        let input = NativeCapture17UploadInput::Begin {
            key: NativeCapture17UploadKey {
                origin: RequestOrigin::Controller,
                session: &session,
                incarnation: &incarnation,
                transfer: &transfer,
            },
            content: &content,
        };
        let actual = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
        let reply = actual.reply_storage_data();
        let small = primitive_future_row_data(limits(), Method::BlobBegin, 1, reply)?;
        let full = primitive_future_row_data(limits(), Method::BlobBegin, 65_536, reply)?;
        assert_eq!(
            full.retained_requested_bytes.get() - small.retained_requested_bytes.get(),
            65_535
        );
        assert_eq!(
            full.maximum_simultaneous_transient_bytes,
            small.maximum_simultaneous_transient_bytes
        );
        assert_eq!(
            full.declared_counter_scratch_bytes,
            small.declared_counter_scratch_bytes
        );
        assert!(primitive_future_row_data(limits(), Method::BlobBegin, 65_537, reply).is_err());
        assert!(primitive_future_row_data(limits(), Method::Begin, 1, reply).is_err());
        let mut changed = limits();
        changed.chunks_per_transfer = usize::MAX;
        assert!(primitive_future_row_data(changed, Method::BlobChunk, 1, reply).is_err());
        assert!(primitive_future_counter_scratch_data() > 0);
        Ok(())
    }
}
