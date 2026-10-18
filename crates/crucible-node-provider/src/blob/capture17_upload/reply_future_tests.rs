//! Compares future grammar with unchanged primitive results, without native grants.

use super::*;
use crate::envelope::Method;
use crucible_node_contract::canonical;

#[derive(Default)]
struct Supervisor(RefCell<Vec<BlobQuarantine>>);
impl BlobSupervisor for Supervisor {
    fn quarantine(&self, custody: BlobQuarantine) {
        self.0.borrow_mut().push(custody);
    }
}

fn future(method: Method) -> Result<NativeSerializationStorageData, ProviderError> {
    let mut out = OriginalSerializationStorageProjection::new(usize::MAX)?;
    BlobReceiver::project_capture17_upload_future_reply_data(method, &mut out)?;
    out.finish(usize::MAX)
}

#[test]
fn future_closed_reply_dominates_real_begin_chunk_finish_in_every_axis() -> Result<(), ProviderError>
{
    let mut receiver = BlobReceiver::new(
        Id::new("session")?,
        Id::new("incarnation")?,
        BlobLimits {
            reserved_bytes: 65536,
            content_bytes: 65536,
            chunk_bytes: 4096,
            transfers_per_origin: 16,
            tombstones_per_origin: 16,
            chunks_per_transfer: 256,
            operation_pins: 16,
        },
        Rc::new(Supervisor::default()),
    )?;
    let key = TransferKey {
        origin: RequestOrigin::Controller,
        session: Id::new("session")?,
        incarnation: Id::new("incarnation")?,
        transfer: Id::new("t".repeat(128))?,
    };
    // Printable quotes/backslashes are legal media bytes and require escaping.
    let reference = canonical::content_ref(b"actual", &"\"\\".repeat(64))?;
    reference.validate()?;
    let progress = receiver.begin(key.clone(), reference.clone())?;
    let actual = actual_serialization_storage_data(
        &completed(Begin {
            transfer_id: &progress.transfer_id,
            next_offset: progress.next_offset,
            maximum_chunk_bytes: progress.maximum_chunk_bytes,
        }),
        Default::default(),
        usize::MAX,
    )?;
    authenticate_geometry(&actual, &future(Method::BlobBegin)?)?;

    let progress = receiver.chunk(&key, U64::new(0), &Bytes::new(b"actual".to_vec()))?;
    let actual = actual_serialization_storage_data(
        &completed(Chunk {
            transfer_id: &progress.transfer_id,
            next_offset: progress.next_offset,
        }),
        Default::default(),
        usize::MAX,
    )?;
    authenticate_geometry(&actual, &future(Method::BlobChunk)?)?;

    let verified = receiver.finish(&key)?;
    let actual = actual_serialization_storage_data(
        &completed(Finish {
            transfer_id: &verified.key.transfer,
            content: &verified.content,
        }),
        Default::default(),
        usize::MAX,
    )?;
    authenticate_geometry(&actual, &future(Method::BlobFinish)?)?;
    Ok(())
}

#[test]
fn future_reply_refuses_nonupload_and_short_projection() -> Result<(), ProviderError> {
    for method in [Method::Observe, Method::Begin, Method::Poll] {
        let mut out = OriginalSerializationStorageProjection::new(usize::MAX)?;
        assert!(
            BlobReceiver::project_capture17_upload_future_reply_data(method, &mut out).is_err()
        );
    }
    for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
        let exact = future(method)?.requested_total()?;
        let mut out = OriginalSerializationStorageProjection::new(exact)?;
        BlobReceiver::project_capture17_upload_future_reply_data(method, &mut out)?;
        assert_eq!(out.finish(exact)?.requested_total()?, exact);
        let refused = (|| {
            let mut out = OriginalSerializationStorageProjection::new(exact - 1)?;
            BlobReceiver::project_capture17_upload_future_reply_data(method, &mut out)?;
            out.finish(exact - 1)
        })();
        assert!(refused.is_err());
    }
    Ok(())
}
