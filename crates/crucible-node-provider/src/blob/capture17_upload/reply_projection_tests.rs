//! Compares borrowed future bodies with actual inert Blob primitive results.

use super::*;
use crucible_node_contract::canonical;

#[derive(Default)]
struct Supervisor(RefCell<Vec<BlobQuarantine>>);

impl BlobSupervisor for Supervisor {
    fn quarantine(&self, custody: BlobQuarantine) {
        self.0.borrow_mut().push(custody);
    }
}

fn receiver() -> Result<(BlobReceiver, Rc<Supervisor>), ProviderError> {
    let supervisor = Rc::new(Supervisor::default());
    let receiver = BlobReceiver::new(
        Id::new("session")?,
        Id::new("incarnation")?,
        BlobLimits {
            reserved_bytes: 65536,
            content_bytes: 65536,
            chunk_bytes: 64,
            transfers_per_origin: 16,
            tombstones_per_origin: 16,
            chunks_per_transfer: 64,
            operation_pins: 16,
        },
        supervisor.clone(),
    )?;
    Ok((receiver, supervisor))
}

fn key() -> Result<TransferKey, ProviderError> {
    Ok(TransferKey {
        origin: RequestOrigin::Controller,
        session: Id::new("session")?,
        incarnation: Id::new("incarnation")?,
        transfer: Id::new("transfer")?,
    })
}

fn borrowed(key: &TransferKey) -> NativeCapture17UploadKey<'_> {
    NativeCapture17UploadKey {
        origin: key.origin,
        session: &key.session,
        incarnation: &key.incarnation,
        transfer: &key.transfer,
    }
}

fn geometry(data: &NativeSerializationStorageData) -> [usize; 11] {
    let NativeSerializationStorageData {
        dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes,
        maximum_encoded_bytes,
        sequence_elements,
        sequence_containers,
        serialized_value_nodes,
        serialized_capacity_records,
    } = data;
    [
        *dom_and_canonical_scratch_bytes,
        *retained_value_backing_bytes,
        *projected_parser_requested_bytes,
        *canonical_output_requested_bytes,
        *serializer_temporary_requested_bytes,
        *declared_counter_scratch_bytes,
        *maximum_encoded_bytes,
        *sequence_elements,
        *sequence_containers,
        *serialized_value_nodes,
        *serialized_capacity_records,
    ]
}

fn projected(
    receiver: &BlobReceiver,
    input: NativeCapture17UploadInput<'_>,
) -> Result<NativeSerializationStorageData, ProviderError> {
    let storage = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    let mut out = OriginalSerializationStorageProjection::new(usize::MAX)?;
    receiver.project_capture17_upload_reply_data(&storage, input, &mut out)?;
    let result = out.finish(usize::MAX)?;
    assert_eq!(geometry(&result), geometry(storage.reply_storage_data()));
    Ok(result)
}

fn matches_actual(
    projected: &NativeSerializationStorageData,
    actual: &impl Serialize,
) -> Result<(), ProviderError> {
    let actual = actual_serialization_storage_data(actual, Default::default(), usize::MAX)?;
    assert_eq!(geometry(projected), geometry(&actual));
    Ok(())
}

#[test]
fn projected_bodies_match_actual_begin_chunk_finish_and_retry_geometry() -> Result<(), ProviderError>
{
    let (mut receiver, _supervisor) = receiver()?;
    let key = key()?;
    let reference = canonical::content_ref(b"actual", "application/octet-stream")?;
    let begin = NativeCapture17UploadInput::Begin {
        key: borrowed(&key),
        content: &reference,
    };
    let row = projected(&receiver, begin)?;

    let actual = receiver.begin(key.clone(), reference.clone())?;

    matches_actual(
        &row,
        &completed(Begin {
            transfer_id: &actual.transfer_id,
            next_offset: actual.next_offset,
            maximum_chunk_bytes: actual.maximum_chunk_bytes,
        }),
    )?;
    let bytes = Bytes::new(b"act".to_vec());
    let chunk = NativeCapture17UploadInput::Chunk {
        key: borrowed(&key),
        offset: U64::new(0),
        bytes: &bytes,
    };
    let row = projected(&receiver, chunk)?;

    let actual = receiver.chunk(&key, U64::new(0), &bytes)?;

    matches_actual(
        &row,
        &completed(Chunk {
            transfer_id: &actual.transfer_id,
            next_offset: actual.next_offset,
        }),
    )?;
    let row = projected(&receiver, begin)?;
    let actual = receiver.begin(key.clone(), reference.clone())?;
    matches_actual(
        &row,
        &completed(Begin {
            transfer_id: &actual.transfer_id,
            next_offset: actual.next_offset,
            maximum_chunk_bytes: actual.maximum_chunk_bytes,
        }),
    )?;
    receiver.chunk(&key, U64::new(3), &Bytes::new(b"ual".to_vec()))?;
    let row = projected(&receiver, chunk)?;
    let actual = receiver.chunk(&key, U64::new(0), &bytes)?;
    matches_actual(
        &row,
        &completed(Chunk {
            transfer_id: &actual.transfer_id,
            next_offset: actual.next_offset,
        }),
    )?;
    for _ in 0..2 {
        let row = projected(
            &receiver,
            NativeCapture17UploadInput::Finish {
                key: borrowed(&key),
            },
        )?;

        let actual = receiver.finish(&key)?;

        matches_actual(
            &row,
            &completed(Finish {
                transfer_id: &actual.key.transfer,
                content: actual.content(),
            }),
        )?;
    }
    Ok(())
}

#[test]
fn borrowed_projection_refuses_changed_input_and_stale_or_foreign_receiver()
-> Result<(), ProviderError> {
    let (mut receiver, _supervisor) = receiver()?;
    let (foreign, _foreign_supervisor) = self::receiver()?;
    let key = key()?;
    let reference = canonical::content_ref(b"actual", "application/octet-stream")?;
    let input = NativeCapture17UploadInput::Begin {
        key: borrowed(&key),
        content: &reference,
    };
    let storage = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    let before = identity::receiver_data(&receiver)?;
    let mut out = OriginalSerializationStorageProjection::new(usize::MAX)?;
    assert!(
        foreign
            .project_capture17_upload_reply_data(&storage, input, &mut out)
            .is_err()
    );
    assert!(
        receiver
            .project_capture17_upload_reply_data(
                &storage,
                NativeCapture17UploadInput::Finish {
                    key: borrowed(&key)
                },
                &mut out,
            )
            .is_err()
    );
    assert_eq!(identity::receiver_data(&receiver)?, before);

    receiver.begin(key.clone(), reference.clone())?;

    assert!(
        receiver
            .project_capture17_upload_reply_data(&storage, input, &mut out)
            .is_err()
    );
    Ok(())
}

#[test]
fn finish_projection_does_not_preverify_or_change_real_quarantine_behavior()
-> Result<(), ProviderError> {
    let (mut receiver, _supervisor) = receiver()?;
    let key = key()?;
    receiver.begin(
        key.clone(),
        canonical::content_ref(b"actual", "application/octet-stream")?,
    )?;
    receiver.chunk(&key, U64::new(0), &Bytes::new(b"wrong!".to_vec()))?;
    let before = identity::receiver_data(&receiver)?;

    projected(
        &receiver,
        NativeCapture17UploadInput::Finish {
            key: borrowed(&key),
        },
    )?;

    assert_eq!(identity::receiver_data(&receiver)?, before);
    assert!(receiver.finish(&key).is_err());
    let state = receiver.state.borrow();
    let record = state.records.get(&key).ok_or_else(refused)?;
    assert!(record.quarantined);
    assert_eq!(record.bytes, b"wrong!");
    assert!(record.charged);
    Ok(())
}

#[test]
fn exact_projection_demand_admits_and_one_short_refuses_without_receiver_mutation()
-> Result<(), ProviderError> {
    let (receiver, _supervisor) = receiver()?;
    let key = key()?;
    let reference = canonical::content_ref(b"actual", "application/octet-stream")?;
    let input = NativeCapture17UploadInput::Begin {
        key: borrowed(&key),
        content: &reference,
    };
    let storage = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    let before = identity::receiver_data(&receiver)?;
    let row = projected(&receiver, input)?;
    let exact = row.requested_total()?;
    for maximum in [exact, exact - 1] {
        let mut out = OriginalSerializationStorageProjection::new(maximum)?;
        receiver.project_capture17_upload_reply_data(&storage, input, &mut out)?;
        assert_eq!(out.finish(maximum).is_ok(), maximum == exact);
    }
    assert_eq!(identity::receiver_data(&receiver)?, before);
    Ok(())
}
