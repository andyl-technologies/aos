//! Checks late record refusal retains the actual partial byte and chunk banks.

use super::*;
use crate::blob::{BlobQuarantine, BlobReceiver, BlobSupervisor};
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};
use std::cell::RefCell;

#[derive(Default)]
struct Supervisor(RefCell<Vec<BlobQuarantine>>);
impl BlobSupervisor for Supervisor {
    fn quarantine(&self, value: BlobQuarantine) {
        self.0.borrow_mut().push(value);
    }
}

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_nodes: 65536,
        // The defining historical JSON codec accepts depths through 64.
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 16384,
    }
}

#[test]
fn final_record_field_error_keeps_partial_payload_chunks_and_key() -> Result<(), ProviderError> {
    // The real registrar must outlive the borrowed authenticated Blob view.
    let (_registrar, authority) = crate::handshake::tests::authority();
    authority.ensure_live()?;
    let supervisor = Rc::new(Supervisor::default());
    let mut actual = BlobReceiver::new(
        authority.session_id().clone(),
        authority.incarnation_id().clone(),
        BlobLimits {
            reserved_bytes: 4096,
            content_bytes: 4096,
            chunk_bytes: 64,
            transfers_per_origin: 4,
            tombstones_per_origin: 4,
            chunks_per_transfer: 4,
            operation_pins: 4,
        },
        supervisor,
    )?;
    let key = TransferKey {
        origin: RequestOrigin::Controller,
        session: authority.session_id().clone(),
        incarnation: authority.incarnation_id().clone(),
        transfer: Id::new("retained-partial-transfer")?,
    };
    let bytes = [7u8; 53];
    actual.begin(
        key.clone(),
        crucible_node_format::canonical::content_ref(&bytes, "application/octet-stream")?,
    )?;
    actual.chunk(
        &key,
        U64::new(0),
        &crucible_node_format::Bytes::new(bytes[..5].to_vec()),
    )?;
    let view = actual.borrowed_owned11_protocol_view(&authority)?;
    let receiver_input =
        serde_json::to_vec(&view).map_err(crucible_node_format::ContractError::from)?;
    let mut fields = Fields::array(&receiver_input)?;
    tag(&mut fields, "source-private.native-blob-receiver/11")?;
    let session = next(&mut fields)?;
    let incarnation = next(&mut fields)?;
    next(&mut fields)?;
    let input = next(&mut fields)?;
    let mut leaf = Fields::array(input)?;
    for _ in 0..4 {
        next(&mut leaf)?;
    }
    let mut records = Fields::array(next(&mut leaf)?)?;
    let row = next(&mut records)?;
    let mut record = Fields::array(row)?;
    for _ in 0..10 {
        next(&mut record)?;
    }
    let charged = next(&mut record)?;
    let offset = (charged.as_ptr() as usize)
        .checked_sub(input.as_ptr() as usize)
        .ok_or_else(invalid)?;
    let mut changed = input[..offset].to_vec();
    changed.extend_from_slice(b"\"invalid-charge\"");
    changed.extend_from_slice(&input[offset + charged.len()..]);
    let mut bank = MetadataRecordBank::reserve(8192)?;
    let mut observer = MetadataObserver::recording(&mut bank);
    view.observe_owned11_metadata(&mut observer)?;
    let facts = observer.finish();
    let encoded = serde_json::to_vec(&bank).map_err(crucible_node_format::ContractError::from)?;
    let rows = ValidatedMetadataRecords::validate(
        &encoded,
        facts.capacity_records,
        limits().maximum_owned_backing_bytes,
    )?;
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.read::<Id>(session, false)?;
    ledger.read::<Id>(incarnation, false)?;
    let (alignment, _, _) = crate::blob::original_blob_alignment17_data();
    assert_eq!(
        ledger.row_aligned(MetadataRecordKind::Shared, 1, alignment)?,
        crate::blob::original_blob_layouts().state
    );
    // Admit the owning child banks under the same fixed 64 MiB test bound.
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    let mut attempt = NativeBlobLedger17ReadAttempt::default();
    assert!(
        HistoricalNativeBlobLedger::read_into_data(&changed, &mut ledger, &mut attempt).is_err()
    );
    assert!(attempt.completed.is_none());
    assert_eq!(attempt.children.len(), 1);
    let pending = &attempt.children[0];
    let payload = pending.partial_bytes_data().ok_or_else(invalid)?;
    assert_eq!(payload.len(), 5);
    assert_eq!(payload.capacity(), 53);
    let pointer = payload.as_ptr();
    assert_eq!(pending.partial_chunks_data().len(), 1);
    let mut observer = MetadataObserver::new();
    HistoricalNativeBlobLedger::observe_attempt_data(&attempt, &mut observer)?;
    let retained = observer.finish();
    let consumed = ledger.rows.encoded_position();
    assert!(HistoricalNativeBlobLedger::read_into_data(input, &mut ledger, &mut attempt).is_err());
    assert_eq!(ledger.rows.encoded_position(), consumed);
    assert_eq!(
        attempt.children[0]
            .partial_bytes_data()
            .ok_or_else(invalid)?
            .as_ptr(),
        pointer
    );
    let mut observer = MetadataObserver::new();
    HistoricalNativeBlobLedger::observe_attempt_data(&attempt, &mut observer)?;
    assert_eq!(observer.finish(), retained);
    Ok(())
}
