//! Pairs real retained upload quotations with their completed historical roots.
//!
//! These controls install inert quotations, including genuinely refused rows.
//! They never construct a native scope, spent action, successful Blob effect or
//! published transaction. Every alias comes from actual recorded Rc edges.

use super::*;
use crate::{
    blob::{
        BlobLimits, BlobReceiver, NativeCapture17UploadInput, NativeCapture17UploadKey,
        NativeCapture17UploadStorageData,
    },
    envelope::RequestOrigin,
    handshake::ConnectionAuthority,
    protocol_snapshot::{
        owned11::{
            json_value::HistoricalJsonLimits,
            native::blob::HistoricalNativeBlobLedger,
            typed::{Fields, Ledger, invalid, plain_string},
        },
        restored_settled17::{
            aliases::{
                RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases,
            },
            current_capture17_upload::{
                CurrentCaptureUploadPhase17, read_current_capture17_upload_data,
            },
            current_shared::{read_reference17, read_shared17},
        },
    },
    reference_packet::service::{
        native_startup::PacketNativeStartupAllocationRow,
        security::{Supervisor, read_current_native17_supervisor_root_data},
    },
    retained_metadata::{
        MetadataObserver,
        aliases::{MetadataAliasBank, MetadataSharedKind},
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    },
};
use crucible_node_format::{Id, U64, canonical};
use std::{mem::align_of, rc::Rc};

const MAXIMUM_ROWS: usize = 4096;

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_nodes: 32768,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 16384,
    }
}

struct Source {
    supervisor: Vec<u8>,
    receiver: Vec<u8>,
    action: Vec<u8>,
    records: Vec<u8>,
    aliases: Vec<u8>,
    record_count: usize,
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ProviderError> {
    serde_json::to_vec(value)
        .map_err(|error| crucible_node_format::ContractError::from(error).into())
}

fn quote(
    authority: &ConnectionAuthority,
    supervisor: &Rc<Supervisor>,
) -> Result<(BlobReceiver, NativeCapture17UploadStorageData), ProviderError> {
    let receiver = BlobReceiver::new(
        authority.session_id().clone(),
        authority.incarnation_id().clone(),
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
    receiver.authenticate_original_supervisor(supervisor)?;
    let transfer = Id::new("historical-upload-quotation")?;
    let content = canonical::content_ref(b"retained source bytes", "application/octet-stream")?;
    let storage = receiver.quote_capture17_upload_storage_data(
        NativeCapture17UploadInput::Begin {
            key: NativeCapture17UploadKey {
                origin: RequestOrigin::Controller,
                session: authority.session_id(),
                incarnation: authority.incarnation_id(),
                transfer: &transfer,
            },
            content: &content,
        },
        limits().maximum_owned_backing_bytes,
    )?;
    Ok((receiver, storage))
}

fn record(
    authority: &ConnectionAuthority,
    supervisor: &Rc<Supervisor>,
    receiver: &BlobReceiver,
    action: &NativeCapture17UploadActionAttempt,
) -> Result<Source, ProviderError> {
    let supervisor_view = supervisor.borrowed_settled_history_data()?;
    let receiver_view = receiver.borrowed_owned11_protocol_view(authority)?;
    let mut records = MetadataRecordBank::reserve(MAXIMUM_ROWS)?;
    let mut aliases = MetadataAliasBank::reserve(MAXIMUM_ROWS)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);

    // This is the real whole-graph predecessor order. The supervisor root and
    // full Blob ledger are completed before the transaction's repeated edges.
    observer.shared_original(MetadataSharedKind::NativeSupervisor, supervisor.as_ref())?;
    supervisor.observe_settled_history_metadata_data(&mut observer)?;
    receiver_view.observe_owned11_metadata(&mut observer)?;
    action.observe_current17_metadata_data(&mut observer)?;
    let facts = observer.finish();

    Ok(Source {
        supervisor: encode(&supervisor_view)?,
        receiver: encode(&receiver_view)?,
        action: encode(action)?,
        records: encode(&records)?,
        aliases: encode(&aliases)?,
        record_count: facts.capacity_records,
    })
}

fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next_value()?.ok_or_else(invalid)
}

fn read_receiver_root(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(usize, usize), ProviderError> {
    let mut fields = Fields::array(input)?;
    if plain_string(next(&mut fields)?)? != "source-private.native-blob-receiver/11" {
        return Err(invalid());
    }
    ledger.read::<Id>(next(&mut fields)?, false)?;
    ledger.read::<Id>(next(&mut fields)?, false)?;
    let mut declared_limits = Fields::array(next(&mut fields)?)?;
    for _ in 0..7 {
        ledger.read::<usize>(next(&mut declared_limits)?, false)?;
    }
    declared_limits.finish()?;
    let layout = crate::blob::original_blob_layouts();
    let (alignment, _, _) = crate::blob::original_blob_alignment17_data();
    let state = read_shared17::<HistoricalNativeBlobLedger>(
        next(&mut fields)?,
        ledger,
        true,
        MetadataSharedKind::BlobLedger,
        (layout.state, alignment),
    )?
    .ok_or_else(invalid)?;
    assert!(state.payload.records.is_empty());
    if plain_string(next(&mut fields)?)? != "source-private.native-supervisor-owner/11" {
        return Err(invalid());
    }
    let supervisor_group = read_reference17(
        ledger,
        MetadataSharedKind::NativeSupervisor,
        (size_of::<Supervisor>(), align_of::<Supervisor>()),
    )?;
    fields.finish()?;
    Ok((state.group, supervisor_group))
}

fn read(
    source: &Source,
    expected_phase: CurrentCaptureUploadPhase17,
    expected_row: PacketNativeStartupAllocationRow,
    roots_first: bool,
) -> Result<(), ProviderError> {
    let records = ValidatedMetadataRecords::validate(
        &source.records,
        source.record_count,
        limits().maximum_owned_backing_bytes,
    )?;
    let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); MAXIMUM_ROWS];
    let mut aliases = ValidatedRestoredSettledNative17Aliases::validate(
        &source.aliases,
        &mut summaries,
        MAXIMUM_ROWS,
    )?;
    let group_count = aliases.group_count();
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.settled_aliases = Some(aliases.views()?);
    if !roots_first {
        // Exact recorded edges alone cannot replace the prior full payloads.
        assert!(read_current_capture17_upload_data(&source.action, &mut ledger).is_err());
        return Ok(());
    }

    let (supervisor, supervisor_group) =
        read_current_native17_supervisor_root_data(&source.supervisor, &mut ledger, false)?;
    assert!(supervisor.is_none());
    let (ledger_group, receiver_supervisor) = read_receiver_root(&source.receiver, &mut ledger)?;
    assert_eq!(receiver_supervisor, supervisor_group);
    let historical = read_current_capture17_upload_data(&source.action, &mut ledger)?;

    assert_eq!(group_count, 2);
    assert!(historical.phase == expected_phase);
    assert_eq!(historical.admitted, expected_row);
    assert_eq!(historical.storage.ledger_group, ledger_group);
    assert_eq!(historical.storage.supervisor_group, supervisor_group);
    assert!(historical.effect.is_none());
    assert!(historical.publication_record.is_none());
    assert_eq!(historical.definition, source.action);
    assert!(ledger.rows.next().is_none());
    ledger.finish_aliases()?;
    Ok(())
}

#[test]
fn installed_nonnull_action_pairs_real_roots_and_refuses_missing_predecessors()
-> Result<(), ProviderError> {
    let (_registrar, authority) = crate::handshake::tests::authority();
    let supervisor = Rc::new(Supervisor::new()?);
    let (receiver, storage) = quote(&authority, &supervisor)?;
    let admitted = storage.row_data();
    let mut destination = None;
    NativeCapture17UploadActionAttempt::install_into_data(storage, admitted, &mut destination)?;
    let actual = destination.as_ref().ok_or_else(invalid)?;
    let source = record(&authority, &supervisor, &receiver, actual)?;

    read(
        &source,
        CurrentCaptureUploadPhase17::Installed,
        admitted,
        true,
    )?;
    read(
        &source,
        CurrentCaptureUploadPhase17::Installed,
        admitted,
        false,
    )?;

    assert_eq!(encode(actual)?, source.action);
    assert!(actual.reply_data().is_err());
    assert!(actual.publication_record_data().is_err());
    Ok(())
}

#[test]
fn each_refused_axis_preserves_nonnull_failed_action_and_actual_aliases()
-> Result<(), ProviderError> {
    for axis in 0..3 {
        let (_registrar, authority) = crate::handshake::tests::authority();
        let supervisor = Rc::new(Supervisor::new()?);
        let (receiver, storage) = quote(&authority, &supervisor)?;
        let mut admitted = storage.row_data();
        let field = match axis {
            0 => &mut admitted.retained_requested_bytes,
            1 => &mut admitted.maximum_simultaneous_transient_bytes,
            _ => &mut admitted.declared_counter_scratch_bytes,
        };
        assert!(field.get() > 0);
        *field = U64::new(field.get() - 1);
        let mut destination = None;

        assert!(
            NativeCapture17UploadActionAttempt::install_into_data(
                storage,
                admitted,
                &mut destination,
            )
            .is_err()
        );
        let actual = destination.as_ref().ok_or_else(invalid)?;
        let source = record(&authority, &supervisor, &receiver, actual)?;
        read(&source, CurrentCaptureUploadPhase17::Failed, admitted, true)?;

        assert_eq!(encode(actual)?, source.action);
        assert!(actual.reply_data().is_err());
        assert!(actual.verified_data().is_err());
        assert!(actual.publication_record_data().is_err());
    }
    Ok(())
}

#[test]
fn another_real_ledger_cannot_borrow_the_preceding_receiver_root() -> Result<(), ProviderError> {
    let (_registrar, authority) = crate::handshake::tests::authority();
    let supervisor = Rc::new(Supervisor::new()?);
    let (root_receiver, root_storage) = quote(&authority, &supervisor)?;
    let (other_receiver, other_storage) = quote(&authority, &supervisor)?;
    assert!(
        root_storage
            .authenticate_same_quotation_data(&other_storage)
            .is_err()
    );
    let admitted = other_storage.row_data();
    let mut destination = None;
    NativeCapture17UploadActionAttempt::install_into_data(
        other_storage,
        admitted,
        &mut destination,
    )?;
    let actual = destination.as_ref().ok_or_else(invalid)?;

    // The recorder sees the real third Rc group. No root payload for that
    // different ledger precedes the Action, so its repeated role must refuse.
    let changed = record(&authority, &supervisor, &root_receiver, actual)?;
    assert!(
        read(
            &changed,
            CurrentCaptureUploadPhase17::Installed,
            admitted,
            true
        )
        .is_err()
    );

    let correct = record(&authority, &supervisor, &other_receiver, actual)?;
    read(
        &correct,
        CurrentCaptureUploadPhase17::Installed,
        admitted,
        true,
    )?;
    assert_eq!(encode(actual)?, correct.action);
    assert!(actual.reply_data().is_err());
    Ok(())
}
