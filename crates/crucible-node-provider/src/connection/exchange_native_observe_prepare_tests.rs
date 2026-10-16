//! Exercises real multi-frame preparation and retained failed prefixes.

use super::*;

fn observed_children(exchange: &PreparedExchange<Memory>) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(&exchange.record.originals)?;
    observer.observe(&exchange.record.canonical)?;
    observer.observe(&exchange.record.original_slots)?;
    observer.vector::<ReceivedFrame>(exchange.record.acknowledgements.capacity())?;
    exchange
        .connection
        .guard
        .observe_owned_metadata(&mut observer)?;
    requested_facts(&observer.finish())
}

fn response(request: &Envelope) -> Result<Envelope, ProviderError> {
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.body = object(&ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(&ObserveResult {
            observations: Vec::new(),
            next_sequence: U64::new(0),
            complete: true,
            inventory_hash: canonical::hash("cnp.packet-inventory.v5", b"retained frame data")?,
        })?,
        extensions: Extensions::new(),
    })?;
    Ok(response)
}

fn projection(
    connection: &Connection<Memory>,
    request: &Envelope,
    terminal: &Envelope,
    maximum: usize,
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    let quote = |value: &Envelope| {
        let mut observer = MetadataObserver::new();
        observer.observe(value)?;
        actual_serialization_storage_data(value, observer.finish(), maximum)
    };
    let original = quote(request)?;
    let terminal = quote(terminal)?;
    let objects = [OriginalContinuationContentExtent {
        maximum_payload_bytes: 8193,
        media_type: "application/json",
    }];
    // This test-only projection has actual original/terminal values and the
    // exact heterogeneous BlobBegin/Finish/Chunk grammar. It grants no profile.
    super::super::packet_projection::native_observe_projection_for_test(
        (
            connection.authority.session_id(),
            connection.authority.incarnation_id(),
        ),
        connection.authority.limits(),
        OriginalPacketPrefixProjectionInput {
            original: &original,
            terminal: &terminal,
            objects: &objects,
            maximum_requested_bytes: maximum,
        },
    )
}

#[test]
fn actual_heterogeneous_preparation_retains_all_banks_under_the_selected_phase_bound() -> TestResult
{
    let (_handshake, connection, request) = fixture()?;
    let terminal = response(&request)?;
    let projection = projection(&connection, &request, &terminal, MAXIMUM)?;
    let selected = super::super::packet_projection::native_observe_preparation_for_test(
        &projection,
        &connection.authority,
    )?;
    let maximum =
        selected.maximum_simultaneous_transient_bytes_data(&projection.exchange, MAXIMUM)?;
    assert!(maximum < projection.exchange.preparation_transient_requested_bytes);
    assert_eq!(
        selected.maximum_simultaneous_transient_bytes_data(&projection.exchange, maximum)?,
        maximum
    );
    assert!(
        selected
            .maximum_simultaneous_transient_bytes_data(&projection.exchange, maximum - 1)
            .is_err()
    );

    let transfer = Id::new("actual-proof-heterogeneous")?;
    let mut begin = request.clone();
    begin.method = Method::BlobBegin;
    begin.request_id = Nullable(Some(Id::new("proof-begin")?));
    begin.sequence = U64::new(3);
    begin.body = object(&BlobBeginRequest {
        transfer_id: transfer.clone(),
        content: canonical::content_ref(&vec![0xff; 8193], "application/json")?,
        extensions: Extensions::new(),
    })?;
    let mut chunk = begin.clone();
    chunk.method = Method::BlobChunk;
    chunk.request_id = Nullable(Some(Id::new("proof-chunk")?));
    chunk.sequence = U64::new(4);
    chunk.body = object(&BlobChunkRequest {
        transfer_id: transfer,
        offset: U64::new(0),
        bytes: Bytes::new(vec![0xff; 4096]),
        extensions: Extensions::new(),
    })?;
    let mut finish = begin.clone();
    finish.method = Method::BlobFinish;
    finish.request_id = Nullable(Some(Id::new("proof-finish")?));
    finish.sequence = U64::new(7);
    finish.body = object(&BlobFinishRequest {
        transfer_id: Id::new("actual-proof-heterogeneous")?,
        extensions: Extensions::new(),
    })?;
    let mut second = chunk.clone();
    second.request_id = Nullable(Some(Id::new("proof-chunk-second")?));
    second.sequence = U64::new(5);
    second.body = object(&BlobChunkRequest {
        transfer_id: Id::new("actual-proof-heterogeneous")?,
        offset: U64::new(4096),
        bytes: Bytes::new(vec![0xff; 4096]),
        extensions: Extensions::new(),
    })?;
    let mut last = chunk.clone();
    last.request_id = Nullable(Some(Id::new("proof-chunk-last")?));
    last.sequence = U64::new(6);
    last.body = object(&BlobChunkRequest {
        transfer_id: Id::new("actual-proof-heterogeneous")?,
        offset: U64::new(8192),
        bytes: Bytes::new(vec![0xff]),
        extensions: Extensions::new(),
    })?;
    let originals = vec![terminal, begin, chunk, second, last, finish];
    let mut exchange = connection.unprepared_exchange(originals.clone());
    exchange.prepare_in_place()?;

    assert_eq!(exchange.record.originals, originals);
    assert_eq!(exchange.record.canonical.len(), projection.exchange.frames);
    assert_eq!(exchange.record.canonical.len(), 6);
    assert!(exchange.record.canonical[2].len() > exchange.record.canonical[0].len());
    let retained = observed_children(&exchange)?;
    let old_partition = projection
        .exchange
        .native_observe_lifetime_storage_data(MAXIMUM)?;
    assert!(retained <= old_partition.retained_requested_bytes);
    assert!(exchange.connection.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn actual_later_frame_refusal_keeps_the_original_and_completed_canonical_prefix() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let terminal = response(&request)?;
    let canonical_first = canonical::canonical_json(&serde_json::to_value(&terminal)?)?;
    let mut invalid = terminal.clone();
    invalid.sequence = U64::new(3);
    invalid.body.clear();
    let originals = vec![terminal, invalid];
    let mut failed = connection.unprepared_exchange(originals.clone());

    assert!(failed.prepare_in_place().is_err());
    assert!(matches!(failed.phase, Phase::Failed));
    assert_eq!(failed.record.originals, originals);
    assert_eq!(failed.record.canonical, vec![canonical_first]);
    assert!(observed_children(&failed)? > 0);
    assert!(failed.prepare_in_place().is_err());
    assert_eq!(failed.record.canonical.len(), 1);
    assert!(failed.connection.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn phase_data_refuses_changed_persistent_or_full_preparation_components() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let terminal = response(&request)?;
    let mut projection = projection(&connection, &request, &terminal, MAXIMUM)?;
    let selected = super::super::packet_projection::native_observe_preparation_for_test(
        &projection,
        &connection.authority,
    )?;
    projection.exchange.canonical_requested_bytes += 1;
    assert!(
        selected
            .maximum_simultaneous_transient_bytes_data(&projection.exchange, MAXIMUM)
            .is_err()
    );
    projection.exchange.canonical_requested_bytes -= 1;
    projection.exchange.preparation_transient_requested_bytes += 1;
    assert!(
        selected
            .maximum_simultaneous_transient_bytes_data(&projection.exchange, MAXIMUM)
            .is_err()
    );
    Ok(())
}

#[test]
fn ordinary_fixture_cannot_create_native_preparation_data() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let terminal = response(&request)?;
    let projection = projection(&connection, &request, &terminal, MAXIMUM)?;
    assert!(connection.native5_codec.is_some());
    assert!(connection.original_canonical_ack_admission.is_none());

    assert!(
        connection
            .quote_original_native_observe_preparation_storage_data(&projection)
            .is_err()
    );
    assert!(connection.original_canonical_ack_admission.is_none());
    Ok(())
}

#[test]
fn selected_output_projection_keeps_retained_owners_and_full_quote_guards() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let terminal = response(&request)?;
    let projection = projection(&connection, &request, &terminal, MAXIMUM)?;
    let preparation = super::super::packet_projection::native_observe_preparation_for_test(
        &projection,
        &connection.authority,
    )?;
    let quote = &projection.exchange;
    let maximum_frame = allowance(connection.authority.limits().frame_bytes.get())?;
    let full = quote.requested_bytes()?;
    let old = quote.native_original_observe_lifetime_storage_data(maximum_frame, full)?;
    let selected = quote.native_original_observe_prepared_lifetime_storage_data(
        &preparation,
        maximum_frame,
        full,
    )?;
    let ack = acknowledgements::native_original_open_ack_lifetime_storage_data(maximum_frame)?;
    let broad_ack = acknowledgements::open_ack_lifetime_storage_data(maximum_frame)?;

    assert_eq!(ack.retained, broad_ack.retained);
    assert_eq!(
        selected.retained_requested_bytes,
        old.retained_requested_bytes
    );
    assert!(ack.returning < broad_ack.returning);
    assert!(
        selected.acknowledgement_work_requested_bytes()?
            < old.acknowledgement_work_requested_bytes()?
    );
    assert!(
        quote
            .native_original_observe_prepared_lifetime_storage_data(
                &preparation,
                maximum_frame,
                full - 1,
            )
            .is_err()
    );
    assert!(
        quote
            .native_original_observe_prepared_lifetime_storage_data(
                &preparation,
                maximum_frame - 1,
                full,
            )
            .is_err()
    );
    assert!(connection.reader.stream_ref().output.is_empty());
    Ok(())
}
