//! Checks exact lifetime partition against actual prepared and failed owners.

use super::*;

fn retained_prefix_children(exchange: &PreparedExchange<Memory>) -> Result<usize, ProviderError> {
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

#[test]
fn native_observe_partition_preserves_exact_old_peak_and_full_open_ack() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let payload = b"independently retained original proof".to_vec();
    let evidence = vec![(
        canonical::content_ref(&payload, "application/json")?,
        payload,
    )];
    let quote = connection.quote_original_packet_prefix_storage_data(
        2,
        &request,
        &Map::new(),
        &evidence,
        MAXIMUM,
    )?;
    let lifetime = quote.native_observe_lifetime_storage_data(MAXIMUM)?;
    let old = quote.requested_bytes()?;
    assert_eq!(
        lifetime.retained_requested_bytes + lifetime.work_requested_bytes()?,
        old
    );
    assert!(lifetime.retained_requested_bytes >= quote.one_open_ack_requested_bytes);
    assert!(lifetime.retained_requested_bytes >= quote.successful_ack_cache_requested_bytes);
    assert_eq!(
        lifetime.maximum_simultaneous_transient_bytes,
        quote.construction_transient_requested_bytes
            + quote.preparation_transient_requested_bytes
            + quote.response_iterator_requested_bytes
    );
    assert_eq!(
        quote
            .native_observe_lifetime_storage_data(old)?
            .work_requested_bytes()?,
        lifetime.work_requested_bytes()?
    );
    assert!(quote.native_observe_lifetime_storage_data(old - 1).is_err());
    assert!(connection.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn actual_native_observe_preparation_and_partial_failure_keep_original_children() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = object(&ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(&ObserveResult {
            observations: Vec::new(),
            next_sequence: U64::new(0),
            complete: true,
            inventory_hash: canonical::hash("cnp.packet-inventory.v5", b"actual owner data")?,
        })?,
        extensions: Extensions::new(),
    })?;
    let quote =
        connection.quote_original_packet_prefix_storage_data(2, &request, &body, &[], MAXIMUM)?;
    let lifetime = quote.native_observe_lifetime_storage_data(MAXIMUM)?;
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.body = body;
    let mut exchange = connection.unprepared_exchange(vec![response.clone()]);
    exchange.reconcile_original_packet_prefix_storage_data(&quote)?;
    exchange.prepare_in_place()?;
    assert!(retained_prefix_children(&exchange)? <= lifetime.retained_requested_bytes);
    assert_eq!(exchange.record.originals, vec![response]);
    assert!(exchange.connection.reader.stream_ref().output.is_empty());

    let (_handshake, connection, request) = fixture()?;
    // The closed counter accepts data, but the actual body validator refuses
    // this missing status/result. The original capsule remains in Failed.
    let body = Map::new();
    let quote =
        connection.quote_original_packet_prefix_storage_data(2, &request, &body, &[], MAXIMUM)?;
    let lifetime = quote.native_observe_lifetime_storage_data(MAXIMUM)?;
    let mut invalid = request.clone();
    invalid.message = MessageKind::Response;
    invalid.body = body;
    let mut failed = connection.unprepared_exchange(vec![invalid.clone()]);
    assert!(failed.prepare_in_place().is_err());
    assert!(matches!(failed.phase, Phase::Failed));
    assert_eq!(failed.record.originals, vec![invalid]);
    // The terminal partial construction remains counted, not reclaimed or
    // treated as an empty successful owner merely because it returned Err.
    assert!(
        retained_prefix_children(&failed)?
            <= lifetime.retained_requested_bytes + lifetime.work_requested_bytes()?
    );
    assert!(failed.connection.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn original_observe_ack_split_preserves_full_error_owners_and_old_quote() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let payload = b"same actual retained proof".to_vec();
    let evidence = vec![(
        canonical::content_ref(&payload, "application/json")?,
        payload,
    )];
    let quote = connection.quote_original_packet_prefix_storage_data(
        2,
        &request,
        &Map::new(),
        &evidence,
        MAXIMUM,
    )?;
    let maximum_frame = allowance(connection.authority.limits().frame_bytes.get())?;
    let old = quote.native_observe_lifetime_storage_data(MAXIMUM)?;
    let split = quote.native_original_observe_lifetime_storage_data(maximum_frame, MAXIMUM)?;
    let ack = acknowledgements::open_ack_lifetime_storage_data(maximum_frame)?;

    assert_eq!(
        ack.retained + ack.returning,
        quote.one_open_ack_requested_bytes
    );
    assert_eq!(
        split.retained_requested_bytes + ack.returning,
        old.retained_requested_bytes
    );
    assert_eq!(
        split.encoding_work_requested_bytes()?,
        old.work_requested_bytes()?
    );
    assert!(split.retained_requested_bytes >= quote.successful_ack_cache_requested_bytes);
    assert!(split.retained_requested_bytes >= ack.retained);
    assert!(
        quote
            .native_original_observe_lifetime_storage_data(maximum_frame - 1, MAXIMUM)
            .is_err()
    );
    assert!(connection.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn terminating_error_details_remain_covered_by_ack_retained_axis() -> TestResult {
    let (_handshake, connection, _) = fixture()?;
    let mut details = Map::new();
    details.insert(
        "dense".into(),
        serde_json::json!([[[1.25,1e-100]],{"retained":"escaped\\\"bytes"}]),
    );
    let error = ErrorRecord {
        code: "PROTOCOL_ERROR".into(),
        message: "original refusal".into(),
        effect: EffectCertainty::Unknown,
        retryable: false,
        details,
    };
    let mut incoming = envelope(&connection.authority, Method::BlobFinish)?;
    incoming.message = MessageKind::Response;
    incoming.body = object(&ResponseShape::Error {
        operation_state: OperationState::Unknown,
        error,
        extensions: Extensions::new(),
    })?;
    let raw = canonical::canonical_json(&serde_json::to_value(&incoming)?)?;
    let envelope = Envelope::decode(&raw, raw.len())?;
    let request = RequestBody::BlobFinish(BlobFinishRequest {
        transfer_id: Id::new("same-transfer")?,
        extensions: Extensions::new(),
    });
    let response = decode_response(&request, &envelope.body)?;
    let ResponseShape::Error {
        error, extensions, ..
    } = &response.shape
    else {
        return Err("actual Error response absent".into());
    };
    let mut retained = MetadataObserver::new();
    retained.observe(&envelope)?;
    retained.boxed_value(&response)?;
    retained.observe(&error.code)?;
    retained.observe(&error.message)?;
    retained.observe(&error.details)?;
    retained.observe(extensions)?;
    retained.vector::<u8>(raw.capacity())?;
    let actual = requested_facts(&retained.finish())?;
    let split = acknowledgements::open_ack_lifetime_storage_data(raw.len())?;

    assert!(actual <= split.retained);
    assert!(split.returning > 0);
    assert_eq!(
        split.retained + split.returning,
        acknowledgements::open_ack_storage(raw.len())?
    );
    assert!(acknowledgements::open_ack_lifetime_storage_data(0).is_err());
    assert_eq!(
        raw,
        canonical::canonical_json(&serde_json::to_value(&envelope)?)?
    );
    Ok(())
}
