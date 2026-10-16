//! Checks exact lifetime partition against actual prepared and failed owners.

use super::*;

fn retained_prefix_children(exchange: &PreparedExchange<Memory>) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(&exchange.record.originals)?;
    observer.observe(&exchange.record.canonical)?;
    observer.observe(&exchange.record.original_slots)?;
    observer.vector::<ReceivedFrame>(exchange.record.acknowledgements.capacity())?;
    exchange.connection.guard.observe_owned_metadata(&mut observer)?;
    requested_facts(&observer.finish())
}

#[test]
fn native_observe_partition_preserves_exact_old_peak_and_full_open_ack() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let payload = b"independently retained original proof".to_vec();
    let evidence = vec![(canonical::content_ref(&payload, "application/json")?, payload)];
    let quote = connection.quote_original_packet_prefix_storage_data(
        2, &request, &Map::new(), &evidence, MAXIMUM,
    )?;
    let lifetime = quote.native_observe_lifetime_storage_data(MAXIMUM)?;
    let old = quote.requested_bytes()?;
    assert_eq!(lifetime.retained_requested_bytes + lifetime.work_requested_bytes()?, old);
    assert!(lifetime.retained_requested_bytes >= quote.one_open_ack_requested_bytes);
    assert!(lifetime.retained_requested_bytes >= quote.successful_ack_cache_requested_bytes);
    assert_eq!(lifetime.maximum_simultaneous_transient_bytes,
        quote.construction_transient_requested_bytes
            + quote.preparation_transient_requested_bytes
            + quote.response_iterator_requested_bytes);
    assert_eq!(quote.native_observe_lifetime_storage_data(old)?.work_requested_bytes()?,
        lifetime.work_requested_bytes()?);
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
            observations: Vec::new(), next_sequence: U64::new(0), complete: true,
            inventory_hash: canonical::hash("cnp.packet-inventory.v5", b"actual owner data")?,
        })?,
        extensions: Extensions::new(),
    })?;
    let quote = connection.quote_original_packet_prefix_storage_data(
        2, &request, &body, &[], MAXIMUM,
    )?;
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
    let quote = connection.quote_original_packet_prefix_storage_data(
        2, &request, &body, &[], MAXIMUM,
    )?;
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
    assert!(retained_prefix_children(&failed)? <= lifetime.retained_requested_bytes
        + lifetime.work_requested_bytes()?);
    assert!(failed.connection.reader.stream_ref().output.is_empty());
    Ok(())
}
