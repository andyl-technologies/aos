//! Checks prospective storage against actual current ordinary Observe owners.
//!
//! These are transport/layout data controls, not native report producer or
//! whole-allocation admission fixtures. Nothing is published to the stream.

use super::*;

fn response_body() -> Result<Map<String, Value>, ProviderError> {
    object(&ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(&ObserveResult {
            observations: Vec::new(),
            next_sequence: U64::new(0),
            complete: true,
            inventory_hash: canonical::hash("node/inventory", b"inert layout control")?,
        })?,
        extensions: Extensions::new(),
    })
}

fn original_data(request: &Envelope) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut fields = MetadataObserver::new();
    fields.observe(request)?;
    actual_serialization_storage_data(request, fields.finish(), MAXIMUM)
}

fn projected(
    connection: &Connection<Memory>,
    request: &Envelope,
    body: &Map<String, Value>,
    evidence: &[(ContentRef, Vec<u8>)],
) -> Result<OriginalPacketPrefixProjectionStorageData, ProviderError> {
    let original = original_data(request)?;
    let terminal = frame_projection(
        &connection.authority,
        Some(request),
        2,
        Method::Observe,
        Body::Response(body),
        MAXIMUM,
    )?;
    let objects = evidence
        .iter()
        .map(|(reference, bytes)| OriginalContinuationContentExtent {
            maximum_payload_bytes: bytes.len(),
            media_type: &reference.media_type,
        })
        .collect::<Vec<_>>();
    connection.quote_original_packet_prefix_projection_storage_data(
        2,
        request,
        OriginalPacketPrefixProjectionInput {
            terminal: &terminal,
            original: &original,
            objects: &objects,
            maximum_requested_bytes: MAXIMUM,
        },
    )
}

#[test]
fn actual_current_observe_owning_counter_fits_prospective_components() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = response_body()?;
    let bytes = b"same actual report proof".to_vec();
    let evidence = vec![(canonical::content_ref(&bytes, "application/json")?, bytes)];

    let projection = projected(&connection, &request, &body, &evidence)?;
    let actual =
        projection.authenticate_actual_inputs(&connection, 2, &request, &body, &evidence)?;

    assert_eq!(actual.frames, 4);
    assert_eq!(actual.requests, 3);
    assert!(
        actual.preparation_transient_requested_bytes
            <= projection.exchange.preparation_transient_requested_bytes
    );
    assert!(projection.requested_bytes()? > actual.requested_bytes()?);
    assert!(connection.reader.stream_ref().output.is_empty());
    assert_eq!(connection.guard.incoming_requests().count(), 1);
    Ok(())
}

#[test]
fn actual_spare_payload_and_evidence_capacity_refuse_before_frames() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = response_body()?;
    let bytes = b"same exact immutable report bytes".to_vec();
    let mut evidence = vec![(canonical::content_ref(&bytes, "application/json")?, bytes)];
    let projection = projected(&connection, &request, &body, &evidence)?;
    projection.authenticate_actual_inputs(&connection, 2, &request, &body, &evidence)?;

    evidence[0]
        .1
        .try_reserve_exact(projection.source_owner_requested_bytes + 1)?;
    // The old owning planner sees identical lengths/references. Erasing the
    // source-capacity guard would therefore let this changed owner reach it.
    connection.quote_original_packet_prefix_storage_data(2, &request, &body, &evidence, MAXIMUM)?;
    assert!(
        projection
            .authenticate_actual_inputs(&connection, 2, &request, &body, &evidence)
            .is_err()
    );

    let bytes = b"same exact immutable report bytes".to_vec();
    evidence = vec![(canonical::content_ref(&bytes, "application/json")?, bytes)];
    evidence.try_reserve_exact(projection.source_owner_requested_bytes + 1)?;
    connection.quote_original_packet_prefix_storage_data(2, &request, &body, &evidence, MAXIMUM)?;
    assert!(
        projection
            .authenticate_actual_inputs(&connection, 2, &request, &body, &evidence)
            .is_err()
    );
    assert!(connection.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn old_simultaneous_request_limit_refuses_three_nonempty_proofs() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = response_body()?;
    let bytes = b"proof".to_vec();
    let reference = canonical::content_ref(&bytes, "application/json")?;
    let evidence = vec![(reference.clone(), bytes.clone()); 3];
    assert_eq!(connection.authority.limits().requests.get(), 8);
    assert!(projected(&connection, &request, &body, &evidence).is_err());
    assert!(
        connection
            .quote_original_packet_prefix_storage_data(2, &request, &body, &evidence, MAXIMUM)
            .is_err()
    );
    assert!(connection.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn changed_original_and_payload_bounds_refuse_on_same_current_connection() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = response_body()?;
    let bytes = b"report".to_vec();
    let mut evidence = vec![(canonical::content_ref(&bytes, "application/json")?, bytes)];
    let projection = projected(&connection, &request, &body, &evidence)?;
    projection.authenticate_actual_inputs(&connection, 2, &request, &body, &evidence)?;

    let mut foreign = request.clone();
    foreign.request_id = Nullable(Some(Id::new("another-original")?));
    assert!(
        projection
            .authenticate_actual_inputs(&connection, 2, &foreign, &body, &evidence)
            .is_err()
    );
    evidence[0].1.push(b'!');
    evidence[0].0 = canonical::content_ref(&evidence[0].1, "application/json")?;
    assert!(
        projection
            .authenticate_actual_inputs(&connection, 2, &request, &body, &evidence)
            .is_err()
    );
    assert!(connection.reader.stream_ref().output.is_empty());
    Ok(())
}

fn longer_scope_fixture()
-> Result<(Handshake, Connection<Memory>, Envelope), Box<dyn std::error::Error>> {
    let suffix = "a-longer-validated-original-scope-with-enough-header-growth";
    let (handshake, authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope_with_identity_suffix(Some(suffix));
    let policy = crate::reference_packet::service::prepared_blob_proof_codec_for_test(
        selection,
        coordinator,
    )?;
    let mut request = envelope(&authority, Method::Observe)?;
    request.body = object(&ObserveRequest {
        binding_hash: canonical::hash("cnp.owner-binding.v1", b"fixture binding data")?,
        owner_generation: U64::new(1),
        after_observation_sequence: U64::new(0),
        maximum_items: U64::new(16),
        extensions: Extensions::new(),
    })?;
    let bytes = canonical::canonical_json(&serde_json::to_value(&request)?)?;
    let mut input = Vec::new();
    input.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    input.extend_from_slice(&bytes);
    let mut connection = Connection::new(
        Memory {
            input: Cursor::new(input),
            ..Memory::default()
        },
        authority,
        Rc::new(Supervisor(RefCell::new(Vec::new()))),
        Rc::new(Uninstalled),
        EndpointRole::Provider,
    )?;
    let mut bank = Some(
        crate::transport::original_frames::OriginalFrameReservation::reserve(1024 * 1024, 64)?,
    );
    connection.install_native5_native_codec(&mut bank, policy)?;
    let received = connection
        .receive()?
        .ok_or("longer actual Observe absent")?;
    assert_eq!(received.envelope, request);
    Ok((handshake, connection, request))
}

#[test]
fn current_proof_header_requote_refuses_a_short_foreign_authority_bound() -> TestResult {
    let (_short_handshake, short, short_request) = fixture()?;
    let (_long_handshake, long, long_request) = longer_scope_fixture()?;
    let body = response_body()?;
    let bytes = b"original report".to_vec();
    let evidence = vec![(canonical::content_ref(&bytes, "application/json")?, bytes)];
    // Both original and terminal use the genuinely larger scope's complete
    // counters. Only the multiplied proof header counter comes from short.
    let original = original_data(&long_request)?;
    let terminal = frame_projection(
        &long.authority,
        Some(&long_request),
        2,
        Method::Observe,
        Body::Response(&body),
        MAXIMUM,
    )?;
    let objects = [OriginalContinuationContentExtent {
        maximum_payload_bytes: evidence[0].1.len(),
        media_type: "application/json",
    }];
    let bound = short.quote_original_packet_prefix_projection_storage_data(
        2,
        &short_request,
        OriginalPacketPrefixProjectionInput {
            terminal: &terminal,
            original: &original,
            objects: &objects,
            maximum_requested_bytes: MAXIMUM,
        },
    )?;
    bound.authenticate_actual_inputs(&short, 2, &short_request, &body, &evidence)?;
    // The old current owning counter itself fits its real bank. The refusal
    // below therefore tests the saved multiplied header bound, not wire no-fit.
    long.quote_original_packet_prefix_storage_data(2, &long_request, &body, &evidence, MAXIMUM)?;
    assert!(
        bound
            .authenticate_actual_inputs(&long, 2, &long_request, &body, &evidence)
            .is_err()
    );
    assert!(long.reader.stream_ref().output.is_empty());
    assert!(short.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn storage_backed_builder_rejects_foreign_authority_before_frames() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let (_foreign_handshake, foreign, _) = longer_scope_fixture()?;
    let body = response_body()?;
    let bytes = b"same actual report proof".to_vec();
    let evidence = vec![(canonical::content_ref(&bytes, "application/json")?, bytes)];
    let projection = projected(&connection, &request, &body, &evidence)?;
    projection.authenticate_actual_inputs(&connection, 2, &request, &body, &evidence)?;

    connection.authenticate_original_packet_prefix_builder_authority_data(&connection.authority)?;
    connection
        .guard
        .preflight_original_packet_prefix_data(&request, 2, 4, 3)?;
    let result =
        connection.authenticate_original_packet_prefix_builder_authority_data(&foreign.authority);

    assert!(matches!(
        result,
        Err(ProviderError::Correlation(
            "packet prefix builder authority changed"
        ))
    ));
    connection
        .guard
        .preflight_original_packet_prefix_data(&request, 2, 4, 3)?;
    assert!(connection.reader.stream_ref().output.is_empty());
    assert_eq!(connection.guard.incoming_requests().count(), 1);
    Ok(())
}
