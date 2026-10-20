//! Checks the startup heap counter independently of runtime wire admission.
//!
//! crucible-lint: panic-shortcut: fixture assertions intentionally stop the test.

use super::*;
use crate::bodies::{OperationState, ResponseShape};
use crate::envelope::Nullable;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const MAXIMUM: usize = usize::MAX;

fn original_and_terminal(
    authority: &ConnectionAuthority,
) -> Result<
    (
        OriginalSerializationStorageData,
        OriginalSerializationStorageData,
    ),
    ProviderError,
> {
    let body = serde_json::to_value(crate::bodies::ObserveRequest {
        binding_hash: crucible_node_format::canonical::hash(
            "cnp.owner-binding.v1",
            b"startup counter scope",
        )?,
        owner_generation: U64::new(1),
        after_observation_sequence: U64::new(0),
        maximum_items: U64::new(1),
        extensions: crucible_node_format::Extensions::new(),
    })
    .map_err(crucible_node_format::ContractError::from)?;
    let Value::Object(body) = body else {
        return Err(refused());
    };
    let mut envelope = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(Id::new("original-startup-counter")?)),
        sequence: U64::new(u64::MAX),
        method: Method::Observe,
        body,
        extensions: crucible_node_format::Extensions::new(),
    };
    let mut observer = MetadataObserver::new();
    observer.observe(&envelope)?;
    let original = actual_serialization_storage_data(&envelope, observer.finish(), MAXIMUM)?;
    envelope.message = MessageKind::Response;
    let result = serde_json::to_value(crate::bodies::ObserveResult {
        observations: Vec::new(),
        next_sequence: U64::new(0),
        complete: true,
        inventory_hash: crucible_node_format::canonical::hash(
            "node/inventory",
            b"startup counter scope",
        )?,
    })
    .map_err(crucible_node_format::ContractError::from)?;
    let Value::Object(result) = result else {
        return Err(refused());
    };
    let terminal = serde_json::to_value(ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result,
        extensions: crucible_node_format::Extensions::new(),
    })
    .map_err(crucible_node_format::ContractError::from)?;
    let Value::Object(terminal) = terminal else {
        return Err(refused());
    };
    envelope.body = terminal;
    let mut observer = MetadataObserver::new();
    observer.observe(&envelope)?;
    let terminal = actual_serialization_storage_data(&envelope, observer.finish(), MAXIMUM)?;
    Ok((original, terminal))
}

#[test]
fn prospective_heap_count_does_not_admit_or_require_a_wire_window() -> TestResult {
    let (_handshake, authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let (original, terminal) = original_and_terminal(&authority)?;
    let objects: [OriginalContinuationContentExtent<'_>; 3] =
        std::array::from_fn(|_| OriginalContinuationContentExtent {
            maximum_payload_bytes: 65_536,
            media_type: "application/json",
        });
    let data = quote_startup_parts(
        (authority.session_id(), authority.incarnation_id()),
        authority.limits(),
        selection.provider.extensions_supported.len(),
        OriginalPacketPrefixProjectionInput {
            original: &original,
            terminal: &terminal,
            objects: &objects,
            maximum_requested_bytes: MAXIMUM,
        },
        false,
    )?;

    assert!(data.exchange.requests > usize::try_from(authority.limits().requests.get())?);
    assert!(data.exchange.original_slots_required > 64);
    assert_eq!(
        data.exchange.one_open_ack_requested_bytes,
        acknowledgements::open_ack_storage(usize::try_from(authority.limits().frame_bytes.get())?)?
    );
    assert!(data.exchange.preparation_transient_requested_bytes > 0);
    assert_eq!(
        data.declared_counter_scratch_bytes + data.exchange.declared_quote_scratch_bytes,
        original_packet_prefix_startup_counter_scratch_data()
    );
    Ok(())
}

#[test]
fn startup_counter_preserves_content_cap_and_total_one_short_refusal() -> TestResult {
    let (_handshake, authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let (original, terminal) = original_and_terminal(&authority)?;
    let mut objects = [OriginalContinuationContentExtent {
        maximum_payload_bytes: 16_384,
        media_type: "application/json",
    }];
    let count = |objects: &[OriginalContinuationContentExtent<'_>], maximum| {
        quote_startup_parts(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            selection.provider.extensions_supported.len(),
            OriginalPacketPrefixProjectionInput {
                original: &original,
                terminal: &terminal,
                objects,
                maximum_requested_bytes: maximum,
            },
            false,
        )
    };
    let data = count(&objects, MAXIMUM)?;
    let total = data.requested_bytes()?;

    count(&objects, total)?;
    assert!(count(&objects, total - 1).is_err());
    objects[0].maximum_payload_bytes = 65_537;
    assert!(count(&objects, MAXIMUM).is_err());
    Ok(())
}

#[test]
fn startup_and_current_proof_headers_use_the_same_closed_field_counter() -> TestResult {
    let (_handshake, authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let binding = selection.realization.bindings.first().ok_or_else(refused)?;
    let extent = ContentExtent {
        payload: 16_384,
        media: 128,
    };
    for (method, body) in [
        (Method::BlobBegin, ProjectedBody::Begin(36, &extent)),
        (Method::BlobChunk, ProjectedBody::Chunk(36, 5464)),
        (Method::BlobFinish, ProjectedBody::Finish(36)),
    ] {
        // The body enum is deliberately reconstructed for the two borrowed
        // visits; it contains only scalar extents and the same reference loan.
        let current_body = match &body {
            ProjectedBody::Begin(a, b) => ProjectedBody::Begin(*a, b),
            ProjectedBody::Chunk(a, b) => ProjectedBody::Chunk(*a, *b),
            ProjectedBody::Finish(a) => ProjectedBody::Finish(*a),
        };
        let current =
            continuation::projected_packet_frame(&authority, method, current_body, MAXIMUM)?;
        let startup = continuation::projected_packet_startup_frame(
            &binding.authority.session_id,
            &binding.authority.incarnation_id,
            method,
            body,
            MAXIMUM,
        )?;
        continuation::within(&current, &startup)?;
        continuation::within(&startup, &current)?;
    }
    Ok(())
}

#[test]
fn startup_containment_charges_both_fresh_keys_for_one_feature() -> TestResult {
    let (_handshake, authority, _, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let (original, _) = original_and_terminal(&authority)?;
    let baseline = startup_containment(0, &original)?;
    let selected = startup_containment(1, &original)?;

    // Two separately retained keys are required before counting their tree nodes.
    assert!(selected >= baseline.checked_add(2 * 128).ok_or_else(credit)?);
    assert!(startup_containment(usize::MAX, &original).is_err());
    Ok(())
}

#[test]
fn native_retained_prefix_counts_real_independent_dom_copies_without_replacing_legacy_work()
-> TestResult {
    let (_handshake, authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let actual = serde_json::to_value(crate::handshake::tests::original_hello_envelope())?;
    let mut observer = MetadataObserver::new();
    observer.observe(&actual)?;
    let shape = actual_serialization_storage_data(&actual, observer.finish(), MAXIMUM)?;
    let clones = [actual.clone(), actual.clone(), actual.clone()];
    let mut owned = 0usize;
    for value in &clones {
        let mut observer = MetadataObserver::new();
        observer.observe(value)?;
        owned = add(owned, requested_facts(&observer.finish())?)?;
    }
    let objects: [OriginalContinuationContentExtent<'_>; 2] =
        std::array::from_fn(|_| OriginalContinuationContentExtent {
            maximum_payload_bytes: 128,
            media_type: "application/json",
        });
    let quote = |baseline| {
        quote_startup_parts(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            selection.provider.extensions_supported.len(),
            OriginalPacketPrefixProjectionInput {
                original: &shape,
                terminal: &shape,
                objects: &objects,
                maximum_requested_bytes: MAXIMUM,
            },
            baseline,
        )
    };
    let native = quote(true)?;
    let legacy = quote(false)?;
    assert!(
        native
            .exchange
            .native_retained_backing_bytes
            .ok_or_else(credit)?
            >= add(owned, shape.canonical_output_requested_bytes)?
    );
    assert_eq!(
        native.exchange.requested_bytes()?,
        legacy.exchange.requested_bytes()?
    );
    assert_eq!(
        native.source_owner_requested_bytes,
        legacy.source_owner_requested_bytes
    );
    assert!(native.native_source_backing_bytes.is_some());
    assert!(legacy.native_source_backing_bytes.is_none());

    let mut backing_one_short = continuation::copy_storage(&shape);
    backing_one_short.retained_value_backing_bytes = shape
        .retained_value_backing_bytes
        .checked_sub(1)
        .ok_or_else(credit)?;
    assert!(continuation::within(&shape, &backing_one_short).is_err());
    Ok(())
}

#[test]
fn input17_five_object_projection_is_separate_from_the_old_three_object_class() -> TestResult {
    let (_, authority) = crate::handshake::tests::authority_with_scope("input17-five-object-quote");
    let (original, terminal) = original_and_terminal(&authority)?;
    let objects: [OriginalContinuationContentExtent<'_>; 5] =
        std::array::from_fn(|_| OriginalContinuationContentExtent {
            maximum_payload_bytes: 257,
            media_type: "application/json",
        });
    let input = |maximum| OriginalPacketPrefixProjectionInput {
        original: &original,
        terminal: &terminal,
        objects: &objects,
        maximum_requested_bytes: maximum,
    };
    assert!(
        quote_startup_parts(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            0,
            input(MAXIMUM),
            false,
        )
        .is_err()
    );
    // This DATA-only test directly exercises the closed component projection.
    // Its real constructor additionally requires the immutable new17 roster;
    // neither constructor issues a native scope or transport allowance.
    let quote = |maximum| {
        quote_startup_parts_for::<5>(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            0,
            input(maximum),
            false,
            PrefixClass::RestoredInput17,
        )
    };
    let data = quote(MAXIMUM)?;
    assert_eq!(data.exchange.frames, 16);
    assert_eq!(data.exchange.requests, 15);
    assert_eq!(data.objects.iter().flatten().count(), 5);
    let exact = data.requested_bytes()?;
    assert_eq!(quote(exact)?.requested_bytes()?, exact);
    assert!(quote(exact - 1).is_err());
    Ok(())
}

#[test]
fn signed_observe17_two_object_class_prices_its_own_validation_axes() -> TestResult {
    let (_, authority) =
        crate::handshake::tests::authority_with_scope("observe17-two-object-quote");
    let (original, terminal) = original_and_terminal(&authority)?;
    let objects: [_; 2] = std::array::from_fn(|_| OriginalContinuationContentExtent {
        maximum_payload_bytes: 257,
        media_type: "application/json",
    });
    let quote = |maximum, class| {
        quote_startup_parts_for::<2>(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            0,
            OriginalPacketPrefixProjectionInput {
                original: &original,
                terminal: &terminal,
                objects: &objects,
                maximum_requested_bytes: maximum,
            },
            false,
            class,
        )
    };
    // Closed component DATA only; the live constructor independently checks
    // the full selected17 schema and actual current native action/connection.
    let legacy = quote(MAXIMUM, PrefixClass::Observe)?;
    let selected = quote(MAXIMUM, PrefixClass::RestoredObserve17)?;
    assert_eq!(selected.exchange.frames, 7);
    assert_eq!(selected.exchange.requests, 6);
    assert_eq!(selected.objects.iter().flatten().count(), 2);
    assert!(selected.class != legacy.class);
    assert_eq!(
        selected.exchange.construction_transient_requested_bytes,
        legacy.exchange.construction_transient_requested_bytes
            + super::super::super::restored_observation17::validation_transient_storage_data()
    );
    assert_eq!(
        selected.exchange.declared_quote_scratch_bytes,
        legacy.exchange.declared_quote_scratch_bytes
            + super::super::super::restored_observation17::counter_scratch_data()
    );
    let transport = selected.observation17_transport_storage_data()?;
    assert!(legacy.observation17_transport_storage_data().is_err());
    assert!(legacy.exchange.native_retained_backing_bytes.is_none());
    assert!(legacy.native_source_backing_bytes.is_none());
    assert_eq!(
        transport.retained_requested_bytes.get(),
        u64::try_from(
            selected
                .exchange
                .native_retained_backing_bytes
                .ok_or_else(refused)?
                + selected.exchange.one_open_ack_requested_bytes,
        )?
    );
    assert_eq!(
        transport.maximum_simultaneous_transient_bytes.get(),
        u64::try_from(selected.exchange.requested_bytes()?)?
    );
    assert_eq!(
        transport.declared_counter_scratch_bytes.get(),
        u64::try_from(
            selected.declared_counter_scratch_bytes
                + selected.exchange.declared_quote_scratch_bytes
        )?
    );
    assert!(selected.native_source_backing_bytes.ok_or_else(refused)? > 0);
    for axis in 0..3 {
        let mut short = transport;
        let field = match axis {
            0 => &mut short.retained_requested_bytes,
            1 => &mut short.maximum_simultaneous_transient_bytes,
            _ => &mut short.declared_counter_scratch_bytes,
        };
        *field = U64::new(field.get() - 1);
        assert!(short.authenticate_actual_data(&transport).is_err());
    }
    transport.authenticate_actual_data(&transport)?;
    let exact = selected.requested_bytes()?;
    assert_eq!(
        quote(exact, PrefixClass::RestoredObserve17)?.requested_bytes()?,
        exact
    );
    assert!(quote(exact - 1, PrefixClass::RestoredObserve17).is_err());
    Ok(())
}

#[path = "exchange_packet_startup_shared_tests.rs"]
mod shared;
