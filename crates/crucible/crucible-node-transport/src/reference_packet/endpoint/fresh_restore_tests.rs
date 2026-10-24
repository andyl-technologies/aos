//! Checks failure retention without manufacturing a native boot or query owner.
//!
//! crucible-lint: panic-shortcut: invariant failures intentionally stop the test.

use super::*;
use crate::bodies::DiscoverRequest;
use crucible_node_format::Extensions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn received() -> Result<ReceivedFrame, ProviderError> {
    let request = DiscoverRequest {
        profile_ids: Vec::new(),
        cursor: None,
        extensions: Extensions::new(),
    };
    let mut envelope = crate::envelope::tests::request();
    envelope.method = Method::Discover;
    let serde_json::Value::Object(body) =
        serde_json::to_value(&request).map_err(crucible_node_format::ContractError::from)?
    else {
        return Err(refused());
    };
    envelope.body = body;
    Ok(ReceivedFrame {
        envelope,
        body: ReceivedBody::Request(Box::new(RequestBody::Discover(request))),
    })
}

#[test]
fn query_slot_retains_actual_received_owner_before_refusal_and_never_overwrites() -> TestResult {
    let mut input = FreshQueryInput::default();
    let first = received()?;
    let expected = first.envelope.clone();
    input.retain_once(first)?;

    assert!(
        matches!(&input.frame.as_ref().ok_or("missing retained frame")?.body,
        ReceivedBody::Request(body) if !matches!(body.as_ref(), RequestBody::Observe(_)))
    );
    assert!(input.retain_once(received()?).is_err());
    assert_eq!(
        input
            .frame
            .as_ref()
            .ok_or("missing retained frame")?
            .envelope,
        expected
    );
    assert!(input.commitments.is_none());
    Ok(())
}

#[test]
fn fresh_input_walk_counts_independent_raw_typed_and_box_backing() -> TestResult {
    let (_, _, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let request = ObserveRequest {
        binding_hash: selection.realization.owner_bindings[0].identity()?,
        owner_generation: crucible_node_format::U64::new(1),
        after_observation_sequence: crucible_node_format::U64::new(0),
        maximum_items: crucible_node_format::U64::new(1),
        extensions: Extensions::new(),
    };
    let mut request = request;
    request.binding_hash.digest.reserve_exact(257);
    let mut envelope = crate::envelope::tests::request();
    envelope.method = Method::Observe;
    envelope.body = serde_json::to_value(&request)?
        .as_object()
        .ok_or("missing body")?
        .clone();
    let typed_capacity = request.binding_hash.digest.capacity();
    let mut input = FreshQueryInput::default();
    input.retain_once(ReceivedFrame {
        envelope,
        body: ReceivedBody::Request(Box::new(RequestBody::Observe(request))),
    })?;
    let mut raw = crate::retained_metadata::MetadataObserver::new();
    raw.observe(
        &input
            .frame
            .as_ref()
            .ok_or("missing retained frame")?
            .envelope,
    )?;
    let raw_facts = raw.finish();

    let mut observer = crate::retained_metadata::MetadataObserver::new();
    input.observe_retained_metadata(&mut observer)?;
    let facts = observer.finish();
    // The raw JSON owner cannot satisfy this independent typed spare bank.
    // Removing the typed child walk makes this delta disappear.
    assert!(
        facts
            .string_capacity_bytes
            .checked_sub(raw_facts.string_capacity_bytes)
            .is_some_and(|additional| additional >= typed_capacity)
    );
    assert_eq!(
        facts
            .boxed_value_bytes
            .checked_sub(raw_facts.boxed_value_bytes),
        Some(std::mem::size_of::<RequestBody>())
    );
    assert!(input.frame.is_some());
    assert!(input.commitments.is_none());
    Ok(())
}
