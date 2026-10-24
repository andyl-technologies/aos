//! Checks real response serialization, partial custody and independent future rows.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::{
    hello::native_import18_hello_declaration_data, inert_bootstrap_fixtures,
};
use crucible_node_format::{Bytes, FacetSelection, Id, NodeManifest};
use serde_json::json;
use std::time::Duration;

fn fixture(reactive: bool) -> (PacketNative5SourceLaunch, Envelope, HelloResult) {
    let launch: PacketNative5SourceLaunch = serde_json::from_value(
        inert_bootstrap_fixtures::initial_selected_launch(reactive)["launch"].clone(),
    )
    .unwrap();
    let declaration = native_import18_hello_declaration_data(&launch).unwrap();
    let mut selected = None;
    declaration
        .retain_selection_into_data(&mut selected)
        .unwrap();
    let result = result_data(&launch, selected.unwrap().0);
    let request: Envelope = serde_json::from_value(json!({
        "protocol":"CNP/1", "message":"request", "sequence":"1", "method":"hello",
        "session_id":null, "incarnation_id":null, "node_id":null,
        "execution_owner_id":null, "capture_owner_id":null, "operation_id":null,
        "request_id":"hello/original",
        "body": {"versions":["CNP/2", "CNP/1"], "opaque_original":[1,2,3]},
        "extensions": {EXTENSION_NEGOTIATION_V1: {"format":"1", "required":[], "optional":[]}},
    }))
    .unwrap();
    (launch, request, result)
}

fn result_data(launch: &PacketNative5SourceLaunch, features: Vec<Id>) -> HelloResult {
    let binding = &launch.selection.realization.bindings[0];
    HelloResult {
        version: "CNP/1".into(),
        session_id: binding.authority.session_id.clone(),
        incarnation_id: binding.authority.incarnation_id.clone(),
        controller_nonce: Bytes::new(vec![19; 32]),
        provider_nonce: Bytes::new(vec![23; 32]),
        selected_features: features,
        limits: launch.limits,
        resume_token: Nullable(None),
        provider_identity: launch.selection.provider.clone(),
        resumed_operations: Vec::new(),
    }
}

fn quoted(launch: &PacketNative5SourceLaunch, cut: OperationalDeadline) -> (Attempt, [usize; 3]) {
    let row = super::super::construction_data(launch, 268_435_456).unwrap();
    let mut attempt = Attempt::empty_data();
    assert_eq!(attempt.retained_backing_data().unwrap(), 0);
    attempt.start_data(cut).unwrap();
    attempt.quote_data(row).unwrap();
    (attempt, row)
}

#[test]
fn actual_completed_and_envelope_keep_two_independent_body_owners_for_both_families() {
    for reactive in [false, true] {
        let (launch, request, result) = fixture(reactive);
        let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let (mut attempt, row) = quoted(&launch, cut);
        let original_body = std::ptr::from_ref(&request.body);
        let original_nonce = result.provider_nonce.as_slice().as_ptr();

        attempt.construct_data(&request, &result, cut).unwrap();
        let actual = attempt.retained_backing_data().unwrap();
        assert!(actual > 0 && actual <= row[0], "{actual} > {row:?}");
        assert!(attempt.result_value.is_none());
        assert!(attempt.body_value.is_none());
        assert!(attempt.selection_value.is_none());
        let envelope = attempt.envelope.as_ref().unwrap();
        assert_eq!(envelope.message, MessageKind::Response);
        assert_eq!(
            envelope.incarnation_id.0.as_ref(),
            Some(&result.incarnation_id)
        );
        assert_eq!(envelope.request_id, request.request_id);
        assert_ne!(
            envelope.request_id.0.as_ref().unwrap().as_str().as_ptr(),
            request.request_id.0.as_ref().unwrap().as_str().as_ptr()
        );
        assert_eq!(envelope.body["status"], "completed");
        assert_eq!(envelope.body["operation_state"], "completed");
        assert_eq!(
            envelope.body["result"],
            serde_json::to_value(&result).unwrap()
        );
        assert_eq!(
            envelope.extensions[EXTENSION_NEGOTIATION_V1],
            json!({"format":"1", "selected":[]})
        );
        let ResponseShape::Completed { result: first, .. } = attempt.completed.as_ref().unwrap()
        else {
            panic!("actual completed owner missing")
        };
        assert_ne!(
            first["provider_nonce"].as_str().unwrap().as_ptr(),
            envelope.body["result"]["provider_nonce"]
                .as_str()
                .unwrap()
                .as_ptr()
        );
        let pointer = std::ptr::from_ref(envelope);

        attempt.complete_data().unwrap();
        assert_eq!(std::ptr::from_ref(attempt.data(cut).unwrap()), pointer);
        assert!(attempt.start_data(cut).is_err());
        assert_eq!(attempt.retained_backing_data().unwrap(), actual);
        assert_eq!(std::ptr::from_ref(&request.body), original_body);
        assert_eq!(result.provider_nonce.as_slice().as_ptr(), original_nonce);
    }
}

#[test]
fn full_manifest_serialization_preserves_profile_facets_and_literal_rawvalue_keys() {
    let (mut launch, request, result) = fixture(false);
    let receipt = launch.selection.admission_receipt.clone();
    let schema = launch.selection.provider.implementation.formats[0].clone();
    launch
        .selection
        .provider
        .supported_profiles
        .push(NodeManifest {
            schema_version: 1,
            profile_id: Id::new("vendor/full-profile/1").unwrap(),
            roles: vec![Id::new("producer").unwrap()],
            configuration_schema: schema.clone(),
            allowed_combinations_ref: receipt.clone(),
            port_templates_ref: receipt.clone(),
            state_formats: vec![schema],
            operation_facets: vec![FacetSelection {
                id: Id::new("vendor/full-facet/1").unwrap(),
                version: 1,
                configuration_ref: receipt.clone(),
                guarantees_ref: receipt,
                extensions: Extensions::from([("vendor/facet".into(), json!({"x":[1,2,3]}))]),
            }],
            extensions: Extensions::from([(
                "$serde_json::private::RawValue".into(),
                json!("[literal text]"),
            )]),
        });
    let result = result_data(&launch, result.selected_features);
    let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut attempt, row) = quoted(&launch, cut);
    launch.selection.provider.supported_profiles.reserve(64);
    assert_eq!(
        super::super::construction_data(&launch, 268_435_456).unwrap(),
        row
    );

    attempt.construct_data(&request, &result, cut).unwrap();

    assert!(attempt.retained_backing_data().unwrap() <= row[0]);
    let body = &attempt.envelope.as_ref().unwrap().body;
    assert_eq!(
        body["result"]["provider_identity"],
        serde_json::to_value(&launch.selection.provider).unwrap()
    );
    let profile = body["result"]["provider_identity"]["supported_profiles"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(
        profile["extensions"]["$serde_json::private::RawValue"],
        "[literal text]"
    );
}

#[test]
fn stale_substituted_or_foreign_initial_branches_refuse_before_serialization() {
    for branch in 0..5 {
        let (launch, mut request, mut result) = fixture(false);
        let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let (mut attempt, _) = quoted(&launch, cut);
        let used_cut = match branch {
            0 => OperationalDeadline::expired_fixture(),
            1 => OperationalDeadline::after(Duration::from_secs(4)).unwrap(),
            2 => {
                request.method = Method::Discover;
                cut
            }
            3 => {
                result.provider_nonce = Bytes::new(vec![23; 31]);
                cut
            }
            _ => {
                result.resume_token = Nullable(Some(Bytes::new(vec![23; 32])));
                cut
            }
        };

        assert!(attempt.construct_data(&request, &result, used_cut).is_err());
        assert!(attempt.result_value.is_none());
        assert!(attempt.completed.is_none());
        assert!(attempt.envelope.is_none());
        assert_eq!(attempt.retained_backing_data().unwrap(), 0);
        assert!(attempt.start_data(cut).is_err());
    }
}

#[test]
fn serializer_failure_keeps_scalar_coordinates_and_the_prior_actual_completed_owner() {
    struct Refusal;
    impl Serialize for Refusal {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("bounded serializer refusal"))
        }
    }
    let (launch, request, result) = fixture(false);
    let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut attempt, _) = quoted(&launch, cut);
    attempt.construct_data(&request, &result, cut).unwrap();
    let completed = std::ptr::from_ref(attempt.completed.as_ref().unwrap());
    let before = attempt.retained_backing_data().unwrap();

    assert!(
        serialize_data(
            &mut attempt.body_value,
            &mut attempt.failure,
            &Refusal,
            SerializationPhase::Completed,
            cut
        )
        .is_err()
    );
    attempt.refuse_data();

    let failure = attempt.failure.as_ref().unwrap();
    assert!(matches!(failure.phase, SerializationPhase::Completed));
    assert!(matches!(
        failure.category,
        serde_json::error::Category::Data
    ));
    assert_eq!((failure.line, failure.column), (0, 0));
    assert_eq!(
        std::ptr::from_ref(attempt.completed.as_ref().unwrap()),
        completed
    );
    assert_eq!(attempt.retained_backing_data().unwrap(), before);
    assert!(attempt.data(cut).is_err());
    assert!(attempt.start_data(cut).is_err());
}

#[test]
fn unexpected_nonobject_move_restores_the_same_allocated_value() {
    let mut slot = Some(json!(["retained", "partial"]));
    let pointer = slot.as_ref().unwrap().as_array().unwrap().as_ptr();

    assert!(take_object_data(&mut slot).is_err());

    assert_eq!(slot.as_ref().unwrap().as_array().unwrap().as_ptr(), pointer);
}

#[test]
fn complete_future_peak_is_exact_and_short_or_zero_credit_refuses() {
    let (launch, _, _) = fixture(false);
    let row = super::super::construction_data(&launch, 268_435_456).unwrap();
    let peak = row.into_iter().sum();

    assert_eq!(super::super::construction_data(&launch, peak).unwrap(), row);
    assert!(super::super::construction_data(&launch, peak - 1).is_err());
    assert!(super::super::construction_data(&launch, 0).is_err());
    assert_eq!(
        super::super::projection::challenge_formatter_data().unwrap(),
        43
    );
}
