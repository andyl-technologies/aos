//! Component evidence that same-incarnation resume cannot change selected features.

use super::*;

fn handshake_with_optional_evidence() -> Handshake {
    Handshake::new(
        TrustedInstallation {
            session_id: id("session"),
            incarnation_id: id("incarnation"),
            measured_implementation: manifest().implementation,
            launch_receipt: reference(),
            admission_token: [7; 32],
        },
        NegotiationPolicy {
            supported_features: vec![
                id("cnp.control-evidence/1"),
                id("cnp.core/1"),
                id("cnp.resume/1"),
            ],
            required_features: vec![id("cnp.core/1")],
            provider_limits: limits(),
            required_schemas: Vec::new(),
            required_guarantees: reference(),
            envelope_extension_features: std::collections::BTreeMap::new(),
        },
    )
    .unwrap()
}

fn selected_evidence() -> (HelloRequest, HelloResult) {
    let mut request = hello();
    let mut response = result();
    request
        .optional_features
        .insert(0, id("cnp.control-evidence/1"));
    response
        .selected_features
        .insert(0, id("cnp.control-evidence/1"));
    (request, response)
}

fn original_operation(request: &mut HelloRequest, response: &mut HelloResult) {
    request
        .resume_session
        .as_mut()
        .unwrap()
        .unresolved_operation_ids = vec![id("operation")];
    response.resumed_operations = vec![ResumedOperation {
        operation_id: id("operation"),
        operation_state: OperationState::Running,
        outcome: Nullable(None),
    }];
}

#[test]
fn previously_selected_optional_feature_cannot_disappear_from_resumed_result() {
    let mut handshake = handshake_with_optional_evidence();
    let mut verifier = Verifier::default();
    let (request, response) = selected_evidence();
    let old = handshake
        .admit_exchange(&request, &response, id("connection/1"), &mut verifier)
        .unwrap();
    let (mut resumed_request, mut resumed_response) = resumed(&request, &response);
    original_operation(&mut resumed_request, &mut resumed_response);
    verifier.retained = resumed_response.resumed_operations.clone();
    let original_journal = verifier.retained.clone();
    resumed_response.selected_features.remove(0);

    assert!(
        handshake
            .admit_exchange(
                &resumed_request,
                &resumed_response,
                id("connection/2"),
                &mut verifier,
            )
            .is_err()
    );
    assert!(old.ensure_live().is_ok());
    assert_eq!(old.epoch(), 1);
    assert!(verifier.fenced.is_empty());
    assert_eq!(verifier.retained, original_journal);

    // The failed proposal cannot rotate the secret or revoke original custody.
    resumed_response.selected_features = response.selected_features;
    let resumed = handshake
        .admit_exchange(
            &resumed_request,
            &resumed_response,
            id("connection/2"),
            &mut verifier,
        )
        .unwrap();
    assert_eq!(resumed.epoch(), 2);
    assert!(old.ensure_live().is_err());
    assert_eq!(verifier.fenced, vec![id("connection/1")]);
    assert_eq!(verifier.retained, original_journal);
}

#[test]
fn previously_selected_optional_feature_cannot_be_unoffered_on_resume() {
    let mut handshake = handshake_with_optional_evidence();
    let mut verifier = Verifier::default();
    let (request, response) = selected_evidence();
    let old = handshake
        .admit_exchange(&request, &response, id("connection/1"), &mut verifier)
        .unwrap();
    let (mut request, mut response) = resumed(&request, &response);
    request.optional_features.remove(0);
    response.selected_features.remove(0);

    assert!(
        handshake
            .admit_exchange(&request, &response, id("connection/2"), &mut verifier)
            .is_err()
    );
    assert!(old.ensure_live().is_ok());
    assert!(verifier.fenced.is_empty());
}

#[test]
fn newly_offered_optional_behavior_requires_a_new_realization() {
    let mut handshake = handshake_with_optional_evidence();
    let mut verifier = Verifier::default();
    let initial_request = hello();
    let initial_response = result();
    let old = handshake
        .admit_exchange(
            &initial_request,
            &initial_response,
            id("connection/1"),
            &mut verifier,
        )
        .unwrap();
    let (mut request, mut response) = resumed(&initial_request, &initial_response);
    request
        .optional_features
        .insert(0, id("cnp.control-evidence/1"));
    response
        .selected_features
        .insert(0, id("cnp.control-evidence/1"));

    assert!(
        handshake
            .admit_exchange(&request, &response, id("connection/2"), &mut verifier)
            .is_err()
    );
    assert!(old.ensure_live().is_ok());
    assert!(verifier.fenced.is_empty());
}
