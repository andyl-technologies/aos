//! Checks the ordinary verifier with real negotiated protocol authority.
//!
//! The installation below is a protocol model, without native acceptance or
//! source-consumption authority. Each hostile control uses the production
//! ordinary verifier and current public commitment grammar.

// crucible-lint: allow panic-shortcut -- Protocol fixture assertions intentionally fail on invariant drift.
// crucible-lint: allow rust-allow -- Protocol model assertions deliberately panic on invalid fixtures.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_format::{HashRef, IdSet, ImplementationIdentity, ProviderManifest};
use crucible_node_transport::{
    bodies::{DiscoverRequest, InputRequest, RequestBody},
    handshake::{HelloResult, Limits, ResumedOperation, TrustedHandshakeVerifier},
    input_commit::{INPUT_COMMIT_FEATURE, InputCommitIntentV1},
};
use serde_json::json;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn reference() -> ContentRef {
    canonical::content_ref(b"protocol-only original", "application/json").unwrap()
}

fn hash(domain: &str) -> HashRef {
    canonical::hash(domain, b"protocol-only original").unwrap()
}

fn manifest() -> ProviderManifest {
    ProviderManifest {
        schema_version: 1,
        provider_id: id("ordinary-schema-model"),
        implementation: ImplementationIdentity {
            schema_version: 1,
            implementation_id: id("ordinary-schema-model/1"),
            artifacts: Vec::new(),
            model_definitions: Vec::new(),
            formats: Vec::new(),
            extensions: Extensions::new(),
        },
        protocol_versions: vec![id("CNP/1")],
        supported_profiles: Vec::new(),
        extensions_supported: Vec::new(),
        qualification_refs: Vec::new(),
        extensions: Extensions::new(),
    }
}

struct ModelInstallation;

impl TrustedHandshakeVerifier for ModelInstallation {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installed: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installed.measured_implementation != manifest().implementation
            || installed.launch_receipt != reference()
            || request.admission_token.as_slice() != [7; 32]
            || result.provider_identity != manifest()
        {
            return Err(ProviderError::Correlation(
                "foreign protocol model installation",
            ));
        }
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        original: &ProviderManifest,
        _: &IdSet,
        schemas: &[crucible_node_format::SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        if original != &manifest() || !schemas.is_empty() || guarantees != &reference() {
            return Err(ProviderError::Correlation(
                "foreign protocol model selection",
            ));
        }
        Ok(())
    }

    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        if !operations.is_empty() {
            return Err(ProviderError::Correlation("model has no resume custody"));
        }
        Ok(Vec::new())
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation("model has no resumed stream"))
    }
}

fn authority(selected: bool) -> ConnectionAuthority {
    let mut features = vec![id("cnp.core/1")];
    if selected {
        features.push(id(INPUT_COMMIT_FEATURE));
    }
    let limits = Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(16),
        journal_entries: U64::new(64),
        blob_chunk_bytes: U64::new(4096),
    };
    let mut handshake = Handshake::new(
        TrustedInstallation {
            session_id: id("session"),
            incarnation_id: id("incarnation"),
            measured_implementation: manifest().implementation,
            launch_receipt: reference(),
            admission_token: [7; 32],
        },
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features.clone(),
            provider_limits: limits,
            required_schemas: Vec::new(),
            required_guarantees: reference(),
            envelope_extension_features: if selected {
                BTreeMap::from([(INPUT_COMMIT_FEATURE.into(), id(INPUT_COMMIT_FEATURE))])
            } else {
                BTreeMap::new()
            },
        },
    )
    .unwrap();
    let request = HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: id("session"),
        controller_nonce: Bytes::new(vec![3; 32]),
        required_features: features.clone(),
        optional_features: Vec::new(),
        limits,
        admission_token: Bytes::new(vec![7; 32]),
        resume_session: None,
        extensions: Extensions::new(),
    };
    let result = HelloResult {
        version: "CNP/1".into(),
        session_id: id("session"),
        incarnation_id: id("incarnation"),
        controller_nonce: Bytes::new(vec![3; 32]),
        provider_nonce: Bytes::new(vec![5; 32]),
        selected_features: features,
        limits,
        resume_token: Nullable(None),
        provider_identity: manifest(),
        resumed_operations: Vec::new(),
    };
    let request = Envelope::decode(&serde_json::to_vec(&json!({
        "protocol": "CNP/1", "message": "request", "session_id": null, "incarnation_id": null,
        "node_id": null, "execution_owner_id": null, "capture_owner_id": null,
        "request_id": "original-hello", "operation_id": null, "sequence": "1", "method": "hello",
        "body": request, "extensions": {},
    })).unwrap(), 65536).unwrap();
    let response = Envelope::decode(&serde_json::to_vec(&json!({
        "protocol": "CNP/1", "message": "response", "session_id": null, "incarnation_id": "incarnation",
        "node_id": null, "execution_owner_id": null, "capture_owner_id": null,
        "request_id": "original-hello", "operation_id": null, "sequence": "1", "method": "hello",
        "body": { "status": "completed", "operation_state": "completed", "result": result, "extensions": {} },
        "extensions": {},
    })).unwrap(), 65536).unwrap();
    handshake
        .admit_envelopes(
            &request,
            &response,
            id("original-connection"),
            &mut ModelInstallation,
        )
        .unwrap()
}

fn original() -> (Envelope, ReceivedBody) {
    let input = InputRequest {
        binding_hash: hash("cnp.owner-binding.v1"),
        owner_generation: U64::new(1),
        batch_id: id("batch"),
        batch_sequence: U64::new(1),
        input_epoch: id("epoch"),
        events: Vec::new(),
        batch_hash: hash("cnp.input-batch.v1"),
        extensions: Extensions::new(),
    };
    let intent = InputCommitIntentV1 {
        schema_version: 1,
        session_id: id("session"),
        incarnation_id: id("incarnation"),
        node_id: id("node"),
        execution_owner_id: id("owner"),
        owner_generation: U64::new(1),
        activation_id: id("activation"),
        world_generation: U64::new(1),
        world_binding_hash: hash("cnp.world-binding.v1"),
        stage_operation_id: id("original-stage"),
        input_request_id: id("original-input"),
        batch_id: input.batch_id.clone(),
        batch_hash: input.batch_hash.clone(),
        staging_receipt: reference(),
        delivery_inventory: canonical::content_ref(
            b"[]",
            "application/vnd.crucible.input-inventory+json",
        )
        .unwrap(),
        cutoff: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    let envelope = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(id("session"))),
        incarnation_id: Nullable(Some(id("incarnation"))),
        node_id: Nullable(Some(id("node"))),
        execution_owner_id: Nullable(Some(id("owner"))),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(Some(id("original-stage"))),
        request_id: Nullable(Some(id("original-commit"))),
        sequence: U64::new(2),
        method: Method::Input,
        body: serde_json::to_value(&input)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
        extensions: BTreeMap::from_iter([(
            INPUT_COMMIT_FEATURE.into(),
            serde_json::to_value(intent).unwrap(),
        )]),
    };
    (
        envelope,
        ReceivedBody::Request(Box::new(RequestBody::Input(input))),
    )
}

#[test]
fn ordinary_closed_schema_accepts_the_exact_negotiated_commit_extension() {
    let authority = authority(true);
    let (envelope, body) = original();
    assert!(ClosedSchemas.verify(&authority, &envelope, &body).is_ok());

    let mut staging = envelope;
    staging.extensions.clear();
    assert!(ClosedSchemas.verify(&authority, &staging, &body).is_ok());
}

#[test]
fn ordinary_closed_schema_rejects_downgrade_foreign_keys_and_malformed_cuts() {
    let selected = authority(true);
    let unselected = authority(false);
    let (original, body) = original();
    assert!(ClosedSchemas.verify(&unselected, &original, &body).is_err());

    for change in 0..6 {
        let mut envelope = original.clone();
        match change {
            0 => {
                let value = envelope.extensions.remove(INPUT_COMMIT_FEATURE).unwrap();
                envelope.extensions.insert("foreign/1".into(), value);
            }
            1 => {
                envelope.extensions.insert("foreign/1".into(), json!({}));
            }
            2 => {
                envelope.extensions.get_mut(INPUT_COMMIT_FEATURE).unwrap()["schema_version"] =
                    json!(2);
            }
            3 => {
                envelope.extensions.get_mut(INPUT_COMMIT_FEATURE).unwrap()["cutoff"]["microstep"] =
                    json!("1");
            }
            4 => {
                envelope.extensions.get_mut(INPUT_COMMIT_FEATURE).unwrap()["unexpected"] =
                    json!(true);
            }
            _ => {
                envelope.body["extensions"] = json!({"foreign/1": {}});
            }
        }
        assert!(
            ClosedSchemas.verify(&selected, &envelope, &body).is_err(),
            "hostile extension change {change}"
        );
    }
}

#[test]
fn ordinary_closed_schema_rejects_commit_extensions_on_another_method() {
    let authority = authority(true);
    let (mut envelope, _) = original();
    let discover = DiscoverRequest {
        profile_ids: Vec::new(),
        cursor: None,
        extensions: Extensions::new(),
    };
    envelope.method = Method::Discover;
    envelope.body = serde_json::to_value(&discover)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    let body = ReceivedBody::Request(Box::new(RequestBody::Discover(discover)));
    assert!(ClosedSchemas.verify(&authority, &envelope, &body).is_err());
}
