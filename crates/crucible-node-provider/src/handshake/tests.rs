//! Exercises host authentication, downgrade refusal, and old-stream fencing.

use super::*;

#[path = "selection_tests.rs"]
mod selection_tests;

#[path = "extension_tests.rs"]
mod extension_tests;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}
fn reference() -> ContentRef {
    canonical::content_ref(b"host fixture", "application/json").unwrap()
}
fn limits() -> Limits {
    Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(16),
        journal_entries: U64::new(64),
        blob_chunk_bytes: U64::new(4096),
    }
}
fn manifest() -> ProviderManifest {
    ProviderManifest {
        schema_version: 1,
        provider_id: id("fixture"),
        implementation: ImplementationIdentity {
            schema_version: 1,
            implementation_id: id("fixture/1"),
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
fn hello() -> HelloRequest {
    HelloRequest {
        versions: vec!["CNP/1".to_owned()],
        session_id: id("session"),
        controller_nonce: Bytes::new(vec![3; 32]),
        required_features: vec![id("cnp.core/1")],
        optional_features: vec![id("cnp.resume/1")],
        limits: limits(),
        admission_token: Bytes::new(vec![7; 32]),
        resume_session: None,
        extensions: Extensions::new(),
    }
}
fn result() -> HelloResult {
    HelloResult {
        version: "CNP/1".to_owned(),
        session_id: id("session"),
        incarnation_id: id("incarnation"),
        controller_nonce: Bytes::new(vec![3; 32]),
        provider_nonce: Bytes::new(vec![5; 32]),
        selected_features: vec![id("cnp.core/1"), id("cnp.resume/1")],
        limits: limits(),
        resume_token: Nullable(Some(Bytes::new(vec![9; 32]))),
        provider_identity: manifest(),
        resumed_operations: Vec::new(),
    }
}
fn handshake_with_limits(receiving: Limits) -> Handshake {
    let installation = TrustedInstallation {
        session_id: id("session"),
        incarnation_id: id("incarnation"),
        measured_implementation: manifest().implementation,
        launch_receipt: reference(),
        admission_token: [7; 32],
    };
    let policy = NegotiationPolicy {
        supported_features: vec![id("cnp.core/1"), id("cnp.resume/1")],
        required_features: vec![id("cnp.core/1")],
        provider_limits: receiving,
        required_schemas: Vec::new(),
        required_guarantees: reference(),
        envelope_extension_features: std::collections::BTreeMap::from([(
            "resume-envelope".to_owned(),
            id("cnp.resume/1"),
        )]),
    };
    Handshake::new(installation, policy).unwrap()
}

fn handshake() -> Handshake {
    handshake_with_limits(limits())
}

#[derive(Default)]
struct Verifier {
    deny_auth: bool,
    deny_contract: bool,
    deny_custody: bool,
    deny_fence: bool,
    authenticated: usize,
    contracts: usize,
    fenced: Vec<Id>,
    retained: Vec<ResumedOperation>,
}

impl TrustedHandshakeVerifier for Verifier {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        _: &TrustedInstallation,
        _: &HelloRequest,
        _: &HelloResult,
    ) -> Result<(), ProviderError> {
        self.authenticated += 1;
        if self.deny_auth {
            Err(ProviderError::Correlation("fixture denied actual peer"))
        } else {
            Ok(())
        }
    }
    fn verify_contract_selection(
        &mut self,
        _: &ProviderManifest,
        _: &IdSet,
        _: &[SchemaRef],
        _: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.contracts += 1;
        if self.deny_contract {
            Err(ProviderError::Correlation(
                "fixture denied qualified contract",
            ))
        } else {
            Ok(())
        }
    }
    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        if self.deny_custody {
            Err(ProviderError::Correlation("fixture native custody unknown"))
        } else {
            Ok(self.retained.clone())
        }
    }
    fn fence_connection(&mut self, connection: &Id) -> Result<(), ProviderError> {
        if self.deny_fence {
            Err(ProviderError::Correlation("fixture fencing failed"))
        } else {
            self.fenced.push(connection.clone());
            Ok(())
        }
    }
}

fn resumed(request: &HelloRequest, response: &HelloResult) -> (HelloRequest, HelloResult) {
    let mut request = request.clone();
    let mut response = response.clone();
    request.resume_session = Some(ResumeSession {
        session_id: id("session"),
        incarnation_id: id("incarnation"),
        resume_token: Bytes::new(vec![9; 32]),
        unresolved_operation_ids: Vec::new(),
    });
    response.resume_token = Nullable(Some(Bytes::new(vec![11; 32])));
    (request, response)
}

pub(crate) fn authority() -> (Handshake, ConnectionAuthority) {
    let mut request = hello();
    let mut result = result();
    let negotiated = Limits {
        frame_bytes: U64::new(4096),
        nesting: U64::new(64),
        requests: U64::new(2),
        journal_entries: U64::new(64),
        blob_chunk_bytes: U64::new(512),
    };
    let mut handshake = handshake_with_limits(negotiated);
    request.limits = negotiated;
    result.limits = negotiated;
    let authority = handshake
        .admit_exchange(
            &request,
            &result,
            id("connection"),
            &mut Verifier::default(),
        )
        .unwrap();
    (handshake, authority)
}

#[test]
fn valid_hello_requires_actual_peer_and_contract_verification() {
    let mut handshake = handshake();
    let mut verifier = Verifier::default();
    let authority = handshake
        .admit_exchange(&hello(), &result(), id("connection/1"), &mut verifier)
        .unwrap();
    assert_eq!(verifier.authenticated, 1);
    assert_eq!(verifier.contracts, 1);
    assert_eq!(authority.session_id(), &id("session"));
    assert_eq!(
        authority.envelope_extensions(),
        &BTreeSet::from(["resume-envelope".to_owned()])
    );
    authority.with_live(|| Ok(())).unwrap();
    assert!(
        handshake
            .admit_exchange(&hello(), &result(), id("connection/2"), &mut verifier)
            .is_err()
    );
}

#[test]
fn peer_or_qualification_refusal_cannot_issue_connection_authority() {
    for contract in [false, true] {
        let mut handshake = handshake();
        let mut verifier = Verifier {
            deny_auth: !contract,
            deny_contract: contract,
            ..Verifier::default()
        };
        assert!(
            handshake
                .admit_exchange(&hello(), &result(), id("connection"), &mut verifier)
                .is_err()
        );
    }
}

#[test]
fn launch_token_nonce_and_installed_measurement_are_bound() {
    let mut request = hello();
    request.admission_token = Bytes::new(vec![8; 32]);
    assert!(
        handshake()
            .admit_exchange(
                &request,
                &result(),
                id("connection"),
                &mut Verifier::default()
            )
            .is_err()
    );
    let mut response = result();
    response.controller_nonce = Bytes::new(vec![4; 32]);
    assert!(
        handshake()
            .admit_exchange(
                &hello(),
                &response,
                id("connection"),
                &mut Verifier::default()
            )
            .is_err()
    );
    response = result();
    response.provider_identity.implementation.implementation_id = id("foreign/1");
    assert!(
        handshake()
            .admit_exchange(
                &hello(),
                &response,
                id("connection"),
                &mut Verifier::default()
            )
            .is_err()
    );
}

#[test]
fn hello_refuses_downgrade_and_changed_limit_intersection() {
    let mut response = result();
    response.selected_features = vec![id("cnp.resume/1")];
    assert!(
        handshake()
            .admit_exchange(
                &hello(),
                &response,
                id("connection"),
                &mut Verifier::default()
            )
            .is_err()
    );
    response = result();
    response.limits.requests = U64::new(8);
    assert!(
        handshake()
            .admit_exchange(
                &hello(),
                &response,
                id("connection"),
                &mut Verifier::default()
            )
            .is_err()
    );
    let mut request = hello();
    request.required_features.push(id("vendor.required/1"));
    assert!(
        handshake()
            .admit_exchange(
                &request,
                &result(),
                id("connection"),
                &mut Verifier::default()
            )
            .is_err()
    );
}

#[test]
fn successful_resume_rotates_secret_and_revokes_every_old_worker_lease() {
    let mut handshake = handshake();
    let mut verifier = Verifier::default();
    let request = hello();
    let response = result();
    let old = handshake
        .admit_exchange(&request, &response, id("connection/1"), &mut verifier)
        .unwrap();
    let worker = old.clone();
    let (request, response) = resumed(&request, &response);
    let new = handshake
        .admit_exchange(&request, &response, id("connection/2"), &mut verifier)
        .unwrap();
    assert_eq!(verifier.fenced, vec![id("connection/1")]);
    assert!(old.ensure_live().is_err());
    assert!(worker.with_live(|| Ok(())).is_err());
    new.with_live(|| Ok(())).unwrap();
    assert!(
        handshake
            .admit_exchange(&request, &response, id("connection/3"), &mut verifier)
            .is_err()
    );
}

#[test]
fn fencing_failure_and_uncertain_native_custody_revoke_all_leases() {
    for custody in [false, true] {
        let mut handshake = handshake();
        let mut verifier = Verifier::default();
        let request = hello();
        let response = result();
        let old = handshake
            .admit_exchange(&request, &response, id("connection/1"), &mut verifier)
            .unwrap();
        verifier.deny_fence = !custody;
        verifier.deny_custody = custody;
        let (request, response) = resumed(&request, &response);
        assert!(
            handshake
                .admit_exchange(&request, &response, id("connection/2"), &mut verifier)
                .is_err()
        );
        assert!(old.ensure_live().is_err());
        verifier.deny_fence = false;
        verifier.deny_custody = false;
        assert!(
            handshake
                .admit_exchange(&request, &response, id("connection/3"), &mut verifier)
                .is_err()
        );
    }
}

#[test]
fn resume_requires_exact_original_operation_inventory_and_outcome() {
    let mut handshake = handshake();
    let mut verifier = Verifier::default();
    let request = hello();
    let response = result();
    handshake
        .admit_exchange(&request, &response, id("connection/1"), &mut verifier)
        .unwrap();
    let (mut request, mut response) = resumed(&request, &response);
    request
        .resume_session
        .as_mut()
        .unwrap()
        .unresolved_operation_ids = vec![id("operation")];
    assert!(
        handshake
            .admit_exchange(&request, &response, id("connection/2"), &mut verifier)
            .is_err()
    );
    response.resumed_operations = vec![ResumedOperation {
        operation_id: id("operation"),
        operation_state: OperationState::Running,
        outcome: Nullable(None),
    }];
    verifier.retained = response.resumed_operations.clone();
    assert!(
        handshake
            .admit_exchange(&request, &response, id("connection/2"), &mut verifier)
            .is_ok()
    );
}

#[test]
fn secret_wire_fields_are_required_bounded_and_redacted_from_debug() {
    let request = hello();
    let response = result();
    let request_debug = format!("{request:?}");
    let response_debug = format!("{response:?}");
    assert!(!request_debug.contains("7, 7"));
    assert!(!response_debug.contains("9, 9"));
    let mut encoded = serde_json::to_value(&response).unwrap();
    encoded.as_object_mut().unwrap().remove("resume_token");
    assert!(serde_json::from_value::<HelloResult>(encoded).is_err());
    let mut short = request.clone();
    short.controller_nonce = Bytes::new(vec![3; 31]);
    assert!(short.validate().is_err());
    let mut limits = limits();
    limits.requests = U64::new(0);
    assert!(limits.validate().is_err());
}

#[test]
fn supervisor_retirement_revokes_still_owned_connection_handles() {
    let authority = {
        let mut handshake = handshake();
        handshake
            .admit_exchange(
                &hello(),
                &result(),
                id("connection"),
                &mut Verifier::default(),
            )
            .unwrap()
    };
    assert!(authority.ensure_live().is_err());
}

#[test]
fn poisoned_registration_callback_revokes_opaque_control_lease() {
    let (_handshake, authority) = authority();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), ProviderError> =
            authority.with_live(|| panic!("fixture registration failed"));
    }));
    assert!(panic.is_err());
    assert!(authority.ensure_live().is_err());
    assert!(authority.with_live(|| Ok(())).is_err());
}

fn envelopes(
    request: &HelloRequest,
    result: &HelloResult,
    request_id: &str,
) -> (crate::envelope::Envelope, crate::envelope::Envelope) {
    use serde_json::json;
    let resumed = request.resume_session.is_some();
    let request=crate::envelope::Envelope::decode(&serde_json::to_vec(&json!({
        "protocol":"CNP/1","message":"request","session_id":if resumed {Some(id("session"))} else {None},"incarnation_id":if resumed {Some(id("incarnation"))} else {None},
        "node_id":null,"execution_owner_id":null,"capture_owner_id":null,"request_id":request_id,"operation_id":null,"sequence":"1","method":"hello","body":request,"extensions":{}
    })).unwrap(),65536).unwrap();
    let response=crate::envelope::Envelope::decode(&serde_json::to_vec(&json!({
        "protocol":"CNP/1","message":"response","session_id":if resumed {Some(id("session"))} else {None},"incarnation_id":"incarnation",
        "node_id":null,"execution_owner_id":null,"capture_owner_id":null,"request_id":request_id,"operation_id":null,"sequence":"1","method":"hello",
        "body":{"status":"completed","operation_state":"completed","result":result,"extensions":{}},"extensions":{}
    })).unwrap(),65536).unwrap();
    (request, response)
}

#[test]
fn initial_and_resumed_hello_frames_bind_correlation_and_fence_old_scope() {
    let mut handshake = handshake();
    let mut verifier = Verifier::default();
    let (request, response) = envelopes(&hello(), &result(), "hello/1");
    let old = handshake
        .admit_envelopes(&request, &response, id("connection/1"), &mut verifier)
        .unwrap();
    assert!(matches!(
        handshake.admit_envelopes(&request, &response, id("connection/2"), &mut verifier),
        Err(ProviderError::Conflict(_))
    ));
    let (hello, result) = resumed(&hello(), &result());
    let (request, mut response) = envelopes(&hello, &result, "hello/2");
    response.request_id = Nullable(Some(id("foreign")));
    assert!(
        handshake
            .admit_envelopes(&request, &response, id("connection/2"), &mut verifier)
            .is_err()
    );
    assert!(old.ensure_live().is_ok());
    response.request_id = request.request_id.clone();
    let new = handshake
        .admit_envelopes(&request, &response, id("connection/2"), &mut verifier)
        .unwrap();
    assert!(old.ensure_live().is_err());
    new.ensure_live().unwrap();
}
