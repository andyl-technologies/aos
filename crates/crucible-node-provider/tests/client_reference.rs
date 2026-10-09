//! Actual authenticated controller transport and complete dynamic control evidence.
//!
//! The checks use source-built service and device processes. Hash-verified bytes
//! remain provider claims; the independently measured fixture authenticates the
//! installed process and checks native child ancestry and original receipt scope.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- actual-process assertions deliberately panic on invalid fixture evidence.
// crucible-lint: allow panic-shortcut -- These client reference tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError, bodies::*, client::*, connection::*, envelope::*, handshake::*,
};
use serde_json::{Map, Value, json};

#[path = "conformance_reference/fixture.rs"]
// crucible-lint: allow rust-allow -- shared process fixture also provides CLI-only helpers.
#[allow(dead_code)]
mod fixture;

#[path = "client_reference/observation.rs"]
mod observation;

struct Installed<'a>(&'a fixture::NativeService);

impl TrustedHandshakeVerifier for Installed<'_> {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        _: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installation.measured_implementation != self.0.profile.implementation
            || installation.launch_receipt != self.0.bootstrap.admission_receipt
            || result.provider_identity != self.0.profile.provider_manifest
        {
            return Err(ProviderError::Correlation("foreign private installation"));
        }
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        _: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        let (binding, _) = self.0.profile.bind(self.0.bootstrap.authority.clone())?;
        if manifest != &self.0.profile.provider_manifest
            || guarantees != &binding.compatibility.guarantees_ref
        {
            return Err(ProviderError::Correlation("foreign selected contract"));
        }
        self.0.profile.content(guarantees)?;
        for schema in schemas {
            self.0.profile.content(&schema.definition)?;
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
            return Err(ProviderError::Correlation(
                "no original operation in fixture",
            ));
        }
        Ok(Vec::new())
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "initial fixture has no previous stream",
        ))
    }
}

#[derive(Default)]
struct Supervisor(RefCell<Vec<ConnectionIncident>>);

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        self.0.borrow_mut().push(incident);
    }
}

struct Schemas;

impl BodySchemaVerifier for Schemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty()
            || envelope
                .body
                .get("extensions")
                .and_then(Value::as_object)
                .is_none_or(|value| !value.is_empty())
        {
            return Err(ProviderError::Frame("fixture extension unavailable"));
        }
        Ok(())
    }
}

fn body(value: impl serde::Serialize) -> Map<String, Value> {
    serde_json::to_value(value)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

fn request(
    service: &fixture::NativeService,
    method: Method,
    request: &str,
    value: Value,
) -> Envelope {
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(service.bootstrap.authority.session_id.clone())),
        incarnation_id: Nullable(Some(service.bootstrap.authority.incarnation_id.clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(fixture::id(request))),
        sequence: 2.into(),
        method,
        body: body(value),
        extensions: Extensions::new(),
    }
}

#[test]
fn real_public_client_receives_native_gate_record_before_admitting_readiness_and_reaps_original_child()
 {
    run_native_client(false);
}

#[test]
fn actual_installed_launch_preserves_qualified_binding_identity_through_native_realize_and_admit() {
    run_native_client(true);
}

fn run_native_client(installed_qualification: bool) {
    let provider = Path::new(env!("CARGO_BIN_EXE_crucible-reference-provider"));
    let device = Path::new(env!("CARGO_BIN_EXE_crucible-reference-device"));
    let evidence =
        b"private host-selected CNP integration fixture; not native fidelity qualification"
            .to_vec();
    let evidence_ref = canonical::content_ref(&evidence, "text/plain").unwrap();
    let qualifications = if installed_qualification {
        vec![evidence_ref.clone()]
    } else {
        Vec::new()
    };
    let service = if installed_qualification {
        fixture::NativeService::launch_installed(
            provider,
            device,
            32,
            true,
            vec![
                crucible_node_provider::reference_service::InstalledContent {
                    reference: evidence_ref,
                    bytes: Bytes::new(evidence),
                },
            ],
        )
    } else {
        fixture::NativeService::launch_public_linked(provider, device, 32, true)
    };
    let bootstrap = &service.bootstrap;
    let (binding, owner_binding) = service
        .profile
        .bind_qualified(bootstrap.authority.clone(), &qualifications)
        .unwrap();
    let features = vec![
        fixture::id("cnp.control-evidence/1"),
        fixture::id("cnp.core/1"),
    ];
    let mut token = [0; 32];
    token.copy_from_slice(bootstrap.admission_token.as_slice());
    let mut handshake = Handshake::new(
        TrustedInstallation {
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            measured_implementation: service.profile.implementation.clone(),
            launch_receipt: bootstrap.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features.clone(),
            provider_limits: bootstrap.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref.clone(),
            envelope_extension_features: BTreeMap::new(),
        },
    )
    .unwrap();
    let mut hello = request(&service, Method::Hello, "client-original-hello", json!({}));
    hello.session_id = Nullable(None);
    hello.incarnation_id = Nullable(None);
    hello.sequence = 1.into();
    hello.body = body(HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: bootstrap.authority.session_id.clone(),
        controller_nonce: Bytes::new(vec![7; 32]),
        required_features: features,
        optional_features: Vec::new(),
        limits: bootstrap.limits,
        admission_token: bootstrap.admission_token.clone(),
        resume_session: None,
        extensions: Extensions::new(),
    });
    let peer = ClientPeer {
        pid: service.process.id(),
        uid: rustix::process::geteuid().as_raw(),
        executable: crucible_node_provider::conformance::measure_executable(provider).unwrap(),
    };
    let mut session = ClientSession::negotiate(
        UnixStream::connect(service.socket()).unwrap(),
        &peer,
        &hello,
        fixture::id("client-connection/1"),
        &mut handshake,
        &mut Installed(&service),
        Rc::new(Supervisor::default()),
        Rc::new(Schemas),
        Duration::from_secs(3),
        1_048_576,
        64,
    )
    .unwrap();
    let mut custody = ClientCustody::new(
        256,
        ClientContent::new(16 * 1024 * 1024, 256, 16_384).unwrap(),
    )
    .unwrap();
    for content in service.profile.content_objects() {
        custody
            .content_mut()
            .install(content.reference.clone(), content.bytes.clone())
            .unwrap();
    }
    for content in &bootstrap.installed_content {
        custody
            .content_mut()
            .install(content.reference.clone(), content.bytes.as_slice().to_vec())
            .unwrap();
    }

    let realize = request(
        &service,
        Method::Realize,
        "original-realize",
        json!({
            "realization_id":bootstrap.authority.realization_id,"configuration":service.profile.configuration_ref,
            "requested_node_ids":[bootstrap.node_id],"resource_limits":bootstrap.resource_limits,"extensions":{}
        }),
    );
    let response = session
        .exchange(&mut custody, realize.clone(), Duration::from_secs(3))
        .unwrap();
    let decoded = decode_response(
        &decode_request(Method::Realize, &realize.body).unwrap(),
        &response.body,
    )
    .unwrap();
    let Some(MethodResult::Realize(result)) = decoded.result else {
        panic!("real realization refused");
    };
    assert_eq!(result.realization_manifest.bindings, vec![binding.clone()]);
    assert_eq!(
        result.realization_manifest.owner_bindings,
        vec![owner_binding]
    );
    assert_eq!(
        result.realization_manifest.bindings[0]
            .compatibility
            .qualification_refs,
        qualifications
    );
    session
        .receive_content(
            &mut custody,
            std::slice::from_ref(&result.closed_gate_receipt),
            Duration::from_secs(3),
        )
        .unwrap();
    let receipt: ControlReceipt = canonical::decode(
        custody.content().get(&result.closed_gate_receipt).unwrap(),
        1_048_576,
    )
    .unwrap();
    let record: ClosedGateRecord = canonical::decode(
        custody.content().get(&receipt.record_ref).unwrap(),
        1_048_576,
    )
    .unwrap();
    let native = canonical::parse_json(
        custody.content().get(&record.physical_status_ref).unwrap(),
        1_048_576,
    )
    .unwrap();

    assert_eq!(receipt.kind, ControlReceiptKind::ClosedGate);
    assert_eq!(receipt.issuer, ReceiptIssuer::Provider);
    assert_eq!(receipt.request_id, fixture::id("original-realize"));
    assert_eq!(record.gate_id, bootstrap.gate_id);
    assert_eq!(record.owner_ids, vec![bootstrap.owner_id.clone()]);
    assert_eq!(native["application_status"], "parked");
    assert_eq!(native["physical_pause"], "unknown");
    let native_pid: U64 = serde_json::from_value(native["child_pid"].clone()).unwrap();
    let status = std::fs::read_to_string(format!("/proc/{}/status", native_pid.get())).unwrap();
    assert!(
        status
            .lines()
            .any(|line| line == format!("PPid:\t{}", service.process.id()))
    );
    assert_eq!(
        session
            .exchange(&mut custody, realize.clone(), Duration::from_secs(3))
            .unwrap()
            .body,
        response.body
    );
    let mut changed = realize;
    changed
        .body
        .insert("realization_id".into(), json!("replacement"));
    assert!(
        session
            .exchange(&mut custody, changed, Duration::from_secs(3))
            .is_err()
    );

    let mut controller = ReferenceController::new_qualified(
        service.profile.clone(),
        bootstrap.clone(),
        session,
        custody,
        Duration::from_secs(3),
        qualifications,
    )
    .unwrap();
    let admitted = controller
        .call(
            fixture::id("original-qualified-admit"),
            None,
            Method::Admit,
            false,
            AdmitRequest {
                bindings: vec![binding.clone()],
                world_binding_hash: bootstrap.world_binding_hash.clone(),
                admission_receipt: bootstrap.admission_receipt.clone(),
                extensions: Extensions::new(),
            },
        )
        .unwrap();
    let Some(MethodResult::Admit(admitted)) = admitted.result else {
        panic!("original host binding was not admitted");
    };
    assert_eq!(
        admitted.accepted_binding_hashes,
        vec![binding.identity().unwrap()]
    );
    let inert = canonical::content_ref(&[1, 2], "application/octet-stream").unwrap();
    controller.upload(&inert, &[1, 2]).unwrap();
    assert_eq!(controller.content(&inert).unwrap(), &[1, 2]);
    let abort = request(
        &service,
        Method::Abort,
        "original-abort",
        json!({
            "transaction_id":bootstrap.transaction_id,"reason":"test-complete","extensions":{}
        }),
    );
    let response = controller
        .call(
            fixture::id("original-abort"),
            None,
            Method::Abort,
            false,
            abort.body,
        )
        .unwrap();
    let Some(MethodResult::Abort(result)) = response.result else {
        panic!("original native cleanup refused");
    };
    let receipt: ControlReceipt = controller.record(&result.cleanup_receipt).unwrap();
    let cleanup: CleanupRecord = controller.record(&receipt.record_ref).unwrap();
    assert_eq!(receipt.request_id, fixture::id("original-abort"));
    assert_eq!(cleanup.disposition, CleanupDisposition::Retained);
    assert!(!Path::new(&format!("/proc/{}", native_pid.get())).exists());
    controller.fence();
}
