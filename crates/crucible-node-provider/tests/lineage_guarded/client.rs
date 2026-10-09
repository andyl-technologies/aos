//! Actual negotiated source evidence custody; this fixture grants no source class.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::Duration;

use crucible_node_contract::*;
use crucible_node_provider::{ProviderError, client::*, connection::*, envelope::*, handshake::*};
use serde_json::{Map, Value};

use super::fixture::{NativeService, id};

struct Installed<'a>(&'a NativeService);

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

pub(super) fn connect(service: &NativeService) -> (Handshake, ReferenceController) {
    let bootstrap = &service.bootstrap;
    let binding = service.profile.bind(bootstrap.authority.clone()).unwrap().0;
    let features = vec![id("cnp.control-evidence/1"), id("cnp.core/1")];
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
            required_guarantees: binding.compatibility.guarantees_ref,
            envelope_extension_features: BTreeMap::new(),
        },
    )
    .unwrap();
    let hello = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(None),
        incarnation_id: Nullable(None),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(id("lineage-evidence-hello"))),
        operation_id: Nullable(None),
        sequence: 1.into(),
        method: Method::Hello,
        body: object(HelloRequest {
            versions: vec!["CNP/1".into()],
            session_id: bootstrap.authority.session_id.clone(),
            controller_nonce: Bytes::new(vec![9; 32]),
            required_features: features,
            optional_features: Vec::new(),
            limits: bootstrap.limits,
            admission_token: bootstrap.admission_token.clone(),
            resume_session: None,
            extensions: Extensions::new(),
        }),
        extensions: Extensions::new(),
    };
    let session = ClientSession::negotiate(
        UnixStream::connect(service.socket()).unwrap(),
        &ClientPeer {
            pid: service.pid,
            uid: rustix::process::geteuid().as_raw(),
            executable: crucible_node_provider::conformance::measure_executable(&service.provider)
                .unwrap(),
        },
        &hello,
        id("lineage-evidence-connection"),
        &mut handshake,
        &mut Installed(service),
        Rc::new(Supervisor::default()),
        Rc::new(Schemas),
        Duration::from_secs(3),
        1_048_576,
        64,
    )
    .unwrap();
    let custody = ClientCustody::new(
        1024,
        ClientContent::new(16 * 1024 * 1024, 1024, 16_384).unwrap(),
    )
    .unwrap();
    let controller = ReferenceController::new(
        service.profile.clone(),
        bootstrap.clone(),
        session,
        custody,
        Duration::from_secs(3),
    )
    .unwrap();
    (handshake, controller)
}

fn object(value: impl serde::Serialize) -> Map<String, Value> {
    serde_json::to_value(value)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}
