//! Installs the fixed source-local Hello comparison and complete incident mailbox.

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use crucible_node_format::*;
use crucible_node_transport::{
    ProviderError,
    connection::{BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody},
    envelope::{Envelope, MessageKind, Method, Nullable},
    handshake::*,
    reference_packet::control::PacketControlSelection,
};

use super::{configuration::encoded, id};

pub(super) struct Verifier {
    provider: ProviderManifest,
    guarantees: ContentRef,
}

impl TrustedHandshakeVerifier for Verifier {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installation.measured_implementation != self.provider.implementation
            || result.provider_identity != self.provider
            || request.session_id != installation.session_id
            || result.session_id != installation.session_id
            || result.incarnation_id != installation.incarnation_id
            || !result.resumed_operations.is_empty()
        {
            return Err(ProviderError::Correlation(
                "fixed original packet peer Hello",
            ));
        }
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        provider: &ProviderManifest,
        _: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        if provider != &self.provider || !schemas.is_empty() || guarantees != &self.guarantees {
            return Err(ProviderError::Correlation(
                "fixed original packet peer contracts",
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
            return Err(ProviderError::Correlation(
                "packet collection has no restore",
            ));
        }
        Ok(vec![])
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "packet collection has no prior connection",
        ))
    }
}

pub(super) struct Incidents(RefCell<Vec<ConnectionIncident>>);

impl Incidents {
    pub(super) fn new() -> Rc<Self> {
        Rc::new(Self(RefCell::new(Vec::with_capacity(1024))))
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }
}

impl ConnectionSupervisor for Incidents {
    fn quarantine(&self, incident: ConnectionIncident) {
        let mut originals = self.0.borrow_mut();
        assert!(originals.len() < 1024, "fixed original incident credit");
        originals.push(incident);
    }
}

pub(super) struct HelloSchema;

impl BodySchemaVerifier for HelloSchema {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if envelope.method != Method::Hello || !envelope.extensions.is_empty() {
            return Err(ProviderError::Correlation(
                "initial packet Hello schema only",
            ));
        }
        Ok(())
    }
}

pub(super) fn handshake(
    member: usize,
    selection: &PacketControlSelection,
    limits: Limits,
    token: [u8; 32],
) -> (Handshake, Verifier, Envelope) {
    let binding = &selection.realization.bindings[0];
    let features = vec![id("cnp.control-evidence/1"), id("cnp.core/1")];
    let guarantees = binding.compatibility.guarantees_ref.clone();
    let installation = TrustedInstallation {
        session_id: binding.authority.session_id.clone(),
        incarnation_id: binding.authority.incarnation_id.clone(),
        measured_implementation: selection.provider.implementation.clone(),
        launch_receipt: selection.admission_receipt.clone(),
        admission_token: token,
    };
    let handshake = Handshake::new(
        installation,
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features.clone(),
            provider_limits: limits,
            required_schemas: vec![],
            required_guarantees: guarantees.clone(),
            envelope_extension_features: BTreeMap::new(),
        },
    )
    .unwrap();
    let body = HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: binding.authority.session_id.clone(),
        controller_nonce: Bytes::new(vec![3 + member as u8; 32]),
        required_features: features,
        optional_features: vec![],
        limits,
        admission_token: Bytes::new(token.to_vec()),
        resume_session: None,
        extensions: Extensions::new(),
    };
    let hello = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(None),
        incarnation_id: Nullable(None),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(id(&format!("packet-world-hello-{member}")))),
        sequence: U64::new(1),
        method: Method::Hello,
        body: canonical::parse_json(&encoded(&body), 65536)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
        extensions: Extensions::new(),
    };
    (
        handshake,
        Verifier {
            provider: selection.provider.clone(),
            guarantees,
        },
        hello,
    )
}
