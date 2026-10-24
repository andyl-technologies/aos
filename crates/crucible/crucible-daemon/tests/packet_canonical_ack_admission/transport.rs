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

use super::{encoded, id};

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

pub(super) struct Incidents {
    incidents: RefCell<Vec<ConnectionIncident>>,
    state: crucible_node_transport::connection::OriginalSupervisorState,
    pending: RefCell<Option<ConnectionIncident>>,
}

impl Incidents {
    pub(super) fn new() -> Rc<Self> {
        Rc::new(Self {
            incidents: RefCell::new(Vec::with_capacity(1024)),
            state: crucible_node_transport::connection::OriginalSupervisorState::new(),
            pending: RefCell::new(None),
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.borrow().is_none() && self.incidents.borrow().is_empty()
    }
}

impl ConnectionSupervisor for Incidents {
    fn quarantine(&self, incident: ConnectionIncident) {
        // Each fixture member owns its own actual Connection supervisor. Retain
        // its incoming incident before the fallible phase or incident-bank gate.
        let mut pending = self.pending.borrow_mut();
        assert!(pending.is_none(), "original incident callback cannot renew");
        *pending = Some(incident);
        let _callback = self.state.begin_quarantine_callback().unwrap();
        let mut originals = self.incidents.borrow_mut();
        assert!(originals.len() < 1024, "fixed original incident credit");
        originals.push(pending.take().unwrap());
    }

    fn with_original_protocol_state(
        &self,
        inspect: &mut dyn FnMut(
            crucible_node_transport::connection::OriginalSupervisorProtocolView<'_>,
        ) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let pending = self
            .pending
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original incident callback borrowed"))?;
        if pending.is_some() {
            return Err(ProviderError::Conflict(
                "original incident callback incomplete",
            ));
        }
        drop(pending);
        self.state
            .with_original_incidents(&self.incidents, &mut |view| {
                let result = inspect(view);
                // A callback attempted during inspection must first retain its
                // incoming incident. Even a visitor that catches that refusal
                // cannot turn the partial callback into complete coverage.
                if self
                    .pending
                    .try_borrow()
                    .map_err(|_| ProviderError::Conflict("original incident callback borrowed"))?
                    .is_some()
                {
                    return Err(ProviderError::Conflict(
                        "original incident callback incomplete",
                    ));
                }
                result
            })
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
        if envelope.method != Method::Hello
            || envelope.extensions.len() != 1
            || !envelope.extensions.contains_key(EXTENSION_NEGOTIATION_V1)
        {
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
    let mut features = vec![
        id("cnp.control-evidence/1"),
        id("cnp.core/1"),
        id("source-owned.packet-input/4"),
        id("packet-complete-original-lineage/5"),
        id(EXTENSION_NEGOTIATION_V1),
        id(crucible_node_transport::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE),
        id(crucible_node_transport::reference_packet::service::ack_emitter::PACKET_NATIVE_CANONICAL_ACK_FEATURE),
        id(crucible_node_transport::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE),
    ];
    features.sort();
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
            envelope_extension_features: BTreeMap::from([
                (EXTENSION_NEGOTIATION_V1.into(), id(EXTENSION_NEGOTIATION_V1)),
                (crucible_node_transport::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.into(), id(crucible_node_transport::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE)),
                (crucible_node_transport::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.into(), id(crucible_node_transport::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE)),
                (
                "source-owned.packet-input/4".into(),
                id("source-owned.packet-input/4"),
            )]),
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
        extensions: BTreeMap::from([(
            EXTENSION_NEGOTIATION_V1.into(),
            serde_json::to_value(ExtensionOfferV1 {
                format: U64::new(1),
                required: Vec::new(),
                optional: Vec::new(),
            })
            .unwrap(),
        )]),
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

#[test]
fn actual_supervisor_loan_borrows_same_incident_bank_and_rejects_callback_reentry() {
    let supervisor = Incidents::new();
    let capacity = supervisor.incidents.borrow().capacity();
    let mut calls = 0;
    supervisor
        .with_original_protocol_state(&mut |view| {
            calls += 1;
            assert!(supervisor.incidents.try_borrow_mut().is_err());
            assert!(supervisor.state.begin_quarantine_callback().is_err());
            let value = serde_json::to_value(view).unwrap();
            assert_eq!(value[5][0], capacity);
            assert_eq!(value[5][1], serde_json::json!([]));
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert!(supervisor.is_empty());
}

#[test]
fn actual_supervisor_failed_callback_keeps_incident_and_refuses_complete_loan() {
    let supervisor = Incidents::new();
    let incident = ConnectionIncident {
        session: id("actual-supervisor-session"),
        incarnation: id("actual-supervisor-incarnation"),
        connection: id("actual-supervisor-connection"),
        failure: crucible_node_transport::connection::ConnectionFailure::Protocol,
        transport_fenced: true,
        outgoing: Vec::new(),
        incoming: Vec::new(),
    };
    *supervisor.pending.borrow_mut() = Some(incident);
    let mut calls = 0;
    assert!(
        supervisor
            .with_original_protocol_state(&mut |_| {
                calls += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(calls, 0);
    assert!(
        supervisor
            .pending
            .borrow()
            .as_ref()
            .unwrap()
            .transport_fenced
    );
    assert!(!supervisor.is_empty());
}

#[test]
fn actual_supervisor_inspection_failure_retains_reentrant_incident() {
    let supervisor = Incidents::new();
    let result = supervisor.with_original_protocol_state(&mut |_| {
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            supervisor.quarantine(ConnectionIncident {
                session: id("actual-supervisor-session"),
                incarnation: id("actual-supervisor-incarnation"),
                connection: id("actual-supervisor-connection"),
                failure: crucible_node_transport::connection::ConnectionFailure::Protocol,
                transport_fenced: true,
                outgoing: Vec::new(),
                incoming: Vec::new(),
            });
        }));
        assert!(refused.is_err());
        Ok(())
    });
    assert!(result.is_err());
    assert!(
        supervisor
            .pending
            .borrow()
            .as_ref()
            .unwrap()
            .transport_fenced
    );
    assert!(supervisor.incidents.borrow().is_empty());
    assert!(
        supervisor
            .with_original_protocol_state(&mut |_| Ok(()))
            .is_err()
    );
}
