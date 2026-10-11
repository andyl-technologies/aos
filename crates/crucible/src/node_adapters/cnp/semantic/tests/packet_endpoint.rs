//! Actual authenticated owning-endpoint mechanism, without behavioral acceptance.
//!
//! The fixture marker and private collector installation cannot admit a common
//! node or issue a class certificate. Native bytes and effects are independently
//! observed; the complete production acceptance population remains separate.

#![cfg(test)]

use super::*;
use crucible_node_provider::{blob::*, reference_packet::endpoint::*};

struct RetainedSupervisor {
    incidents: std::cell::RefCell<Vec<ConnectionIncident>>,
    blobs: std::cell::RefCell<Vec<BlobQuarantine>>,
}

impl ConnectionSupervisor for RetainedSupervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        self.incidents.borrow_mut().push(incident);
    }
}

impl BlobSupervisor for RetainedSupervisor {
    fn quarantine(&self, ledger: BlobQuarantine) {
        self.blobs.borrow_mut().push(ledger);
    }
}

struct SourcePolicy {
    selection: PacketControlSelection,
    definition: ContentRef,
}

impl PacketEndpointPolicy for SourcePolicy {
    fn authenticate_source(
        &self,
        authority: &ConnectionAuthority,
        selection: &PacketControlSelection,
    ) -> Result<(), ProviderError> {
        let binding = &selection.realization.bindings[0];
        if selection != &self.selection
            || authority.session_id() != &binding.authority.session_id
            || authority.incarnation_id() != &binding.authority.incarnation_id
            || authority.limits().requests.get() != 64
        {
            return Err(ProviderError::Correlation(
                "changed owning packet collection scope",
            ));
        }
        Ok(())
    }

    fn consuming_schema(&self, _: &ContentRef, _: &Envelope) -> Result<ContentRef, ProviderError> {
        Ok(self.definition.clone())
    }
}

impl BlobSchemaVerifier for SourcePolicy {
    fn verify_schema(
        &self,
        schema: &ContentRef,
        content: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        content.verify(bytes)?;
        if schema != &self.definition || content.media_type != "application/json" {
            return Err(ProviderError::Correlation(
                "uninstalled packet collector schema",
            ));
        }
        let value = canonical::parse_json(bytes, FRAME)?;
        match value.get("schema").and_then(Value::as_str) {
            Some("packet.native-lifecycle-test.v1")
                if value
                    == serde_json::json!({
                        "schema":"packet.native-lifecycle-test.v1","world":self.selection.world
                    }) =>
            {
                Ok(())
            }
            Some("source-owned.packet-common-grant.v1") => {
                let _: crucible_node_provider::reference_packet::common::PacketCommonGrant =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                Ok(())
            }
            Some("source-owned.packet-consumption.v1") => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Consumption {
                    schema: String,
                    operation: Id,
                    outputs: Vec<Id>,
                }
                let body: Consumption =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                if body.schema != "source-owned.packet-consumption.v1" || body.outputs.len() > 1 {
                    return Err(ProviderError::Correlation(
                        "packet collector consumption width",
                    ));
                }
                body.operation.validate()?;
                for id in body.outputs {
                    id.validate()?;
                }
                Ok(())
            }
            None => {
                let manifest: ActivationManifest =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                manifest.validate()?;
                Ok(())
            }
            _ => Err(ProviderError::Correlation(
                "packet collector consuming schema absent",
            )),
        }
    }
}

pub(super) fn serve(socket: &std::path::Path, bootstrap: NativeBootstrap) {
    let listener = UnixListener::bind(socket).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let credentials = rustix::net::sockopt::socket_peercred(&stream).unwrap();
    assert_eq!(
        credentials.uid.as_raw(),
        rustix::process::geteuid().as_raw()
    );
    assert_eq!(
        credentials.pid.as_raw_nonzero().get() as u32,
        bootstrap.controller_pid
    );
    let peer_executable =
        std::path::PathBuf::from(format!("/proc/{}/exe", bootstrap.controller_pid));
    assert_eq!(
        crucible_node_provider::conformance::measure_executable(&peer_executable).unwrap(),
        bootstrap.protocol.executable
    );
    assert_eq!(
        crucible_node_provider::conformance::measure_executable(&std::env::current_exe().unwrap())
            .unwrap(),
        bootstrap.protocol.executable
    );
    let mut reader = FrameReader::new(stream.try_clone().unwrap(), FRAME).unwrap();
    let hello: Envelope = serde_json::from_value(reader.read().unwrap().unwrap()).unwrap();
    let RequestBody::Hello(request) = decode_request(hello.method, &hello.body).unwrap() else {
        panic!("initial Hello absent")
    };
    let mut response = hello.clone();
    response.message = MessageKind::Response;
    response.incarnation_id = Nullable(Some(id("packet-incarnation")));
    response.body = object(ResponseShape::Completed {
        operation_state: OperationState::Completed,
        extensions: Extensions::new(),
        result: object(HelloResult {
            version: "CNP/1".into(),
            session_id: id("packet-session"),
            incarnation_id: id("packet-incarnation"),
            controller_nonce: request.controller_nonce,
            provider_nonce: Bytes::new(vec![5; 32]),
            selected_features: bootstrap.protocol.features(),
            limits: bootstrap.protocol.limits(),
            resume_token: Nullable(None),
            provider_identity: bootstrap.protocol.manifest.clone(),
            resumed_operations: vec![],
        }),
    });
    let mut handshake = bootstrap.protocol.handshake();
    let authority = handshake
        .admit_envelopes(
            &hello,
            &response,
            id("owning-packet-source"),
            &mut Verifier(&bootstrap.protocol),
        )
        .unwrap();
    write_frame(&mut stream, &serde_json::to_value(response).unwrap(), FRAME).unwrap();
    let supervisor = Rc::new(RetainedSupervisor {
        incidents: std::cell::RefCell::new(Vec::with_capacity(256)),
        blobs: std::cell::RefCell::new(Vec::with_capacity(256)),
    });
    let connection = Connection::new(
        stream,
        authority,
        supervisor.clone(),
        Rc::new(Schemas),
        EndpointRole::Provider,
    )
    .unwrap();
    let native_socket = UnixDatagram::unbound().unwrap();
    native_socket.connect(&bootstrap.effects).unwrap();
    let program = PacketProgram::new(bootstrap.events, native_socket).unwrap();
    let native = PacketControl::new_immediate(bootstrap.selection.clone(), program).unwrap();
    let policy = Rc::new(SourcePolicy {
        selection: bootstrap.selection,
        definition: reference(b"independent finite packet collector schema; no qualification"),
    });
    let mut endpoint = match PacketEndpoint::new(connection, native, policy, supervisor.clone()) {
        Ok(endpoint) => endpoint,
        Err(_) => panic!("genuine original endpoint installation refused"),
    };
    loop {
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| endpoint.step()));
        if matches!(attempt, Ok(Ok(()))) {
            continue;
        }
        assert!(endpoint.is_held());
        // Keep the complete endpoint/native/transfer/supervisor owner outside
        // unwind until the parent kills and reaps this same original process.
        std::fs::write(
            &bootstrap.retained_native,
            bytes(endpoint.native().inventory()),
        )
        .unwrap();
        loop {
            std::thread::park();
        }
    }
}

#[test]
fn actual_owning_endpoint_prepares_native_burst_and_retains_original_output_once() {
    assert_original_burst(Fixture::launch_owning());
}

#[test]
fn actual_installed_packet_executable_prepares_original_burst_and_output_custody() {
    assert_original_burst(Fixture::launch_installed());
}

fn assert_original_burst(mut fixture: Fixture) {
    fixture.prepare_and_open();
    let limit = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);

    let response = fixture.begin("owning-original", initial_position(), limit);
    assert!(!response.shape.is_accepted());
    let original = fixture.poll("owning-original");
    assert_eq!(original.native_pid.get(), u64::from(fixture.child.id()));
    assert_eq!(original.inventory.private_mutations.get(), 1);
    assert_eq!(original.inventory.packet_effects.get(), 1);
    assert_eq!(
        fixture.effects_now(),
        vec![vec![0], [vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );
    let grant = original.grant.as_ref().unwrap();
    assert_eq!(grant.newborn.len(), 1);
    assert_eq!(grant.newborn[0].sequence.get(), 1);
    assert_eq!(
        grant.newborn[0].publication,
        fixture.bootstrap.events[1].completion
    );
    assert_eq!(grant.newborn[0].payload.as_slice(), b"actual\0packet\xff");
    let repeated = fixture.poll("owning-original");
    assert_eq!(repeated, original);
    assert!(fixture.effects_now().is_empty());
    fixture.retire("owning-original", &[id("packet-native-1")]);
    fixture.retire("owning-original", &[id("packet-native-1")]);
    assert!(fixture.effects_now().is_empty());
}
