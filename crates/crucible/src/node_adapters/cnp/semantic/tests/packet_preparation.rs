//! Actual generic realization, original native gate and mandatory policy ordering.
//!
//! The fixture acceptance callback tests a mandatory trust seam. It is not a
//! complete RFC behavioral report and cannot qualify a vendor class or Ready.

#![cfg(test)]

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::{
        fs::DirBuilderExt,
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    process::{Command, Stdio},
    rc::Rc,
    time::Duration,
};

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    bodies::*,
    client::*,
    connection::*,
    envelope::*,
    handshake::*,
    transport::{FrameReader, write_frame},
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::super::*;
use super::packet_definition::Definition;
use crate::{node_contract::*, node_scheduling::*};

#[path = "packet_collection_guard.rs"]
mod collection_guard;
#[path = "packet_native.rs"]
mod native;
#[path = "packet_oracle.rs"]
mod oracle;

use super::packet_protocol::*;
use oracle::*;

#[derive(Default)]
struct Supervisor;

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, _: ConnectionIncident) {}
}

struct Schemas;

impl BodySchemaVerifier for Schemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if envelope.extensions.is_empty() {
            Ok(())
        } else {
            Err(ProviderError::Frame("packet source has no extensions"))
        }
    }
}

struct Slot(Rc<RefCell<Vec<CnpSemanticProcessCustody>>>);

impl CnpSemanticProcessSlot for Slot {
    fn identity(&self) -> U64 {
        U64::new(1)
    }

    fn retain(&mut self, custody: CnpSemanticProcessCustody) {
        let mut retained = self.0.borrow_mut();
        assert!(retained.is_empty());
        assert_eq!(retained.capacity(), 1);
        retained.push(custody);
    }
}

struct Fixture {
    definition: Rc<Definition>,
    retained: Rc<RefCell<Vec<CnpSemanticProcessCustody>>>,
    directory: std::path::PathBuf,
    registry: CnpSemanticRegistry,
    source: Rc<PacketSource>,
    acceptance: Rc<Acceptance>,
    policy: Rc<Registration>,
}

impl Fixture {
    fn new(accept: bool, native_gate: bool) -> Self {
        let executable = std::env::current_exe().unwrap();
        let definition = Rc::new(Definition::new(
            crucible_node_provider::conformance::measure_executable(&executable).unwrap(),
        ));
        let mut entropy = [0; 16];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut entropy)
            .unwrap();
        let directory = std::path::PathBuf::from(format!(
            "/tmp/cnp-common-{}",
            canonical::hash("cnp.common-native-test.v1", &entropy)
                .unwrap()
                .digest
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let policy = Rc::new(Registration {
            original: registry::installation_identity(&definition.installation).unwrap(),
            current: Cell::new(true),
        });
        let source = Rc::new(PacketSource {
            definition: definition.clone(),
            native_gate: Cell::new(native_gate),
            gate_checks: Cell::new(0),
        });
        let acceptance = Rc::new(Acceptance {
            allow: accept,
            calls: Cell::new(0),
            source: source.clone(),
        });
        Self {
            definition,
            directory,
            registry: CnpSemanticRegistry::new(policy.clone(), 1).unwrap(),
            retained: Rc::new(RefCell::new(Vec::with_capacity(1))),
            source,
            acceptance,
            policy,
        }
    }

    fn prepare(&mut self) -> Result<CnpSemanticPreparation, CnpSemanticPreparationFailure> {
        let installed = self
            .registry
            .install(self.source.clone(), self.acceptance.clone())
            .unwrap();
        CnpSemanticPreparation::prepare(self.launch_guard(), installed)
    }

    fn launch_guard(&self) -> CnpSemanticLaunchGuard {
        let bootstrap = Bootstrap::new(&self.definition);
        let socket = self.directory.join("native.sock");
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "node_adapters::cnp::semantic::tests::packet_preparation::packet_original_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CRUCIBLE_COMMON_PACKET_SOCKET", &socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut guard = CnpSemanticLaunchGuard::new(
            child,
            self.directory.clone(),
            bootstrap.executable.clone(),
            Box::new(Slot(self.retained.clone())),
        )
        .ok()
        .unwrap();
        let child = guard.custody.as_mut().unwrap().child.as_mut().unwrap();
        let mut input = child.stdin.take().unwrap();
        write_frame(
            &mut input,
            &serde_json::to_value(&bootstrap).unwrap(),
            FRAME,
        )
        .unwrap();
        drop(input);
        let stream = connect_original_peer(child, &socket);
        let mut handshake = bootstrap.handshake();
        let session = ClientSession::negotiate(
            stream,
            &ClientPeer {
                pid,
                uid: rustix::process::geteuid().as_raw(),
                executable: bootstrap.executable.clone(),
            },
            &bootstrap.hello(),
            id("packet-connection"),
            &mut handshake,
            &mut Verifier(&bootstrap),
            Rc::new(Supervisor),
            Rc::new(Schemas),
            Duration::from_secs(3),
            FRAME,
            64,
        )
        .unwrap();
        let mut content = ClientContent::new(256 * 1024 * 1024, 256, 4096).unwrap();
        for (reference, bytes) in &self.definition.content {
            content.install(reference.clone(), bytes.clone()).unwrap();
        }
        let manifest = bytes(&self.definition.installation.provider);
        content.install(reference(&manifest), manifest).unwrap();
        content
            .install(
                bootstrap.executable,
                std::fs::read(std::env::current_exe().unwrap()).unwrap(),
            )
            .unwrap();
        let controller = CnpController::new(
            session,
            ClientCustody::new(256, content).unwrap(),
            ControllerRoute {
                node: id("packet"),
                execution_owner: id("packet-owner"),
            },
            Duration::from_secs(3),
        )
        .unwrap();
        guard.attach(controller, handshake).ok().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let mut retained = self.retained.borrow_mut();
        super::operational_poll::original_poll(|| {
            let mut complete = true;
            for original in retained.iter_mut() {
                complete &= original.poll_reclamation().unwrap();
            }
            complete.then_some(())
        });
        for original in retained.iter() {
            assert!(original.kernel_resources_reclaimed().unwrap());
        }
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn actual_packet_realization_rechecks_current_source_without_claiming_readiness() {
    let mut fixture = Fixture::new(true, true);
    let preparation = fixture.prepare().unwrap_or_else(|failure| {
        panic!(
            "actual original packet preparation refused: {:?}",
            failure.error
        )
    });

    assert_eq!(preparation.descriptor().ports[0].id, id("wire_tx"));
    assert_eq!(
        preparation.realization.prepared_token,
        id("packet-original-prepared-token")
    );
    assert_eq!(fixture.acceptance.calls.get(), 1);
    assert_eq!(fixture.source.gate_checks.get(), 1);
    assert!(
        preparation
            .guard
            .custody()
            .unwrap()
            .controller()
            .unwrap()
            .original(&id("cnp-admit-packet-realization"))
            .is_none()
    );

    fixture.policy.current.set(false);
    assert!(preparation.reauthenticate().is_err());
    assert_eq!(
        fixture.acceptance.calls.get(),
        1,
        "stale registration refuses before acceptance callback"
    );
    drop(preparation);
    assert_eq!(fixture.retained.borrow().len(), 1);
}

#[test]
fn actual_missing_current_acceptance_keeps_realization_and_never_admits() {
    let mut fixture = Fixture::new(false, true);
    let failed = fixture.prepare().err().unwrap();

    assert_eq!(fixture.source.gate_checks.get(), 1);
    assert_eq!(fixture.acceptance.calls.get(), 1);
    let controller = failed.guard.custody().unwrap().controller().unwrap();
    assert!(
        controller
            .original(&id("cnp-realize-packet-realization"))
            .is_some()
    );
    assert!(
        controller
            .original(&id("cnp-admit-packet-realization"))
            .is_none()
    );
    assert!(failed.error.reason.contains("not a vendor class"));

    drop(failed);
    assert_eq!(fixture.retained.borrow().len(), 1);
}

#[test]
fn actual_native_gate_refusal_precedes_acceptance_and_preserves_raw_original() {
    let mut fixture = Fixture::new(true, false);
    let failed = fixture.prepare().err().unwrap();

    assert_eq!(fixture.acceptance.calls.get(), 0);
    assert!(
        failed
            .guard
            .custody()
            .unwrap()
            .controller()
            .unwrap()
            .original(&id("cnp-realize-packet-realization"))
            .is_some()
    );
    assert_eq!(failed.error.effects, EffectKnowledge::Unknown);

    drop(failed);
    assert_eq!(fixture.retained.borrow().len(), 1);
}

#[test]
#[ignore = "actual packet process helper; not a qualified public Ready or vendor class"]
fn packet_original_process() {
    let socket =
        std::path::PathBuf::from(std::env::var_os("CRUCIBLE_COMMON_PACKET_SOCKET").unwrap());
    let mut reader = FrameReader::new(std::io::stdin(), FRAME).unwrap();
    let bootstrap: Bootstrap = serde_json::from_value(reader.read().unwrap().unwrap()).unwrap();
    native::serve(&socket, bootstrap);
}
