//! Actual output-only native CNP source and independent packet effect witness.
//!
//! This cohort exercises original native lifecycle/grant/publication custody.
//! Its records remain mechanism evidence until the complete independently
//! installed normative witness plan accepts all applicable class obligations.

#![cfg(test)]

use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::{
        fs::DirBuilderExt,
        net::{UnixDatagram, UnixListener, UnixStream},
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
    reference_packet::{PacketEvent, PacketProgram, PacketProgramDefinition, control::*},
    transport::{FrameReader, write_frame},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::packet_definition::Definition;

use super::packet_protocol::*;

#[path = "packet_execution_server.rs"]
mod server;

#[derive(Clone, Serialize, Deserialize)]
struct NativeBootstrap {
    protocol: Bootstrap,
    selection: PacketControlSelection,
    events: Vec<PacketEvent>,
    effects: std::path::PathBuf,
    lose_completed_response: bool,
    lose_world_activate_response: bool,
    immediate: bool,
    refuse_reply_preflight: Option<Method>,
    panic_reply_preflight: bool,
    retained_native: std::path::PathBuf,
    #[serde(default)]
    owning_endpoint: bool,
    #[serde(default)]
    controller_pid: u32,
}

struct Fixture {
    child: std::process::Child,
    directory: std::path::PathBuf,
    bootstrap: NativeBootstrap,
    controller: CnpController,
    handshake: Handshake,
    effects: UnixDatagram,
    observed_effects: std::cell::RefCell<Vec<Vec<u8>>>,
}

struct SpawnedFixture {
    child: std::process::Child,
    directory: std::path::PathBuf,
    bootstrap: NativeBootstrap,
    effects: UnixDatagram,
    definition: Definition,
    executable: std::path::PathBuf,
    socket: std::path::PathBuf,
}

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

impl Fixture {
    fn launch() -> Self {
        Self::launch_with_response_loss(false)
    }

    fn launch_with_response_loss(lose_completed_response: bool) -> Self {
        Self::launch_selected(lose_completed_response, false)
    }

    fn launch_immediate() -> Self {
        Self::launch_selected(false, true)
    }

    fn launch_selected(lose_completed_response: bool, immediate: bool) -> Self {
        Self::launch_with_faults(lose_completed_response, false, immediate)
    }

    fn launch_with_faults(
        lose_completed_response: bool,
        lose_world_activate_response: bool,
        immediate: bool,
    ) -> Self {
        Self::launch_configured(
            lose_completed_response,
            lose_world_activate_response,
            immediate,
            None,
            false,
        )
    }

    fn launch_with_preflight_refusal(method: Method) -> Self {
        Self::launch_configured(false, false, true, Some(method), false)
    }

    fn launch_with_preflight_panic(method: Method) -> Self {
        Self::launch_configured(false, false, true, Some(method), true)
    }

    fn launch_configured(
        lose_completed_response: bool,
        lose_world_activate_response: bool,
        immediate: bool,
        refuse_reply_preflight: Option<Method>,
        panic_reply_preflight: bool,
    ) -> Self {
        Self::launch_transport_configured(
            lose_completed_response,
            lose_world_activate_response,
            immediate,
            refuse_reply_preflight,
            panic_reply_preflight,
            false,
            None,
        )
    }

    fn launch_owning() -> Self {
        Self::launch_transport_configured(false, false, true, None, false, true, None)
    }

    fn launch_installed() -> Self {
        let executable = std::env::var_os("CRUCIBLE_INSTALLED_PACKET_SOURCE")
            .map(std::path::PathBuf::from)
            .unwrap();
        Self::launch_transport_configured(false, false, true, None, false, false, Some(executable))
    }

    fn launch_transport_configured(
        lose_completed_response: bool,
        lose_world_activate_response: bool,
        immediate: bool,
        refuse_reply_preflight: Option<Method>,
        panic_reply_preflight: bool,
        owning_endpoint: bool,
        installed: Option<std::path::PathBuf>,
    ) -> Self {
        let SpawnedFixture {
            mut child,
            directory,
            bootstrap,
            effects,
            definition,
            executable,
            socket,
        } = Self::spawn_transport_configured(
            lose_completed_response,
            lose_world_activate_response,
            immediate,
            refuse_reply_preflight,
            panic_reply_preflight,
            owning_endpoint,
            installed,
        );
        let stream = connect_original_peer(&mut child, &socket);
        let mut handshake = bootstrap.protocol.handshake();
        let session = ClientSession::negotiate(
            stream,
            &ClientPeer {
                pid: child.id(),
                uid: rustix::process::geteuid().as_raw(),
                executable: bootstrap.protocol.executable.clone(),
            },
            &bootstrap.protocol.hello(),
            id("packet-source-connection"),
            &mut handshake,
            &mut Verifier(&bootstrap.protocol),
            Rc::new(Supervisor),
            Rc::new(Schemas),
            Duration::from_secs(3),
            FRAME,
            64,
        )
        .unwrap();
        let mut content = ClientContent::new(256 * 1024 * 1024, 256, 4096).unwrap();
        content
            .install(
                bootstrap.protocol.executable.clone(),
                std::fs::read(&executable).unwrap(),
            )
            .unwrap();
        for (root, body) in &definition.content {
            content.install(root.clone(), body.clone()).unwrap();
        }
        let manifest = bytes(&bootstrap.selection.provider);
        content.install(reference(&manifest), manifest).unwrap();
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
        Self {
            child,
            directory,
            bootstrap,
            controller,
            handshake,
            effects,
            observed_effects: std::cell::RefCell::new(Vec::with_capacity(32)),
        }
    }

    fn spawn_transport_configured(
        lose_completed_response: bool,
        lose_world_activate_response: bool,
        immediate: bool,
        refuse_reply_preflight: Option<Method>,
        panic_reply_preflight: bool,
        owning_endpoint: bool,
        installed: Option<std::path::PathBuf>,
    ) -> SpawnedFixture {
        let executable = installed
            .clone()
            .unwrap_or_else(|| std::env::current_exe().unwrap());
        let events = vec![
            PacketEvent {
                id: id("private-native-1"),
                evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                payload: None,
            },
            PacketEvent {
                id: id("packet-native-1"),
                evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                payload: Some(Bytes::new(b"actual\0packet\xff".to_vec())),
            },
        ];
        let program = PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(),
            events: events.clone(),
        };
        let measured =
            crucible_node_provider::conformance::measure_executable(&executable).unwrap();
        let definition = if installed.is_some() {
            Definition::with_installed_model(measured, &program)
        } else if immediate {
            Definition::with_immediate_model(measured, &program)
        } else {
            Definition::with_model(measured, &program)
        };
        let mut entropy = [0; 16];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut entropy)
            .unwrap();
        let directory = std::path::PathBuf::from(format!(
            "/tmp/cnp-source-{}",
            canonical::hash("packet.source-native.v1", &entropy)
                .unwrap()
                .digest
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let effects_path = directory.join("effects.sock");
        let effects = UnixDatagram::bind(&effects_path).unwrap();
        effects.set_nonblocking(true).unwrap();
        let mut protocol = Bootstrap::new(&definition);
        if owning_endpoint || installed.is_some() {
            protocol.source_requests = Some(64);
        }
        if installed.is_some() {
            protocol.source_guarantees = Some(
                definition
                    .installation
                    .binding
                    .compatibility
                    .guarantees_ref
                    .clone(),
            );
        }
        let installation = &definition.installation;
        let bootstrap = NativeBootstrap {
            selection: PacketControlSelection {
                provider: protocol.manifest.clone(),
                realization: protocol.realization.clone(),
                realize: installation.realize.clone(),
                prepared_token: id("packet-original-prepared-token"),
                admission: installation.admission.clone(),
                transaction: installation.transaction.clone(),
                gate: installation.gate.clone(),
                world: installation.world_binding_hash.clone(),
                admission_receipt: installation.admission_receipt.clone(),
            },
            protocol,
            events,
            effects: effects_path,
            lose_completed_response,
            lose_world_activate_response,
            immediate,
            refuse_reply_preflight,
            panic_reply_preflight,
            retained_native: directory.join("retained-native.json"),
            owning_endpoint,
            controller_pid: std::process::id(),
        };
        let socket = directory.join("native.sock");
        let mut command = Command::new(&executable);
        if installed.is_some() {
            command.arg(&socket);
        } else {
            command.args([
                "--ignored", "--exact", "node_adapters::cnp::semantic::tests::packet_execution::native_packet_source_process",
                "--nocapture", "--test-threads=1",
            ]).env("CRUCIBLE_NATIVE_PACKET_SOURCE", &socket);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn()
            .unwrap();
        let launch = if installed.is_some() {
            let coordinator = bytes(
                serde_json::json!({"schema":"packet.native-lifecycle-test.v1","world":bootstrap.selection.world}),
            );
            serde_json::to_value(
                crucible_node_provider::reference_packet::service::PacketSourceLaunch {
                    schema_version: 1,
                    selection: bootstrap.selection.clone(),
                    program: program.clone(),
                    controller_pid: U64::new(u64::from(std::process::id())),
                    controller_uid: U64::new(u64::from(rustix::process::geteuid().as_raw())),
                    controller_executable: crucible_node_provider::conformance::measure_executable(
                        &std::env::current_exe().unwrap(),
                    )
                    .unwrap(),
                    admission_token: Bytes::new(vec![7; 32]),
                    limits: bootstrap.protocol.limits(),
                    initial_coordinator:
                        crucible_node_provider::reference_service::InstalledContent {
                            reference: reference(&coordinator),
                            bytes: Bytes::new(coordinator),
                        },
                    effects: bootstrap.effects.clone(),
                },
            )
            .unwrap()
        } else {
            serde_json::to_value(&bootstrap).unwrap()
        };
        write_frame(child.stdin.as_mut().unwrap(), &launch, 1024 * 1024).unwrap();
        drop(child.stdin.take());
        SpawnedFixture {
            child,
            directory,
            bootstrap,
            effects,
            definition,
            executable,
            socket,
        }
    }

    fn call(
        &mut self,
        request: &str,
        operation: Option<&str>,
        method: Method,
        body: impl Serialize,
    ) -> ResponseBody {
        self.controller
            .call(
                id(request),
                operation.map(id),
                method,
                matches!(
                    method,
                    Method::Begin
                        | Method::Poll
                        | Method::Observe
                        | Method::Retire
                        | Method::Cancel
                ),
                body,
            )
            .unwrap()
    }

    fn prepare_and_open(&mut self) {
        let world = self.prepare_staged();
        let response = self.call("source-world", None, Method::WorldActivate, world);
        assert!(matches!(
            response.result,
            Some(MethodResult::WorldActivate(_))
        ));
        assert!(self.effects_now().is_empty());
    }

    fn prepare_staged(&mut self) -> WorldActivateRequest {
        let selection = self.bootstrap.selection.clone();
        let response = self.call(
            "source-discover",
            None,
            Method::Discover,
            DiscoverRequest {
                profile_ids: vec![selection.provider.supported_profiles[0].profile_id.clone()],
                cursor: None,
                extensions: Extensions::new(),
            },
        );
        assert!(matches!(response.result, Some(MethodResult::Discover(_))));
        let response = self.call("source-realize", None, Method::Realize, &selection.realize);
        let Some(MethodResult::Realize(realized)) = response.result else {
            panic!("source realization absent")
        };
        let record: PacketNativeRecord = serde_json::from_slice(
            self.controller
                .content(&realized.closed_gate_receipt)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(record.native_pid.get(), u64::from(self.child.id()));
        assert!(record.inventory.gate_closed);
        assert_eq!(record.inventory.pending, self.bootstrap.events);
        assert_eq!(record.inventory.packet_effects.get(), 0);
        assert!(self.effects_now().is_empty());
        let response = self.call(
            "source-admit",
            None,
            Method::Admit,
            AdmitRequest {
                bindings: selection.realization.bindings.clone(),
                world_binding_hash: selection.world.clone(),
                admission_receipt: selection.admission_receipt.clone(),
                extensions: Extensions::new(),
            },
        );
        assert!(matches!(response.result, Some(MethodResult::Admit(_))));
        let response = self.call(
            "source-stage",
            None,
            Method::Activate,
            ActivateRequest {
                admission_id: selection.admission,
                activation_id: id("packet-activation"),
                world_generation: U64::new(1),
                prepared_token: selection.prepared_token.clone(),
                world_binding_hash: selection.world.clone(),
                gate_id: selection.gate.clone(),
                extensions: Extensions::new(),
            },
        );
        let Some(MethodResult::Activate(ready)) = response.result else {
            panic!("source readiness absent")
        };
        let record: PacketNativeRecord =
            serde_json::from_slice(self.controller.content(&ready.activation_receipt).unwrap())
                .unwrap();
        assert!(record.inventory.gate_closed);
        assert!(self.effects_now().is_empty());
        let binding = &selection.realization.bindings[0];
        let coordinator = bytes(
            serde_json::json!({"schema":"packet.native-lifecycle-test.v1","world":selection.world}),
        );
        let coordinator_ref = reference(&coordinator);
        self.controller
            .upload(&coordinator_ref, &coordinator)
            .unwrap();
        let manifest = ActivationManifest {
            schema_version: 1,
            transaction_id: selection.transaction.clone(),
            activation_id: id("packet-activation"),
            world_generation: U64::new(1),
            gate_id: selection.gate.clone(),
            world_binding_hash: selection.world.clone(),
            owners: vec![PreparedOwner {
                owner_id: id("packet-owner"),
                incarnation_id: binding.authority.incarnation_id.clone(),
                owner_generation: binding.authority.owner_generation,
                binding_hashes: vec![binding.identity().unwrap()],
                prepared_token: selection.prepared_token.clone(),
                ready_receipt: ready.activation_receipt,
                extensions: Extensions::new(),
            }],
            coordinator_state_ref: coordinator_ref,
            extensions: Extensions::new(),
        };
        let body = bytes(&manifest);
        let root = reference(&body);
        self.controller.upload(&root, &body).unwrap();
        WorldActivateRequest {
            transaction_id: selection.transaction,
            activation_id: manifest.activation_id,
            world_generation: manifest.world_generation,
            prepared_token: selection.prepared_token,
            world_binding_hash: selection.world,
            gate_id: selection.gate,
            activation_manifest: root,
            extensions: Extensions::new(),
        }
    }

    fn common_authorization(&self, operation: &str, start: Position, limit: Position) -> Value {
        let selection = &self.bootstrap.selection;
        let binding = &selection.realization.bindings[0];
        let owner = serde_json::json!({
            "owner": selection.realization.owners[0].id,
            "incarnation": binding.authority.incarnation_id,
            "generation": binding.authority.owner_generation,
        });
        let request = if limit.microstep.get() == 0 && limit.phase == Phase::BoundaryControl {
            serde_json::json!({"ExactRun": {"start":start,"limit":limit,"boundary_policy":"HorizonPark"}})
        } else {
            serde_json::json!({"BoundarySettle": {"start":start,"limit":limit}})
        };
        // This peer fixture retains correlation data only. The common source
        // callback must obtain this shape from actual opaque OperationAdmission;
        // this helper does not manufacture common activation or grant authority.
        serde_json::json!({
            "schema":"source-owned.packet-common-grant.v1", "operation":id(operation),
            "route":{"node":selection.realization.descriptors[0].id,"owners":[owner.clone()]},
            "activation":{"generation":"1","activation_id":"packet-activation",
                "world_binding_hash":selection.world,"owners":[owner],"boundary":initial_position()},
            "request":request,"input_batch":null,"input_watermark":"0",
        })
    }

    fn begin(&mut self, operation: &str, start: Position, limit: Position) -> ResponseBody {
        let authorization = self.common_authorization(operation, start, limit);
        self.begin_with_authorization(operation, start, limit, authorization)
    }

    fn begin_with_authorization(
        &mut self,
        operation: &str,
        start: Position,
        limit: Position,
        authorization: Value,
    ) -> ResponseBody {
        let request = self.begin_request(operation, start, limit, authorization);
        self.call(
            &format!("cnp-begin-{operation}"),
            Some(operation),
            Method::Begin,
            request,
        )
    }

    fn begin_request(
        &mut self,
        operation: &str,
        start: Position,
        limit: Position,
        authorization: Value,
    ) -> BeginRequest {
        let selection = self.bootstrap.selection.clone();
        let authorization = bytes(authorization);
        let root = reference(&authorization);
        self.controller.upload(&root, &authorization).unwrap();
        BeginRequest {
            kind: if limit.microstep.get() == 0 && limit.phase == Phase::BoundaryControl {
                BeginKind::ExactRun
            } else {
                assert_eq!(start.time_ps, limit.time_ps);
                BeginKind::BoundarySettle
            },
            binding_hash: selection.realization.owner_bindings[0].identity().unwrap(),
            owner_generation: U64::new(1),
            activation_id: Nullable(Some(id("packet-activation"))),
            world_generation: U64::new(1),
            arguments: object(ExactRunArguments {
                grant_id: id(operation),
                participant_ids: vec![id("packet")],
                realization_id: selection.realization.realization_id,
                activation_id: id("packet-activation"),
                world_generation: U64::new(1),
                owner_generation: U64::new(1),
                input_epoch: id("packet-input-epoch"),
                mode: OperatingMode::Exact,
                ordering_profile: "superdense-v1".into(),
                start,
                limit,
                boundary_policy: BoundaryPolicy::OrdinaryStop,
                input_authorization: root,
                input_watermark: U64::new(0),
            }),
            extensions: Extensions::new(),
        }
    }

    fn poll(&mut self, operation: &str) -> PacketNativeRecord {
        let response = self.call(
            &format!("source-poll-{operation}"),
            Some(operation),
            Method::Poll,
            PollRequest {
                after_observation_sequence: U64::new(0),
                extensions: Extensions::new(),
            },
        );
        let Some(MethodResult::Poll(poll)) = response.result else {
            panic!("source poll absent")
        };
        let original = self
            .controller
            .original(&id(&format!("cnp-begin-{operation}")))
            .unwrap();
        let RequestBody::Begin(begin) =
            decode_request(Method::Begin, &original.request.body).unwrap()
        else {
            panic!("source Begin absent")
        };
        let result = poll.validated_outcome(&begin).unwrap().unwrap();
        let result = match result.result {
            Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) => result,
            _ => panic!("source native result absent"),
        };
        serde_json::from_slice(self.controller.content(&result.stop_receipt).unwrap()).unwrap()
    }

    fn retire(&mut self, operation: &str, outputs: &[Id]) {
        let body = bytes(
            serde_json::json!({"schema":"source-owned.packet-consumption.v1","operation":id(operation),"outputs":outputs}),
        );
        let root = reference(&body);
        self.controller.upload(&root, &body).unwrap();
        let response = self.call(
            &format!("source-retire-{operation}"),
            None,
            Method::Retire,
            RetireRequest {
                request_ids: vec![id(&format!("cnp-begin-{operation}"))],
                operation_ids: vec![id(operation)],
                disposition: RetirementDisposition::Consumed,
                custody_receipt: Nullable(Some(root)),
                extensions: Extensions::new(),
            },
        );
        assert!(matches!(response.result, Some(MethodResult::Retire(_))));
    }

    fn effects_now(&self) -> Vec<Vec<u8>> {
        let mut observed = Vec::new();
        let mut buffer = [0; 1025];
        loop {
            match self.effects.recv(&mut buffer) {
                Ok(count) => {
                    let mut retained = self.observed_effects.borrow_mut();
                    assert!(retained.len() < 32);
                    retained.push(buffer[..count].to_vec());
                    observed.push(buffer[..count].to_vec());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("source independent effect observer failed: {error}"),
            }
        }
        observed
    }
}

#[path = "packet_witness.rs"]
mod witness;

#[path = "packet_probe.rs"]
mod independent_probe;

#[path = "packet_lifecycle.rs"]
mod lifecycle;

#[path = "packet_endpoint.rs"]
mod owning_endpoint;

impl Drop for Fixture {
    fn drop(&mut self) {
        let evidence = witness::save(self);
        self.controller.fence();
        self.handshake.contain();
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
        std::fs::remove_dir_all(&self.directory).unwrap();
        if let Err(error) = evidence {
            if std::thread::panicking() {
                eprintln!("original witness retention failed during assertion failure: {error}");
            } else {
                panic!("original witness retention failed: {error}");
            }
        }
    }
}

#[test]
fn actual_native_packet_originals_straddle_then_publish_and_retire_once() {
    let mut fixture = Fixture::launch();
    fixture.prepare_and_open();
    let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let private_cut = Position::new(U64::new(4), U64::new(0), Phase::BoundaryControl);
    assert!(
        fixture
            .begin("excluded-private", zero, private_cut)
            .shape
            .is_accepted()
    );
    let private_stopped = fixture.poll("excluded-private");
    assert_eq!(private_stopped.inventory.private_mutations.get(), 0);
    assert_eq!(private_stopped.inventory.pending, fixture.bootstrap.events);
    assert!(fixture.effects_now().is_empty());
    fixture.retire("excluded-private", &[]);

    let packet_cut = Position::new(U64::new(5), U64::new(0), Phase::BoundaryControl);
    assert!(
        fixture
            .begin(
                "excluded-tick",
                private_stopped.inventory.reached,
                packet_cut
            )
            .shape
            .is_accepted()
    );
    let tick_stopped = fixture.poll("excluded-tick");
    assert_eq!(tick_stopped.inventory.private_mutations.get(), 1);
    assert_eq!(tick_stopped.inventory.packet_effects.get(), 0);
    assert_eq!(fixture.effects_now(), vec![vec![0]]);
    fixture.retire("excluded-tick", &[]);

    let excluded = Position::new(U64::new(5), U64::new(1), Phase::Publication);
    assert!(
        fixture
            .begin("excluded", tick_stopped.inventory.reached, excluded)
            .shape
            .is_accepted()
    );
    assert!(
        fixture.effects_now().is_empty(),
        "registration is not execution"
    );
    let stopped = fixture.poll("excluded");
    assert_eq!(stopped.inventory.packet_effects.get(), 0);
    assert_eq!(stopped.inventory.private_mutations.get(), 1);
    assert_eq!(stopped.inventory.pending, fixture.bootstrap.events[1..]);
    assert!(fixture.effects_now().is_empty());
    fixture.retire("excluded", &[]);

    let limit = Position::new(U64::new(5), U64::new(2), Phase::Publication);
    assert!(
        fixture
            .begin("original-packet", stopped.inventory.reached, limit)
            .shape
            .is_accepted()
    );
    let original = fixture.poll("original-packet");
    let grant = original.grant.as_ref().unwrap();
    assert_eq!(grant.newborn.len(), 1);
    assert_eq!(grant.newborn[0].sequence.get(), 1);
    assert_eq!(
        grant.newborn[0].publication,
        fixture.bootstrap.events[1].completion
    );
    assert_eq!(
        fixture.effects_now(),
        vec![[vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );
    let repeated = fixture.poll("original-packet");
    assert_eq!(repeated, original);
    assert!(fixture.effects_now().is_empty());
    fixture.retire("original-packet", &[id("packet-native-1")]);
    fixture.retire("original-packet", &[id("packet-native-1")]);
    assert!(fixture.effects_now().is_empty());
    assert_eq!(
        fixture
            .controller
            .content(&reference(&bytes(&original)))
            .unwrap(),
        bytes(&original)
    );
}

#[test]
#[ignore = "actual measured packet source endpoint; requires predeclared private native bootstrap"]
fn native_packet_source_process() {
    let socket =
        std::path::PathBuf::from(std::env::var_os("CRUCIBLE_NATIVE_PACKET_SOURCE").unwrap());
    let mut input = FrameReader::new(std::io::stdin(), FRAME).unwrap();
    let bootstrap: NativeBootstrap =
        serde_json::from_value(input.read().unwrap().unwrap()).unwrap();
    server::serve(&socket, bootstrap);
}

#[test]
fn actual_native_packet_base_refusals_preserve_original_gate_and_effects() {
    base_refusals(false);
}

#[test]
fn actual_immediate_packet_base_refusals_preserve_original_gate_and_effects() {
    base_refusals(true);
}

fn base_refusals(immediate: bool) {
    let mut fixture = Fixture::launch_selected(false, immediate);
    let selection = fixture.bootstrap.selection.clone();
    let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let limit = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);

    let refused = fixture.begin("before-global", zero, limit);
    assert!(matches!(
        refused.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            ..
        }
    ));
    assert!(fixture.effects_now().is_empty());

    let refused = fixture.call(
        "unknown-profile",
        None,
        Method::Discover,
        DiscoverRequest {
            profile_ids: vec![id("foreign.packet-profile/99")],
            cursor: None,
            extensions: Extensions::new(),
        },
    );
    assert!(matches!(
        refused.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            ..
        }
    ));
    let original = fixture.controller.original(&id("unknown-profile")).unwrap();
    let original_refusal = decode_response(
        &decode_request(Method::Discover, &original.request.body).unwrap(),
        &original.response.as_ref().unwrap().body,
    )
    .unwrap();
    let repeated = fixture.call(
        "unknown-profile",
        None,
        Method::Discover,
        DiscoverRequest {
            profile_ids: vec![id("foreign.packet-profile/99")],
            cursor: None,
            extensions: Extensions::new(),
        },
    );
    assert_eq!(repeated, original_refusal);

    let changed_configuration = bytes(serde_json::json!({"schema":"foreign.packet-program.v1"}));
    let changed_root = reference(&changed_configuration);
    fixture
        .controller
        .upload(&changed_root, &changed_configuration)
        .unwrap();
    let mut wrong_realize = selection.realize.clone();
    wrong_realize.configuration = changed_root;
    let refused = fixture.call("wrong-realization", None, Method::Realize, wrong_realize);
    assert!(matches!(
        refused.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            ..
        }
    ));
    assert!(fixture.effects_now().is_empty());

    fixture.prepare_and_open();
    let refused = fixture.call(
        "duplicate-realization",
        None,
        Method::Realize,
        &selection.realize,
    );
    assert!(matches!(
        refused.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            ..
        }
    ));
    let capture = fixture.call(
        "unsupported-capture",
        Some("capture-operation"),
        Method::Begin,
        BeginRequest {
            kind: BeginKind::Capture,
            binding_hash: selection.realization.owner_bindings[0].identity().unwrap(),
            owner_generation: U64::new(1),
            activation_id: Nullable(Some(id("packet-activation"))),
            world_generation: U64::new(1),
            arguments: object(CaptureArguments {
                capture_id: id("capture-operation"),
                participant_ids: vec![id("packet")],
                cut_id: id("unqualified-cut"),
                cut: zero,
                event_ordinal: U64::new(0),
                ordering_profile: "superdense-v1".into(),
                preservation_contract: id("unsupported-preservation"),
            }),
            extensions: Extensions::new(),
        },
    );
    assert!(matches!(
        capture.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            ..
        }
    ));
    assert!(fixture.effects_now().is_empty());

    let accepted = fixture.begin("original-after-refusals", zero, limit);
    assert!(if immediate {
        matches!(accepted.result, Some(MethodResult::ExactRun(_)))
    } else {
        accepted.shape.is_accepted()
    });
    let original = fixture.poll("original-after-refusals");
    assert_eq!(original.inventory.private_mutations.get(), 1);
    assert_eq!(original.inventory.packet_effects.get(), 1);
    assert_eq!(
        fixture.effects_now(),
        vec![vec![0], [vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );
    fixture.retire("original-after-refusals", &[id("packet-native-1")]);
    assert!(fixture.effects_now().is_empty());
}

#[test]
fn actual_native_packet_lost_completion_keeps_original_output_without_redispatch() {
    let mut fixture = Fixture::launch_with_response_loss(true);
    fixture.prepare_and_open();
    let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let limit = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);
    assert!(
        fixture
            .begin("lost-original", zero, limit)
            .shape
            .is_accepted()
    );

    let poll = PollRequest {
        after_observation_sequence: U64::new(0),
        extensions: Extensions::new(),
    };
    assert!(
        fixture
            .controller
            .call(
                id("lost-poll"),
                Some(id("lost-original")),
                Method::Poll,
                true,
                &poll
            )
            .is_err()
    );
    let submitted = fixture.controller.original(&id("lost-poll")).unwrap();
    assert!(submitted.response.is_none());
    let original_request = submitted.request.clone();
    assert!(
        fixture.child.try_wait().unwrap().is_none(),
        "native original custody is still held"
    );

    // This private diagnostic reads the already retained native body. It is not
    // a capture/restore codec or permission, and independently observed socket
    // effects must agree with its original operation and full output inventory.
    let bytes = std::fs::read(&fixture.bootstrap.retained_native).unwrap();
    let native: PacketNativeRecord =
        serde_json::from_value(canonical::parse_json(&bytes, FRAME).unwrap()).unwrap();
    assert_eq!(native.original, original_request);
    assert_eq!(native.native_pid.get(), u64::from(fixture.child.id()));
    assert_eq!(native.inventory.private_mutations.get(), 1);
    assert_eq!(native.inventory.packet_effects.get(), 1);
    let grant = native.grant.as_ref().unwrap();
    assert_eq!(grant.operation, id("lost-original"));
    assert!(grant.complete);
    assert_eq!(native.inventory.retained_outputs, grant.newborn);
    assert_eq!(grant.newborn[0].payload.as_slice(), b"actual\0packet\xff");
    assert_eq!(
        fixture.effects_now(),
        vec![vec![0], [vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );

    assert!(
        fixture
            .controller
            .call(
                id("lost-poll"),
                Some(id("lost-original")),
                Method::Poll,
                true,
                &poll
            )
            .is_err()
    );
    let original_begin = fixture
        .controller
        .original(&id("cnp-begin-lost-original"))
        .unwrap();
    let RequestBody::Begin(mut replacement) =
        decode_request(Method::Begin, &original_begin.request.body).unwrap()
    else {
        panic!("original native Begin absent")
    };
    replacement.arguments.insert(
        "grant_id".into(),
        serde_json::to_value(id("replacement-after-loss")).unwrap(),
    );
    assert!(
        fixture
            .controller
            .call(
                id("replacement-begin"),
                Some(id("replacement-after-loss")),
                Method::Begin,
                true,
                replacement
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(&fixture.bootstrap.retained_native).unwrap(),
        bytes
    );
    assert!(fixture.effects_now().is_empty());
}

#[test]
fn actual_native_packet_common_binding_refuses_counterfactual_without_callback() {
    let mut fixture = Fixture::launch();
    fixture.prepare_and_open();
    let limit = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);
    for changed in 0..8 {
        let operation = format!("changed-common-{changed}");
        let mut body = fixture.common_authorization(&operation, initial_position(), limit);
        match changed {
            0 => body["route"]["owners"][0]["incarnation"] = Value::String("foreign".into()),
            1 => body["route"]["owners"] = serde_json::json!([]),
            2 => body["activation"]["activation_id"] = Value::String("foreign".into()),
            3 => body["activation"]["owners"] = serde_json::json!([]),
            4 => body["operation"] = Value::String("foreign-original".into()),
            5 => {
                body["request"]["ExactRun"]["limit"] =
                    serde_json::to_value(initial_position()).unwrap()
            }
            6 => body["input_batch"] = serde_json::json!({"empty_is_not_absence":true}),
            7 => {
                body.as_object_mut().unwrap().remove("input_batch");
            }
            _ => unreachable!(),
        }
        let refused = fixture.begin_with_authorization(&operation, initial_position(), limit, body);
        assert!(matches!(
            refused.shape,
            ResponseShape::Error {
                operation_state: OperationState::NotStarted,
                error: ErrorRecord {
                    effect: EffectCertainty::NotStarted,
                    ..
                },
                ..
            }
        ));
        assert!(fixture.effects_now().is_empty());
    }
    assert!(matches!(
        fixture
            .begin("unaltered-common", initial_position(), limit)
            .result,
        Some(MethodResult::BeginAccepted(_))
    ));
    let native = fixture.poll("unaltered-common");
    assert_eq!(native.inventory.private_mutations.get(), 1);
    assert_eq!(native.inventory.packet_effects.get(), 1);
    assert_eq!(fixture.effects_now().len(), 2);
    fixture.retire("unaltered-common", &[id("packet-native-1")]);
}

fn initial_position() -> Position {
    Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
}

#[test]
fn actual_native_packet_immediate_original_begin_poll_cancel_and_held_output_once() {
    let mut fixture = Fixture::launch_immediate();
    fixture.prepare_and_open();
    let limit = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);
    let completed = fixture.begin("immediate-original", initial_position(), limit);
    assert!(matches!(completed.result, Some(MethodResult::ExactRun(_))));
    // The entire actual native prefix belongs to Begin. Poll and cancellation
    // are read-only even before retirement; they cannot release another packet.
    assert_eq!(
        fixture.effects_now(),
        vec![vec![0], [vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );
    let native = fixture.poll("immediate-original");
    assert_eq!(native.schema, "source-owned.packet-native/2");
    assert_eq!(native.original.method, Method::Begin);
    assert_eq!(native.inventory.packet_effects.get(), 1);
    assert!(fixture.effects_now().is_empty());
    let cancelled = fixture.call(
        "cancel-immediate",
        Some("immediate-original"),
        Method::Cancel,
        CancelRequest {
            reason: id("operator-stop"),
            extensions: Extensions::new(),
        },
    );
    assert!(matches!(
        cancelled.result,
        Some(MethodResult::Cancel(CancelResult {
            cancel_requested: false,
            operation_state: OperationState::Completed,
        }))
    ));
    let refused = fixture.begin(
        "foreign-while-held",
        limit,
        Position::new(U64::new(11), U64::new(0), Phase::BoundaryControl),
    );
    assert!(matches!(
        refused.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            ..
        }
    ));
    assert_eq!(fixture.poll("immediate-original"), native);
    assert!(fixture.effects_now().is_empty());
    fixture.retire("immediate-original", &[id("packet-native-1")]);
    let later = fixture.begin(
        "new-after-original-ack",
        limit,
        Position::new(U64::new(11), U64::new(0), Phase::BoundaryControl),
    );
    assert!(matches!(later.result, Some(MethodResult::ExactRun(_))));
    assert!(fixture.effects_now().is_empty());
    fixture.retire("new-after-original-ack", &[]);
}

#[test]
fn actual_immediate_packet_excluded_private_and_atomic_completion_cuts() {
    let mut fixture = Fixture::launch_immediate();
    fixture.prepare_and_open();
    let private_cut = Position::new(U64::new(4), U64::new(0), Phase::BoundaryControl);
    let private = fixture.begin("excluded-private", initial_position(), private_cut);
    assert!(matches!(private.result, Some(MethodResult::ExactRun(_))));
    let retained = fixture.poll("excluded-private");
    assert_eq!(retained.inventory.reached, private_cut);
    assert_eq!(retained.inventory.private_mutations.get(), 0);
    assert_eq!(retained.inventory.packet_effects.get(), 0);
    assert_eq!(retained.inventory.pending, fixture.bootstrap.events);
    assert!(fixture.effects_now().is_empty());
    fixture.retire("excluded-private", &[]);

    let before_packet = Position::new(U64::new(5), U64::new(0), Phase::BoundaryControl);
    fixture.begin("private-before-packet", private_cut, before_packet);
    let retained = fixture.poll("private-before-packet");
    assert_eq!(retained.inventory.reached, before_packet);
    assert_eq!(retained.inventory.private_mutations.get(), 1);
    assert_eq!(retained.inventory.packet_effects.get(), 0);
    assert_eq!(fixture.effects_now(), vec![vec![0]]);
    fixture.retire("private-before-packet", &[]);

    // Completion at the excluded limit cannot be rounded into authorized work.
    // This native early-stop is a component witness. The common source refuses
    // this straddling grant rather than pretending it parked at the ceiling.
    let excluded_completion = Position::new(U64::new(5), U64::new(1), Phase::Publication);
    let straddle = fixture.begin("excluded-completion", before_packet, excluded_completion);
    let Some(MethodResult::BoundarySettle(result)) = straddle.result else {
        panic!("actual BoundarySettle result absent");
    };
    let unexecuted_reaction = fixture.bootstrap.events[1].evaluation;
    assert_eq!(result.reached, unexecuted_reaction);
    assert_eq!(result.stop_reason, StopReason::Attention);
    assert!(result.reached < excluded_completion);
    let retained = fixture.poll("excluded-completion");
    assert_eq!(retained.inventory.packet_effects.get(), 0);
    assert_eq!(retained.inventory.pending, fixture.bootstrap.events[1..]);
    assert!(fixture.effects_now().is_empty());
    fixture.retire("excluded-completion", &[]);

    let after = Position::new(U64::new(6), U64::new(0), Phase::BoundaryControl);
    fixture.begin("original-packet-after-cut", unexecuted_reaction, after);
    let native = fixture.poll("original-packet-after-cut");
    let publication = &native.grant.as_ref().unwrap().newborn[0];
    assert_eq!(
        publication.evaluation,
        fixture.bootstrap.events[1].evaluation
    );
    assert_eq!(publication.publication, excluded_completion);
    assert_eq!(publication.sequence.get(), 1);
    assert_eq!(publication.operation, id("original-packet-after-cut"));
    assert_eq!(publication.payload.as_slice(), b"actual\0packet\xff");
    assert_eq!(
        fixture.effects_now(),
        vec![[vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );
    assert_eq!(fixture.poll("original-packet-after-cut"), native);
    assert!(fixture.effects_now().is_empty());
    fixture.retire("original-packet-after-cut", &[id("packet-native-1")]);
}

#[test]
fn actual_immediate_packet_lost_original_begin_retains_completed_effects_and_fence() {
    let mut fixture = Fixture::launch_selected(true, true);
    fixture.prepare_and_open();
    let limit = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);
    let authorization =
        fixture.common_authorization("lost-native-begin", initial_position(), limit);
    let root = reference(&bytes(&authorization));
    fixture
        .controller
        .upload(&root, &bytes(&authorization))
        .unwrap();
    let selection = &fixture.bootstrap.selection;
    let begin = BeginRequest {
        kind: BeginKind::ExactRun,
        binding_hash: selection.realization.owner_bindings[0].identity().unwrap(),
        owner_generation: U64::new(1),
        activation_id: Nullable(Some(id("packet-activation"))),
        world_generation: U64::new(1),
        arguments: object(ExactRunArguments {
            grant_id: id("lost-native-begin"),
            participant_ids: vec![id("packet")],
            realization_id: selection.realization.realization_id.clone(),
            activation_id: id("packet-activation"),
            world_generation: U64::new(1),
            owner_generation: U64::new(1),
            input_epoch: id("packet-input-epoch"),
            mode: OperatingMode::Exact,
            ordering_profile: "superdense-v1".into(),
            start: initial_position(),
            limit,
            boundary_policy: BoundaryPolicy::OrdinaryStop,
            input_authorization: root,
            input_watermark: U64::new(0),
        }),
        extensions: Extensions::new(),
    };
    assert!(
        fixture
            .controller
            .call(
                id("lost-begin-request"),
                Some(id("lost-native-begin")),
                Method::Begin,
                true,
                &begin
            )
            .is_err()
    );
    let original = fixture
        .controller
        .original(&id("lost-begin-request"))
        .unwrap();
    assert!(original.response.is_none());
    let request = original.request.clone();
    assert!(fixture.child.try_wait().unwrap().is_none());
    let body = std::fs::read(&fixture.bootstrap.retained_native).unwrap();
    let native: PacketNativeRecord =
        serde_json::from_value(canonical::parse_json(&body, FRAME).unwrap()).unwrap();
    assert_eq!(native.schema, "source-owned.packet-native/2");
    assert_eq!(native.original, request);
    assert_eq!(native.inventory.private_mutations.get(), 1);
    assert_eq!(native.inventory.packet_effects.get(), 1);
    assert_eq!(native.native_pid.get(), u64::from(fixture.child.id()));
    let grant = native.grant.as_ref().unwrap();
    assert!(grant.complete);
    assert_eq!(grant.operation, id("lost-native-begin"));
    assert_eq!(grant.inventory, native.inventory);
    assert_eq!(grant.newborn, native.inventory.retained_outputs);
    assert_eq!(
        fixture.effects_now(),
        vec![vec![0], [vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );

    assert!(
        fixture
            .controller
            .call(
                id("lost-begin-request"),
                Some(id("lost-native-begin")),
                Method::Begin,
                true,
                &begin
            )
            .is_err()
    );
    assert!(
        fixture
            .controller
            .call(
                id("lost-native-poll"),
                Some(id("lost-native-begin")),
                Method::Poll,
                true,
                PollRequest {
                    after_observation_sequence: U64::new(0),
                    extensions: Extensions::new(),
                }
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(&fixture.bootstrap.retained_native).unwrap(),
        body
    );
    assert!(fixture.effects_now().is_empty());
}

#[test]
fn actual_immediate_source_response_undercredit_refuses_before_original_dispatch() {
    let mut fixture = Fixture::launch_immediate();
    assert_eq!(fixture.controller.originals().count(), 0);
    let exact_journal = 38 * 65_536;
    assert!(
        fixture
            .controller
            .preflight_source_reply(1, 18, exact_journal, 1, 65_536)
            .is_ok()
    );
    assert!(
        fixture
            .controller
            .preflight_source_reply(129, 18, exact_journal, 1, 65_536)
            .is_err()
    );
    assert!(
        fixture
            .controller
            .preflight_source_reply(1, 129, exact_journal, 1, 65_536)
            .is_err()
    );
    assert!(
        fixture
            .controller
            .preflight_source_reply(1, 18, exact_journal, 257, 65_536)
            .is_err()
    );
    assert!(
        fixture
            .controller
            .preflight_source_reply(1, 18, 256 * 1024 * 1024 + 1, 1, 65_536)
            .is_err()
    );
    assert_eq!(fixture.controller.originals().count(), 0);
    assert!(fixture.effects_now().is_empty());

    fixture.prepare_and_open();
    fixture
        .controller
        .preflight_source_reply(1, 18, exact_journal, 1, 65_536)
        .unwrap();
    fixture.begin(
        "after-credit-refusals",
        initial_position(),
        Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl),
    );
    let native = fixture.poll("after-credit-refusals");
    assert_eq!(native.inventory.private_mutations.get(), 1);
    assert_eq!(native.inventory.packet_effects.get(), 1);
    assert_eq!(
        fixture.effects_now(),
        vec![vec![0], [vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );
    fixture.retire("after-credit-refusals", &[id("packet-native-1")]);
}
