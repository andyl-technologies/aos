//! Actual native Arm correlation for the distinct static common coordinator grammar.
//!
//! These controls exercise source data and actual native prepared receipts only.
//! They issue neither a behavioral certificate nor common runtime activation.

#![cfg(test)]

use std::os::unix::net::UnixDatagram;

use crucible_node_contract::*;
use crucible_node_provider::{
    bodies::*,
    envelope::*,
    reference_packet::{
        PacketEvent, PacketProgram, PacketProgramDefinition,
        control::{PacketControl, PacketControlSelection},
        coordinator::PacketCoordinatorInstallation,
    },
};
use serde_json::{Value, json};

use super::{packet_definition::Definition, packet_protocol::*};

struct Fixture {
    definition: Definition,
    selection: PacketControlSelection,
    installation: PacketCoordinatorInstallation,
    staged: ActivateRequest,
}

impl Fixture {
    fn new() -> Self {
        let program = PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(),
            events: vec![
                PacketEvent {
                    id: id("private"),
                    evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    payload: None,
                },
                PacketEvent {
                    id: id("packet"),
                    evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                    payload: Some(Bytes::new(vec![0, 255])),
                },
            ],
        };
        let definition =
            Definition::with_installed_model(reference(b"fixture executable"), &program);
        let selected = &definition.installation;
        let bootstrap = Bootstrap::new(&definition);
        let selection = PacketControlSelection {
            provider: bootstrap.manifest,
            realization: bootstrap.realization,
            realize: selected.realize.clone(),
            prepared_token: id("packet-original-prepared-token"),
            admission: selected.admission.clone(),
            transaction: selected.transaction.clone(),
            gate: selected.gate.clone(),
            world: selected.world_binding_hash.clone(),
            admission_receipt: selected.admission_receipt.clone(),
        };
        let staged = ActivateRequest {
            admission_id: selection.admission.clone(),
            activation_id: id("packet-activation"),
            world_generation: U64::new(1),
            prepared_token: selection.prepared_token.clone(),
            world_binding_hash: selection.world.clone(),
            gate_id: selection.gate.clone(),
            extensions: Extensions::new(),
        };
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let identity = json!({"owner":selected.owner.owner.id,
            "incarnation":selected.binding.authority.incarnation_id,
            "generation":selected.binding.authority.owner_generation});
        let content = |reference: &ContentRef| {
            canonical::parse_json(&definition.content[reference], 65_536).unwrap()
        };
        let installation = PacketCoordinatorInstallation {
            schema: "source-owned.packet-common-coordinator-installation/1".into(),
            template: json!({
                "schema":"crucible/coordinator-initial/1", "schema_version":1,
                "activation":{"generation":staged.world_generation,
                    "activation_id":staged.activation_id,"world_binding_hash":selection.world,
                    "owners":[identity],"boundary":zero},
                "world":definition.world,
                "ownership":content(&definition.world.ownership_ref),
                "coordinator":content(&definition.world.coordinator_contract_ref),
                "requirements":definition.requirements,
                "nodes":[{"descriptor":selected.descriptor,"binding":selected.binding,
                    "route":{"node":selected.descriptor.id,"owners":[identity]},
                    "facets":["exact-execution"],"native_thread_custody":"owner-thread",
                    "operating_policy":null,"guarantees":selected.guarantees,
                    "effective_repeatability":Repeatability::Nondeterministic,
                    "ports":[[selected.descriptor.ports[0].id,
                        content(&selected.descriptor.ports[0].configuration_ref)]]}],
                "owners":[{"identity":identity,"lifecycle":"Prepared",
                    "operation":null,"domains":selected.owner.owner.state_domain_ids}],
                "owner_bindings":[selected.owner],
                "owner_conflicts":[[selected.owner.owner.id,[]]],
                "preparations":[],"connections":[],
                "limits":{"maximum_nodes":1,"maximum_owners":1,
                    "maximum_operations":64,"maximum_retained_outputs":1},
                "world_repeatability":Repeatability::Nondeterministic,"clock":zero,
                "scheduler":{"state":"not_initialized","operations":[],"inputs":[],
                    "publications":[],"deliveries":[],"reservations":[]}
            }),
        };
        installation.validate(&selection).unwrap();
        Self {
            definition,
            selection,
            installation,
            staged,
        }
    }

    fn native_arm(&self) -> (PacketControl, ContentRef, UnixDatagram) {
        let programme: PacketProgramDefinition = serde_json::from_slice(
            &self.definition.content[&self.definition.installation.descriptor.model_ref],
        )
        .unwrap();
        let (native, effects) = UnixDatagram::pair().unwrap();
        effects.set_nonblocking(true).unwrap();
        let mut control = PacketControl::new_immediate(
            self.selection.clone(),
            PacketProgram::new(programme.events, native).unwrap(),
        )
        .unwrap();
        let requests = [
            (
                Method::Realize,
                serde_json::to_value(&self.selection.realize).unwrap(),
            ),
            (
                Method::Admit,
                json!(AdmitRequest {
                    bindings: self.selection.realization.bindings.clone(),
                    world_binding_hash: self.selection.world.clone(),
                    admission_receipt: self.selection.admission_receipt.clone(),
                    extensions: Extensions::new(),
                }),
            ),
            (Method::Activate, json!(&self.staged)),
        ];
        let mut ready = None;
        for (index, (method, body)) in requests.into_iter().enumerate() {
            let binding = &self.selection.realization.bindings[0];
            let envelope = Envelope {
                protocol: "CNP/1".into(),
                message: MessageKind::Request,
                session_id: Nullable(Some(binding.authority.session_id.clone())),
                incarnation_id: Nullable(Some(binding.authority.incarnation_id.clone())),
                node_id: Nullable(None),
                execution_owner_id: Nullable(None),
                capture_owner_id: Nullable(None),
                operation_id: Nullable(None),
                request_id: Nullable(Some(id(&format!("original-{index}")))),
                sequence: U64::new(index as u64 + 1),
                method,
                body: body.as_object().unwrap().clone(),
                extensions: Extensions::new(),
            };
            let original = control.dispatch(&envelope).unwrap();
            if method == Method::Activate {
                let request = decode_request(method, &envelope.body).unwrap();
                let response = decode_response(&request, &original.body).unwrap();
                let Some(MethodResult::Activate(result)) = response.result else {
                    panic!("actual native Arm did not return its original receipt")
                };
                ready = Some(result.activation_receipt);
            }
        }
        assert!(control.inventory().gate_closed);
        assert_eq!(control.inventory().packet_effects.get(), 0);
        (control, ready.unwrap(), effects)
    }

    fn complete(&self, ready: &ContentRef) -> Value {
        let selected = &self.definition.installation;
        let identity = json!({"owner":selected.owner.owner.id,
            "incarnation":selected.binding.authority.incarnation_id,
            "generation":selected.binding.authority.owner_generation});
        let mut complete = self.installation.template.clone();
        complete["preparations"] = json!([{
            "node":selected.descriptor.id,
            "readiness":{"owners":[identity],"boundary":complete["clock"],
                "state_inventory":ready,"ready_receipt":ready},
            "prepared_owners":[PreparedOwner {
                owner_id:selected.owner.owner.id.clone(),
                incarnation_id:selected.binding.authority.incarnation_id.clone(),
                owner_generation:selected.binding.authority.owner_generation,
                binding_hashes:vec![selected.binding.identity().unwrap()],
                prepared_token:self.selection.prepared_token.clone(),ready_receipt:ready.clone(),
                extensions:Extensions::new(),
            }]
        }]);
        complete
    }
}

#[test]
fn complete_body_binds_actual_retained_native_arm() {
    let fixture = Fixture::new();
    let (control, ready, effects) = fixture.native_arm();
    let complete = bytes(fixture.complete(&ready));
    fixture
        .installation
        .authenticate_staged(&complete, &fixture.selection, &fixture.staged, &ready)
        .unwrap();

    let record = control.original(&id("original-2")).unwrap();
    assert!(
        record
            .evidence
            .iter()
            .any(|(reference, _)| reference == &ready)
    );
    let mut trace = [0; 33];
    assert_eq!(
        effects.recv(&mut trace).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn missing_duplicate_foreign_or_predicted_ready_is_refused() {
    let fixture = Fixture::new();
    let (_, ready, _) = fixture.native_arm();
    let complete = fixture.complete(&ready);
    let mut changed = Vec::new();
    let mut missing = complete.clone();
    missing["preparations"] = json!([]);
    changed.push(missing);
    let mut duplicate = complete.clone();
    duplicate["preparations"] = json!([complete["preparations"][0], complete["preparations"][0]]);
    changed.push(duplicate);
    let mut foreign = complete.clone();
    foreign["preparations"][0]["prepared_owners"][0]["owner_id"] = json!("foreign-owner");
    changed.push(foreign);
    let mut predicted = complete.clone();
    predicted["preparations"][0]["readiness"]["ready_receipt"] =
        json!(reference(b"predicted-ready"));
    changed.push(predicted);
    for body in changed {
        assert!(
            fixture
                .installation
                .authenticate_staged(&bytes(body), &fixture.selection, &fixture.staged, &ready)
                .is_err()
        );
    }
}

#[test]
fn static_world_route_roster_and_limits_are_source_bound() {
    let fixture = Fixture::new();
    for field in ["nodes", "owners", "owner_bindings", "owner_conflicts"] {
        let mut changed = fixture.installation.clone();
        changed.template[field] = json!([]);
        assert!(changed.validate(&fixture.selection).is_err(), "{field}");
    }
    let mut changed = fixture.installation.clone();
    changed.template["nodes"][0]["route"]["owners"][0]["owner"] = json!("foreign-owner");
    assert!(changed.validate(&fixture.selection).is_err());
    let mut changed = fixture.installation.clone();
    changed.template["limits"]["maximum_operations"] = json!(65);
    assert!(changed.validate(&fixture.selection).is_err());
    let mut changed = fixture.selection.clone();
    changed.world = canonical::hash("cnp.world.v1", b"stale").unwrap();
    assert!(fixture.installation.validate(&changed).is_err());
}

#[test]
fn post_arm_tampering_and_stale_activation_are_refused() {
    let fixture = Fixture::new();
    let (_, ready, _) = fixture.native_arm();
    let mut complete = fixture.complete(&ready);
    complete["requirements"]["accepted_nondeterministic_nodes"] = json!([]);
    assert!(
        fixture
            .installation
            .authenticate_staged(
                &bytes(complete),
                &fixture.selection,
                &fixture.staged,
                &ready
            )
            .is_err()
    );
    let mut staged = fixture.staged.clone();
    staged.activation_id = id("foreign-activation");
    assert!(
        fixture
            .installation
            .authenticate_staged(
                &bytes(fixture.complete(&ready)),
                &fixture.selection,
                &staged,
                &ready
            )
            .is_err()
    );
}

#[test]
fn static_installation_is_bounded_canonical_and_never_contains_ready() {
    let fixture = Fixture::new();
    let encoded = bytes(&fixture.installation);
    assert_eq!(
        PacketCoordinatorInstallation::decode(&encoded, &fixture.selection).unwrap(),
        fixture.installation
    );
    let mut changed = fixture.installation.clone();
    changed.template["preparations"] = json!([{"predicted":"ready"}]);
    assert!(changed.validate(&fixture.selection).is_err());
    let mut changed = fixture.installation.clone();
    changed.template["padding"] = json!("x".repeat(65_536));
    assert!(changed.validate(&fixture.selection).is_err());
    let mut noncanonical = encoded;
    noncanonical.push(b' ');
    assert!(PacketCoordinatorInstallation::decode(&noncanonical, &fixture.selection).is_err());
}
