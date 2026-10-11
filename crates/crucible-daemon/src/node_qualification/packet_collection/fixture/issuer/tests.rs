//! Checks actual installed policy ownership rather than synthetic callback answers.

// crucible-lint: allow panic-shortcut -- The bounded model controls use assertions as their oracle.
#![allow(clippy::unwrap_used)]

use std::{collections::BTreeMap, path::Path, rc::Rc};

use crucible::node_admission::{CoordinatorPolicy, OwnershipPolicy};
use crucible_node_contract::{Bytes, ContentRef, Phase, Position, SchemaRef, U64, canonical};
use crucible_node_provider::reference_packet::{PacketEvent, PacketProgramDefinition, contracts};

use super::super::PacketFixtureArtifact;
use super::*;

#[path = "tests/definition.rs"]
mod definition;

fn put<T: serde::Serialize>(content: &mut BTreeMap<ContentRef, Vec<u8>>, value: &T) -> ContentRef {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    content.insert(reference.clone(), bytes);
    reference
}

struct Fixture {
    _directory: tempfile::TempDir,
    source: Rc<PacketSemanticSource>,
    measurements: PacketFixtureMeasurements,
    world: WorldBinding,
    requirements: ScenarioRequirements,
    content: BTreeMap<ContentRef, Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_inventory_flags(false, false)
    }

    fn with_inventory_flags(extra: bool, preservation: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let executable = std::fs::read("/proc/self/exe").unwrap();
        let executable = canonical::content_ref(&executable, "application/octet-stream").unwrap();
        let program = PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(),
            events: vec![
                PacketEvent {
                    id: definition::id("private"),
                    evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    payload: None,
                },
                PacketEvent {
                    id: definition::id("packet"),
                    evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                    payload: Some(Bytes::new(b"fixed-policy-only".to_vec())),
                },
            ],
        };
        let mut selected = definition::Definition::new(executable.clone(), &program);
        let ingress = contracts::common_ingress_contract().unwrap();
        let ingress_ref = canonical::content_ref(&ingress, "application/json").unwrap();
        selected.content.insert(ingress_ref.clone(), ingress);
        let formats = &mut selected.installation.provider.implementation.formats;
        formats.retain(|format| {
            !format
                .id
                .as_str()
                .starts_with("source-owned.packet-ingress/")
        });
        formats.push(SchemaRef {
            id: definition::id("source-owned.packet-ingress/2"),
            version: 2,
            definition: ingress_ref,
            extensions: Default::default(),
        });
        formats.sort_by(|left, right| left.id.cmp(&right.id));
        selected.installation.binding.compatibility.implementation =
            selected.installation.provider.implementation.clone();
        let binding = selected.installation.binding.identity().unwrap();
        selected.installation.owner.node_bindings[0].binding_hash = binding.clone();
        selected.world.node_bindings[0].binding_hash = binding;

        let proof_bytes = packet_independent_graph_contract().unwrap();
        let proof = canonical::content_ref(&proof_bytes, "application/json").unwrap();
        selected.content.insert(proof.clone(), proof_bytes);
        let mut inventory: OwnershipPolicy =
            records::decode(&selected.content, &selected.world.ownership_ref).unwrap();
        inventory.inventory_proof_ref = proof.clone();
        inventory.capture_owners[0].cut_procedure_ref = proof.clone();
        inventory.capture_owners[0].complete_model = preservation;
        if extra {
            inventory.objects.push(inventory.objects[0].clone());
        }
        selected.world.ownership_ref = put(&mut selected.content, &inventory);
        let mut coordinator: CoordinatorPolicy =
            records::decode(&selected.content, &selected.world.coordinator_contract_ref).unwrap();
        coordinator.state_closure_ref = proof.clone();
        coordinator.operational_policy_ref = proof;
        selected.world.coordinator_contract_ref = put(&mut selected.content, &coordinator);
        selected.installation.world_binding_hash = selected.world.identity().unwrap();
        let source = Rc::new(PacketSemanticSource::new(selected.installation, program).unwrap());

        let sources = [
            "adapter_source",
            "build_closure",
            "contract_source",
            "harness_source",
            "native_source",
            "program_source",
            "provider_source",
            "recipe",
        ]
        .into_iter()
        .map(|role| {
            let path = directory.path().join(role);
            let bytes = format!("model-only independent policy control: {role}");
            std::fs::write(&path, &bytes).unwrap();
            PacketFixtureArtifact {
                role: role.into(),
                path,
                content: canonical::content_ref(bytes.as_bytes(), "text/plain").unwrap(),
            }
        })
        .collect();
        let measurements = PacketFixtureMeasurements {
            peer: PacketFixtureArtifact {
                role: "executable".into(),
                path: Path::new("/proc/self/exe").to_path_buf(),
                content: executable.clone(),
            },
            host: executable,
            sources,
        };
        Self {
            _directory: directory,
            source,
            measurements,
            world: selected.world,
            requirements: selected.requirements,
            content: selected.content,
        }
    }

    fn request(&self) -> PacketIndependentGraphRequest<'_> {
        PacketIndependentGraphRequest {
            source: Rc::clone(&self.source),
            measurements: &self.measurements,
            world: &self.world,
            requirements: &self.requirements,
            content: &self.content,
        }
    }
}

#[test]
fn original_installed_owner_revocation_refuses_retained_wrapper() {
    let fixture = Fixture::new();
    let mut owner = PacketIndependentGraphOwner::install(fixture.request()).unwrap();
    let issued = owner.graph_policy().unwrap();
    let schema = &fixture
        .source
        .installation()
        .provider
        .implementation
        .formats[0];
    assert!(issued.authenticate_schema(schema).is_ok());
    let binding = &fixture.source.installation().binding.compatibility;
    let binding_hash = binding.identity().unwrap();
    assert!(
        issued
            .qualify(QualificationClaim::Node {
                binding,
                binding_hash: &binding_hash,
                qualification_refs: &binding.qualification_refs,
            })
            .is_err()
    );

    owner.revoke();
    let mut dispatches = 0;
    if issued.authenticate_schema(schema).is_ok() {
        dispatches += 1;
    }

    assert_eq!(dispatches, 0);
    assert!(owner.graph_policy().is_err());
}

#[test]
fn owner_drop_does_not_extend_authorization_through_evidence_rc() {
    let fixture = Fixture::new();
    let owner = PacketIndependentGraphOwner::install(fixture.request()).unwrap();
    let issued = owner.graph_policy().unwrap();
    let schema = &fixture
        .source
        .installation()
        .provider
        .implementation
        .formats[0];

    drop(owner);

    assert!(issued.authenticate_schema(schema).is_err());
}

#[test]
fn original_policy_current_read_rejects_foreign_world_scope() {
    let fixture = Fixture::new();
    let owner = PacketIndependentGraphOwner::install(fixture.request()).unwrap();
    let mut foreign = fixture.world.clone();
    foreign.initialization_ref = fixture.world.scenario_ref.clone();
    let original = &owner.evidence;

    let result = original.authenticate_current_packet_graph_scope(PacketGraphCurrentScope {
        selection: fixture.source.installation(),
        world: &foreign,
        requirements_hash: &original.requirements,
        content: &original.content,
        schemas: &original.schemas,
        capabilities: &[],
        predicates: &original.predicates,
    });

    assert!(result.is_err());
    assert!(original.current().is_ok());
}

#[test]
fn changed_original_source_file_revokes_issuer_without_native_or_plan_change() {
    let fixture = Fixture::new();
    let owner = PacketIndependentGraphOwner::install(fixture.request()).unwrap();
    let issued = owner.graph_policy().unwrap();
    let schema = &fixture
        .source
        .installation()
        .provider
        .implementation
        .formats[0];
    let source = &fixture.measurements.sources[0];
    let replacement = fixture._directory.path().join("replacement");
    std::fs::write(&replacement, std::fs::read(&source.path).unwrap()).unwrap();

    std::fs::rename(replacement, &source.path).unwrap();

    assert!(issued.authenticate_schema(schema).is_err());
}

#[test]
fn widened_inventory_and_finite_body_limit_refuse_before_issuer_creation() {
    let fixture = Fixture::with_inventory_flags(true, false);
    assert!(PacketIndependentGraphOwner::install(fixture.request()).is_err());

    let mut fixture = Fixture::new();
    let oversized = vec![0u8; 1024 * 1024 + 1];
    let reference = canonical::content_ref(&oversized, "application/octet-stream").unwrap();
    fixture.content.insert(reference, oversized);
    assert!(PacketIndependentGraphOwner::install(fixture.request()).is_err());
}

#[test]
fn no_preservation_claim_matches_only_the_installed_limitation() {
    let fixture = Fixture::new();
    let owner = PacketIndependentGraphOwner::install(fixture.request()).unwrap();
    let issued = owner.graph_policy().unwrap();
    let selected = fixture.source.installation();
    let bytes = packet_independent_graph_contract().unwrap();
    let limitation = canonical::content_ref(&bytes, "application/json").unwrap();

    assert!(
        issued
            .qualify(QualificationClaim::Capture {
                world_binding_hash: &selected.world_binding_hash,
                capture_owner_id: &selected.owner.owner.id,
                procedure_ref: &limitation,
            })
            .is_ok()
    );
    assert!(
        issued
            .qualify(QualificationClaim::Capture {
                world_binding_hash: &selected.world_binding_hash,
                capture_owner_id: &selected.owner.owner.id,
                procedure_ref: &fixture.world.initialization_ref,
            })
            .is_err()
    );

    let unsupported = Fixture::with_inventory_flags(false, true);
    assert!(PacketIndependentGraphOwner::install(unsupported.request()).is_err());
}
