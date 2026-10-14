//! Tests full preparation-only source structure without issuing native readiness.
//!
//! Static program/source records are controlled fixtures. File custody tests
//! measure the actual test ELF and eight real scratch files; they never launch
//! that ELF as a packet peer or interpret it as native implementation authority.

// crucible-lint: allow panic-shortcut -- Assertions and fixture setup panics are the test oracle.
#![allow(clippy::unwrap_used)]

use crucible::node_adapters::cnp::PacketCompleteSemanticSource;
use crucible::node_admission::{AdmissionEvidence, QualificationClaim};
use crucible_node_contract::{ContentRef, Id, canonical};
use crucible_node_provider::reference_packet::service::PacketConnectedSourceProgram;
use std::{collections::BTreeMap, rc::Rc};

use super::super::super::{PacketFixtureArtifact, PacketFixtureMeasurements};
use super::{PacketCompleteGraphOwner, PacketCompleteGraphRequest, PacketCompleteRoster, records};

#[path = "tests/configuration.rs"]
mod configuration;
#[path = "tests/definition.rs"]
mod definition;
#[path = "tests/host.rs"]
mod host;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

struct Scene {
    world: configuration::World,
    roster: PacketCompleteRoster,
    measurements: PacketFixtureMeasurements,
    _directory: tempfile::TempDir,
}

impl Scene {
    fn new() -> Self {
        Self::with_effect_phases(false, &[1, 2])
    }

    fn with_effect_phases(distinct: bool, effect_phases: &[u16]) -> Self {
        Self::with_selected_effect_phases(distinct, effect_phases, None, None, false)
    }

    fn with_selected_effect_phases(
        distinct: bool,
        effect_phases: &[u16],
        confirmation: Option<
            crucible_node_provider::reference_packet::service::PacketNative5ConfirmationSelection,
        >,
        ack: Option<crucible_node_provider::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
        native_extent: bool,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let host = canonical::content_ref(
            &std::fs::read(&executable).unwrap(),
            "application/octet-stream",
        )
        .unwrap();
        let (peer_path, peer_reference) = if distinct {
            // A copied ELF with inert trailing bytes distinguishes the complete
            // peer measurement from the original host ELF. It is never launched.
            let mut bytes = std::fs::read(&executable).unwrap();
            bytes.extend_from_slice(b"connected graph file-dispatch fixture");
            let path = directory.path().join("distinct-peer");
            std::fs::write(&path, &bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::metadata(&executable).unwrap().permissions())
                .unwrap();
            let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
            (path, reference)
        } else {
            (executable, host.clone())
        };
        let roles = [
            "adapter_source",
            "build_closure",
            "contract_source",
            "harness_source",
            "native_source",
            "program_source",
            "provider_source",
            "recipe",
        ];
        let sources = roles
            .iter()
            .map(|role| {
                let path = directory.path().join(role);
                let bytes = format!("preparation-only controlled {role} bytes");
                std::fs::write(&path, bytes.as_bytes()).unwrap();
                PacketFixtureArtifact {
                    role: (*role).into(),
                    path,
                    content: canonical::content_ref(bytes.as_bytes(), "text/plain").unwrap(),
                }
            })
            .collect();
        let measurements = PacketFixtureMeasurements {
            peer: PacketFixtureArtifact {
                role: "executable".into(),
                path: peer_path,
                content: peer_reference.clone(),
            },
            host: host.clone(),
            sources,
        };
        let proof = records::packet_complete_measured_graph_proof(&[
            measurements.clone(),
            measurements.clone(),
            measurements.clone(),
        ])
        .unwrap();
        let mut world = if confirmation.is_some() || ack.is_some() {
            configuration::World::with_native_selection(
                peer_reference,
                host,
                proof,
                effect_phases,
                confirmation,
                ack,
            )
        } else if effect_phases == [1, 2] {
            configuration::World::new(peer_reference, host, proof)
        } else {
            configuration::World::with_effect_phases(peer_reference, host, proof, effect_phases)
        };
        let interpretation = records::packet_complete_independent_graph_contract().unwrap();
        world.content.insert(
            canonical::content_ref(&interpretation, "application/json").unwrap(),
            interpretation,
        );
        let sources = std::array::from_fn(|member| {
            let selection = world.members[member].take().unwrap().installation;
            let mut source = match &world.programmes[member] {
                PacketConnectedSourceProgram::Producer { program } => {
                    PacketCompleteSemanticSource::new_producer_for_collecting_world(
                        selection,
                        program.clone(),
                        world.coordinator.clone(),
                        storage_selection(),
                    )
                }
                PacketConnectedSourceProgram::Reactive { program } => {
                    PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                        selection,
                        program.clone(),
                        world.coordinator.clone(),
                        storage_selection(),
                    )
                }
            }
            .unwrap();
            if confirmation.is_some() || ack.is_some() {
                source.bind_original_capture_profile(
                    crucible_node_provider::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
                ).unwrap();
                source
                    .bind_original_confirmation_selection(confirmation)
                    .unwrap();
                source.bind_original_ack_emitter_selection(ack).unwrap();
                if ack.is_some() {
                    let extent = crucible_node_provider::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB;
                    source
                        .bind_original_ack_codec_metadata_extent(extent)
                        .unwrap();
                    if native_extent {
                        source
                            .bind_original_native_ack_codec_metadata_extent(extent)
                            .unwrap();
                    }
                }
            }
            Rc::new(source)
        });
        let roster = PacketCompleteRoster::new(sources, &world.coordinator).unwrap();
        assert_eq!(
            world.activation.world_binding_hash,
            world.world.identity().unwrap()
        );
        Self {
            world,
            roster,
            measurements,
            _directory: directory,
        }
    }

    fn request<'a>(
        &'a self,
        content: &'a BTreeMap<ContentRef, Vec<u8>>,
    ) -> PacketCompleteGraphRequest<'a> {
        PacketCompleteGraphRequest {
            roster: self.roster.clone(),
            host: self.world.host_source.clone(),
            measurements: [&self.measurements; 3],
            world: &self.world.world,
            requirements: &self.world.requirements,
            content,
            coordinator: &self.world.coordinator,
        }
    }
}

fn storage_selection()
-> crucible_node_provider::reference_packet::control::PacketNative5StorageSelection {
    use crucible_node_contract::U64;
    use crucible_node_provider::{
        handshake::Limits,
        reference_packet::{
            control::PacketNative5StorageSelection, service::PacketNative5StorageLimits,
        },
    };
    // These values are test declaration data, not physical bank allocation.
    PacketNative5StorageSelection {
        storage: PacketNative5StorageLimits {
            snapshot_bytes: U64::new(65536),
            control_snapshot_bytes: U64::new(65536),
            protocol_snapshot_bytes: U64::new(1024 * 1024),
            frame_bank_bytes: U64::new(1024 * 1024),
            frames_per_direction: U64::new(64),
            hello_bytes: U64::new(131080),
            settlement_bytes: U64::new(1024 * 1024),
        },
        limits: Limits {
            frame_bytes: U64::new(65536),
            nesting: U64::new(64),
            requests: U64::new(32),
            journal_entries: U64::new(64),
            blob_chunk_bytes: U64::new(4096),
        },
    }
}

#[test]
fn complete_structure_uses_genuine_host_factory_without_live_capture() {
    let scene = Scene::new();
    let interpreted = records::validate(&scene.request(&scene.world.content)).unwrap();
    assert_eq!(interpreted.connections.len(), 2);
    assert_eq!(interpreted.closures.len(), 4);
    scene
        .world
        .host_source
        .authenticate_preparation_source(scene.world.host_source.world())
        .unwrap();
    assert!(scene.world.host_source.authenticate_current().is_err());
    assert!(scene.roster.current_native().is_err());
}

#[test]
fn complete_roster_refuses_reordered_and_duplicate_originals() {
    let scene = Scene::new();
    let mut swapped = scene.roster.sources.clone();
    swapped.swap(0, 1);
    assert!(PacketCompleteRoster::new(swapped, &scene.world.coordinator).is_err());
    let mut swapped_reactive = scene.roster.sources.clone();
    swapped_reactive.swap(1, 2);
    assert!(PacketCompleteRoster::new(swapped_reactive, &scene.world.coordinator).is_err());

    let mut duplicated = scene.roster.sources.clone();
    duplicated[2] = Rc::clone(&duplicated[1]);
    assert!(PacketCompleteRoster::new(duplicated, &scene.world.coordinator).is_err());
    scene.roster.current_scope().unwrap();
}

#[test]
fn structural_policy_refuses_capture_even_with_complete_declarations() {
    let scene = Scene::new();
    let owner = PacketCompleteGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    let policy = owner.graph_policy().unwrap();
    let inventory: crucible::node_admission::OwnershipPolicy =
        records::decode(&scene.world.content, &scene.world.world.ownership_ref).unwrap();
    let row = &inventory.capture_owners[0];
    assert!(row.complete_model && row.exact_continuation && row.durable_restart);
    assert!(
        policy
            .qualify(QualificationClaim::Capture {
                world_binding_hash: &scene.world.world.identity().unwrap(),
                capture_owner_id: &row.owner_id,
                procedure_ref: &row.cut_procedure_ref,
            })
            .is_err()
    );
    assert!(policy.authenticate_original_participants().is_err());
    drop(owner);
    assert!(
        policy
            .content(&scene.measurements.host, 512 * 1024 * 1024)
            .is_err()
    );
}

#[test]
fn complete_graph_refuses_direction_only_lane_contracts() {
    for phases in [&[1][..], &[2][..], &[1, 2, 3][..]] {
        let scene = Scene::with_effect_phases(false, phases);
        assert!(records::validate(&scene.request(&scene.world.content)).is_err());
    }
}

#[path = "tests/authority.rs"]
mod authority;

#[path = "tests/selected.rs"]
mod selected;
