//! Tests full preparation-only source structure without issuing native readiness.
//!
//! Static program/source records are controlled fixtures. File custody tests
//! measure the actual test ELF and eight real scratch files; they never launch
//! that ELF as a packet peer or interpret it as native implementation authority.

// crucible-lint: allow panic-shortcut -- Assertions and fixture setup panics are the test oracle.
#![allow(clippy::unwrap_used)]

use crucible::node_adapters::cnp::{CnpSemanticSource, PacketCompleteSemanticSource};
use crucible::node_admission::{AdmissionEvidence, QualificationClaim};
use crucible_node_contract::{ContentRef, Id, canonical};
use crucible_node_provider::reference_packet::service::PacketConnectedSourceProgram;
use std::{collections::BTreeMap, rc::Rc};

use super::super::super::{PacketFixtureArtifact, PacketFixtureMeasurements};
use super::{PacketCompleteGraphOwner, PacketCompleteGraphRequest, PacketCompleteRoster, records};

/// Selects a finite 2 GiB allowance for positive startup fixture setup.
///
/// Exact and one-short controls subsequently install their actual derived peak.
/// This test-only policy does not change production limits or establish fit.
pub(super) const POSITIVE_STARTUP_SETUP_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Selects a finite 3 GiB setup allowance for the two Host SDK boundary controls.
///
/// Their three SDK/Hello windows coexist with prior native commitments. Exact
/// and one-short checks replace this allowance with the actual derived peak.
pub(super) const POSITIVE_HOST_SDK_SETUP_MEMORY_BYTES: u64 = 3 * 1024 * 1024 * 1024;

#[path = "tests/configuration.rs"]
mod configuration;
#[path = "tests/definition.rs"]
mod definition;
#[path = "tests/host.rs"]
mod host;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

pub(super) struct Scene {
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
        Self::with_selected_report_startup(
            distinct,
            effect_phases,
            confirmation,
            ack,
            native_extent,
            None,
        )
    }

    fn report_startup(frame_bytes: u64) -> Self {
        use crucible_node_provider::reference_packet::service::{
            PacketNative5ConfirmationSelection, ack_emitter::PacketNative5AckEmitterSelection,
        };
        Self::with_selected_report_startup(
            false,
            &[1, 2],
            Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5),
            Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
            true,
            Some(frame_bytes),
        )
    }

    fn with_selected_report_startup(
        distinct: bool,
        effect_phases: &[u16],
        confirmation: Option<
            crucible_node_provider::reference_packet::service::PacketNative5ConfirmationSelection,
        >,
        ack: Option<crucible_node_provider::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
        native_extent: bool,
        report_frame_bytes: Option<u64>,
    ) -> Self {
        Self::with_selected_report_startup_executable(
            distinct,
            effect_phases,
            confirmation,
            ack,
            native_extent,
            report_frame_bytes,
            None,
        )
    }

    fn with_selected_report_startup_executable(
        distinct: bool,
        effect_phases: &[u16],
        confirmation: Option<
            crucible_node_provider::reference_packet::service::PacketNative5ConfirmationSelection,
        >,
        ack: Option<crucible_node_provider::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
        native_extent: bool,
        report_frame_bytes: Option<u64>,
        native_executable: Option<&std::path::Path>,
    ) -> Self {
        let report_startup = report_frame_bytes.is_some();
        let mut selected_storage = storage_selection();
        if let Some(frame_bytes) = report_frame_bytes {
            selected_storage.limits.frame_bytes = crucible_node_contract::U64::new(frame_bytes);
            selected_storage.validate().unwrap();
        }
        let directory = if report_startup {
            // Unix socket paths must fit sun_path even when TMPDIR is deeply
            // nested. Scene owns this root and removes it when the fixture drops.
            tempfile::Builder::new()
                .prefix("crucible-packet-")
                .tempdir_in("/tmp")
                .unwrap()
        } else {
            tempfile::tempdir().unwrap()
        };
        let executable = std::env::current_exe().unwrap();
        let host = canonical::content_ref(
            &std::fs::read(&executable).unwrap(),
            "application/octet-stream",
        )
        .unwrap();
        let (peer_path, peer_reference) = if let Some(path) = native_executable {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let original = std::fs::canonicalize(path).unwrap();
            assert!(std::fs::metadata(&original).unwrap().is_file());
            let bytes = std::fs::read(&original).unwrap();
            let path = directory.path().join("packet-provider");
            std::fs::copy(&original, &path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
            (path, reference)
        } else if distinct {
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
        let mut world = if report_startup {
            configuration::World::with_native_fixture(
                peer_reference,
                host,
                proof,
                effect_phases,
                confirmation,
                ack,
                true,
                native_executable.is_some(),
            )
        } else if confirmation.is_some() || ack.is_some() {
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
                        selected_storage.clone(),
                    )
                }
                PacketConnectedSourceProgram::Reactive { program } => {
                    PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                        selection,
                        program.clone(),
                        world.coordinator.clone(),
                        selected_storage.clone(),
                    )
                }
            }
            .unwrap();
            if confirmation.is_some() || ack.is_some() {
                use crucible_node_contract::U64;
                use crucible_node_provider::reference_packet::service::PacketNative5CaptureProfile;
                // Trial windows are constructor inputs, never a whole-memory admission.
                let profile = if report_startup {
                    PacketNative5CaptureProfile::OwnedProtocol11 {
                        native_before_protocol_bytes: U64::new(1024 * 1024),
                        native_after_protocol_bytes: U64::new(1024 * 1024),
                        host_protocol_bytes: U64::new(1024 * 1024),
                    }
                } else {
                    PacketNative5CaptureProfile::OriginalArrays6
                };
                source.bind_original_capture_profile(profile).unwrap();
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
            if report_startup {
                use crucible_node_provider::reference_packet::service::{
                    PacketNative5ProtocolMetadataLimits,
                    capture_allocation::PacketNative5CaptureAllocationSelection,
                };
                source
                    .bind_original_protocol_metadata_limits(PacketNative5ProtocolMetadataLimits {
                        native_before_rows: crucible_node_contract::U64::new(8192),
                        native_after_rows: crucible_node_contract::U64::new(8192),
                    })
                    .unwrap();
                source
                    .bind_original_capture_allocation_selection(Some(
                        PacketNative5CaptureAllocationSelection::OriginalObserve12,
                    ))
                    .unwrap();
                if native_executable.is_some() {
                    use crucible_node_provider::reference_packet::service::{
                        complete_restore::{
                            PacketNative5CompleteRestoreSelection,
                            PacketNative5RestoreInputEmitterSelection,
                        },
                        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
                    };
                    source
                        .bind_original_complete_restore_selection(Some(
                            PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
                        ))
                        .unwrap();
                    source
                        .bind_original_restore_input_emitter_selection(Some(
                            PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12,
                        ))
                        .unwrap();
                    source
                        .bind_original_fresh_restore_allocation_selection(Some(
                            PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13,
                        ))
                        .unwrap();
                    source
                        .bind_original_restoration_observation_declaration()
                        .unwrap();
                }
                source
                    .reserve_complete_capture_banks_owned11(
                        crucible::node_adapters::cnp::PacketCompleteCaptureBankLimits {
                            host_protocol_bytes: 1024 * 1024,
                            semantic_bytes: 65_536,
                            ancestry_bytes: 65_536,
                            journal_bytes: 65_536,
                        },
                        8192,
                        64 * 1024 * 1024,
                    )
                    .unwrap();
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

/// Borrows the same controlled scene's real immutable source content for SDK controls.
pub(super) fn report_startup_content_data(scene: &Scene) -> &BTreeMap<ContentRef, Vec<u8>> {
    &scene.world.content
}

/// Builds actual ready private births without constructing a Child or native session.
///
/// This control performs executable/file measurements, socket binds and entropy
/// reads. Its trial bank windows do not establish native whole-memory admission.
pub(super) fn report_startup_fixture() -> (
    Scene,
    Rc<std::cell::RefCell<super::PacketCompleteReportStartupHolder>>,
) {
    report_startup_fixture_with_frame(16 * 1024)
}

/// Selects the actual common finite frame limit before constructing any Source.
///
/// The 64 KiB variant deliberately retains its 512 MiB refusal coverage.
pub(super) fn report_startup_fixture_with_frame(
    frame_bytes: u64,
) -> (
    Scene,
    Rc<std::cell::RefCell<super::PacketCompleteReportStartupHolder>>,
) {
    use crucible::node_adapters::cnp::{
        PacketCompleteAckHostRegistrationPlan, PacketCompleteEffectReceiverGroup,
    };
    use crucible_node_contract::{Extensions, ResourceLimits, U64};
    use std::os::unix::{fs::MetadataExt, net::UnixDatagram};

    let mut scene = Scene::report_startup(frame_bytes);
    let mut launches = authority::launches(&scene);
    for launch in &mut launches {
        launch.controller_uid = U64::new(u64::from(std::fs::metadata("/proc/self").unwrap().uid()));
    }
    let receivers =
        std::array::from_fn(|member| UnixDatagram::bind(&launches[member].effects).unwrap());
    let (group, reader) = PacketCompleteEffectReceiverGroup::from_original_receivers(receivers);
    for member in 0..3 {
        let source = Rc::get_mut(&mut scene.roster.sources[member]).unwrap();
        source
            .bind_original_effect_receiver(
                Rc::clone(&group),
                member,
                launches[member].effects.clone(),
            )
            .unwrap();
        let mut features = source.installation().provider.extensions_supported.clone();
        features.push(id("cnp.core/1"));
        features.push(id("cnp.extension-negotiation/1"));
        features.sort();
        features.dedup();
        let mut envelope_extensions = vec![
            "cnp.extension-negotiation/1".into(),
            "source-owned.packet-canonical-ack-admission/5".into(),
            "source-owned.packet-input/4".into(),
            crucible_node_provider::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.into(),
        ];
        envelope_extensions.sort();
        source
            .reserve_original_canonical_ack_peer_birth(
                &launches[member],
                id(&format!("report-startup-private-{member}")),
                PacketCompleteAckHostRegistrationPlan {
                    connection_id: id(&format!("report-startup-connection-{member}")),
                    features,
                    extensions: Vec::new(),
                    envelope_extensions,
                },
                64 * 1024 * 1024,
            )
            .unwrap();
    }
    let (graph_owner, authority) = authority::try_collection_authority(&scene, launches).unwrap();
    let plan = Rc::new(authority.collection_plan().unwrap());
    let resources = ResourceLimits {
        cpu_budget_ns: U64::new(3_000_000_000),
        memory_bytes: U64::new(512 * 1024 * 1024),
        writable_bytes: U64::new(1024 * 1024),
        processes: U64::new(3),
        descriptors: U64::new(128),
        pending_events: U64::new(16),
        content_bytes: U64::new(512 * 1024 * 1024),
        maximum_operations: U64::new(64),
        extensions: Extensions::new(),
    };
    let holder = super::PacketCompleteReportStartupHolder::install_original_scene(
        graph_owner,
        authority,
        plan,
        resources,
        group,
        reader,
    )
    .unwrap();
    (scene, holder)
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
    let hello_bytes = crucible_node_provider::native_hello::OriginalNativeHelloJournal::reservation_requested_storage_data(65_536).unwrap();
    // These values are test declaration data, not physical bank allocation.
    PacketNative5StorageSelection {
        storage: PacketNative5StorageLimits {
            snapshot_bytes: U64::new(65536),
            control_snapshot_bytes: U64::new(65536),
            protocol_snapshot_bytes: U64::new(1024 * 1024),
            frame_bank_bytes: U64::new(1024 * 1024),
            frames_per_direction: U64::new(64),
            // The same fixed native constructor retains two Slot descriptors
            // beside the literal framed bytes. Declare their complete layout.
            hello_bytes: U64::new(u64::try_from(hello_bytes).unwrap()),
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

#[path = "tests/report_frame_fit.rs"]
mod report_frame_fit;

/// Supplies only source declarations to the production installer controls.
/// No report verdict, native owner, readiness or permission is serialized.
pub(super) fn installed_scene_declaration() -> (Scene, serde_json::Value) {
    let scene = Scene::report_startup(16 * 1024);
    let declaration = scene_declaration(&scene);
    (scene, declaration)
}

fn scene_declaration(scene: &Scene) -> serde_json::Value {
    use crucible_node_contract::{Extensions, ResourceLimits, U64};
    let participant = |member: usize| {
        let source = &scene.roster.sources[member];
        let one = source.installation();
        serde_json::json!({
            "installation": {
                "provider":one.provider, "profile":one.profile, "descriptor":one.descriptor,
                "binding":one.binding, "capabilities":one.capabilities, "exact_facet":one.exact_facet,
                "guarantees":one.guarantees, "owner":one.owner, "realize":one.realize,
                "admission":one.admission, "transaction":one.transaction, "gate":one.gate,
                "admission_receipt":one.admission_receipt, "world_binding_hash":one.world_binding_hash,
                "receipt_schema":one.receipt_schema, "maximum_operations":one.maximum_operations,
                "maximum_result_bytes":one.maximum_result_bytes,
                "maximum_authorization_bytes":one.maximum_authorization_bytes,
                "maximum_semantic_bytes":one.maximum_semantic_bytes,
            },
            "program":scene.world.programmes[member],
            "storage":source.selected_storage_selection().unwrap(),
            "capture_profile":source.selected_capture_profile().unwrap(),
            "protocol_metadata":source.selected_protocol_metadata_limits().unwrap().unwrap(),
        })
    };
    let content: Vec<_> = scene.world.content.iter().map(|(reference,bytes)| {
        serde_json::json!({"reference":reference,"bytes":crucible_node_contract::Bytes::new(bytes.clone())})
    }).collect();
    let declaration = serde_json::json!({
        "schema":"crucible.complete-scene.installation/1",
        "measurements":[scene.measurements,scene.measurements,scene.measurements],
        "participants":[participant(0),participant(1),participant(2)],
        "host":scene.world.host_source.selection(), "world":scene.world.world,
        "requirements":scene.world.requirements, "coordinator":scene.world.coordinator,
        "content":content,
        "resources":ResourceLimits {
            cpu_budget_ns:U64::new(3_000_000_000),memory_bytes:U64::new(512*1024*1024),
            writable_bytes:U64::new(1024*1024),processes:U64::new(3),descriptors:U64::new(128),
            pending_events:U64::new(16),content_bytes:U64::new(512*1024*1024),maximum_operations:U64::new(64),extensions:Extensions::new(),
        },
        "maximum_initial_bytes":64*1024*1024,"maximum_native_rows":8192,
        "maximum_operations":64,"maximum_retained_outputs":64,"write_watchdog_ms":1000,
    });
    declaration
}

#[path = "tests/native_roundtrip.rs"]
pub(super) mod native_roundtrip;

#[path = "tests/schema_roster.rs"]
mod schema_roster;

#[test]
fn original_callback_parent_guard_keeps_graph_revocation_after_scope_comparison() {
    use crucible::node_contract::RuntimeError;

    let scene = Scene::new();
    let mut owner = PacketCompleteGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    let policy = owner.graph_policy().unwrap();
    let requirements =
        canonical::json_hash("cnp.admission-requirements.v1", &scene.world.requirements).unwrap();
    policy
        .authenticate_original_initial_callback_parents_data()
        .unwrap();
    policy
        .authenticate_original_initial_callback_scope_roster_data(
            &scene.roster,
            &scene.world.host_source,
            &scene.world.world,
            &requirements,
        )
        .unwrap();

    owner.revoke();

    // Immutable scope equality is DATA and remains insufficient after revocation.
    policy
        .authenticate_original_initial_callback_scope_roster_data(
            &scene.roster,
            &scene.world.host_source,
            &scene.world.world,
            &requirements,
        )
        .unwrap();
    assert!(matches!(
        policy.authenticate_original_initial_callback_parents_data(),
        Err(RuntimeError::ForeignAuthority),
    ));
    assert!(matches!(
        policy.read_original_initial_callback_data(),
        Err(RuntimeError::ForeignAuthority),
    ));
    assert!(owner.graph_policy().is_err());
}

#[test]
fn original_callback_parent_guard_keeps_actual_host_owner_revocation() {
    use crucible::node_contract::RuntimeError;

    let mut scene = Scene::new();
    let owner = PacketCompleteGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    let policy = owner.graph_policy().unwrap();
    policy
        .authenticate_original_initial_callback_parents_data()
        .unwrap();

    scene.world._host_owner.revoke();

    assert!(matches!(
        policy.authenticate_original_initial_callback_parents_data(),
        Err(RuntimeError::ForeignAuthority),
    ));
    assert!(matches!(
        policy.read_original_initial_callback_data(),
        Err(RuntimeError::ForeignAuthority),
    ));
    assert!(owner.graph_policy().is_err());
}
