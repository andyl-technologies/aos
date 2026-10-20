//! Tests complete static coordinator contracts without native capture authority.
//!
//! The retained edition-four template came from the actual connected144 scene.
//! Request/provider fixtures below are inert controlled records. Source-five
//! selections are freshly assembled test metadata, never an installed factory.

// crucible-lint: allow panic-shortcut -- Assertion panics are the control verdict.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::bodies::RealizeRequest;

#[path = "legacy_four.rs"]
mod legacy_four;

fn id(name: &str) -> Id {
    Id::new(name).unwrap()
}

fn content(value: &impl Serialize) -> ContentRef {
    canonical::content_ref(
        &canonical::canonical_json(&json!(value)).unwrap(),
        "application/json",
    )
    .unwrap()
}

fn four() -> super::super::PacketConnectedCoordinatorInstallation {
    let template: Value = serde_json::from_slice(include_bytes!("template-four.json")).unwrap();
    let world: WorldBinding = serde_json::from_value(template["world"].clone()).unwrap();
    let mut participants = Vec::new();
    for index in 0..3 {
        let node = &template["nodes"][index];
        let descriptor: NodeDescriptor =
            serde_json::from_value(node["descriptor"].clone()).unwrap();
        let binding: NodeBinding = serde_json::from_value(node["binding"].clone()).unwrap();
        let owner: OwnerBinding =
            serde_json::from_value(template["owner_bindings"][index].clone()).unwrap();
        let configuration_schema = binding
            .compatibility
            .implementation
            .formats
            .iter()
            .find(|schema| {
                schema.id.as_str()
                    == if index == 0 {
                        "source-owned.packet-program/1"
                    } else {
                        "source-owned.packet-connected-program/4"
                    }
            })
            .unwrap()
            .clone();
        let profile = NodeManifest {
            schema_version: 1,
            profile_id: id(if index == 0 {
                "source-owned.packet-emitter-world/3"
            } else {
                "source-owned.packet-connected/4"
            }),
            roles: descriptor.roles.clone(),
            configuration_schema,
            allowed_combinations_ref: descriptor.model_ref.clone(),
            port_templates_ref: content(&descriptor.ports),
            state_formats: vec![],
            operation_facets: binding.compatibility.operating_contract.facets.clone(),
            extensions: Extensions::new(),
        };
        let provider = ProviderManifest {
            schema_version: 1,
            provider_id: id("source-owned.packet-provider"),
            implementation: binding.compatibility.implementation.clone(),
            protocol_versions: vec![id("CNP/1")],
            supported_profiles: vec![profile],
            extensions_supported: vec![
                id("cnp.control-evidence/1"),
                id(super::super::super::input::PACKET_INPUT_FEATURE),
            ],
            qualification_refs: binding.compatibility.qualification_refs.clone(),
            extensions: Extensions::new(),
        };
        let realization = RealizationManifest {
            schema_version: 1,
            realization_id: binding.authority.realization_id.clone(),
            provider_manifest: content(&provider),
            descriptors: vec![descriptor.clone()],
            bindings: vec![binding.clone()],
            owners: vec![owner.owner.clone()],
            owner_bindings: vec![owner],
            extensions: Extensions::new(),
        };
        let realize = RealizeRequest {
            realization_id: realization.realization_id.clone(),
            configuration: descriptor.configuration_ref.clone(),
            requested_node_ids: vec![descriptor.id.clone()],
            resource_limits: serde_json::from_value(json!({
                "cpu_budget_ns":"1","memory_bytes":"1","writable_bytes":"1","processes":"1",
                "descriptors":"1","pending_events":"1","content_bytes":"1","maximum_operations":"64","extensions":{}
            })).unwrap(), extensions: Extensions::new(),
        };
        participants.push(PacketControlSelection {
            provider,
            realization,
            realize,
            prepared_token: id(&format!("preparation-{index}")),
            admission: id(&format!("admission-{index}")),
            transaction: id(&format!("transaction-{index}")),
            gate: id(&format!("gate-{index}")),
            world: world.identity().unwrap(),
            admission_receipt: binding.authority.host_receipt.clone(),
        });
    }
    let initial_node = template["nodes"][3].clone();
    let host = PacketConnectedHostSelection {
        descriptor: serde_json::from_value(initial_node["descriptor"].clone()).unwrap(),
        binding: serde_json::from_value(initial_node["binding"].clone()).unwrap(),
        owner: serde_json::from_value(template["owner_bindings"][3].clone()).unwrap(),
        prepared_token: id("original-host-preparation"),
        initial_node,
    };
    super::super::PacketConnectedCoordinatorInstallation {
        schema: "source-owned.packet-connected-coordinator-installation/4".into(),
        participants,
        host,
        template,
    }
}

fn complete_guarantees(value: &Value) -> GuaranteeProfile {
    let mut guarantees: GuaranteeProfile = serde_json::from_value(value.clone()).unwrap();
    guarantees.repeatability = Repeatability::Unqualified;
    guarantees.capture_scope = CaptureScope::CompleteModel;
    guarantees.continuation = Continuation::Exact;
    guarantees.durable_restart = true;
    guarantees
}

fn five() -> PacketNative5CoordinatorInstallation {
    five_with_ack_emitter(None, None)
}

fn five_with_ack_emitter(
    confirmation: Option<&crate::reference_packet::service::PacketNative5ConfirmationSelection>,
    ack_emitter: Option<&crate::reference_packet::service::PacketNative5AckEmitterSelection>,
) -> PacketNative5CoordinatorInstallation {
    let four = four();
    let mut result = PacketNative5CoordinatorInstallation {
        schema: contracts::PACKET_NATIVE5_COORDINATOR_SCHEMA.into(),
        participants: four.participants,
        host: four.host,
        template: four.template,
    };
    for (index, peer) in result.participants.iter_mut().enumerate() {
        let guarantees = complete_guarantees(&result.template["nodes"][index]["guarantees"]);
        let binding = &mut peer.realization.bindings[0].compatibility;
        binding.guarantees_ref = content(&guarantees);
        binding.operating_contract.facets = [
            contracts::PACKET_COMPLETE_LINEAGE_PROFILE,
            "source-owned.packet-exact/5",
        ]
        .into_iter()
        .map(|name| FacetSelection {
            id: id(name),
            version: 5,
            configuration_ref: binding.configuration_ref.clone(),
            guarantees_ref: binding.guarantees_ref.clone(),
            extensions: Extensions::new(),
        })
        .collect();
        let receipt = contracts::complete_packet_receipt_schema().unwrap();
        let continuation = contracts::complete_packet_continuation_schema().unwrap();
        let ingress = contracts::complete_packet_ingress_schema().unwrap();
        let profile = &mut peer.provider.supported_profiles[0];
        profile.profile_id = id(contracts::PACKET_COMPLETE_LINEAGE_PROFILE);
        profile.configuration_schema.definition = receipt.definition.clone();
        profile.operation_facets = binding.operating_contract.facets.clone();
        profile.state_formats = vec![continuation.clone()];
        binding.profile_ref = content(profile);
        binding.implementation.implementation_id = id(contracts::PACKET_NATIVE5_IMPLEMENTATION);
        binding
            .implementation
            .formats
            .retain(|schema| schema.id.as_str() == "source-owned.packet-octets/1");
        binding.implementation.formats.extend([
            receipt,
            continuation,
            ingress,
            profile.configuration_schema.clone(),
        ]);
        binding
            .implementation
            .formats
            .sort_by(|a, b| a.id.cmp(&b.id));
        peer.provider.implementation = binding.implementation.clone();
        peer.provider
            .extensions_supported
            .push(id(contracts::PACKET_COMPLETE_LINEAGE_FEATURE));
        peer.provider.extensions_supported.sort();
        let declaration = contracts::complete_packet_ack_emitter_declaration(
            &peer.provider,
            confirmation,
            ack_emitter,
        )
        .unwrap();
        peer.provider = declaration.provider;
        peer.realization.bindings[0].compatibility.implementation =
            peer.provider.implementation.clone();
        peer.realization.provider_manifest = content(&peer.provider);
        let hash = peer.realization.bindings[0].identity().unwrap();
        peer.realization.owner_bindings[0].node_bindings[0].binding_hash = hash;
        result.template["nodes"][index]["binding"] = json!(peer.realization.bindings[0]);
        result.template["nodes"][index]["guarantees"] = json!(guarantees);
        result.template["nodes"][index]["facets"] = json!(["exact-execution", "preservation"]);
    }
    let host = &mut result.host;
    let definition = contracts::complete_host_definition().unwrap();
    let guarantees = complete_guarantees(&host.initial_node["guarantees"]);
    let configuration = host_configuration(host, &result.template).unwrap();
    host.descriptor.configuration_ref = configuration.clone();
    host.descriptor.initialization_ref = configuration.clone();
    host.binding.compatibility.configuration_ref = configuration;
    host.descriptor.model_ref = definition.clone();
    let binding = &mut host.binding.compatibility;
    binding.descriptor_hash = host.descriptor.identity().unwrap();
    binding.profile_ref = definition.clone();
    binding.guarantees_ref = content(&guarantees);
    binding.operating_contract.facets = vec![FacetSelection {
        id: id("source-owned.host-scheduling-original-lineage/2"),
        version: 2,
        configuration_ref: binding.configuration_ref.clone(),
        guarantees_ref: binding.guarantees_ref.clone(),
        extensions: Extensions::new(),
    }];
    binding.implementation.implementation_id = id("source-owned.host-scheduling-owner/2");
    binding.implementation.formats = vec![
        contracts::complete_host_continuation_schema().unwrap(),
        SchemaRef {
            id: id("source-owned.host-scheduling-complete-preparation/2"),
            version: 2,
            definition,
            extensions: Extensions::new(),
        },
    ];
    binding
        .implementation
        .formats
        .sort_by(|a, b| a.id.cmp(&b.id));
    host.initial_node["descriptor"] = json!(host.descriptor);
    host.initial_node["binding"] = json!(host.binding);
    host.initial_node["guarantees"] = json!(guarantees);
    host.initial_node["facets"] = json!(["preservation"]);
    host.owner.node_bindings[0].binding_hash = host.binding.identity().unwrap();
    result.template["nodes"][3] = host.initial_node.clone();

    let mut world: WorldBinding = serde_json::from_value(result.template["world"].clone()).unwrap();
    for (index, peer) in result.participants.iter().enumerate() {
        world.node_bindings[index].binding_hash = peer.realization.bindings[0].identity().unwrap();
        result.template["owner_bindings"][index] = json!(peer.realization.owner_bindings[0]);
    }
    world.node_bindings[3].binding_hash = host.binding.identity().unwrap();
    result.template["owner_bindings"][3] = json!(host.owner);
    result.template["world"] = json!(world);
    let identity = world.identity().unwrap();
    result.template["activation"]["world_binding_hash"] = json!(identity);
    for peer in &mut result.participants {
        peer.world = identity.clone();
    }
    result
}

#[test]
fn old_four_matches_retained_original_predicates() {
    let baseline = four();
    let local = baseline.participants[0].clone();
    baseline.validate(&local).unwrap();
    let mut cases = vec![baseline.clone()];
    for field in [
        "clock",
        "scheduler",
        "preparations",
        "owners",
        "owner_bindings",
    ] {
        let mut changed = baseline.clone();
        changed.template[field] = json!(null);
        cases.push(changed);
    }
    let mut changed = baseline.clone();
    changed.schema = contracts::PACKET_NATIVE5_COORDINATOR_SCHEMA.into();
    cases.push(changed);
    let mut changed = baseline.clone();
    changed.template["nodes"][0]["facets"] = json!(["exact-execution", "preservation"]);
    cases.push(changed);
    let mut changed = baseline.clone();
    changed.participants.swap(0, 1);
    cases.push(changed);
    for selected in cases {
        let encoded = canonical::canonical_json(&json!(selected)).unwrap();
        let original: legacy_four::PacketConnectedCoordinatorInstallation =
            serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            selected.validate(&local).is_ok(),
            original.validate(&local).is_ok()
        );
        assert_eq!(
            canonical::canonical_json(&json!(selected)).unwrap(),
            canonical::canonical_json(&json!(original)).unwrap()
        );
    }
}

#[test]
fn complete_five_static_whole_tuple_and_changed_contract_refusal() {
    let selected = five();
    let local = selected.participants[0].clone();
    for (index, peer) in selected.participants.iter().enumerate() {
        peer.provider.validate().unwrap();
        peer.realization.validate().unwrap();
        peer.realize.validate().unwrap();
        validate_native(peer, &selected.template["nodes"][index]).unwrap();
    }
    validate_host(&selected.host, &selected.template).unwrap();
    selected.validate(&local).unwrap();
    selected.validate_template(&selected.template).unwrap();
    let bytes = canonical::canonical_json(&json!(selected)).unwrap();
    assert_eq!(
        PacketNative5CoordinatorInstallation::decode(&bytes, &local).unwrap(),
        selected
    );
    let mut changed = selected.clone();
    changed.schema = "source-owned.packet-connected-coordinator-installation/4".into();
    assert!(changed.validate(&local).is_err());
    let mut changed = selected.clone();
    changed.participants[1]
        .provider
        .extensions_supported
        .retain(|feature| feature.as_str() != contracts::PACKET_COMPLETE_LINEAGE_FEATURE);
    assert!(changed.validate(&local).is_err());
    let mut changed = selected.clone();
    changed.template["nodes"][1]["guarantees"]["continuation"] = json!("unsupported");
    assert!(changed.validate(&local).is_err());
    let mut changed = selected.clone();
    changed
        .host
        .binding
        .compatibility
        .implementation
        .formats
        .clear();
    assert!(changed.validate(&local).is_err());
    let mut changed = selected.clone();
    changed.template["nodes"][1]["facets"] = json!(["exact-execution"]);
    assert!(changed.validate(&local).is_err());
    let mut changed = selected.clone();
    changed.template["preparations"] = json!([{}]);
    assert!(changed.validate(&local).is_err());
    assert!(
        PacketNative5CoordinatorInstallation::decode(
            &vec![b' '; PACKET_CONNECTED_COORDINATOR_BYTES + 1],
            &local
        )
        .is_err()
    );
}

struct PreparationFixture {
    bytes: Vec<u8>,
    staged: ActivateRequest,
    ready: ContentRef,
    manifest: ActivationManifest,
}

fn preparations(
    peers: &[PacketControlSelection],
    host: &PacketConnectedHostSelection,
    template: &Value,
) -> PreparationFixture {
    let local = &peers[0];
    let mut owners = Vec::new();
    let mut rows = Vec::new();
    let mut local_ready = None;
    for index in 0..4 {
        let (descriptor, binding, owner, token) = if index < peers.len() {
            let peer = &peers[index];
            (
                &peer.realization.descriptors[0],
                &peer.realization.bindings[0],
                &peer.realization.owners[0],
                &peer.prepared_token,
            )
        } else {
            (
                &host.descriptor,
                &host.binding,
                &host.owner.owner,
                &host.prepared_token,
            )
        };
        let receipt = content(&json!({"inert_fixture_owner":owner.id}));
        if index == 0 {
            local_ready = Some(receipt.clone());
        }
        let prepared = PreparedOwner {
            owner_id: owner.id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            owner_generation: binding.authority.owner_generation,
            prepared_token: token.clone(),
            binding_hashes: vec![binding.identity().unwrap()],
            ready_receipt: receipt.clone(),
            extensions: Extensions::new(),
        };
        rows.push(json!({"node":descriptor.id,"readiness":{
            "owners":[{"owner":owner.id,"incarnation":binding.authority.incarnation_id,
                "generation":binding.authority.owner_generation}],
            "boundary":template["clock"],"state_inventory":receipt,"ready_receipt":receipt},
            "prepared_owners":[prepared]}));
        owners.push(prepared);
    }
    let mut body = template.clone();
    body["preparations"] = json!(rows);
    let bytes = canonical::canonical_json(&body).unwrap();
    let staged = ActivateRequest {
        admission_id: local.admission.clone(),
        activation_id: serde_json::from_value(template["activation"]["activation_id"].clone())
            .unwrap(),
        world_generation: serde_json::from_value(template["activation"]["generation"].clone())
            .unwrap(),
        prepared_token: local.prepared_token.clone(),
        world_binding_hash: local.world.clone(),
        gate_id: local.gate.clone(),
        extensions: Extensions::new(),
    };
    let manifest = ActivationManifest {
        schema_version: 1,
        transaction_id: local.transaction.clone(),
        activation_id: staged.activation_id.clone(),
        world_generation: staged.world_generation,
        gate_id: staged.gate_id.clone(),
        world_binding_hash: staged.world_binding_hash.clone(),
        owners,
        coordinator_state_ref: content(&body),
        extensions: Extensions::new(),
    };
    PreparationFixture {
        bytes,
        staged,
        ready: local_ready.unwrap(),
        manifest,
    }
}

#[test]
fn whole_original_preparation_conjunction_keeps_initial_and_restore_routes_separate() {
    let four = four();
    let local = &four.participants[0];
    let encoded = canonical::canonical_json(&json!(four)).unwrap();
    let legacy =
        legacy_four::PacketConnectedCoordinatorInstallation::decode(&encoded, local).unwrap();
    let fixture = preparations(&four.participants, &four.host, &four.template);
    four.validate_body(&fixture.bytes).unwrap();
    legacy.validate_body(&fixture.bytes).unwrap();
    four.authenticate_staged(
        &fixture.bytes,
        local,
        &fixture.staged,
        &fixture.ready,
        &fixture.manifest,
    )
    .unwrap();
    legacy
        .authenticate_staged(
            &fixture.bytes,
            local,
            &fixture.staged,
            &fixture.ready,
            &fixture.manifest,
        )
        .unwrap();

    let five = five();
    let local = &five.participants[0];
    let fixture = preparations(&five.participants, &five.host, &five.template);
    five.validate_body(&fixture.bytes).unwrap();
    five.authenticate_staged(
        &fixture.bytes,
        local,
        &fixture.staged,
        &fixture.ready,
        &fixture.manifest,
    )
    .unwrap();
    let mut changed = fixture.manifest.clone();
    changed.owners.pop();
    assert!(
        five.authenticate_staged(
            &fixture.bytes,
            local,
            &fixture.staged,
            &fixture.ready,
            &changed
        )
        .is_err()
    );
    let mut changed: Value = serde_json::from_slice(&fixture.bytes).unwrap();
    changed["preparations"][1]["prepared_owners"][0]["prepared_token"] = json!("another-original");
    let changed = canonical::canonical_json(&changed).unwrap();
    assert!(
        five.authenticate_staged(
            &changed,
            local,
            &fixture.staged,
            &fixture.ready,
            &fixture.manifest
        )
        .is_err()
    );

    // An actual captured nonzero cut is not an initial coordinator template.
    // It needs the separate opaque target/factory admission, never zeroing here.
    let mut changed = five.template.clone();
    changed["clock"] = json!(Position::new(U64::new(6), U64::new(0), Phase::Delivery));
    assert!(five.validate_template(&changed).is_err());
    let mut changed = five.clone();
    changed.host.descriptor.configuration_ref = four.host.descriptor.configuration_ref.clone();
    assert!(changed.validate(local).is_err());
}

#[path = "native5_codec_tests.rs"]
mod native5_codec_tests;

#[test]
fn selected_canonical_ack_declaration_binds_all_original_tuples_before_hashes() {
    use crate::reference_packet::service::{
        PacketNative5AckEmitterSelection, PacketNative5ConfirmationSelection,
    };
    let old = five();
    let absent = five_with_ack_emitter(None, None);
    assert_eq!(
        canonical::canonical_json(&json!(old)).unwrap(),
        canonical::canonical_json(&json!(absent)).unwrap()
    );
    let selected = five_with_ack_emitter(
        Some(&PacketNative5ConfirmationSelection::AfterProtocolPoll5),
        Some(&PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
    );
    selected.validate(&selected.participants[0]).unwrap();
    let schema =
        crate::reference_packet::service::ack_emitter::native_canonical_blob_ack_schema().unwrap();
    let admission_schema =
        crate::reference_packet::service::ack_emitter::native_canonical_ack_admission_schema()
            .unwrap();
    for peer in &selected.participants {
        assert!(peer.provider.implementation.formats.contains(&schema));
        assert!(
            peer.provider
                .implementation
                .formats
                .contains(&admission_schema)
        );
        assert!(peer.provider.extensions_supported.iter().any(|id| id.as_str() == crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE));
        assert_eq!(
            peer.provider.implementation,
            peer.realization.bindings[0].compatibility.implementation
        );
        assert!(peer.provider.extensions_supported.iter().any(|id| id.as_str() == crate::reference_packet::service::ack_emitter::PACKET_NATIVE_CANONICAL_ACK_FEATURE));
    }
}

pub(super) fn original_native5_controller_scope() -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    native5_codec_tests::original_native5_controller_scope()
}

pub(super) fn original_canonical_ack_controller_scope() -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    native5_codec_tests::original_canonical_ack_controller_scope()
}

#[cfg(test)]
pub(super) fn original_canonical_ack_controller_scope_with_identity_suffix(
    suffix: Option<&str>,
) -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    native5_codec_tests::original_canonical_ack_controller_scope_with_identity_suffix(suffix)
}

#[test]
fn complete_installation_extent_counts_full_rosters_without_widening_old_blob_limits() {
    let mut installation = five();
    // Exercise the actual typed serializer and component guards. Repeated rows
    // make this size-only DATA fixture semantically invalid; the full validator
    // must still independently reject them. No native authority is constructed.
    for peer in &mut installation.participants {
        let formats = peer.provider.implementation.formats.clone();
        for _ in 0..8 {
            peer.provider.implementation.formats.extend(formats.clone());
        }
        peer.realization.bindings[0].compatibility.implementation =
            peer.provider.implementation.clone();
    }
    let actual = crate::connection::serialized_credit(&installation, usize::MAX).unwrap();
    assert!(actual > PACKET_CONNECTED_COORDINATOR_BYTES);
    assert!(actual <= PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES);
    installation
        .view()
        .validate_installation_extent_data(actual)
        .unwrap();
    assert!(matches!(
        installation
            .view()
            .validate_installation_extent_data(actual - 1),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
    assert!(
        installation
            .validate(&installation.participants[0])
            .is_err()
    );

    let legacy = super::super::PacketConnectedCoordinatorInstallation {
        schema: "source-owned.packet-connected-coordinator-installation/4".into(),
        participants: installation.participants.clone(),
        host: installation.host.clone(),
        template: installation.template.clone(),
    };
    assert!(matches!(
        legacy.validate(&legacy.participants[0]),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
    assert_eq!(PACKET_CONNECTED_COORDINATOR_BYTES, 131_072);
}

#[test]
fn complete_installation_keeps_each_foreign_component_and_control_template_bounded() {
    let mut foreign = five();
    let feature = Id::new("x".repeat(128)).unwrap();
    foreign.participants[1].provider.extensions_supported = vec![feature; 600];
    assert!(
        crate::connection::serialized_credit(
            &foreign,
            PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES
        )
        .is_ok()
    );
    assert!(matches!(
        foreign
            .view()
            .validate_installation_extent_data(PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));

    let mut host = five();
    host.host.initial_node = Value::String("x".repeat(super::super::LIMIT));
    assert!(matches!(
        host.view()
            .validate_installation_extent_data(PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));

    let mut template = five();
    template.template = Value::String("x".repeat(PACKET_CONNECTED_COORDINATOR_BYTES));
    assert!(matches!(
        template
            .view()
            .validate_installation_extent_data(PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
}
