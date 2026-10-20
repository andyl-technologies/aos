//! Retains independent inert coordinator fixtures for actual model construction controls.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::bodies::RealizeRequest;
use crate::reference_packet::continuation_contracts as contracts;
use crate::reference_packet::coordinator::{
    PacketConnectedCoordinatorInstallation, PacketConnectedHostSelection,
};
use serde_json::json;
fn refused() -> ProviderError {
    ProviderError::Correlation("native5 fixture host domain shape")
}
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

fn four() -> PacketConnectedCoordinatorInstallation {
    let template: Value = serde_json::from_slice(include_bytes!(
        "../../coordinator/continuation/template-four.json"
    ))
    .unwrap();
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
                id(crate::reference_packet::input::PACKET_INPUT_FEATURE),
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
    PacketConnectedCoordinatorInstallation {
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

pub(in super::super) fn five() -> PacketNative5CoordinatorInstallation {
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

fn host_configuration(
    host: &PacketConnectedHostSelection,
    template: &Value,
) -> Result<ContentRef, ProviderError> {
    let rows = template["connections"].as_array().ok_or_else(refused)?;
    if rows.is_empty() || rows.len() > 4 {
        return Err(refused());
    }
    let mut domains = std::collections::BTreeSet::new();
    let mut connections = Vec::new();
    for row in rows {
        let pair = row
            .as_array()
            .filter(|pair| pair.len() == 2)
            .ok_or_else(refused)?;
        let connection: Id =
            serde_json::from_value(pair[0].clone()).map_err(ContractError::from)?;
        connection.validate()?;
        let selected: Vec<Id> = serde_json::from_value(pair[1]["state_domain_ids"].clone())
            .map_err(ContractError::from)?;
        if selected.len() != 1
            || !domains.insert(selected[0].clone())
            || !host.owner.owner.state_domain_ids.contains(&selected[0])
        {
            return Err(refused());
        }
        selected[0].validate()?;
        connections.push(json!({"connection":connection,"domain":selected[0]}));
    }
    let coordinator = host
        .owner
        .owner
        .state_domain_ids
        .iter()
        .filter(|domain| !domains.contains(*domain))
        .collect::<Vec<_>>();
    if coordinator.len() != 1 {
        return Err(refused());
    }
    let value = json!({"schema":"source-owned.host-scheduling-complete-configuration/2",
        "definition":contracts::complete_host_definition()?,
        "domains":{"coordinator":coordinator[0],"connections":connections}});
    Ok(canonical::content_ref(
        &canonical::canonical_json(&value)?,
        "application/json",
    )?)
}
