//! Defines a reusable semantic unit separately from original live enrollment.
//!
//! ```text
//! unit-v1 = source package | exact regenerated profiles | native limits |
//!           fixed direct route | admitted operation scope | measured context
//! witness = original binding/world | session/incarnation/PID | raw receipts
//! ```
//!
//! Qualification and live authority are deliberately separate records. This
//! codec selects named immutable fields; it never strips keys from a binding,
//! rewrites an original reference, or treats a caller-accepted claim as authority.

use std::{collections::BTreeMap, rc::Rc};

use crucible_node_contract::*;
use crucible_node_provider::{ProviderError, handshake::Limits};
use serde::{Deserialize, Serialize};

use super::{
    installation::SourcePublicReferenceInstallation, package::InstalledPublicReferencePackage,
    world::CandidateWorldDefinition,
};
use crate::node_qualification::QualificationUnit;

/// Retains independently selected source/tool/oracle/environment bytes.
///
/// The source-owned issuer must authenticate these objects before accepting a
/// claim. Constructing this data record does not authenticate its provenance.
pub(super) struct UnitSourceObjects {
    pub(super) environment: Vec<u8>,
    pub(super) harness: Vec<u8>,
    pub(super) fixtures: Vec<u8>,
    pub(super) specification: Vec<u8>,
}

/// Retains the exact closed semantic identity and its bounded raw objects.
pub(super) struct SemanticQualificationUnit {
    pub(super) identity: QualificationUnit,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeSemantics {
    provider: ProviderSemantics,
    selected_features: IdSet,
    descriptor: NodeDescriptor,
    implementation: ImplementationIdentity,
    operating_contract: OperatingContract,
    capabilities: CapabilityProfile,
    guarantees: GuaranteeProfile,
    owner: OwnerRef,
    node_manifest: NodeManifest,
    configuration_ref: ContentRef,
    content_possession_schema: SchemaRef,
    resource_limits: ResourceLimits,
    transport_limits: Limits,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderSemantics {
    schema_version: Version,
    provider_id: Id,
    implementation: ImplementationIdentity,
    protocol_versions: IdSet,
    supported_profiles: Vec<NodeManifest>,
    extensions_supported: IdSet,
    extensions: Extensions,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealizationSemantics {
    schema: String,
    nodes: Vec<NodeSemantics>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectRouteSemantics {
    id: Id,
    producer: Endpoint,
    consumer: Endpoint,
    interface_id: Id,
    payload_schema: SchemaRef,
    latency_ps: U64,
    visibility: String,
    maximum_payload_bytes: U64,
    maximum_pending_events: U64,
    maximum_pending_bytes: U64,
    custody_domain: Id,
    capture_owner: Id,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationSemantics {
    schema: String,
    ordering_profile: String,
    maximum_microsteps: U64,
    execution: String,
    input_cut: String,
    publication: String,
    capture: String,
    repeatability: Repeatability,
    external_ingress: bool,
    faults: Vec<Id>,
    assertions: Vec<Id>,
    controller_operations: Vec<String>,
    route: DirectRouteSemantics,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImplementationSemantics {
    schema: String,
    package: ContentRef,
    implementations: Vec<ImplementationIdentity>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortSemantics {
    schema: String,
    ports: Vec<(Id, Vec<PortDescriptor>)>,
    roles: Vec<(Id, Vec<Id>)>,
}

impl SemanticQualificationUnit {
    /// Measures the immutable source-selected pair without hashing live authority.
    pub(super) fn build(
        package: Rc<InstalledPublicReferencePackage>,
        definition: &CandidateWorldDefinition,
        installations: &[SourcePublicReferenceInstallation],
        sources: UnitSourceObjects,
    ) -> Result<Self, ProviderError> {
        if installations.len() != 2
            || installations[0].profile.descriptor.id.as_str() != "consumer"
            || installations[1].profile.descriptor.id.as_str() != "producer"
        {
            return Err(ProviderError::Correlation(
                "semantic unit requires fixed direct pair",
            ));
        }
        definition.authenticate_fixed_world(
            Rc::clone(&package),
            installations[0].bootstrap.quantum_ps,
            installations[0].bootstrap.host_budget_ns,
        )?;
        let mut nodes = Vec::with_capacity(2);
        let mut objects = BTreeMap::new();
        for (index, installed) in installations.iter().enumerate() {
            installed.bootstrap.validate()?;
            let measured = package
                .profile(
                    installed.profile.descriptor.id.clone(),
                    installed.profile.owner.id.clone(),
                    installed.bootstrap.quantum_ps,
                    installed.bootstrap.host_budget_ns,
                    index == 1,
                )
                .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))?;
            // This comparison regenerates immutable semantics directly. It does
            // not normalize the original candidate's binding or qualifications.
            if installed.package.identity() != package.identity()
                || measured.descriptor != installed.profile.descriptor
                || measured.implementation != installed.profile.implementation
                || measured.operating_contract != installed.profile.operating_contract
                || measured.capabilities != installed.profile.capabilities
                || measured.guarantees != installed.profile.guarantees
                || measured.owner != installed.profile.owner
                || measured.node_manifest != installed.profile.node_manifest
                || measured.provider_manifest != installed.profile.provider_manifest
                || measured.configuration_ref != installed.profile.configuration_ref
                || measured.content_possession_schema != installed.profile.content_possession_schema
                || measured.contents != installed.profile.contents
                || installed.bootstrap.node_id != measured.descriptor.id
                || installed.bootstrap.owner_id != measured.owner.id
            {
                return Err(ProviderError::Correlation(
                    "semantic profile differs from installed source",
                ));
            }
            for content in measured.content_objects() {
                content.reference.verify(&content.bytes)?;
                insert(
                    &mut objects,
                    content.reference.clone(),
                    content.bytes.clone(),
                )?;
            }
            let provider = ProviderSemantics {
                schema_version: measured.provider_manifest.schema_version,
                provider_id: measured.provider_manifest.provider_id.clone(),
                implementation: measured.provider_manifest.implementation.clone(),
                protocol_versions: measured.provider_manifest.protocol_versions.clone(),
                supported_profiles: measured.provider_manifest.supported_profiles.clone(),
                extensions_supported: measured.provider_manifest.extensions_supported.clone(),
                extensions: measured.provider_manifest.extensions.clone(),
            };
            nodes.push(NodeSemantics {
                provider,
                selected_features: required_features()?,
                descriptor: measured.descriptor,
                implementation: measured.implementation,
                operating_contract: measured.operating_contract,
                capabilities: measured.capabilities,
                guarantees: measured.guarantees,
                owner: measured.owner,
                node_manifest: measured.node_manifest,
                configuration_ref: measured.configuration_ref,
                content_possession_schema: measured.content_possession_schema,
                resource_limits: installed.bootstrap.resource_limits.clone(),
                transport_limits: installed.bootstrap.limits,
            });
        }
        if nodes[0].operating_contract.resolution_ps != nodes[1].operating_contract.resolution_ps {
            return Err(ProviderError::Correlation(
                "semantic direct-pair quantum differs",
            ));
        }
        let producer = nodes[1]
            .descriptor
            .ports
            .iter()
            .find(|port| port.id.as_str() == "data")
            .ok_or(ProviderError::Correlation("semantic producer port absent"))?;
        let output = producer
            .lanes
            .iter()
            .find(|lane| lane.id.as_str() == "output")
            .ok_or(ProviderError::Correlation(
                "semantic producer output absent",
            ))?;
        let consumer = nodes[0]
            .descriptor
            .ports
            .iter()
            .find(|port| port.id.as_str() == "data")
            .ok_or(ProviderError::Correlation("semantic consumer port absent"))?;
        let input = consumer
            .lanes
            .iter()
            .find(|lane| lane.id.as_str() == "input")
            .ok_or(ProviderError::Correlation("semantic consumer input absent"))?;
        if input.payload_schema != output.payload_schema
            || consumer.interface_id != producer.interface_id
            || nodes[0].owner.state_domain_ids.len() != 1
        {
            return Err(ProviderError::Correlation("semantic direct route differs"));
        }
        let contracts = put(
            &mut objects,
            &OperationSemantics {
                schema: "crucible.reference.operation-unit.v1".into(),
                ordering_profile: "superdense-v1".into(),
                maximum_microsteps: U64::new(1024),
                execution: "phase-zero-quantized-checksum-v1".into(),
                input_cut: "next-physical-boundary-control-exclusive-v1".into(),
                publication: "completed-window-boundary-publication-v1".into(),
                capture: "none".into(),
                repeatability: Repeatability::Nondeterministic,
                external_ingress: false,
                faults: Vec::new(),
                assertions: Vec::new(),
                controller_operations: [
                    "discover",
                    "realize",
                    "admit",
                    "arm",
                    "world_activate",
                    "observe",
                    "stage_input",
                    "quantum_begin",
                    "quantum_close",
                    "consume_ack",
                    "retire",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                route: DirectRouteSemantics {
                    id: Id::new("connection/producer/consumer")?,
                    producer: Endpoint {
                        node_id: nodes[1].descriptor.id.clone(),
                        port_id: producer.id.clone(),
                        lane_id: output.id.clone(),
                    },
                    consumer: Endpoint {
                        node_id: nodes[0].descriptor.id.clone(),
                        port_id: consumer.id.clone(),
                        lane_id: input.id.clone(),
                    },
                    interface_id: producer.interface_id.clone(),
                    payload_schema: output.payload_schema.clone(),
                    latency_ps: U64::new(0),
                    visibility: "boundary-sampling-v1".into(),
                    maximum_payload_bytes: U64::new(4096),
                    maximum_pending_events: U64::new(1),
                    maximum_pending_bytes: U64::new(4096),
                    custody_domain: nodes[0].owner.state_domain_ids[0].clone(),
                    capture_owner: nodes[0].owner.id.clone(),
                },
            },
        )?;
        let implementation = put(
            &mut objects,
            &ImplementationSemantics {
                schema: "crucible.reference.implementation-unit.v1".into(),
                package: package.identity().clone(),
                implementations: nodes
                    .iter()
                    .map(|node| node.implementation.clone())
                    .collect(),
            },
        )?;
        let descriptors = put(
            &mut objects,
            &nodes
                .iter()
                .map(|node| &node.descriptor)
                .collect::<Vec<_>>(),
        )?;
        let port_profiles = put(
            &mut objects,
            &PortSemantics {
                schema: "crucible.reference.port-unit.v1".into(),
                ports: nodes
                    .iter()
                    .map(|node| (node.descriptor.id.clone(), node.descriptor.ports.clone()))
                    .collect(),
                roles: nodes
                    .iter()
                    .map(|node| (node.descriptor.id.clone(), node.descriptor.roles.clone()))
                    .collect(),
            },
        )?;
        let realization = put(
            &mut objects,
            &RealizationSemantics {
                schema: "crucible.reference.realization-unit.v1".into(),
                nodes,
            },
        )?;
        let identity = QualificationUnit {
            implementation,
            realization,
            descriptors,
            contracts,
            port_profiles,
            environment: put_source(&mut objects, sources.environment)?,
            harness: put_source(&mut objects, sources.harness)?,
            fixtures: put_source(&mut objects, sources.fixtures)?,
            specification: put_source(&mut objects, sources.specification)?,
        };
        Ok(Self { identity, objects })
    }
}

fn put(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &impl Serialize,
) -> Result<ContentRef, ProviderError> {
    let bytes =
        canonical::canonical_json(&serde_json::to_value(value).map_err(ContractError::from)?)?;
    put_source(objects, bytes)
}

fn put_source(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    bytes: Vec<u8>,
) -> Result<ContentRef, ProviderError> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(ProviderError::ResourceExhausted(
            "semantic unit object geometry",
        ));
    }
    let value = canonical::parse_json(&bytes, 1024 * 1024)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(ProviderError::Frame(
            "semantic source object is not canonical JSON",
        ));
    }
    let reference = canonical::content_ref(&bytes, "application/json")?;
    insert(objects, reference.clone(), bytes)?;
    Ok(reference)
}

fn insert(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    reference: ContentRef,
    bytes: Vec<u8>,
) -> Result<(), ProviderError> {
    if reference.length.get() != bytes.len() as u64 || reference.length.get() > 1024 * 1024 {
        return Err(ProviderError::ResourceExhausted(
            "semantic content geometry",
        ));
    }
    let existing_total = objects
        .values()
        .try_fold(0usize, |total, object| total.checked_add(object.len()))
        .ok_or(ProviderError::ResourceExhausted(
            "semantic content sum overflow",
        ))?;
    if existing_total
        .checked_add(bytes.len())
        .is_none_or(|total| total > 8 * 1024 * 1024)
    {
        return Err(ProviderError::ResourceExhausted(
            "semantic unit aggregate geometry",
        ));
    }
    if let Some(original) = objects.get(&reference) {
        if original != &bytes {
            return Err(ProviderError::Correlation(
                "semantic object identity collision",
            ));
        }
        return Ok(());
    }
    if objects
        .keys()
        .any(|original| original.hash == reference.hash && original != &reference)
    {
        return Err(ProviderError::Correlation(
            "semantic object metadata collision",
        ));
    }
    objects.insert(reference, bytes);
    Ok(())
}

/// Pins the complete fixed source-selected feature population.
pub(super) fn required_features() -> Result<IdSet, ProviderError> {
    Ok(vec![
        Id::new("cnp.control-evidence/1")?,
        Id::new("cnp.core/1")?,
    ])
}
