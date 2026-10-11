//! Regenerates one fixed three-source collecting world before native launch.
//!
//! The public data has no admission or execution authority. It contains exactly
//! two boundary-sampled producer routes and the independently selected native
//! source profiles. The owning installed fixture must authenticate every actual
//! realization and the same original refused plan before collection admission.

use super::{InstalledTypedReaderPackage, TypedReaderProgramme};
use crucible::node_admission::*;
use crucible_node_contract::*;
use crucible_node_provider::{ProviderError, reference_service::ReferenceProfile};
use std::collections::BTreeMap;

/// Retains the exact finite source-selected collection world as immutable data.
///
/// This record cannot expose an admitted graph or authorize Child. All fields
/// are private and regenerated from the fixed programme and measured profiles.
pub struct TypedReaderCollectionWorld {
    pub(super) world: WorldBinding,
    pub(super) descriptors: Vec<NodeDescriptor>,
    pub(super) requirements: ScenarioRequirements,
    pub(super) ownership: OwnershipPolicy,
    pub(super) content: BTreeMap<ContentRef, Vec<u8>>,
}

impl TypedReaderCollectionWorld {
    /// Regenerates the whole three-source world before private launch issuance.
    ///
    /// Qualification references are constructor data, not accepted evidence.
    /// The host must independently retain and authenticate its complete Refused
    /// audit and plan; source installation checks the actual private launches.
    ///
    /// # Errors
    /// Refuses foreign package/programme, unsorted or insufficient qualifications,
    /// profile/domain/port changes, whole record credit or canonical failures.
    pub fn prepare(
        package: &InstalledTypedReaderPackage,
        programme: &TypedReaderProgramme,
        qualifications: &[ContentRef],
    ) -> Result<Self, ProviderError> {
        if package.identity() != programme.package()
            || qualifications.len() < 2
            || qualifications.len() > 8
            || qualifications.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid());
        }
        let mut profiles = Vec::new();
        profiles.try_reserve_exact(3).map_err(|_| invalid())?;
        for (index, peer) in programme.peers.iter().enumerate() {
            profiles.push(
                package
                    .profile(
                        peer.node.clone(),
                        peer.owner.clone(),
                        U64::new(1000),
                        U64::new(1_000_000_000),
                        index < 2,
                    )
                    .map_err(|_| invalid())?,
            );
        }
        build(programme, &profiles, qualifications)
    }

    /// Borrows the complete original immutable world without an admission seal.
    pub fn world(&self) -> &WorldBinding {
        &self.world
    }

    /// Borrows the complete source-generated immutable policy bodies.
    pub fn objects(&self) -> &BTreeMap<ContentRef, Vec<u8>> {
        &self.content
    }
}

fn build(
    programme: &TypedReaderProgramme,
    profiles: &[ReferenceProfile],
    qualifications: &[ContentRef],
) -> Result<TypedReaderCollectionWorld, ProviderError> {
    if profiles.len() != 3
        || qualifications.len() < 2
        || qualifications.len() > 8
        || qualifications.windows(2).any(|pair| pair[0] >= pair[1])
        || profiles
            .iter()
            .zip(&programme.peers)
            .any(|(profile, peer)| {
                profile.descriptor.id != peer.node || profile.owner.id != peer.owner
            })
    {
        return Err(invalid());
    }
    // All three complete public profile bodies are charged together before any
    // object or world projection is retained. Native/private launches are absent.
    super::programme::count(
        &(BorrowedProfiles(profiles), qualifications),
        4 * 1024 * 1024,
    )?;
    let proof = programme.reference();
    let mut content = BTreeMap::new();
    content.insert(proof.clone(), programme.bytes().to_vec());
    for profile in profiles {
        profile.preflight_retention(1024 * 1024)?;
        for object in profile.content_objects() {
            object.reference.verify(&object.bytes)?;
            insert(&mut content, &object.reference, &object.bytes)?;
        }
    }
    let mut references = Vec::new();
    let mut domains = Vec::new();
    let mut objects = Vec::new();
    let mut captures = Vec::new();
    for profile in profiles {
        let peer = programme.peer(&profile.descriptor.id)?;
        // Live authority is excluded from NodeBinding.identity. This temporary
        // data only computes the durable projection; actual native authority
        // must come from the separately issued private bootstrap at admission.
        let authority = LiveAuthority {
            schema_version: 1,
            session_id: Id::new(format!("typed-fixture/{}/session", peer.node))?,
            incarnation_id: peer.incarnation.clone(),
            realization_id: Id::new(format!("typed-fixture/{}/realization", peer.node))?,
            activation_id: None,
            world_generation: U64::new(0),
            owner_generation: U64::new(1),
            input_epoch: Id::new(format!("typed-fixture/{}/input", peer.node))?,
            host_receipt: proof.clone(),
            extensions: Extensions::new(),
        };
        let (binding, _) = profile.bind_qualified(authority, qualifications)?;
        references.push(NodeBindingRef {
            node_id: peer.node.clone(),
            binding_hash: binding.identity()?,
            extensions: Extensions::new(),
        });
        let [domain] = profile.owner.state_domain_ids.as_slice() else {
            return Err(invalid());
        };
        domains.push(StateDomain {
            id: domain.clone(),
            capture_owner_id: peer.owner.clone(),
            execution_owner_ids: vec![peer.owner.clone()],
            future_affecting: true,
        });
        objects.push(StateObject {
            id: peer.node.clone(),
            node_ids: vec![peer.node.clone()],
            future_affecting: true,
            state: ObjectState::Mutable {
                domain_id: domain.clone(),
            },
        });
        captures.push(OwnerCapturePolicy {
            owner_id: peer.owner.clone(),
            complete_model: false,
            unchanged_cut: false,
            exact_continuation: false,
            durable_restart: false,
            isolated_fork: false,
            dependencies: Vec::new(),
            cut_procedure_ref: proof.clone(),
        });
    }
    let consumer = &profiles[2];
    let mut connections = Vec::new();
    for producer in &profiles[..2] {
        let id = Id::new(format!(
            "typed-fixture/route/{}/{}",
            producer.descriptor.id, consumer.descriptor.id
        ))?;
        let port = producer
            .descriptor
            .ports
            .iter()
            .find(|port| port.id.as_str() == "data")
            .ok_or_else(invalid)?;
        let lane = port
            .lanes
            .iter()
            .find(|lane| lane.id.as_str() == "output")
            .ok_or_else(invalid)?;
        let domain = consumer.owner.state_domain_ids[0].clone();
        let policy = ConnectionPolicy {
            schema_version: 1,
            maximum_payload_bytes: U64::new(4096),
            maximum_pending_events: U64::new(1),
            maximum_pending_bytes: U64::new(4096),
            visibility: VisibilityConversion::BoundarySampling {
                contract_ref: proof.clone(),
            },
            delivery: ConnectionDelivery::Fixed {
                latency_ps: U64::new(0),
            },
            causal_proof_ref: proof.clone(),
            state_domain_ids: vec![domain.clone()],
        };
        let policy_ref = put(&mut content, &policy)?;
        connections.push(ConnectionDescriptor {
            schema_version: 1,
            id: id.clone(),
            producer: Endpoint {
                node_id: producer.descriptor.id.clone(),
                port_id: Id::new("data")?,
                lane_id: Id::new("output")?,
            },
            consumer: Endpoint {
                node_id: consumer.descriptor.id.clone(),
                port_id: Id::new("data")?,
                lane_id: Id::new("input")?,
            },
            interface_id: port.interface_id.clone(),
            features: Vec::new(),
            payload_schema: lane.payload_schema.clone(),
            minimum_latency_ps: U64::new(0),
            policy_ref,
            capture_owner_id: consumer.owner.id.clone(),
            extensions: Extensions::new(),
        });
        let mut nodes = vec![
            producer.descriptor.id.clone(),
            consumer.descriptor.id.clone(),
        ];
        nodes.sort();
        objects.push(StateObject {
            id,
            node_ids: nodes,
            future_affecting: true,
            state: ObjectState::Mutable { domain_id: domain },
        });
    }
    references.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    domains.sort_by(|a, b| a.id.cmp(&b.id));
    objects.sort_by(|a, b| a.id.cmp(&b.id));
    captures.sort_by(|a, b| a.owner_id.cmp(&b.owner_id));
    connections.sort_by(|a, b| a.id.cmp(&b.id));
    let ownership = OwnershipPolicy {
        schema_version: 1,
        domains,
        objects,
        internal_dependencies: Vec::new(),
        capture_owners: captures,
        inventory_proof_ref: proof.clone(),
    };
    let coordinator = CoordinatorPolicy {
        schema_version: 1,
        state_closure_ref: proof.clone(),
        maximum_microsteps_per_instant: U64::new(1024),
        same_time_closure: Vec::new(),
        operational_policy_ref: proof.clone(),
        external_inputs: Vec::new(),
    };
    let mut nodes: Vec<_> = profiles
        .iter()
        .map(|profile| profile.descriptor.id.clone())
        .collect();
    nodes.sort();
    let requirements = ScenarioRequirements {
        accepted_quantized_nodes: nodes.clone(),
        accepted_nondeterministic_nodes: nodes.clone(),
        accepted_limited_state_nodes: nodes,
        accepted_visibility_conversions: connections
            .iter()
            .map(|connection| connection.id.clone())
            .collect(),
        ..ScenarioRequirements::default()
    };
    let ownership_ref = put(&mut content, &ownership)?;
    let coordinator_contract_ref = put(&mut content, &coordinator)?;
    let scenario_ref = put(&mut content, &requirements)?;
    let mut initialization: Vec<_> = profiles
        .iter()
        .map(|profile| {
            (
                &profile.descriptor.id,
                &profile.descriptor.initialization_ref,
            )
        })
        .collect();
    initialization.sort_by(|a, b| a.0.cmp(b.0));
    let initialization_ref = put(&mut content, &initialization)?;
    let world = WorldBinding {
        schema_version: 1,
        scenario_ref,
        node_bindings: references,
        connections,
        ownership_ref,
        coordinator_contract_ref,
        ordering_profile: "superdense-v1".into(),
        initialization_ref,
        extensions: Extensions::new(),
    };
    world.validate()?;
    let mut descriptors: Vec<_> = profiles
        .iter()
        .map(|profile| profile.descriptor.clone())
        .collect();
    descriptors.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(TypedReaderCollectionWorld {
        world,
        descriptors,
        requirements,
        ownership,
        content,
    })
}

fn put(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &impl serde::Serialize,
) -> Result<ContentRef, ProviderError> {
    let bytes = super::source_fixture::launch::encode(value, 1024 * 1024)?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    insert(content, &reference, &bytes)?;
    Ok(reference)
}
fn insert(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    reference.verify(bytes)?;
    if let Some(old) = content.get(reference) {
        return if old == bytes { Ok(()) } else { Err(invalid()) };
    }
    content.insert(reference.clone(), bytes.to_vec());
    Ok(())
}
fn invalid() -> ProviderError {
    ProviderError::Correlation(
        "typed collecting world differs from fixed original source programme",
    )
}

struct BorrowedProfiles<'a>(&'a [ReferenceProfile]);

impl serde::Serialize for BorrowedProfiles<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for profile in self.0 {
            sequence.serialize_element(&(
                &profile.descriptor,
                &profile.implementation,
                &profile.operating_contract,
                &profile.capabilities,
                &profile.guarantees,
                &profile.owner,
                &profile.node_manifest,
                &profile.provider_manifest,
                &profile.configuration_ref,
                &profile.content_possession_schema,
                &profile.contents,
            ))?;
        }
        sequence.end()
    }
}

#[cfg(test)]
// Inert source data controls cannot enroll a kernel tuple or admit a graph.
#[path = "collection_world_tests.rs"]
mod tests;
