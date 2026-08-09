//! Executable world declarations addressed by signal-driven fault bindings.
//!
//! The ordinary VM, I/O-node, and point-to-point link declarations describe
//! processes and scheduler participants. This module describes the stable
//! hardware and networking objects inside that world which fault selectors may
//! address. These declarations are immutable, validated, and included in world
//! identity; runtime state is stored by the owning adapter instead.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::*;

/// Hard maximum number of declarations in any one world fault registry table.
pub const HARD_WORLD_FAULT_DECLARATIONS_PER_KIND: usize = 262_144;
/// Hard maximum number of references carried by one world fault declaration.
pub const HARD_WORLD_FAULT_REFERENCES_PER_DECLARATION: usize = 16_384;

/// One exact fault-addressable stage traversed by a routed network frame.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldNetworkRouteFaultTarget {
    /// Fully resolved world object that owns the opportunity.
    pub target: ResolvedFaultTarget,
    /// Closed operation performed at this route stage.
    pub operation: FaultOperation,
    /// Direction visible to opportunity filters.
    pub direction: FaultDirection,
}

impl WorldNetworkRouteFaultTarget {
    /// Returns the ordered phases exposed by this route stage.
    #[must_use]
    pub const fn phases(&self) -> &'static [FaultPhase] {
        match self.target.kind() {
            FaultTargetKind::NetworkInterface => &[
                FaultPhase::Produce,
                FaultPhase::Admit,
                FaultPhase::Queue,
                FaultPhase::Resolve,
                FaultPhase::Deliver,
            ],
            FaultTargetKind::NetworkSegment => &[
                FaultPhase::Admit,
                FaultPhase::Queue,
                FaultPhase::Resolve,
                FaultPhase::Deliver,
            ],
            FaultTargetKind::NetworkMedium | FaultTargetKind::NetworkQueue => {
                &[FaultPhase::Admit, FaultPhase::Queue, FaultPhase::Resolve]
            }
            FaultTargetKind::NetworkForwarder | FaultTargetKind::NetworkPath => {
                &[FaultPhase::Admit, FaultPhase::Resolve]
            }
            FaultTargetKind::NetworkAttachment | FaultTargetKind::NetworkContact => {
                &[FaultPhase::Resolve]
            }
            _ => &[],
        }
    }
}

/// Complete immutable world registry used by fault selectors and adapters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldFaultTopology {
    /// Named fault domains which resolve to finite typed target sets.
    pub fault_domains: Vec<WorldFaultDomain>,
    /// Network interfaces owned by VM endpoints.
    pub network_interfaces: Vec<WorldNetworkInterface>,
    /// Directed-capable physical or logical network segments.
    pub network_segments: Vec<WorldNetworkSegment>,
    /// Shared or point-to-point transmission media.
    pub network_media: Vec<WorldNetworkMedium>,
    /// Switches, routers, gateways, and other forwarding elements.
    pub network_forwarders: Vec<WorldNetworkForwarder>,
    /// Bounded queues owned by interfaces, media, or forwarders.
    pub network_queues: Vec<WorldNetworkQueue>,
    /// Ordered routes through declared segments and forwarders.
    pub network_paths: Vec<WorldNetworkPath>,
    /// Association state machines for intermittently attached endpoints.
    pub network_attachments: Vec<WorldNetworkAttachment>,
    /// Scheduled contact plans for delay/disruption-tolerant links.
    pub network_contact_plans: Vec<WorldNetworkContactPlan>,
    /// Closed policy and lookup declarations referenced by network effects.
    pub network_policy_artifacts: Vec<WorldNetworkPolicyArtifact>,
    /// Mobile endpoints whose truth trajectory is supplied by a signal.
    pub mobile_endpoints: Vec<WorldMobileEndpoint>,
    /// Durability and media contracts for deterministic block/9p nodes.
    pub storage_devices: Vec<WorldStorageFaultDevice>,
    /// Storage controllers, namespaces, and access paths.
    pub storage_controllers: Vec<WorldStorageController>,
    /// Storage arrays and their member/path topology.
    pub storage_arrays: Vec<WorldStorageArray>,
    /// Closed policy declarations referenced by storage and 9p effects.
    pub storage_policy_artifacts: Vec<WorldStoragePolicyArtifact>,
    /// Live-QEMU capability contracts for VM nodes.
    pub node_capabilities: Vec<WorldNodeFaultCapabilities>,
}

impl WorldFaultTopology {
    /// Returns one scenario-owned network policy declaration by stable ID.
    #[must_use]
    pub fn network_policy_artifact(
        &self,
        id: &FaultObjectId,
    ) -> Option<&WorldNetworkPolicyArtifact> {
        self.network_policy_artifacts
            .binary_search_by(|candidate| candidate.id.cmp(id))
            .ok()
            .map(|index| &self.network_policy_artifacts[index])
    }

    /// Returns one scenario-owned storage policy declaration by stable ID.
    #[must_use]
    pub fn storage_policy_artifact(
        &self,
        id: &FaultObjectId,
    ) -> Option<&WorldStoragePolicyArtifact> {
        self.storage_policy_artifacts
            .binary_search_by(|candidate| candidate.id.cmp(id))
            .ok()
            .map(|index| &self.storage_policy_artifacts[index])
    }

    /// Returns whether the registry contains no fault-addressable declarations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Computes the content address of the complete canonical registry.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError::Codec`] if the closed registry cannot
    /// be encoded by its derived canonical JSON representation.
    pub fn content_hash(&self) -> Result<ContentHash, WorldFaultTopologyError> {
        let mut bytes = b"crucible.model.world-fault-topology.v1\0".to_vec();
        bytes.extend_from_slice(&self.canonical_bytes()?);
        Ok(ContentHash::from_bytes(&bytes))
    }

    /// Encodes the canonical registry payload used by world persistence.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError::Codec`] if the closed derived schema
    /// cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorldFaultTopologyError> {
        serde_json::to_vec(self).map_err(|error| WorldFaultTopologyError::Codec(error.to_string()))
    }

    /// Validates and canonicalizes a complete world fault registry.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError`] for duplicate IDs, excessive
    /// collections, dangling references, self-references, invalid geometry, or
    /// a sensor-backed field which is specification-only in schema v3.
    pub fn admit(mut self, world: &World) -> Result<Self, WorldFaultTopologyError> {
        hard_count(&self.fault_domains, "fault domains", 65_536)?;
        hard_count(&self.network_interfaces, "network interfaces", 65_536)?;
        hard_count(&self.network_segments, "network segments", 262_144)?;
        hard_count(&self.network_media, "network media", 16_384)?;
        hard_count(&self.network_forwarders, "network forwarders", 32_768)?;
        hard_count(&self.network_queues, "network queues", 262_144)?;
        expand_direct_segment_paths(&mut self, world)?;
        hard_count(&self.network_paths, "network paths", 262_144)?;
        hard_count(&self.network_attachments, "network attachments", 65_536)?;
        hard_count(&self.network_contact_plans, "network contact plans", 65_536)?;
        hard_count(
            &self.network_policy_artifacts,
            "network policy artifacts",
            HARD_NETWORK_POLICY_ARTIFACTS,
        )?;
        hard_count(&self.mobile_endpoints, "mobile endpoints", 65_536)?;
        hard_count(&self.storage_devices, "storage devices", 16_384)?;
        hard_count(&self.storage_controllers, "storage controllers", 16_384)?;
        hard_count(&self.storage_arrays, "storage arrays", 16_384)?;
        hard_count(
            &self.storage_policy_artifacts,
            "storage policy artifacts",
            HARD_STORAGE_POLICY_ARTIFACTS,
        )?;
        hard_count(&self.node_capabilities, "node capabilities", 16_384)?;
        canonicalize_by_id(&mut self.fault_domains, WorldFaultDomain::id)?;
        canonicalize_by_id(&mut self.network_interfaces, WorldNetworkInterface::id)?;
        canonicalize_by_id(&mut self.network_segments, WorldNetworkSegment::id)?;
        canonicalize_by_id(&mut self.network_media, WorldNetworkMedium::id)?;
        canonicalize_by_id(&mut self.network_forwarders, WorldNetworkForwarder::id)?;
        canonicalize_by_id(&mut self.network_queues, WorldNetworkQueue::id)?;
        canonicalize_by_id(&mut self.network_paths, WorldNetworkPath::id)?;
        canonicalize_by_id(&mut self.network_attachments, WorldNetworkAttachment::id)?;
        canonicalize_by_id(&mut self.network_contact_plans, WorldNetworkContactPlan::id)?;
        self.network_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        require(
            !self
                .network_policy_artifacts
                .windows(2)
                .any(|pair| pair[0].id == pair[1].id),
            "network policy artifact identity",
        )?;
        for artifact in &self.network_policy_artifacts {
            artifact.validate()?;
        }
        for artifact in &self.network_policy_artifacts {
            match &artifact.artifact {
                NetworkPolicyArtifactKind::ContactPlan { intervals } => {
                    for interval in intervals {
                        require(
                            self.network_policy_artifact(&interval.capacity_profile)
                                .is_some_and(|capacity| {
                                    capacity.artifact.class()
                                        == NetworkPolicyArtifactClass::ServiceCurve
                                }),
                            "network contact capacity profile",
                        )?;
                    }
                }
                NetworkPolicyArtifactKind::MediumAccess(policy) => {
                    if let Some(key) = &policy.arbitration_key {
                        require(
                            self.network_policy_artifact(key).is_some_and(|key| {
                                key.artifact.class() == NetworkPolicyArtifactClass::PacketKey
                            }),
                            "network medium arbitration key",
                        )?;
                    }
                    if let Some(transform) = policy
                        .contention
                        .as_ref()
                        .and_then(|contention| contention.undetected_transform.as_ref())
                    {
                        require(
                            self.network_policy_artifact(transform)
                                .is_some_and(|transform| {
                                    matches!(
                                        &transform.artifact,
                                        NetworkPolicyArtifactKind::ByteTemplate { bytes }
                                            if !bytes.is_empty()
                                    )
                                }),
                            "network medium undetected transform",
                        )?;
                    }
                }
                NetworkPolicyArtifactKind::Overflow {
                    typed_error: Some(typed_error),
                    ..
                } => {
                    require(
                        self.network_policy_artifact(typed_error)
                            .is_some_and(|result| {
                                matches!(
                                    result.artifact.class(),
                                    NetworkPolicyArtifactClass::ControlResult
                                        | NetworkPolicyArtifactClass::TypedResponse
                                )
                            }),
                        "network overflow typed error",
                    )?;
                }
                _ => {}
            }
        }
        canonicalize_by_id(&mut self.mobile_endpoints, WorldMobileEndpoint::id)?;
        canonicalize_by_id(&mut self.storage_devices, WorldStorageFaultDevice::id)?;
        canonicalize_by_id(&mut self.storage_controllers, WorldStorageController::id)?;
        canonicalize_by_id(&mut self.storage_arrays, WorldStorageArray::id)?;
        self.storage_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        require(
            !self
                .storage_policy_artifacts
                .windows(2)
                .any(|pair| pair[0].id == pair[1].id),
            "storage policy artifact identity",
        )?;
        for artifact in &self.storage_policy_artifacts {
            artifact.validate()?;
        }
        for artifact in &self.storage_policy_artifacts {
            match &artifact.artifact {
                StoragePolicyArtifactKind::Cache(StoragePolicyCache {
                    dirty_eviction: StoragePolicyDirtyEviction::Fail { result },
                    ..
                }) => {
                    validate_storage_policy_reference(
                        &self,
                        result,
                        StoragePolicyArtifactClass::TypedResult,
                        "storage nested typed result",
                    )?;
                    require(
                        self.storage_policy_artifact(result)
                            .is_some_and(|artifact| {
                                matches!(
                                    artifact.artifact,
                                    StoragePolicyArtifactKind::TypedResult(
                                        StoragePolicyTypedResult::Block { result }
                                    ) if result != StoragePolicyResult::Success
                                )
                            }),
                        "storage cache failure result",
                    )?;
                }
                StoragePolicyArtifactKind::DuplicateCompletion(
                    StoragePolicyDuplicateCompletion::ProtocolError { result },
                ) => {
                    validate_storage_policy_reference(
                        &self,
                        result,
                        StoragePolicyArtifactClass::TypedResult,
                        "storage nested typed result",
                    )?;
                    require(
                        self.storage_policy_artifact(result)
                            .is_some_and(|artifact| {
                                !matches!(
                                    artifact.artifact,
                                    StoragePolicyArtifactKind::TypedResult(
                                        StoragePolicyTypedResult::Block {
                                            result: StoragePolicyResult::Success
                                        }
                                    )
                                )
                            }),
                        "storage duplicate protocol error result",
                    )?;
                }
                StoragePolicyArtifactKind::DuplicateCompletion(
                    StoragePolicyDuplicateCompletion::Reset { transition_policy },
                ) => {
                    validate_storage_policy_reference(
                        &self,
                        transition_policy,
                        StoragePolicyArtifactClass::ControllerTransition,
                        "storage duplicate controller reset",
                    )?;
                    require(
                        self.storage_policy_artifact(transition_policy)
                            .is_some_and(|artifact| {
                                matches!(
                                    artifact.artifact,
                                    StoragePolicyArtifactKind::ControllerTransition(
                                        StoragePolicyControllerTransition {
                                            transition: StorageControllerTransition::Reset,
                                            ..
                                        }
                                    )
                                )
                            }),
                        "storage duplicate reset transition policy",
                    )?;
                }
                StoragePolicyArtifactKind::ControllerTransition(policy) => {
                    validate_storage_policy_reference(
                        &self,
                        &policy.failure_result,
                        StoragePolicyArtifactClass::TypedResult,
                        "storage reset failure result",
                    )?;
                    require(
                        self.storage_policy_artifact(&policy.failure_result)
                            .is_some_and(|artifact| {
                                matches!(
                                    artifact.artifact,
                                    StoragePolicyArtifactKind::TypedResult(
                                        StoragePolicyTypedResult::Block { result }
                                    ) if result != StoragePolicyResult::Success
                                )
                            }),
                        "storage reset failure result",
                    )?;
                }
                _ => {}
            }
        }
        canonicalize_by_id(&mut self.node_capabilities, WorldNodeFaultCapabilities::id)?;

        for domain in &mut self.fault_domains {
            canonicalize_set(&mut domain.targets, "fault domain targets")?;
        }
        for interface in &mut self.network_interfaces {
            canonicalize_set(&mut interface.addresses, "network interface addresses")?;
            canonicalize_set(
                &mut interface.fault_domains,
                "network interface fault domains",
            )?;
        }
        for segment in &mut self.network_segments {
            canonicalize_set(&mut segment.forwarders, "network segment forwarders")?;
            canonicalize_set(&mut segment.fault_domains, "network segment fault domains")?;
        }
        for medium in &mut self.network_media {
            canonicalize_set(&mut medium.resources, "network medium resources")?;
            canonicalize_set(&mut medium.fault_domains, "network medium fault domains")?;
        }
        for forwarder in &mut self.network_forwarders {
            canonicalize_set(&mut forwarder.ports, "network forwarder ports")?;
            canonicalize_set(
                &mut forwarder.fault_domains,
                "network forwarder fault domains",
            )?;
        }
        for queue in &mut self.network_queues {
            canonicalize_set(&mut queue.fault_domains, "network queue fault domains")?;
        }
        for attachment in &mut self.network_attachments {
            canonicalize_set(&mut attachment.candidates, "network attachment candidates")?;
        }
        for storage in &mut self.storage_devices {
            canonicalize_set(&mut storage.fault_domains, "storage device fault domains")?;
        }
        for controller in &mut self.storage_controllers {
            canonicalize_by_id(&mut controller.namespaces, WorldStorageNamespace::id)?;
            canonicalize_by_id(&mut controller.paths, WorldStoragePath::id)?;
            canonicalize_set(
                &mut controller.fault_domains,
                "storage controller fault domains",
            )?;
        }
        for array in &mut self.storage_arrays {
            canonicalize_by_id(&mut array.members, WorldStorageArrayMember::id)?;
            canonicalize_by_id(&mut array.paths, WorldStoragePath::id)?;
            canonicalize_set(&mut array.fault_domains, "storage array fault domains")?;
        }
        for capabilities in &mut self.node_capabilities {
            canonicalize_by_id(&mut capabilities.registers, WorldNodeRegister::id)?;
            for register in &mut capabilities.registers {
                canonicalize_set(&mut register.model_phases, "register model phases")?;
                canonicalize_set(&mut register.side_effects, "register side effects")?;
            }
            canonicalize_by_id(&mut capabilities.address_spaces, WorldNodeAddressSpace::id)?;
            canonicalize_by_id(&mut capabilities.interrupts, WorldNodeInterrupt::id)?;
            canonicalize_by_id(&mut capabilities.clock_sources, WorldNodeClockSource::id)?;
            canonicalize_by_id(&mut capabilities.accelerators, WorldNodeAccelerator::id)?;
            for interrupt in &mut capabilities.interrupts {
                canonicalize_set(&mut interrupt.target_vcpus, "interrupt target vCPUs")?;
            }
        }

        let vm_nodes = world
            .vm_nodes()
            .iter()
            .map(|node| node.id.name.as_str())
            .collect::<BTreeSet<_>>();
        let io_nodes = world
            .io_nodes()
            .map(|node| (node.id.name.as_str(), node.kind.family()))
            .collect::<BTreeMap<_, _>>();
        let interfaces = ids(&self.network_interfaces);
        let segments = ids(&self.network_segments);
        let media = ids(&self.network_media);
        let forwarders = ids(&self.network_forwarders);
        let queues = ids(&self.network_queues);
        let fault_domains = ids(&self.fault_domains);

        for interface in &self.network_interfaces {
            require_all(
                &interface.fault_domains,
                &fault_domains,
                "network interface fault domain",
            )?;
        }

        for interface in &self.network_interfaces {
            require(
                vm_nodes.contains(interface.endpoint.as_str())
                    || forwarders.contains(&interface.endpoint),
                "network interface endpoint",
            )?;
        }
        for segment in &self.network_segments {
            require_all(
                &segment.fault_domains,
                &fault_domains,
                "network segment fault domain",
            )?;
            require(
                segment.interface_a != segment.interface_b,
                "network segment self-loop",
            )?;
            require(
                interfaces.contains(&segment.interface_a),
                "network segment interface_a",
            )?;
            require(
                interfaces.contains(&segment.interface_b),
                "network segment interface_b",
            )?;
            require(
                segment.minimum_latency_nanos > 0,
                "network segment minimum latency",
            )?;
            require(segment.mtu_bytes > 0, "network segment MTU")?;
            if let Some(reference) = &segment.medium {
                require(media.contains(reference), "network segment medium")?;
            }
            require_all(
                &segment.forwarders,
                &forwarders,
                "network segment forwarder",
            )?;
        }
        for medium in &self.network_media {
            require_all(
                &medium.fault_domains,
                &fault_domains,
                "network medium fault domain",
            )?;
            require(!medium.resources.is_empty(), "network medium resources")?;
            hard_count(&medium.resources, "network medium resources", 16_384)?;
            require(
                self.network_policy_artifacts.iter().any(|artifact| {
                    artifact.id.as_str() == medium.access_policy.as_str()
                        && artifact.artifact.class() == NetworkPolicyArtifactClass::MediumAccess
                }),
                "network medium access policy",
            )?;
        }
        for forwarder in &self.network_forwarders {
            require_all(
                &forwarder.fault_domains,
                &fault_domains,
                "network forwarder fault domain",
            )?;
            require(!forwarder.ports.is_empty(), "network forwarder ports")?;
            require_all(&forwarder.ports, &interfaces, "network forwarder port")?;
            require(
                forwarder.table_capacity > 0,
                "network forwarder table capacity",
            )?;
        }
        for queue in &self.network_queues {
            require_all(
                &queue.fault_domains,
                &fault_domains,
                "network queue fault domain",
            )?;
            require(queue.capacity_packets > 0, "network queue capacity")?;
            require(
                interfaces.contains(&queue.owner)
                    || media.contains(&queue.owner)
                    || forwarders.contains(&queue.owner),
                "network queue owner",
            )?;
        }
        for path in &self.network_paths {
            require(!path.hops.is_empty(), "network path hops")?;
            require(path.mtu_bytes > 0, "network path MTU")?;
            require(
                matches!(path.direction, FaultDirection::AToB | FaultDirection::BToA),
                "network path direction",
            )?;
            hard_count(&path.hops, "network path hops", 1_024)?;
            let mut previous_exit: Option<&SignalId> = None;
            let mut first_entry: Option<&SignalId> = None;
            let mut forwarding_ports: Option<&[SignalId]> = None;
            for hop in &path.hops {
                match hop {
                    WorldNetworkPathHop::Segment { segment, direction } => {
                        let declaration = self
                            .network_segments
                            .iter()
                            .find(|candidate| &candidate.id == segment)
                            .ok_or_else(|| invalid("network path segment"))?;
                        let (entry, exit) = match direction {
                            FaultDirection::AToB => {
                                (&declaration.interface_a, &declaration.interface_b)
                            }
                            FaultDirection::BToA => {
                                (&declaration.interface_b, &declaration.interface_a)
                            }
                            _ => return Err(invalid("network path direction")),
                        };
                        first_entry.get_or_insert(entry);
                        if let Some(ports) = forwarding_ports.take() {
                            require(ports.contains(entry), "network path forwarder egress")?;
                        } else if let Some(previous) = previous_exit {
                            require(previous == entry, "network path continuity")?;
                        }
                        previous_exit = Some(exit);
                    }
                    WorldNetworkPathHop::Forwarder { forwarder } => {
                        require(
                            forwarding_ports.is_none(),
                            "network path adjacent forwarders",
                        )?;
                        let declaration = self
                            .network_forwarders
                            .iter()
                            .find(|candidate| &candidate.id == forwarder)
                            .ok_or_else(|| invalid("network path forwarder"))?;
                        if let Some(previous) = previous_exit {
                            require(
                                declaration.ports.contains(previous),
                                "network path forwarder ingress",
                            )?;
                        }
                        forwarding_ports = Some(&declaration.ports);
                    }
                    WorldNetworkPathHop::Queue { queue } => {
                        require(queues.contains(queue), "network path queue")?;
                    }
                }
            }
            require(
                forwarding_ports.is_none(),
                "network path trailing forwarder",
            )?;
            let entry = first_entry.ok_or_else(|| invalid("network path entry"))?;
            let exit = previous_exit.ok_or_else(|| invalid("network path exit"))?;
            let entry_owner = self
                .network_interfaces
                .iter()
                .find(|interface| &interface.id == entry)
                .map(|interface| &interface.endpoint)
                .ok_or_else(|| invalid("network path entry interface"))?;
            let exit_owner = self
                .network_interfaces
                .iter()
                .find(|interface| &interface.id == exit)
                .map(|interface| &interface.endpoint)
                .ok_or_else(|| invalid("network path exit interface"))?;
            require(
                vm_nodes.contains(entry_owner.as_str()) && vm_nodes.contains(exit_owner.as_str()),
                "network path endpoint owner",
            )?;
            require(entry_owner != exit_owner, "network path endpoint self-loop")?;
            let expected_direction = if entry_owner < exit_owner {
                FaultDirection::AToB
            } else {
                FaultDirection::BToA
            };
            require(
                path.direction == expected_direction,
                "network path declared direction",
            )?;
        }
        if !self.network_interfaces.is_empty() || !self.network_segments.is_empty() {
            let interface_endpoints = self
                .network_interfaces
                .iter()
                .map(|interface| (&interface.id, &interface.endpoint))
                .collect::<BTreeMap<_, _>>();
            let mut declared_pairs = BTreeSet::new();
            for segment in &self.network_segments {
                let endpoint_a = interface_endpoints
                    .get(&segment.interface_a)
                    .ok_or_else(|| invalid("network segment interface_a"))?;
                let endpoint_b = interface_endpoints
                    .get(&segment.interface_b)
                    .ok_or_else(|| invalid("network segment interface_b"))?;
                if vm_nodes.contains(endpoint_a.as_str()) && vm_nodes.contains(endpoint_b.as_str())
                {
                    declared_pairs.insert(canonical_name_pair(
                        endpoint_a.as_str(),
                        endpoint_b.as_str(),
                    ));
                }
            }
            for path in &self.network_paths {
                let (entry, exit) = network_path_endpoint_interfaces(&self, path)?;
                let endpoint_a = interface_endpoints
                    .get(entry)
                    .ok_or_else(|| invalid("network path entry interface"))?;
                let endpoint_b = interface_endpoints
                    .get(exit)
                    .ok_or_else(|| invalid("network path exit interface"))?;
                declared_pairs.insert(canonical_name_pair(
                    endpoint_a.as_str(),
                    endpoint_b.as_str(),
                ));
            }
            let world_pairs = world
                .links()
                .iter()
                .map(|link| {
                    let (endpoint_a, endpoint_b) = link.endpoints();
                    canonical_name_pair(&endpoint_a.name, &endpoint_b.name)
                })
                .collect::<BTreeSet<_>>();
            require(
                world_pairs.is_subset(&declared_pairs),
                "network path and world link correspondence",
            )?;
        }
        for attachment in &self.network_attachments {
            require(
                interfaces.contains(&attachment.interface),
                "network attachment interface",
            )?;
            require(
                !attachment.candidates.is_empty(),
                "network attachment candidates",
            )?;
            require_all(
                &attachment.candidates,
                &segments,
                "network attachment candidate",
            )?;
            require(
                attachment.semantic_version == 1,
                "network attachment semantic version",
            )?;
            require(
                FaultObjectId::parse(attachment.technology.as_str().to_owned()).is_ok(),
                "network attachment technology",
            )?;
        }
        for plan in &self.network_contact_plans {
            require(
                vm_nodes.contains(plan.endpoint_a.as_str()),
                "contact endpoint_a",
            )?;
            require(
                vm_nodes.contains(plan.endpoint_b.as_str()),
                "contact endpoint_b",
            )?;
            require(
                plan.endpoint_a < plan.endpoint_b,
                "contact plan endpoint order",
            )?;
            require(!plan.contacts.is_empty(), "contact plan contacts")?;
            hard_count(&plan.contacts, "network contact entries", 16_777_216)?;
            let mut previous_end = 0;
            let mut contact_ids = BTreeSet::new();
            for contact in &plan.contacts {
                require(contact_ids.insert(&contact.id), "duplicate contact ID")?;
                require(contact.start_nanos < contact.end_nanos, "contact interval")?;
                require(contact.start_nanos >= previous_end, "contact ordering")?;
                previous_end = contact.end_nanos;
            }
        }
        let mut mobile_nodes = BTreeSet::new();
        for endpoint in &self.mobile_endpoints {
            require(
                vm_nodes.contains(endpoint.node.as_str()),
                "mobile endpoint node",
            )?;
            require(
                mobile_nodes.insert(&endpoint.node),
                "duplicate mobile endpoint node",
            )?;
        }
        let mut declared_storage_devices = BTreeSet::new();
        for storage in &self.storage_devices {
            require(
                declared_storage_devices.insert(&storage.device),
                "duplicate storage device contract",
            )?;
            require_all(
                &storage.fault_domains,
                &fault_domains,
                "storage device fault domain",
            )?;
            let family = io_nodes
                .get(storage.device.as_str())
                .ok_or_else(|| invalid("storage device"))?;
            require(
                matches!(
                    (family, storage.kind),
                    (WorldDeviceKind::Block, WorldStorageKind::Block)
                        | (WorldDeviceKind::NineP, WorldStorageKind::NineP)
                ),
                "storage device kind",
            )?;
            let node = world
                .io_nodes()
                .find(|node| node.id.name == storage.device.as_str())
                .ok_or_else(|| invalid("storage device"))?;
            if let WorldIoNodeKind::Block { base_length, .. } = &node.kind {
                require(
                    storage.persistence.length_bytes == *base_length,
                    "storage device length",
                )?;
            }
            storage.validate()?;
            if let WorldStorageMedia::Remote { protocol } = &storage.media {
                require(
                    self.storage_policy_artifacts.iter().any(|artifact| {
                        artifact.id.as_str() == protocol.as_str()
                            && artifact.artifact.class()
                                == StoragePolicyArtifactClass::RemoteProtocol
                    }),
                    "storage remote media protocol",
                )?;
            }
        }
        let storage_devices = self
            .storage_devices
            .iter()
            .map(|item| item.device.clone())
            .collect::<BTreeSet<_>>();
        let storage_device_contracts = self
            .storage_devices
            .iter()
            .map(|item| (item.device.as_str(), item))
            .collect::<BTreeMap<_, _>>();
        let path_policy_exists = |policy: &SignalId| {
            self.storage_policy_artifacts.iter().any(|artifact| {
                artifact.id.as_str() == policy.as_str()
                    && artifact.artifact.class() == StoragePolicyArtifactClass::Path
            })
        };
        for controller in &self.storage_controllers {
            require(
                controller.semantic_version == 1,
                "storage controller semantic version",
            )?;
            require_all(
                &controller.fault_domains,
                &fault_domains,
                "storage controller fault domain",
            )?;
            require(
                !controller.namespaces.is_empty(),
                "storage controller namespaces",
            )?;
            for namespace in &controller.namespaces {
                require(
                    storage_devices.contains(&namespace.device),
                    "storage controller namespace device",
                )?;
                let device = storage_device_contracts
                    .get(namespace.device.as_str())
                    .ok_or_else(|| invalid("storage controller namespace device"))?;
                require(
                    device.kind == WorldStorageKind::Block
                        && namespace.capacity_bytes > 0
                        && namespace.capacity_bytes <= device.persistence.length_bytes
                        && namespace
                            .capacity_bytes
                            .is_multiple_of(u64::from(device.persistence.logical_block_bytes)),
                    "storage namespace capacity and geometry",
                )?;
            }
            require(!controller.paths.is_empty(), "storage controller paths")?;
            for path in &controller.paths {
                require(path.queue_depth > 0, "storage controller path queue depth")?;
                require(
                    path_policy_exists(&path.policy),
                    "storage controller path policy",
                )?;
            }
        }
        for array in &self.storage_arrays {
            require(
                array.semantic_version == 1,
                "storage array semantic version",
            )?;
            require_all(
                &array.fault_domains,
                &fault_domains,
                "storage array fault domain",
            )?;
            require(!array.members.is_empty(), "storage array members")?;
            hard_count(&array.members, "storage array members", 4_096)?;
            require(
                array.chunk_bytes.is_power_of_two(),
                "storage array chunk geometry",
            )?;
            require(array.read_quorum > 0, "storage array read quorum")?;
            require(array.write_quorum > 0, "storage array write quorum")?;
            require(
                usize::from(array.read_quorum) <= array.members.len()
                    && usize::from(array.write_quorum) <= array.members.len(),
                "storage array quorum",
            )?;
            for member in &array.members {
                require(
                    storage_devices.contains(&member.device)
                        && storage_device_contracts
                            .get(member.device.as_str())
                            .is_some_and(|device| device.kind == WorldStorageKind::Block),
                    "storage array member device",
                )?;
            }
            let ordinals = array
                .members
                .iter()
                .map(|member| member.ordinal)
                .collect::<BTreeSet<_>>();
            require(
                ordinals.len() == array.members.len(),
                "storage array member ordinal",
            )?;
            for path in &array.paths {
                require(path.queue_depth > 0, "storage array path queue depth")?;
                require(
                    path_policy_exists(&path.policy),
                    "storage array path policy",
                )?;
            }
        }
        let mut declared_node_capabilities = BTreeSet::new();
        for capabilities in &self.node_capabilities {
            require(
                declared_node_capabilities.insert(&capabilities.node),
                "duplicate node capability contract",
            )?;
            let node = world
                .vm_nodes()
                .iter()
                .find(|node| node.id.name == capabilities.node.as_str())
                .ok_or_else(|| invalid("node capability node"))?;
            require(
                capabilities.architecture.matches_vm(node.arch),
                "node capability architecture",
            )?;
            capabilities.validate()?;
            for interrupt in &capabilities.interrupts {
                require(
                    interrupt
                        .target_vcpus
                        .iter()
                        .all(|vcpu| *vcpu < u32::from(node.smp_vcpus)),
                    "node interrupt target vCPU",
                )?;
            }
        }

        let targets = self.all_target_refs();
        for domain in &self.fault_domains {
            require(!domain.targets.is_empty(), "fault domain targets")?;
            bounded(&domain.targets, "fault domain targets")?;
            for target in &domain.targets {
                require(targets.contains(target), "fault domain target")?;
                require(
                    self.target_fault_domains(target).contains(&domain.id),
                    "fault domain inverse membership",
                )?;
            }
        }
        for target in targets {
            for domain in self.target_fault_domains(&target) {
                let declaration = self
                    .fault_domain(domain)
                    .ok_or_else(|| invalid("fault domain membership"))?;
                require(
                    declaration
                        .targets
                        .iter()
                        .any(|declared| same_target_object(declared, &target)),
                    "fault domain inverse target",
                )?;
            }
        }
        let _ = queues;
        Ok(self)
    }

    /// Returns the named fault domain, if declared.
    #[must_use]
    pub fn fault_domain(&self, id: &SignalId) -> Option<&WorldFaultDomain> {
        self.fault_domains.iter().find(|domain| &domain.id == id)
    }

    /// Returns the named network path, if declared.
    #[must_use]
    pub fn network_path(&self, id: &SignalId) -> Option<&WorldNetworkPath> {
        self.network_paths.iter().find(|path| &path.id == id)
    }

    /// Returns the directed endpoint pair traversed by a declared path.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError::Invalid`] when the path is absent or
    /// does not contain validated endpoint interfaces.
    pub fn network_path_endpoints(
        &self,
        path_version: &FaultObjectId,
        direction: FaultDirection,
    ) -> Result<(SignalId, SignalId), WorldFaultTopologyError> {
        let path = self
            .network_paths
            .iter()
            .find(|path| path.id.as_str() == path_version.as_str())
            .ok_or_else(|| invalid("network path endpoint path"))?;
        require(
            path.direction == direction,
            "network path endpoint direction",
        )?;
        let (entry, exit) = network_path_endpoint_interfaces(self, path)?;
        let entry = self
            .network_interfaces
            .iter()
            .find(|interface| &interface.id == entry)
            .ok_or_else(|| invalid("network path endpoint interface"))?;
        let exit = self
            .network_interfaces
            .iter()
            .find(|interface| &interface.id == exit)
            .ok_or_else(|| invalid("network path endpoint interface"))?;
        Ok((entry.endpoint.clone(), exit.endpoint.clone()))
    }

    /// Resolves every fault-addressable stage on one directed World link.
    ///
    /// The returned order is the physical traversal order: source interface,
    /// segment, medium resources, forwarders, attachment machines, active
    /// contacts, and destination interface. Queues and paths are not inferred
    /// from shared ownership or partial containment; they enter traversal only
    /// through an explicitly selected ordered path. Each object appears at most
    /// once. An empty fault topology returns an empty route so ordinary worlds
    /// do not acquire implicit fault objects.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError::Invalid`] when a nonempty registry
    /// does not contain exactly one segment for the endpoint pair or a
    /// validated identifier cannot be converted to a fault target.
    pub fn network_route_fault_targets(
        &self,
        source: &str,
        destination: &str,
        virtual_nanos: u64,
    ) -> Result<Vec<WorldNetworkRouteFaultTarget>, WorldFaultTopologyError> {
        self.network_route_fault_targets_with_path(source, destination, virtual_nanos, None)
    }

    /// Resolves a directed World link through one explicitly selected path.
    ///
    /// A `None` override preserves canonical lowest-ID path selection. This is
    /// the only route-resolution entry point used by a committed dynamic route
    /// transition; the selected path must still describe the same directed
    /// segment as the scheduler-validated endpoint route.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError::Invalid`] under the ordinary route
    /// errors or when `path_version` does not name a compatible declared path.
    pub fn network_route_fault_targets_with_path(
        &self,
        source: &str,
        destination: &str,
        virtual_nanos: u64,
        path_version: Option<&FaultObjectId>,
    ) -> Result<Vec<WorldNetworkRouteFaultTarget>, WorldFaultTopologyError> {
        if self.network_interfaces.is_empty() && self.network_segments.is_empty() {
            return Ok(Vec::new());
        }
        let interfaces = self
            .network_interfaces
            .iter()
            .map(|interface| (&interface.id, &interface.endpoint))
            .collect::<BTreeMap<_, _>>();
        let path_matches_endpoints = |path: &WorldNetworkPath| {
            let Ok((entry, exit)) = network_path_endpoint_interfaces(self, path) else {
                return false;
            };
            interfaces
                .get(entry)
                .is_some_and(|owner| owner.as_str() == source)
                && interfaces
                    .get(exit)
                    .is_some_and(|owner| owner.as_str() == destination)
        };
        let selected_path = match path_version {
            Some(path_version) => self
                .network_paths
                .iter()
                .find(|path| {
                    path.id.as_str() == path_version.as_str() && path_matches_endpoints(path)
                })
                .ok_or_else(|| invalid("network route path override"))?,
            None => self
                .network_paths
                .iter()
                .filter(|path| path_matches_endpoints(path))
                .min_by(|left, right| left.id.cmp(&right.id))
                .ok_or_else(|| invalid("network route path"))?,
        };
        let (source_interface, destination_interface) =
            network_path_endpoint_interfaces(self, selected_path)?;
        let direction = selected_path.direction;
        let source_endpoint = fault_object_id_from_signal(
            interfaces
                .get(source_interface)
                .ok_or_else(|| invalid("network route source interface"))?,
        )?;
        let destination_endpoint = fault_object_id_from_signal(
            interfaces
                .get(destination_interface)
                .ok_or_else(|| invalid("network route destination interface"))?,
        )?;
        let mut route = vec![WorldNetworkRouteFaultTarget {
            target: ResolvedFaultTarget::NetworkInterface {
                endpoint: source_endpoint.clone(),
                interface: fault_object_id_from_signal(source_interface)?,
            },
            operation: FaultOperation::NetworkTransmit,
            direction: FaultDirection::Egress,
        }];
        route.push(WorldNetworkRouteFaultTarget {
            target: ResolvedFaultTarget::NetworkPath {
                path_version: fault_object_id_from_signal(&selected_path.id)?,
                direction,
            },
            operation: FaultOperation::NetworkTraverse,
            direction,
        });
        let mut selected_segments = BTreeSet::new();
        for hop in &selected_path.hops {
            match hop {
                WorldNetworkPathHop::Segment {
                    segment,
                    direction: segment_direction,
                } => {
                    selected_segments.insert(segment);
                    push_network_segment_route_stages(
                        self,
                        &mut route,
                        segment,
                        *segment_direction,
                    )?;
                }
                WorldNetworkPathHop::Forwarder { forwarder } => {
                    route.push(WorldNetworkRouteFaultTarget {
                        target: ResolvedFaultTarget::NetworkForwarder {
                            forwarder: fault_object_id_from_signal(forwarder)?,
                        },
                        operation: FaultOperation::NetworkLookup,
                        direction,
                    });
                }
                WorldNetworkPathHop::Queue { queue } => {
                    let queue = self
                        .network_queues
                        .iter()
                        .find(|candidate| &candidate.id == queue)
                        .ok_or_else(|| invalid("selected network path queue"))?;
                    route.push(WorldNetworkRouteFaultTarget {
                        target: ResolvedFaultTarget::NetworkQueue {
                            owner: fault_object_id_from_signal(&queue.owner)?,
                            queue: fault_object_id_from_signal(&queue.id)?,
                        },
                        operation: FaultOperation::NetworkEnqueue,
                        direction,
                    });
                }
            }
        }
        for attachment in &self.network_attachments {
            if (attachment.interface == *source_interface
                || attachment.interface == *destination_interface)
                && attachment
                    .candidates
                    .iter()
                    .any(|candidate| selected_segments.contains(candidate))
            {
                let (endpoint, interface_direction) = if attachment.interface == *source_interface {
                    (source_endpoint.clone(), FaultDirection::Egress)
                } else {
                    (destination_endpoint.clone(), FaultDirection::Ingress)
                };
                route.push(WorldNetworkRouteFaultTarget {
                    target: ResolvedFaultTarget::NetworkAttachment {
                        endpoint,
                        interface: fault_object_id_from_signal(&attachment.interface)?,
                        attachment: fault_object_id_from_signal(&attachment.id)?,
                    },
                    operation: FaultOperation::NetworkAssociate,
                    direction: interface_direction,
                });
            }
        }
        let endpoint_pair = canonical_name_pair(source, destination);
        for plan in &self.network_contact_plans {
            if canonical_name_pair(plan.endpoint_a.as_str(), plan.endpoint_b.as_str())
                != endpoint_pair
            {
                continue;
            }
            for contact in &plan.contacts {
                if contact.start_nanos <= virtual_nanos && virtual_nanos < contact.end_nanos {
                    route.push(WorldNetworkRouteFaultTarget {
                        target: ResolvedFaultTarget::NetworkContact {
                            plan: fault_object_id_from_signal(&plan.id)?,
                            endpoint_a: fault_object_id_from_signal(&plan.endpoint_a)?,
                            endpoint_b: fault_object_id_from_signal(&plan.endpoint_b)?,
                            contact: fault_object_id_from_signal(&contact.id)?,
                        },
                        operation: FaultOperation::NetworkTransmit,
                        direction,
                    });
                }
            }
        }
        route.push(WorldNetworkRouteFaultTarget {
            target: ResolvedFaultTarget::NetworkInterface {
                endpoint: destination_endpoint,
                interface: fault_object_id_from_signal(destination_interface)?,
            },
            operation: FaultOperation::NetworkReceive,
            direction: FaultDirection::Ingress,
        });
        let mut seen = BTreeSet::new();
        route.retain(|stage| seen.insert(stage.clone()));
        Ok(route)
    }

    fn target_fault_domains(&self, target: &WorldFaultTargetRef) -> &[SignalId] {
        match target {
            WorldFaultTargetRef::NetworkInterface { interface } => self
                .network_interfaces
                .iter()
                .find(|item| &item.id == interface)
                .map_or(&[], |item| item.fault_domains.as_slice()),
            WorldFaultTargetRef::NetworkSegment { segment, .. } => self
                .network_segments
                .iter()
                .find(|item| &item.id == segment)
                .map_or(&[], |item| item.fault_domains.as_slice()),
            WorldFaultTargetRef::NetworkMedium { medium, .. } => self
                .network_media
                .iter()
                .find(|item| &item.id == medium)
                .map_or(&[], |item| item.fault_domains.as_slice()),
            WorldFaultTargetRef::NetworkForwarder { forwarder } => self
                .network_forwarders
                .iter()
                .find(|item| &item.id == forwarder)
                .map_or(&[], |item| item.fault_domains.as_slice()),
            WorldFaultTargetRef::NetworkQueue { queue } => self
                .network_queues
                .iter()
                .find(|item| &item.id == queue)
                .map_or(&[], |item| item.fault_domains.as_slice()),
            WorldFaultTargetRef::BlockDevice { device }
            | WorldFaultTargetRef::NinePDevice { device } => self
                .storage_devices
                .iter()
                .find(|item| &item.device == device)
                .map_or(&[], |item| item.fault_domains.as_slice()),
            WorldFaultTargetRef::StorageController { controller, .. } => self
                .storage_controllers
                .iter()
                .find(|item| &item.id == controller)
                .map_or(&[], |item| item.fault_domains.as_slice()),
            WorldFaultTargetRef::StorageArray { array, .. } => self
                .storage_arrays
                .iter()
                .find(|item| &item.id == array)
                .map_or(&[], |item| item.fault_domains.as_slice()),
            WorldFaultTargetRef::NetworkPath { .. }
            | WorldFaultTargetRef::NetworkAttachment { .. }
            | WorldFaultTargetRef::NetworkContact { .. }
            | WorldFaultTargetRef::Node { .. } => &[],
        }
    }

    fn all_target_refs(&self) -> BTreeSet<WorldFaultTargetRef> {
        let mut targets = BTreeSet::new();
        targets.extend(self.network_interfaces.iter().map(|item| {
            WorldFaultTargetRef::NetworkInterface {
                interface: item.id.clone(),
            }
        }));
        targets.extend(self.network_segments.iter().flat_map(|item| {
            [FaultDirection::AToB, FaultDirection::BToA].map(|direction| {
                WorldFaultTargetRef::NetworkSegment {
                    segment: item.id.clone(),
                    direction,
                }
            })
        }));
        targets.extend(self.network_media.iter().flat_map(|item| {
            item.resources
                .iter()
                .map(|resource| WorldFaultTargetRef::NetworkMedium {
                    medium: item.id.clone(),
                    resource: resource.clone(),
                })
        }));
        targets.extend(self.network_forwarders.iter().map(|item| {
            WorldFaultTargetRef::NetworkForwarder {
                forwarder: item.id.clone(),
            }
        }));
        targets.extend(
            self.network_queues
                .iter()
                .map(|item| WorldFaultTargetRef::NetworkQueue {
                    queue: item.id.clone(),
                }),
        );
        targets.extend(self.network_paths.iter().flat_map(|item| {
            [FaultDirection::AToB, FaultDirection::BToA].map(|direction| {
                WorldFaultTargetRef::NetworkPath {
                    path: item.id.clone(),
                    direction,
                }
            })
        }));
        targets.extend(self.network_attachments.iter().map(|item| {
            WorldFaultTargetRef::NetworkAttachment {
                attachment: item.id.clone(),
            }
        }));
        targets.extend(self.network_contact_plans.iter().flat_map(|plan| {
            plan.contacts
                .iter()
                .map(|contact| WorldFaultTargetRef::NetworkContact {
                    plan: plan.id.clone(),
                    contact: contact.id.clone(),
                })
        }));
        targets.extend(self.storage_devices.iter().map(|item| match item.kind {
            WorldStorageKind::Block => WorldFaultTargetRef::BlockDevice {
                device: item.device.clone(),
            },
            WorldStorageKind::NineP => WorldFaultTargetRef::NinePDevice {
                device: item.device.clone(),
            },
        }));
        targets.extend(self.storage_controllers.iter().flat_map(|controller| {
            controller
                .namespaces
                .iter()
                .map(|namespace| WorldFaultTargetRef::StorageController {
                    controller: controller.id.clone(),
                    namespace_or_path: namespace.id.clone(),
                })
                .chain(
                    controller
                        .paths
                        .iter()
                        .map(|path| WorldFaultTargetRef::StorageController {
                            controller: controller.id.clone(),
                            namespace_or_path: path.id.clone(),
                        }),
                )
        }));
        targets.extend(self.storage_arrays.iter().flat_map(|array| {
            array
                .members
                .iter()
                .map(|member| WorldFaultTargetRef::StorageArray {
                    array: array.id.clone(),
                    member_or_path: member.id.clone(),
                })
                .chain(
                    array
                        .paths
                        .iter()
                        .map(|path| WorldFaultTargetRef::StorageArray {
                            array: array.id.clone(),
                            member_or_path: path.id.clone(),
                        }),
                )
        }));
        targets.extend(
            self.node_capabilities
                .iter()
                .map(|item| WorldFaultTargetRef::Node {
                    node: item.node.clone(),
                }),
        );
        targets
    }
}

/// One finite, world-owned fault-domain declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldFaultDomain {
    /// Stable domain ID.
    pub id: SignalId,
    /// Canonical finite target membership.
    pub targets: Vec<WorldFaultTargetRef>,
}
impl WorldFaultDomain {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One typed reference which may be included in a fault domain.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldFaultTargetRef {
    /// One network interface.
    NetworkInterface {
        /// Interface ID.
        interface: SignalId,
    },
    /// One direction of one network segment.
    NetworkSegment {
        /// Segment ID.
        segment: SignalId,
        /// Directed side of the segment.
        direction: FaultDirection,
    },
    /// One network medium.
    NetworkMedium {
        /// Medium ID.
        medium: SignalId,
        /// Channel or resource ID.
        resource: SignalId,
    },
    /// One forwarding element.
    NetworkForwarder {
        /// Forwarder ID.
        forwarder: SignalId,
    },
    /// One bounded network queue.
    NetworkQueue {
        /// Queue ID.
        queue: SignalId,
    },
    /// One declared network path.
    NetworkPath {
        /// Path ID.
        path: SignalId,
        /// Direction through the path.
        direction: FaultDirection,
    },
    /// One endpoint attachment state machine.
    NetworkAttachment {
        /// Attachment ID.
        attachment: SignalId,
    },
    /// One scheduled contact in a contact plan.
    NetworkContact {
        /// Contact-plan ID.
        plan: SignalId,
        /// Contact ID.
        contact: SignalId,
    },
    /// One deterministic block node.
    BlockDevice {
        /// Block-node ID.
        device: SignalId,
    },
    /// One deterministic 9p node.
    NinePDevice {
        /// 9p-node ID.
        device: SignalId,
    },
    /// One namespace or path on a storage controller.
    StorageController {
        /// Controller ID.
        controller: SignalId,
        /// Namespace or path ID.
        namespace_or_path: SignalId,
    },
    /// One member or path of a storage array.
    StorageArray {
        /// Array ID.
        array: SignalId,
        /// Member or path ID.
        member_or_path: SignalId,
    },
    /// One VM node.
    Node {
        /// VM-node ID.
        node: SignalId,
    },
}

/// Closed network-interface technology family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkTechnology {
    /// IEEE 802.3 family.
    Ethernet,
    /// IEEE 802.11 family.
    Wifi,
    /// Cellular radio family.
    Cellular,
    /// Bluetooth radio family.
    Bluetooth,
    /// LoRa radio family.
    Lora,
    /// Zigbee radio family.
    Zigbee,
    /// Thread radio family.
    Thread,
    /// Controller-area network.
    Can,
    /// Point-to-point serial transport.
    Serial,
    /// Optical transport.
    Optical,
    /// Terrestrial microwave transport.
    Microwave,
    /// Satellite transport.
    Satellite,
    /// Acoustic transport.
    Acoustic,
    /// Purely virtual interface.
    Virtual,
}

/// One world network interface.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkInterface {
    /// Stable interface ID.
    pub id: SignalId,
    /// Owning VM endpoint ID.
    pub endpoint: SignalId,
    /// Interface technology.
    pub technology: WorldNetworkTechnology,
    /// Stable address identifiers.
    pub addresses: Vec<SignalId>,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkInterface {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed network-segment technology family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkSegmentKind {
    /// Ethernet link.
    Ethernet,
    /// Wi-Fi link.
    Wifi,
    /// Cellular link.
    Cellular,
    /// Bluetooth link.
    Bluetooth,
    /// Low-power mesh link.
    LowPowerMesh,
    /// Controller-area network.
    Can,
    /// Serial link.
    Serial,
    /// Optical link.
    Optical,
    /// Microwave link.
    Microwave,
    /// Satellite link.
    Satellite,
    /// Acoustic link.
    Acoustic,
    /// Encapsulated tunnel.
    Tunnel,
    /// Purely virtual link.
    Virtual,
}

/// One physical or logical bidirectional segment.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkSegment {
    /// Stable segment ID.
    pub id: SignalId,
    /// Segment technology.
    pub kind: WorldNetworkSegmentKind,
    /// First interface ID.
    pub interface_a: SignalId,
    /// Second interface ID.
    pub interface_b: SignalId,
    /// Strict lower latency bound.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub minimum_latency_nanos: u64,
    /// Positive maximum frame size before a dynamic MTU effect applies.
    pub mtu_bytes: u32,
    /// Optional shared medium ID.
    pub medium: Option<SignalId>,
    /// Forwarding elements traversed by this segment.
    pub forwarders: Vec<SignalId>,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkSegment {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed transmission-medium family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkMediumKind {
    /// Dedicated conductive medium.
    DedicatedWire,
    /// Shared conductive medium.
    SharedWire,
    /// Fiber-optic medium.
    Fiber,
    /// Free-space RF medium.
    FreeSpaceRf,
    /// Guided RF medium.
    GuidedRf,
    /// Free-space optical medium.
    OpticalFreeSpace,
    /// Acoustic medium.
    Acoustic,
    /// Purely virtual medium.
    Virtual,
}

/// One shared or dedicated transmission medium.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkMedium {
    /// Stable medium ID.
    pub id: SignalId,
    /// Medium family.
    pub kind: WorldNetworkMediumKind,
    /// Closed resource IDs shared by users of the medium.
    pub resources: Vec<SignalId>,
    /// Registered access-policy ID.
    pub access_policy: SignalId,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkMedium {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed forwarding-element family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkForwarderKind {
    /// Layer-2 bridge.
    Bridge,
    /// Layer-2 switch.
    Switch,
    /// Layer-3 router.
    Router,
    /// Protocol gateway.
    Gateway,
    /// Network-address translator.
    Nat,
    /// Stateful or stateless firewall.
    Firewall,
    /// Physical or logical repeater.
    Repeater,
    /// Satellite relay.
    SatelliteRelay,
}

/// One deterministic forwarding element.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkForwarder {
    /// Stable forwarder ID.
    pub id: SignalId,
    /// Forwarder family.
    pub kind: WorldNetworkForwarderKind,
    /// Attached interface IDs.
    pub ports: Vec<SignalId>,
    /// Maximum forwarding-table entries.
    pub table_capacity: u32,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkForwarder {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed queue discipline.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkQueueDiscipline {
    /// First-in, first-out service.
    Fifo,
    /// Strict class priority.
    StrictPriority,
    /// Weighted round-robin service.
    WeightedRoundRobin,
    /// Deficit round-robin service.
    DeficitRoundRobin,
    /// Per-flow fair queueing.
    FairQueue,
}

/// Closed queue overflow behavior.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkQueueOverflow {
    /// Drops the arriving tail packet.
    DropTail,
    /// Drops the oldest head packet.
    DropHead,
    /// Marks ECN and drops when marking is unavailable.
    MarkEcn,
}

/// One bounded network queue.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkQueue {
    /// Stable queue ID.
    pub id: SignalId,
    /// Owning interface, medium, or forwarder ID.
    pub owner: SignalId,
    /// Packet-count capacity.
    pub capacity_packets: u32,
    /// Byte-count capacity, or zero when only packets bound the queue.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub capacity_bytes: u64,
    /// Queue discipline.
    pub discipline: WorldNetworkQueueDiscipline,
    /// Overflow behavior.
    pub overflow: WorldNetworkQueueOverflow,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkQueue {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One hop in an authored network path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldNetworkPathHop {
    /// Traverses one directed segment.
    Segment {
        /// Segment ID.
        segment: SignalId,
        /// Traversal direction.
        direction: FaultDirection,
    },
    /// Traverses one forwarding element.
    Forwarder {
        /// Forwarder ID.
        forwarder: SignalId,
    },
    /// Traverses one explicitly declared service queue.
    Queue {
        /// Queue ID.
        queue: SignalId,
    },
}

/// One ordered network path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkPath {
    /// Stable path ID.
    pub id: SignalId,
    /// Direction of the complete authored endpoint-to-endpoint path.
    pub direction: FaultDirection,
    /// Ordered path hops.
    pub hops: Vec<WorldNetworkPathHop>,
    /// Effective path MTU.
    pub mtu_bytes: u32,
}
impl WorldNetworkPath {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One endpoint association state machine.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkAttachment {
    /// Stable attachment-machine ID.
    pub id: SignalId,
    /// Endpoint interface controlled by the machine.
    pub interface: SignalId,
    /// Candidate segment IDs.
    pub candidates: Vec<SignalId>,
    /// Closed technology contract shared by control-operation effects.
    pub technology: SignalId,
    /// Exact attachment-machine semantic version.
    pub semantic_version: u16,
    /// Registered authentication policy.
    pub authentication: SignalId,
    /// Registered address-continuity policy.
    pub address_continuity: SignalId,
}
impl WorldNetworkAttachment {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One interval in a scheduled contact plan.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkContact {
    /// Stable contact ID within its plan.
    pub id: SignalId,
    /// Inclusive contact start.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub start_nanos: u64,
    /// Exclusive contact end.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub end_nanos: u64,
    /// One-way range delay.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub range_delay_nanos: u64,
    /// Contact service rate.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub rate_bps: u64,
    /// Optional beam ID.
    pub beam: Option<SignalId>,
    /// Optional gateway ID.
    pub gateway: Option<SignalId>,
}

/// One disruption-tolerant contact plan.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkContactPlan {
    /// Stable contact-plan ID.
    pub id: SignalId,
    /// First VM endpoint.
    pub endpoint_a: SignalId,
    /// Second VM endpoint.
    pub endpoint_b: SignalId,
    /// Ordered non-overlapping contact intervals.
    pub contacts: Vec<WorldNetworkContact>,
    /// Registered routing policy.
    pub routing_policy: SignalId,
    /// Registered custody policy.
    pub custody_policy: SignalId,
}
impl WorldNetworkContactPlan {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One mobile endpoint driven by an executable truth-trajectory signal.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldMobileEndpoint {
    /// Stable mobile-endpoint ID.
    pub id: SignalId,
    /// Owning VM node ID.
    pub node: SignalId,
    /// Spatial truth signal ID.
    pub truth_trajectory: SignalId,
}
impl WorldMobileEndpoint {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Storage adapter family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldStorageKind {
    /// Deterministic block device.
    Block,
    /// Deterministic 9p filesystem endpoint.
    NineP,
}

/// Closed flush ordering contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldFlushSemantics {
    /// A flush is an ordered persistence barrier.
    OrderedBarrier,
    /// A flush drains a writeback cache at the barrier.
    WritebackBarrier,
    /// Durability is expressed through force-unit-access requests.
    ForceUnitAccess,
}

/// Closed discard-result contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldDiscardSemantics {
    /// Discarded bytes read back as zero.
    DeterministicZero,
    /// Discarded bytes retain their prior value.
    ReadsOldData,
    /// Discarded reads use a recorded deterministic result.
    UndefinedRecorded,
}

/// Closed successful-completion durability layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldCompletionDurability {
    /// Success may be reported after controller admission.
    ControllerAccepted,
    /// Success may be reported after volatile-cache admission.
    VolatileCacheAccepted,
    /// Success is reported only after durable persistence.
    Durable,
}

/// Immutable storage durability contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStoragePersistence {
    /// Guest-visible logical block size.
    pub logical_block_bytes: u32,
    /// Physical persistence-sector size.
    pub physical_sector_bytes: u32,
    /// Smallest all-or-nothing write size.
    pub atomic_write_bytes: u32,
    /// Exact guest-visible device or namespace length.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub length_bytes: u64,
    /// Discard granularity, or zero when discard is unsupported.
    pub discard_granularity_bytes: u32,
    /// Maximum admitted request size.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub maximum_request_bytes: u64,
    /// Volatile write-cache capacity.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub volatile_cache_bytes: u64,
    /// Controller-accepted write-buffer capacity.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub controller_buffer_bytes: u64,
    /// Flush ordering contract.
    pub flush_semantics: WorldFlushSemantics,
    /// Discard readback contract.
    pub discard_semantics: WorldDiscardSemantics,
    /// Durability layer required before ordinary success completion.
    pub completion_durability: WorldCompletionDurability,
    /// Maximum volatile cache entry count.
    pub cache_entries: u32,
    /// Maximum controller-accepted write-buffer entry count.
    pub controller_entries: u32,
    /// Maximum persistence dependency edge count.
    pub persistence_dependencies: u32,
    /// Maximum retained logical versions per interval.
    pub retained_versions_per_interval: u16,
}

/// Closed storage media geometry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldStorageMedia {
    /// Flash media with erase/program geometry and finite endurance.
    Flash {
        /// Erase-block size.
        #[serde(
            deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
            serialize_with = "super::toml::serialize_u64_toml_number_or_string"
        )]
        erase_block_bytes: u64,
        /// Program-page size.
        program_page_bytes: u32,
        /// Rated erase cycles per block.
        #[serde(
            deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
            serialize_with = "super::toml::serialize_u64_toml_number_or_string"
        )]
        endurance_cycles: u64,
    },
    /// Magnetic media with sector/track geometry.
    Magnetic {
        /// Physical sector size.
        sector_bytes: u32,
        /// Track size.
        #[serde(
            deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
            serialize_with = "super::toml::serialize_u64_toml_number_or_string"
        )]
        track_bytes: u64,
    },
    /// Volatile or persistent RAM media.
    Ram {
        /// Page size.
        page_bytes: u32,
    },
    /// Remote media accessed through a registered protocol.
    Remote {
        /// Protocol contract ID.
        protocol: SignalId,
    },
}

impl WorldStorageMedia {
    /// Returns exact erase, program-page, and endurance geometry for flash media.
    #[must_use]
    pub const fn flash_geometry(&self) -> Option<(u64, u32, u64)> {
        match self {
            Self::Flash {
                erase_block_bytes,
                program_page_bytes,
                endurance_cycles,
            } => Some((*erase_block_bytes, *program_page_bytes, *endurance_cycles)),
            Self::Magnetic { .. } | Self::Ram { .. } | Self::Remote { .. } => None,
        }
    }
}

/// One storage node's executable durability/media declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageFaultDevice {
    /// Stable storage declaration ID.
    pub id: SignalId,
    /// Referenced block/9p world-node ID.
    pub device: SignalId,
    /// Storage adapter family.
    pub kind: WorldStorageKind,
    /// Durability contract.
    pub persistence: WorldStoragePersistence,
    /// Media geometry.
    pub media: WorldStorageMedia,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldStorageFaultDevice {
    const fn id(&self) -> &SignalId {
        &self.id
    }
    fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        require(
            self.persistence.logical_block_bytes.is_power_of_two()
                && (512..=65_536).contains(&self.persistence.logical_block_bytes),
            "storage logical block geometry",
        )?;
        require(
            self.persistence.physical_sector_bytes.is_power_of_two()
                && self
                    .persistence
                    .physical_sector_bytes
                    .is_multiple_of(self.persistence.logical_block_bytes),
            "storage physical sector geometry",
        )?;
        require(
            self.persistence.atomic_write_bytes > 0
                && self
                    .persistence
                    .atomic_write_bytes
                    .is_multiple_of(self.persistence.logical_block_bytes)
                && self.persistence.atomic_write_bytes <= self.persistence.physical_sector_bytes,
            "storage atomic write geometry",
        )?;
        require(
            self.persistence.length_bytes > 0
                && self
                    .persistence
                    .length_bytes
                    .is_multiple_of(u64::from(self.persistence.logical_block_bytes)),
            "storage length geometry",
        )?;
        require(
            self.persistence.discard_granularity_bytes == 0
                || (self.persistence.discard_granularity_bytes.is_power_of_two()
                    && self
                        .persistence
                        .discard_granularity_bytes
                        .is_multiple_of(self.persistence.logical_block_bytes)),
            "storage discard geometry",
        )?;
        require(
            self.persistence.maximum_request_bytes > 0
                && self.persistence.maximum_request_bytes <= self.persistence.length_bytes
                && self.persistence.maximum_request_bytes <= 67_108_864
                && self
                    .persistence
                    .maximum_request_bytes
                    .is_multiple_of(u64::from(self.persistence.logical_block_bytes)),
            "storage maximum request geometry",
        )?;
        require(
            self.persistence.volatile_cache_bytes <= 68_719_476_736
                && (self.persistence.volatile_cache_bytes == 0)
                    == (self.persistence.cache_entries == 0)
                && (self.persistence.completion_durability
                    != WorldCompletionDurability::VolatileCacheAccepted
                    || self.persistence.volatile_cache_bytes > 0),
            "storage cache byte limit",
        )?;
        require(
            self.persistence.controller_buffer_bytes <= 68_719_476_736
                && (self.persistence.controller_buffer_bytes == 0)
                    == (self.persistence.controller_entries == 0)
                && (self.persistence.completion_durability
                    != WorldCompletionDurability::ControllerAccepted
                    || self.persistence.controller_buffer_bytes > 0),
            "storage controller buffer limit",
        )?;
        require(
            self.persistence.cache_entries <= 4_194_304,
            "storage cache entry limit",
        )?;
        require(
            self.persistence.controller_entries <= 4_194_304,
            "storage controller entry limit",
        )?;
        require(
            self.persistence.persistence_dependencies <= 16_777_216,
            "storage dependency limit",
        )?;
        require(
            self.persistence.retained_versions_per_interval > 0
                && self.persistence.retained_versions_per_interval <= 1_024,
            "storage retained version limit",
        )?;
        match self.media {
            WorldStorageMedia::Flash {
                erase_block_bytes,
                program_page_bytes,
                endurance_cycles,
            } => require(
                erase_block_bytes > 0
                    && program_page_bytes > 0
                    && erase_block_bytes % u64::from(program_page_bytes) == 0
                    && endurance_cycles > 0,
                "flash geometry",
            ),
            WorldStorageMedia::Magnetic {
                sector_bytes,
                track_bytes,
            } => require(
                sector_bytes > 0 && track_bytes > 0 && track_bytes % u64::from(sector_bytes) == 0,
                "magnetic geometry",
            ),
            WorldStorageMedia::Ram { page_bytes } => {
                require(page_bytes.is_power_of_two(), "RAM media page geometry")
            }
            WorldStorageMedia::Remote { .. } => Ok(()),
        }
    }
}

/// One controller namespace bound to a deterministic storage device.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageNamespace {
    /// Stable namespace ID within its controller.
    pub id: SignalId,
    /// Referenced storage-device node ID.
    pub device: SignalId,
    /// Guest-visible namespace capacity.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub capacity_bytes: u64,
    /// Whether force-unit-access requests are accepted.
    pub supports_fua: bool,
    /// Whether discard requests are accepted.
    pub supports_discard: bool,
}
impl WorldStorageNamespace {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One deterministic path to a controller or array.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStoragePath {
    /// Stable path ID within its owner.
    pub id: SignalId,
    /// Maximum admitted in-flight operation count.
    pub queue_depth: u32,
    /// Registered path-selection and retry policy ID.
    pub policy: SignalId,
}
impl WorldStoragePath {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One deterministic storage controller with explicit namespaces and paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageController {
    /// Stable controller ID.
    pub id: SignalId,
    /// Exact controller state-machine semantic version.
    pub semantic_version: u16,
    /// Closed namespace declarations.
    pub namespaces: Vec<WorldStorageNamespace>,
    /// Closed access-path declarations.
    pub paths: Vec<WorldStoragePath>,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldStorageController {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed storage-array layout family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldStorageArrayLayout {
    /// Replicates each logical range across members.
    Mirror,
    /// Stripes logical ranges without parity.
    Stripe,
    /// Uses single distributed parity.
    SingleParity,
    /// Uses dual distributed parity.
    DualParity,
}

/// One member of a deterministic storage array.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageArrayMember {
    /// Stable member ID within its array.
    pub id: SignalId,
    /// Referenced storage-device node ID.
    pub device: SignalId,
    /// Stable member position used by parity and selection rules.
    pub ordinal: u16,
}
impl WorldStorageArrayMember {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One deterministic storage array with explicit members, paths, and quorums.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageArray {
    /// Stable array ID.
    pub id: SignalId,
    /// Exact array state-machine and parity semantic version.
    pub semantic_version: u16,
    /// Array layout.
    pub layout: WorldStorageArrayLayout,
    /// Stripe chunk size.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub chunk_bytes: u64,
    /// Minimum members required for a read.
    pub read_quorum: u16,
    /// Minimum members required for a write.
    pub write_quorum: u16,
    /// Closed member declarations.
    pub members: Vec<WorldStorageArrayMember>,
    /// Closed multipath declarations.
    pub paths: Vec<WorldStoragePath>,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldStorageArray {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed architecture register groups exported by the live QEMU manifest.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeRegisterGroup {
    /// Integer data and address registers.
    GeneralPurpose,
    /// Program counters and other explicit control-flow registers.
    ControlFlow,
    /// Integer condition and status flags.
    Flags,
    /// Segment selectors, bases, limits, and attributes.
    Segment,
    /// Translation and execution control registers.
    Control,
    /// Other guest-visible architecture system registers.
    System,
    /// Guest-visible debug registers.
    Debug,
    /// Floating-point data and control registers.
    FloatingPoint,
    /// SIMD, vector, and predicate registers.
    Vector,
    /// Architecture-defined error status and syndrome registers.
    Error,
}

/// Closed derived-state actions completed by a QEMU register setter.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeRegisterSideEffect {
    /// Flushes the vCPU translation lookaside buffer.
    TlbFlush,
    /// Flushes translated-code blocks affected by the new state.
    TranslationBlockFlush,
    /// Recomputes cached flags or architecture execution state.
    FlagsRecompute,
    /// Reevaluates interrupt masking and delivery state.
    InterruptReevaluate,
    /// Rearms timers derived from the mutated register.
    TimerRearm,
    /// Synchronizes the next guest control-flow location.
    ControlFlowSynchronize,
}

/// One architecture register exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeRegister {
    /// Stable scenario object ID selected by fault bindings.
    pub id: SignalId,
    /// Canonical lowercase name in the QEMU target manifest.
    pub name: String,
    /// Nonzero numeric row ID in the canonical target manifest.
    pub numeric_id: u32,
    /// Closed architecture register group.
    pub group: WorldNodeRegisterGroup,
    /// Register width in bits.
    pub width_bits: u32,
    /// Whether the register has one independent value per vCPU.
    pub per_vcpu: bool,
    /// Ordered model phases at which persistent transforms are safe.
    pub model_phases: Vec<FaultPhase>,
    /// Derived-state actions acknowledged by the architecture setter.
    pub side_effects: Vec<WorldNodeRegisterSideEffect>,
    /// Whether an exact one-shot mutation is supported.
    pub impulse: bool,
    /// Whether an exact persistent transform is supported.
    pub persistent: bool,
    /// Whether the architectural value and persistent transform have VMState coverage.
    pub vmstate: bool,
    /// Lowercase byte-order hex mask of bits which the ABI may mutate.
    pub writable_mask_hex: String,
    /// Lowercase byte-order hex mask of architecturally reserved bits.
    pub reserved_mask_hex: String,
    /// Lowercase byte-order hex mask of writes which are architecturally ignored.
    pub ignored_mask_hex: String,
    /// Lowercase byte-order hex mask of readable but immutable bits.
    pub read_only_mask_hex: String,
}
impl WorldNodeRegister {
    const fn id(&self) -> &SignalId {
        &self.id
    }

    /// Returns whether every bit in a nonempty range is manifest-writable.
    #[must_use]
    pub fn range_is_writable(&self, first_bit: u32, bit_count: u32) -> bool {
        let Some(end) = first_bit.checked_add(bit_count) else {
            return false;
        };
        if bit_count == 0 || end > self.width_bits {
            return false;
        }
        let Some(mask) = decode_world_mask(&self.writable_mask_hex) else {
            return false;
        };
        (first_bit..end).all(|bit| {
            let byte = (bit / 8) as usize;
            mask.get(byte)
                .is_some_and(|value| value & (1_u8 << (bit % 8)) != 0)
        })
    }
}

/// One guest memory address space exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeAddressSpace {
    /// Stable address-space ID.
    pub id: SignalId,
    /// Inclusive first address.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub start_address: u64,
    /// Positive byte length.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub length_bytes: u64,
}
impl WorldNodeAddressSpace {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One fully routed interrupt exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeInterrupt {
    /// Stable manifest row ID.
    pub id: SignalId,
    /// Interrupt controller ID.
    pub controller: SignalId,
    /// Interrupt source ID.
    pub source: SignalId,
    /// Architecture vector or interrupt type.
    pub vector: u32,
    /// Closed set of routable target vCPU indices.
    pub target_vcpus: Vec<u32>,
}
impl WorldNodeInterrupt {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One guest-visible clock source exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeClockSource {
    /// Stable clock-source ID.
    pub id: SignalId,
    /// Exact clock transform semantic version.
    pub semantic_version: u16,
    /// Whether the guest contract requires monotonic reads.
    pub monotonic: bool,
}
impl WorldNodeClockSource {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed accelerator class implemented by the patched QEMU device.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeAcceleratorKind {
    /// Virtio GPU device.
    Gpu,
    /// Crucible TPU co-simulation device.
    Tpu,
    /// Crucible FPGA co-simulation device.
    Fpga,
}

/// One accelerator device exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeAccelerator {
    /// Stable device ID.
    pub id: SignalId,
    /// Accelerator class.
    pub kind: WorldNodeAcceleratorKind,
    /// Exact accelerator fault-device semantic version.
    pub semantic_version: u16,
    /// Content address of the device-specific capability manifest.
    pub capability_manifest: ContentHash,
}
impl WorldNodeAccelerator {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed architecture ABIs supported by live QEMU node faults.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeArchitecture {
    /// x86-64 architectural register, interrupt, and machine-check ABI.
    X86_64,
    /// AArch64 architectural register, interrupt, and hardware-error ABI.
    Aarch64,
}

impl WorldNodeArchitecture {
    /// Returns the canonical selector spelling used by resolved register targets.
    #[must_use]
    pub const fn selector_id(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
            Self::Aarch64 => "aarch64",
        }
    }

    const fn matches_vm(self, architecture: VmArchitecture) -> bool {
        matches!(
            (self, architecture),
            (Self::X86_64, VmArchitecture::X86_64) | (Self::Aarch64, VmArchitecture::Aarch64)
        )
    }
}

/// One closed VM-node fault capability declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeFaultCapabilities {
    /// Stable capability declaration ID.
    pub id: SignalId,
    /// Referenced VM-node ID.
    pub node: SignalId,
    /// Registered architecture ABI.
    pub architecture: WorldNodeArchitecture,
    /// Exact realized QOM CPU typename reported by QEMU.
    pub cpu_model: String,
    /// Content address of the exact register schema.
    pub register_schema: ContentHash,
    /// Exact architecture register manifest.
    pub registers: Vec<WorldNodeRegister>,
    /// Registered memory address spaces.
    pub address_spaces: Vec<WorldNodeAddressSpace>,
    /// Guest page size used by memory mutation contracts.
    #[serde(
        deserialize_with = "super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::toml::serialize_u64_toml_number_or_string"
    )]
    pub page_bytes: u64,
    /// Exact GPA-to-DRAM coordinate mapping implemented by patched QEMU.
    pub dram_geometry: WorldNodeDramGeometry,
    /// Exact routable interrupt manifest.
    pub interrupts: Vec<WorldNodeInterrupt>,
    /// Registered guest-visible clock sources.
    pub clock_sources: Vec<WorldNodeClockSource>,
    /// Registered accelerator devices.
    pub accelerators: Vec<WorldNodeAccelerator>,
    /// Exact capability schema semantic version.
    pub semantic_version: u16,
}
impl WorldNodeFaultCapabilities {
    const fn id(&self) -> &SignalId {
        &self.id
    }
    fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        require(
            self.semantic_version == 1,
            "node capability semantic version",
        )?;
        require(self.page_bytes.is_power_of_two(), "node page geometry")?;
        self.dram_geometry.validate()?;
        require(!self.registers.is_empty(), "node register manifest")?;
        require(!self.address_spaces.is_empty(), "node address spaces")?;
        let mut numeric_ids = BTreeSet::new();
        let mut register_names = BTreeSet::new();
        for register in &self.registers {
            let mask_hex_bytes = usize::try_from(register.width_bits)
                .ok()
                .map(|width| width.div_ceil(8).saturating_mul(2));
            require(
                register.numeric_id > 0
                    && register.width_bits > 0
                    && register.width_bits <= 65_536
                    && register.per_vcpu,
                "node register capability",
            )?;
            require(
                numeric_ids.insert(register.numeric_id)
                    && register_names.insert(register.name.as_str()),
                "node register manifest identity",
            )?;
            require(
                !register.name.is_empty()
                    && register.name.len() <= 96
                    && register.name.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_' | b'.')
                    }),
                "node register name",
            )?;
            require(
                register.model_phases.iter().all(|phase| {
                    matches!(
                        phase,
                        FaultPhase::BeforeInstruction | FaultPhase::AfterInstruction
                    )
                }) && !register
                    .model_phases
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1]),
                "node register model phases",
            )?;
            require(
                !register
                    .side_effects
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1]),
                "node register side effects",
            )?;
            let masks = [
                &register.writable_mask_hex,
                &register.reserved_mask_hex,
                &register.ignored_mask_hex,
                &register.read_only_mask_hex,
            ];
            require(
                mask_hex_bytes.is_some_and(|length| {
                    masks.iter().all(|mask| {
                        mask.len() == length
                            && mask
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                }),
                "node register masks",
            )?;
            let decoded_masks = masks
                .map(|mask| decode_world_mask(mask))
                .into_iter()
                .collect::<Option<Vec<_>>>();
            require(
                decoded_masks.is_some_and(|masks| {
                    let writable = masks[0].iter().any(|byte| *byte != 0);
                    (0..register.width_bits).all(|bit| {
                        let byte = (bit / 8) as usize;
                        let mask = 1_u8 << (bit % 8);
                        masks.iter().filter(|value| value[byte] & mask != 0).count() == 1
                    }) && (register.width_bits..register.width_bits.div_ceil(8) * 8).all(|bit| {
                        let byte = (bit / 8) as usize;
                        let mask = 1_u8 << (bit % 8);
                        masks.iter().all(|value| value[byte] & mask == 0)
                    }) && if writable {
                        (register.impulse || register.persistent)
                            && register.vmstate
                            && !register.model_phases.is_empty()
                    } else {
                        !register.impulse
                            && !register.persistent
                            && register.model_phases.is_empty()
                            && register.side_effects.is_empty()
                    }
                }),
                "node register mask partition",
            )?;
        }
        require(
            !self.cpu_model.is_empty()
                && self.cpu_model.len() <= 96
                && self
                    .cpu_model
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace()),
            "node realized CPU model",
        )?;
        for space in &self.address_spaces {
            require(space.length_bytes > 0, "node address-space length")?;
            require(
                space
                    .start_address
                    .checked_add(space.length_bytes)
                    .is_some(),
                "node address-space range",
            )?;
        }
        for interrupt in &self.interrupts {
            require(!interrupt.target_vcpus.is_empty(), "node interrupt targets")?;
        }
        require(
            self.clock_sources
                .iter()
                .all(|source| source.semantic_version == 1),
            "node clock semantic version",
        )?;
        require(
            self.accelerators
                .iter()
                .all(|device| device.semantic_version == 1),
            "node accelerator semantic version",
        )?;
        hard_count(&self.accelerators, "node accelerators", 1_024)
    }
}

fn decode_world_mask(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = world_hex_nibble(pair[0])?;
            let low = world_hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

const fn world_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Exact striped DRAM geometry used by memory-region fault processes.
///
/// A physical address is split into `interleave_bytes` lines. Successive lines
/// select channel, then bank, then rank; the remaining byte coordinate selects
/// the row using the row size declared by the rowhammer effect. This is the
/// `2c2r16b64` mapping implemented by the current patched-QEMU capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeDramGeometry {
    /// Number of interleaved memory channels.
    pub channels: u16,
    /// Number of ranks per channel.
    pub ranks: u16,
    /// Number of banks per rank.
    pub banks: u16,
    /// Number of consecutive bytes assigned before selecting the next channel.
    pub interleave_bytes: u16,
    /// Exact geometry schema semantic version.
    pub semantic_version: u16,
}

impl WorldNodeDramGeometry {
    /// Returns the only DRAM mapping implemented by the current QEMU patch set.
    #[must_use]
    pub const fn qemu_v1() -> Self {
        Self {
            channels: 2,
            ranks: 2,
            banks: 16,
            interleave_bytes: 64,
            semantic_version: 1,
        }
    }

    fn validate(self) -> Result<(), WorldFaultTopologyError> {
        require(
            self == Self::qemu_v1(),
            "node DRAM geometry must match qemu 2c2r16b64",
        )
    }
}

/// Error returned while admitting a world fault registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorldFaultTopologyError {
    /// A bounded collection exceeds its compiled ceiling.
    CollectionLimit {
        /// Collection name.
        field: &'static str,
        /// Authored element count.
        actual: usize,
        /// Compiled ceiling.
        hard: usize,
    },
    /// Two declarations share one ID in a registry table.
    DuplicateId(SignalId),
    /// A field is invalid or references an absent declaration.
    Invalid(&'static str),
    /// Canonical registry encoding failed.
    Codec(String),
}

impl fmt::Display for WorldFaultTopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectionLimit {
                field,
                actual,
                hard,
            } => write!(
                formatter,
                "{field} contains {actual} entries; hard limit is {hard}"
            ),
            Self::DuplicateId(id) => {
                write!(formatter, "duplicate world fault declaration ID `{id}`")
            }
            Self::Invalid(field) => write!(formatter, "invalid or dangling {field}"),
            Self::Codec(reason) => write!(formatter, "world fault registry codec failed: {reason}"),
        }
    }
}
impl Error for WorldFaultTopologyError {}

fn canonicalize_by_id<T>(
    values: &mut [T],
    id: impl Fn(&T) -> &SignalId,
) -> Result<(), WorldFaultTopologyError> {
    if values.len() > HARD_WORLD_FAULT_DECLARATIONS_PER_KIND {
        return Err(WorldFaultTopologyError::CollectionLimit {
            field: "world fault declarations",
            actual: values.len(),
            hard: HARD_WORLD_FAULT_DECLARATIONS_PER_KIND,
        });
    }
    values.sort_by(|left, right| id(left).cmp(id(right)));
    if let Some(pair) = values.windows(2).find(|pair| id(&pair[0]) == id(&pair[1])) {
        return Err(WorldFaultTopologyError::DuplicateId(id(&pair[0]).clone()));
    }
    Ok(())
}
fn canonicalize_set<T: Ord>(
    values: &mut [T],
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
    bounded(values, field)?;
    values.sort();
    require(values.windows(2).all(|pair| pair[0] != pair[1]), field)
}
fn ids<T>(values: &[T]) -> BTreeSet<SignalId>
where
    T: HasWorldFaultId,
{
    values
        .iter()
        .map(|value| value.world_fault_id().clone())
        .collect()
}
trait HasWorldFaultId {
    fn world_fault_id(&self) -> &SignalId;
}
macro_rules! impl_id { ($($ty:ty),+ $(,)?) => { $(impl HasWorldFaultId for $ty { fn world_fault_id(&self) -> &SignalId { &self.id } })+ }; }
impl_id!(
    WorldFaultDomain,
    WorldNetworkInterface,
    WorldNetworkSegment,
    WorldNetworkMedium,
    WorldNetworkForwarder,
    WorldNetworkQueue,
    WorldNetworkPath,
    WorldStorageController,
    WorldStorageArray
);
pub(super) fn require(condition: bool, field: &'static str) -> Result<(), WorldFaultTopologyError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(field))
    }
}
fn expand_direct_segment_paths(
    topology: &mut WorldFaultTopology,
    world: &World,
) -> Result<(), WorldFaultTopologyError> {
    let interface_owners = topology
        .network_interfaces
        .iter()
        .map(|interface| (interface.id.clone(), interface.endpoint.clone()))
        .collect::<BTreeMap<_, _>>();
    let world_pairs = world
        .links()
        .iter()
        .map(|link| {
            let (left, right) = link.endpoints();
            canonical_name_pair(&left.name, &right.name)
        })
        .collect::<BTreeSet<_>>();
    let mut generated = Vec::new();
    for segment in &topology.network_segments {
        let Some(owner_a) = interface_owners.get(&segment.interface_a) else {
            return Err(invalid("network direct path interface_a"));
        };
        let Some(owner_b) = interface_owners.get(&segment.interface_b) else {
            return Err(invalid("network direct path interface_b"));
        };
        if !world_pairs.contains(&canonical_name_pair(owner_a.as_str(), owner_b.as_str())) {
            continue;
        }
        for (hop_direction, source, destination) in [
            (FaultDirection::AToB, owner_a, owner_b),
            (FaultDirection::BToA, owner_b, owner_a),
        ] {
            let direction = if source < destination {
                FaultDirection::AToB
            } else {
                FaultDirection::BToA
            };
            let already_declared = topology.network_paths.iter().any(|path| {
                path.direction == direction
                    && network_path_endpoint_interfaces(topology, path)
                        .ok()
                        .and_then(|(entry, exit)| {
                            Some((interface_owners.get(entry)?, interface_owners.get(exit)?))
                        })
                        .is_some_and(|(entry, exit)| entry == source && exit == destination)
            });
            if already_declared {
                continue;
            }
            let material = format!(
                "segment={};direction={}",
                segment.id,
                hop_direction.as_str()
            );
            let digest = ContentHash::from_canonical_material(
                "crucible.world-network-direct-path.v1",
                &material,
            );
            let id = SignalId::parse(format!("direct-path-{}", digest.to_hex()))
                .map_err(|_error| invalid("network direct path identity"))?;
            generated.push(WorldNetworkPath {
                id,
                direction,
                hops: vec![WorldNetworkPathHop::Segment {
                    segment: segment.id.clone(),
                    direction: hop_direction,
                }],
                mtu_bytes: segment.mtu_bytes,
            });
        }
    }
    topology.network_paths.extend(generated);
    Ok(())
}

fn network_path_endpoint_interfaces<'a>(
    topology: &'a WorldFaultTopology,
    path: &'a WorldNetworkPath,
) -> Result<(&'a SignalId, &'a SignalId), WorldFaultTopologyError> {
    let mut first = None;
    let mut last = None;
    for hop in &path.hops {
        let WorldNetworkPathHop::Segment { segment, direction } = hop else {
            continue;
        };
        let segment = topology
            .network_segments
            .iter()
            .find(|candidate| &candidate.id == segment)
            .ok_or_else(|| invalid("network path endpoint segment"))?;
        let (entry, exit) = match direction {
            FaultDirection::AToB => (&segment.interface_a, &segment.interface_b),
            FaultDirection::BToA => (&segment.interface_b, &segment.interface_a),
            FaultDirection::Ingress
            | FaultDirection::Egress
            | FaultDirection::Read
            | FaultDirection::Write => {
                return Err(invalid("network path endpoint direction"));
            }
        };
        first.get_or_insert(entry);
        last = Some(exit);
    }
    let first = first.ok_or_else(|| invalid("network path endpoint segment"))?;
    let last = last.ok_or_else(|| invalid("network path endpoint segment"))?;
    if first == last {
        return Err(invalid("network path endpoint direction"));
    }
    Ok((first, last))
}
fn push_network_segment_route_stages(
    topology: &WorldFaultTopology,
    route: &mut Vec<WorldNetworkRouteFaultTarget>,
    segment: &SignalId,
    direction: FaultDirection,
) -> Result<(), WorldFaultTopologyError> {
    let segment = topology
        .network_segments
        .iter()
        .find(|candidate| &candidate.id == segment)
        .ok_or_else(|| invalid("selected network path segment"))?;
    route.push(WorldNetworkRouteFaultTarget {
        target: ResolvedFaultTarget::NetworkSegment {
            segment: fault_object_id_from_signal(&segment.id)?,
            direction,
        },
        operation: FaultOperation::NetworkTraverse,
        direction,
    });
    if let Some(medium_id) = &segment.medium {
        let medium = topology
            .network_media
            .iter()
            .find(|medium| &medium.id == medium_id)
            .ok_or_else(|| invalid("network route medium"))?;
        for resource in &medium.resources {
            route.push(WorldNetworkRouteFaultTarget {
                target: ResolvedFaultTarget::NetworkMedium {
                    medium: fault_object_id_from_signal(&medium.id)?,
                    resource: fault_object_id_from_signal(resource)?,
                },
                operation: FaultOperation::NetworkContend,
                direction,
            });
        }
    }
    Ok(())
}
pub(super) fn invalid(field: &'static str) -> WorldFaultTopologyError {
    WorldFaultTopologyError::Invalid(field)
}
fn fault_object_id_from_signal(id: &SignalId) -> Result<FaultObjectId, WorldFaultTopologyError> {
    FaultObjectId::parse(id.as_str()).map_err(|_| invalid("world fault object ID"))
}
fn bounded<T>(values: &[T], field: &'static str) -> Result<(), WorldFaultTopologyError> {
    if values.len() <= HARD_WORLD_FAULT_REFERENCES_PER_DECLARATION {
        Ok(())
    } else {
        Err(WorldFaultTopologyError::CollectionLimit {
            field,
            actual: values.len(),
            hard: HARD_WORLD_FAULT_REFERENCES_PER_DECLARATION,
        })
    }
}
fn hard_count<T>(
    values: &[T],
    field: &'static str,
    hard: usize,
) -> Result<(), WorldFaultTopologyError> {
    if values.len() <= hard {
        Ok(())
    } else {
        Err(WorldFaultTopologyError::CollectionLimit {
            field,
            actual: values.len(),
            hard,
        })
    }
}
fn require_all(
    values: &[SignalId],
    available: &BTreeSet<SignalId>,
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
    bounded(values, field)?;
    require(values.iter().all(|value| available.contains(value)), field)
}

fn canonical_name_pair(left: &str, right: &str) -> (String, String) {
    if left <= right {
        (left.to_owned(), right.to_owned())
    } else {
        (right.to_owned(), left.to_owned())
    }
}

fn same_target_object(left: &WorldFaultTargetRef, right: &WorldFaultTargetRef) -> bool {
    match (left, right) {
        (
            WorldFaultTargetRef::NetworkInterface { interface: left },
            WorldFaultTargetRef::NetworkInterface { interface: right },
        ) => left == right,
        (
            WorldFaultTargetRef::NetworkSegment { segment: left, .. },
            WorldFaultTargetRef::NetworkSegment { segment: right, .. },
        ) => left == right,
        (
            WorldFaultTargetRef::NetworkMedium { medium: left, .. },
            WorldFaultTargetRef::NetworkMedium { medium: right, .. },
        ) => left == right,
        (
            WorldFaultTargetRef::NetworkForwarder { forwarder: left },
            WorldFaultTargetRef::NetworkForwarder { forwarder: right },
        ) => left == right,
        (
            WorldFaultTargetRef::NetworkQueue { queue: left },
            WorldFaultTargetRef::NetworkQueue { queue: right },
        ) => left == right,
        (
            WorldFaultTargetRef::NetworkPath { path: left, .. },
            WorldFaultTargetRef::NetworkPath { path: right, .. },
        ) => left == right,
        (
            WorldFaultTargetRef::NetworkAttachment { attachment: left },
            WorldFaultTargetRef::NetworkAttachment { attachment: right },
        ) => left == right,
        (
            WorldFaultTargetRef::NetworkContact { plan: left, .. },
            WorldFaultTargetRef::NetworkContact { plan: right, .. },
        ) => left == right,
        (
            WorldFaultTargetRef::BlockDevice { device: left },
            WorldFaultTargetRef::BlockDevice { device: right },
        )
        | (
            WorldFaultTargetRef::NinePDevice { device: left },
            WorldFaultTargetRef::NinePDevice { device: right },
        ) => left == right,
        (
            WorldFaultTargetRef::StorageController {
                controller: left, ..
            },
            WorldFaultTargetRef::StorageController {
                controller: right, ..
            },
        ) => left == right,
        (
            WorldFaultTargetRef::StorageArray { array: left, .. },
            WorldFaultTargetRef::StorageArray { array: right, .. },
        ) => left == right,
        (WorldFaultTargetRef::Node { node: left }, WorldFaultTargetRef::Node { node: right }) => {
            left == right
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "world_faults_test.rs"]
mod tests;
