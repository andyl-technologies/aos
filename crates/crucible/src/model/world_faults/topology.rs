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
        let mut array_logical_devices = BTreeSet::new();
        let mut array_member_devices = BTreeSet::new();
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
            require(
                storage_device_contracts
                    .get(array.device.as_str())
                    .is_some_and(|device| device.kind == WorldStorageKind::Block),
                "storage array logical device",
            )?;
            require(
                array_logical_devices.insert(array.device.clone()),
                "storage array logical device ownership",
            )?;
            require(!array.members.is_empty(), "storage array members")?;
            hard_count(&array.members, "storage array members", 4_096)?;
            let minimum_members = match array.layout {
                WorldStorageArrayLayout::Mirror | WorldStorageArrayLayout::Stripe => 1,
                WorldStorageArrayLayout::SingleParity => 3,
                WorldStorageArrayLayout::DualParity => 4,
            };
            require(
                array.members.len() >= minimum_members,
                "storage array layout member count",
            )?;
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
            let member_devices = array
                .members
                .iter()
                .map(|member| member.device.clone())
                .collect::<BTreeSet<_>>();
            require(
                member_devices.len() == array.members.len(),
                "storage array backing devices",
            )?;
            require(
                member_devices
                    .iter()
                    .all(|device| array_member_devices.insert(device.clone())),
                "storage array backing device ownership",
            )?;
            for member in &array.members {
                require(
                    member.device != array.device
                        && storage_devices.contains(&member.device)
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
                ordinals.len() == array.members.len()
                    && ordinals
                        .iter()
                        .enumerate()
                        .all(|(expected, ordinal)| usize::from(*ordinal) == expected),
                "storage array member ordinal",
            )?;
            let logical_length = storage_device_contracts
                .get(array.device.as_str())
                .map(|device| device.persistence.length_bytes)
                .ok_or_else(|| invalid("storage array logical capacity"))?;
            let minimum_member_length = array
                .members
                .iter()
                .filter_map(|member| storage_device_contracts.get(member.device.as_str()))
                .map(|device| device.persistence.length_bytes)
                .min()
                .ok_or_else(|| invalid("storage array member capacity"))?;
            let data_members = match array.layout {
                WorldStorageArrayLayout::Mirror => 1_u64,
                WorldStorageArrayLayout::Stripe => array.members.len() as u64,
                WorldStorageArrayLayout::SingleParity => array.members.len() as u64 - 1,
                WorldStorageArrayLayout::DualParity => array.members.len() as u64 - 2,
            };
            let stripe_capacity = minimum_member_length
                .checked_div(array.chunk_bytes)
                .and_then(|chunks| chunks.checked_mul(array.chunk_bytes))
                .and_then(|member_bytes| member_bytes.checked_mul(data_members))
                .ok_or_else(|| invalid("storage array capacity overflow"))?;
            require(
                logical_length <= stripe_capacity,
                "storage array logical capacity",
            )?;
            for path in &array.paths {
                require(path.queue_depth > 0, "storage array path queue depth")?;
                require(
                    path_policy_exists(&path.policy),
                    "storage array path policy",
                )?;
            }
            let state = self
                .storage_policy_artifact(&array.member_path_state)
                .ok_or_else(|| invalid("storage array member/path state"))?;
            let StoragePolicyArtifactKind::ArrayState { members, paths } = &state.artifact else {
                return Err(invalid("storage array member/path state"));
            };
            require(
                members
                    .iter()
                    .map(|member| member.member.as_str())
                    .eq(array.members.iter().map(|member| member.id.as_str()))
                    && paths
                        .iter()
                        .map(|path| path.path.as_str())
                        .eq(array.paths.iter().map(|path| path.id.as_str())),
                "storage array complete member/path state",
            )?;
            require(
                self.storage_policy_artifact(&array.selection_policy)
                    .is_some_and(|artifact| {
                        matches!(
                            artifact.artifact,
                            StoragePolicyArtifactKind::ArraySelection(_)
                        )
                    }),
                "storage array selection policy",
            )?;
            require(
                self.storage_policy_artifact(&array.rebuild_service)
                    .is_some_and(|artifact| {
                        matches!(artifact.artifact, StoragePolicyArtifactKind::Rebuild(_))
                    }),
                "storage array rebuild service",
            )?;
            require(
                self.storage_policy_artifact(&array.consistency_policy)
                    .is_some_and(|artifact| {
                        matches!(
                            artifact.artifact,
                            StoragePolicyArtifactKind::ArrayConsistency(_)
                        )
                    }),
                "storage array consistency policy",
            )?;
            require(
                self.storage_policy_artifact(&array.failure_result)
                    .is_some_and(|artifact| {
                        matches!(
                            artifact.artifact,
                            StoragePolicyArtifactKind::TypedResult(
                                StoragePolicyTypedResult::Block { result }
                            ) if result != StoragePolicyResult::Success
                        )
                    }),
                "storage array failure result",
            )?;
        }
        require(
            array_logical_devices.is_disjoint(&array_member_devices),
            "storage array logical and backing device roles",
        )?;
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
pub(in crate::model) fn require(
    condition: bool,
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
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
pub(in crate::model) fn invalid(field: &'static str) -> WorldFaultTopologyError {
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
pub(super) fn hard_count<T>(
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
