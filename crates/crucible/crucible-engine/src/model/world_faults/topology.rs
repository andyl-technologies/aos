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

mod admission;

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
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.model.world-fault-topology.v1\0");
        serde_json::to_writer(&mut hasher, self)
            .map_err(|error| WorldFaultTopologyError::Codec(error.to_string()))?;
        Ok(ContentHash {
            bytes: *hasher.finalize().as_bytes(),
        })
    }

    /// Encodes the canonical registry payload used by world persistence.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError::Codec`] if the closed derived schema
    /// cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorldFaultTopologyError> {
        crate::owned_decode::to_json_vec(self).map_err(WorldFaultTopologyError::OriginalAdmission)
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
        virtual_ticks: u64,
    ) -> Result<Vec<WorldNetworkRouteFaultTarget>, WorldFaultTopologyError> {
        self.network_route_fault_targets_with_path(source, destination, virtual_ticks, None)
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
        virtual_ticks: u64,
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
                if contact.start_ticks <= virtual_ticks && virtual_ticks < contact.end_ticks {
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

    fn admit_target_index(&self) -> Result<(), WorldFaultTopologyError> {
        for item in &self.network_interfaces {
            admit_target_names(&[item.id.as_str()])?;
        }
        for item in &self.network_segments {
            for _ in 0..2 {
                admit_target_names(&[item.id.as_str()])?;
            }
        }
        for item in &self.network_media {
            for resource in &item.resources {
                admit_target_names(&[item.id.as_str(), resource.as_str()])?;
            }
        }
        for item in &self.network_forwarders {
            admit_target_names(&[item.id.as_str()])?;
        }
        for item in &self.network_queues {
            admit_target_names(&[item.id.as_str()])?;
        }
        for item in &self.network_paths {
            for _ in 0..2 {
                admit_target_names(&[item.id.as_str()])?;
            }
        }
        for item in &self.network_attachments {
            admit_target_names(&[item.id.as_str()])?;
        }
        for plan in &self.network_contact_plans {
            for contact in &plan.contacts {
                admit_target_names(&[plan.id.as_str(), contact.id.as_str()])?;
            }
        }
        for item in &self.storage_devices {
            admit_target_names(&[item.device.as_str()])?;
        }
        for controller in &self.storage_controllers {
            for namespace in &controller.namespaces {
                admit_target_names(&[controller.id.as_str(), namespace.id.as_str()])?;
            }
            for path in &controller.paths {
                admit_target_names(&[controller.id.as_str(), path.id.as_str()])?;
            }
        }
        for array in &self.storage_arrays {
            for member in &array.members {
                admit_target_names(&[array.id.as_str(), member.id.as_str()])?;
            }
            for path in &array.paths {
                admit_target_names(&[array.id.as_str(), path.id.as_str()])?;
            }
        }
        for item in &self.node_capabilities {
            admit_target_names(&[item.node.as_str()])?;
        }
        Ok(())
    }

    fn all_target_refs(&self) -> Result<BTreeSet<WorldFaultTargetRef>, WorldFaultTopologyError> {
        self.admit_target_index()?;
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
        Ok(targets)
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
    /// World content addressing lost its original resource admission.
    Canonical(Box<crate::model::EngineError>),
    /// Original artifact authority refused registry ownership or indexes.
    OriginalAdmission(crate::owned_decode::DecodeAdmissionError),
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
            Self::Canonical(source) => {
                write!(formatter, "world canonical identity failed: {source}")
            }
            Self::OriginalAdmission(source) => source.fmt(formatter),
        }
    }
}
impl Error for WorldFaultTopologyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(source) => Some(source.as_ref()),
            Self::OriginalAdmission(source) => Some(source),
            _ => None,
        }
    }
}

fn admit_target_names(names: &[&str]) -> Result<(), WorldFaultTopologyError> {
    crate::owned_decode::charge_btree_set_entry::<WorldFaultTargetRef>()
        .map_err(WorldFaultTopologyError::OriginalAdmission)?;
    for name in names {
        crate::owned_decode::charge_array::<u8>(name.len())
            .map_err(WorldFaultTopologyError::OriginalAdmission)?;
    }
    Ok(())
}

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
    values.sort_unstable_by(|left, right| id(left).cmp(id(right)));
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
    values.sort_unstable();
    require(values.windows(2).all(|pair| pair[0] != pair[1]), field)
}
fn ids<T>(values: &[T]) -> Result<BTreeSet<&SignalId>, WorldFaultTopologyError>
where
    T: HasWorldFaultId,
{
    let mut ids = BTreeSet::new();
    for value in values {
        crate::owned_decode::charge_btree_set_entry::<&SignalId>()
            .map_err(WorldFaultTopologyError::OriginalAdmission)?;
        ids.insert(value.world_fault_id());
    }
    Ok(ids)
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
    let mut interface_owners = BTreeMap::new();
    for interface in &topology.network_interfaces {
        crate::owned_decode::charge_btree_entry::<&SignalId, &SignalId>()
            .map_err(WorldFaultTopologyError::OriginalAdmission)?;
        interface_owners.insert(&interface.id, &interface.endpoint);
    }
    let mut generated = Vec::new();
    let capacity = topology
        .network_segments
        .len()
        .checked_mul(2)
        .ok_or_else(|| invalid("network direct path count overflow"))?;
    crate::owned_decode::reserve_vec(&mut generated, capacity)
        .map_err(WorldFaultTopologyError::OriginalAdmission)?;
    for segment in &topology.network_segments {
        let Some(owner_a) = interface_owners.get(&segment.interface_a) else {
            return Err(invalid("network direct path interface_a"));
        };
        let Some(owner_b) = interface_owners.get(&segment.interface_b) else {
            return Err(invalid("network direct path interface_b"));
        };
        if !world.links().iter().any(|link| {
            let (left, right) = link.endpoints();
            canonical_name_pair(&left.name, &right.name)
                == canonical_name_pair(owner_a.as_str(), owner_b.as_str())
        }) {
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
            let digest = crate::model::canonical::hash_material(
                "crucible.world-network-direct-path.v1",
                &DirectPathMaterial {
                    id: &segment.id,
                    direction: hop_direction,
                },
            )
            .map_err(|source| WorldFaultTopologyError::Canonical(Box::new(source)))?;
            let id_text = crate::model::canonical::material_string(&DirectPathId(digest))
                .map_err(|source| WorldFaultTopologyError::Canonical(Box::new(source)))?;
            let id = SignalId::parse(id_text)
                .map_err(|_error| invalid("network direct path identity"))?;
            crate::owned_decode::charge_array::<WorldNetworkPathHop>(1)
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
            crate::owned_decode::charge_array::<u8>(segment.id.as_str().len())
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
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
    crate::owned_decode::reserve_vec(&mut topology.network_paths, generated.len())
        .map_err(WorldFaultTopologyError::OriginalAdmission)?;
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
    available: &BTreeSet<&SignalId>,
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
    bounded(values, field)?;
    require(values.iter().all(|value| available.contains(value)), field)
}

fn canonical_name_pair<'a>(left: &'a str, right: &'a str) -> (&'a str, &'a str) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

struct DirectPathMaterial<'a> {
    id: &'a SignalId,
    direction: FaultDirection,
}

impl fmt::Display for DirectPathMaterial<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "segment={};direction={}",
            self.id,
            self.direction.as_str()
        )
    }
}

struct DirectPathId(ContentHash);

impl fmt::Display for DirectPathId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("direct-path-")?;
        for byte in self.0.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
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
