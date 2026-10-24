//! Quotes closed four-owner collecting graph construction before its allocations.
//!
//! Borrowed original metadata and exact source-owned content determine future
//! tuple clones, typed policies, private map layouts and graph working sets.
//! This DATA cannot authenticate content, substitute for graph admission or
//! grant an operation. The concrete holder separately admits its callbacks.

use super::*;
use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
use crate::node_contract::{NodeRuntime, RuntimeError, RuntimeOwnedStorage};
use std::mem::size_of;

/// Borrows the four original fixed owner rows and immutable policy banks.
pub struct FixedFourConformanceGraphConstructionInputs<'a> {
    /// Borrows the same complete installed world, with exactly two connections.
    pub world: &'a WorldBinding,
    /// Borrows actual Source3 and Host descriptors before any future clone.
    pub descriptors: [&'a NodeDescriptor; 4],
    /// Borrows actual corresponding Source3 and Host live bindings.
    pub bindings: [&'a NodeBinding; 4],
    /// Borrows the actual one-owner-per-node roster.
    pub owners: [&'a OwnerBinding; 4],
    /// Borrows the same installed original scenario requirements.
    pub requirements: &'a ScenarioRequirements,
    /// Retains the exact structural limits passed to genuine graph admission.
    ///
    /// The closed construction supports four nodes/owners, at most eight state
    /// objects/domains and two internal dependencies in addition to two edges.
    pub limits: AdmissionLimits,
    /// Borrows the actual population and graph-policy content banks.
    pub content: [&'a BTreeMap<crucible_node_format::ContentRef, Vec<u8>>; 2],
}

/// Separates new retained graph requests from transient construction and counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedFourConformanceGraphConstructionStorageData {
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl FixedFourConformanceGraphConstructionStorageData {
    /// Returns upper bounds for new full tuple, map and typed policy backing.
    pub fn retained_requested_bytes(self) -> usize {
        self.retained
    }

    /// Returns temporary parse, canonical, hash and graph working-set requests.
    pub fn maximum_simultaneous_transient_bytes(self) -> usize {
        self.transient
    }

    /// Returns explicit fixed counter/view headers, excluding compiler frames.
    pub fn declared_counter_scratch_bytes(self) -> usize {
        self.scratch
    }
}

impl ConformanceGraph {
    /// Quotes only the closed original four-owner graph constructor's new requests.
    ///
    /// All content is still authenticated by real graph admission. This walk
    /// invokes no evidence callback, hash, parser, currentness or serializer with
    /// provider-defined behavior. The caller first admits its fixed counter and
    /// the known U64 formatter bank, then the complete owning conjunction.
    ///
    /// # Errors
    /// Refuses an unsupported world/extension/capability family, another fixed
    /// roster, absent original policy bytes or checked requests above the bound.
    pub fn original_fixed_four_construction_storage_data(
        input: FixedFourConformanceGraphConstructionInputs<'_>,
        maximum: usize,
    ) -> Result<FixedFourConformanceGraphConstructionStorageData, RuntimeError> {
        if input.limits.maximum_nodes != 4
            || input.limits.maximum_owners != 4
            || input.limits.maximum_state_objects > 8
            || input.limits.maximum_connections != 2
            || input.limits.maximum_ports_or_lanes > 4
            || input.limits.maximum_owner_conflict_pairs > 12
            || input.world.node_bindings.len() != 4
            || input.world.connections.len() != 2
            || !input.world.extensions.is_empty()
            || input.world.scenario_ref.media_type == CAPABILITY_SELECTION_MEDIA_TYPE
            || input
                .descriptors
                .iter()
                .any(|node| !node.extensions.is_empty())
            || input
                .bindings
                .iter()
                .any(|binding| !binding.extensions.is_empty())
            || input
                .owners
                .iter()
                .any(|owner| owner.owner.participant_ids.len() != 1)
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        for index in 0..4 {
            if input.descriptors[..index]
                .iter()
                .any(|previous| previous.id == input.descriptors[index].id)
                || input.owners[..index]
                    .iter()
                    .any(|previous| previous.owner.id == input.owners[index].owner.id)
                || input.bindings[index].compatibility.node_id != input.descriptors[index].id
                || input.owners[index].owner.participant_ids[0] != input.descriptors[index].id
                || input.bindings[index].compatibility.execution_owner.id
                    != input.owners[index].owner.id
                || input.bindings[index].compatibility.capture_owner.id
                    != input.owners[index].owner.id
            {
                return Err(RuntimeError::InvalidRoute);
            }
        }
        let mut originals = RetainedRuntimeCounter::new(maximum);
        originals.world(input.world)?;
        let world_clone = originals.bytes();
        let mut retained = sum(
            &[
                size_of::<ConformanceGraph>(),
                world_clone,
                8 * (size_of::<NodeDescriptor>()
                    + size_of::<NodeBinding>()
                    + size_of::<OwnerBinding>()),
            ],
            maximum,
        )?;
        // Admission clones the authored requirements and owns a new world hash.
        for ids in [
            &input.requirements.accepted_quantized_nodes,
            &input.requirements.accepted_nondeterministic_nodes,
            &input.requirements.accepted_limited_state_nodes,
            &input.requirements.accepted_visibility_conversions,
        ] {
            retained = add(retained, ids.owned_storage()?, maximum)?;
        }
        retained = add(
            retained,
            "blake3-256".len() + "cnp.world-binding.v1".len() + 64,
            maximum,
        )?;
        let mut transient = NodeRuntime::capture_serialization_storage(input.world, maximum)?;
        transient = add(
            transient,
            NodeRuntime::capture_serialization_storage(input.requirements, maximum)?,
            maximum,
        )?;
        let mut ports = 0usize;
        let mut largest_fetch = 0usize;
        for index in 0..4 {
            let descriptor = input.descriptors[index];
            let binding = input.bindings[index];
            let owner = input.owners[index];
            // Caller Vec4, actual graph maps and ConformanceGraph Vec4 are three
            // independent copies. Source metadata is not moved into these rows.
            for _ in 0..3 {
                retained = add(retained, descriptor.owned_storage()?, maximum)?;
                retained = add(retained, binding.owned_storage()?, maximum)?;
                retained = add(retained, owner.owned_storage()?, maximum)?;
            }
            for phase in [
                NodeRuntime::capture_serialization_storage(descriptor, maximum)?,
                NodeRuntime::capture_serialization_storage(binding, maximum)?,
                NodeRuntime::capture_serialization_storage(owner, maximum)?,
            ] {
                transient = add(transient, phase, maximum)?;
            }
            for reference in [
                &binding.compatibility.operating_contract.policy_ref,
                &binding.compatibility.capabilities_ref,
                &binding.compatibility.guarantees_ref,
            ] {
                policy(reference, &input, maximum, &mut retained, &mut transient)?;
            }
            for port in &descriptor.ports {
                ports = ports.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
                if ports > 8 || !port.extensions.is_empty() || port.lanes.len() > 4 {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                policy(
                    &port.configuration_ref,
                    &input,
                    maximum,
                    &mut retained,
                    &mut transient,
                )?;
            }
        }
        for reference in [
            &input.world.scenario_ref,
            &input.world.ownership_ref,
            &input.world.coordinator_contract_ref,
        ] {
            policy(reference, &input, maximum, &mut retained, &mut transient)?;
        }
        for connection in &input.world.connections {
            policy(
                &connection.policy_ref,
                &input,
                maximum,
                &mut retained,
                &mut transient,
            )?;
        }
        // GraphPolicy and source population bytes are existing owners. Each
        // VerifiedContent::read creates only one fresh bounded Vec at a time.
        for bank in input.content {
            for bytes in bank.values() {
                largest_fetch = largest_fetch.max(bytes.len());
            }
        }
        transient = add(transient, largest_fetch, maximum)?;
        retained = add(retained, graph_maps(ports, maximum)?, maximum)?;
        transient = add(transient, graph_working_sets(ports, maximum)?, maximum)?;
        transient = add(transient, graph_collect_buffers(maximum)?, maximum)?;
        // validate_sorted holds adjacent cloned keys. OwnerBinding::validate
        // separately collects its actual node-binding IDs into a fresh Vec.
        transient = add(transient, 4 * 128, maximum)?;
        for owner in input.owners {
            transient = add(
                transient,
                owner
                    .node_bindings
                    .len()
                    .max(4)
                    .checked_mul(size_of::<Id>())
                    .ok_or(RuntimeError::ResourceLimit)?,
                maximum,
            )?;
            for binding in &owner.node_bindings {
                transient = add(transient, binding.node_id.allocated_capacity(), maximum)?;
            }
        }
        // One structured failure may retain required/observed Strings plus a
        // delegated fixed observed string while that error is converted. The
        // subject independently owns at most one public128-byte Id.
        transient = add(
            transient,
            error::original_construction_diagnostic_requested_bytes(),
            maximum,
        )?;
        let scratch = Self::original_fixed_four_construction_counter_scratch_data();
        sum(&[retained, transient, scratch], maximum)?;
        Ok(FixedFourConformanceGraphConstructionStorageData {
            retained,
            transient,
            scratch,
        })
    }

    /// Counts actual fixed graph projection and selected decoder/serializer banks.
    pub fn original_fixed_four_construction_counter_scratch_data() -> usize {
        size_of::<FixedFourConformanceGraphConstructionInputs<'static>>()
            + 2 * size_of::<FixedFourConformanceGraphConstructionStorageData>()
            + size_of::<RetainedRuntimeCounter>()
            + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + size_of::<[usize; 16]>()
            + size_of::<[u8; 20]>()
            + size_of::<error::OriginalConstructionDiagnosticScope>()
            + size_of::<AdmissionError>()
            + graph_sort_fixed_scratch_data()
    }
}

fn policy(
    reference: &crucible_node_format::ContentRef,
    input: &FixedFourConformanceGraphConstructionInputs<'_>,
    maximum: usize,
    retained: &mut usize,
    transient: &mut usize,
) -> Result<(), RuntimeError> {
    let bytes = input
        .content
        .iter()
        .find_map(|bank| bank.get(reference))
        .ok_or(RuntimeError::UnsupportedFacet)?;
    let slot = [
        size_of::<OwnershipPolicy>(),
        size_of::<CoordinatorPolicy>(),
        size_of::<PortPolicy>(),
        size_of::<LanePolicy>(),
        size_of::<ConnectionPolicy>(),
        size_of::<crucible_node_format::CapabilityProfile>(),
        size_of::<GuaranteeProfile>(),
        size_of::<ScenarioRequirements>(),
        size_of::<InternalDependency>(),
        size_of::<crate::node_scheduling::ExecutionPolicy>(),
        size_of::<StateDomain>(),
        size_of::<StateObject>(),
        size_of::<OwnerCapturePolicy>(),
        size_of::<SameTimeClosure>(),
    ]
    .into_iter()
    .max()
    .ok_or(RuntimeError::UnsupportedFacet)?;
    let map = [
        NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
        NodeRuntime::capture_map_node_storage::<Id, PortPolicy>(),
        NodeRuntime::capture_map_node_storage::<Id, StateDomain>(),
        NodeRuntime::capture_map_node_storage::<Id, StateObject>(),
        NodeRuntime::capture_map_node_storage::<Id, OwnerCapturePolicy>(),
        NodeRuntime::capture_map_node_storage::<Id, ConnectionPolicy>(),
        NodeRuntime::capture_map_node_storage::<Id, GuaranteeProfile>(),
    ]
    .into_iter()
    .max()
    .ok_or(RuntimeError::UnsupportedFacet)?;
    let (typed, parser, canonical) =
        NodeRuntime::capture_selected_json_decode_axes_data(bytes, slot, map, maximum)?;
    *retained = add(*retained, typed, maximum)?;
    // Explicit numeric formatter/sort workspaces supplement the older core
    // selected decode scanner; unrelated unused pools supply no implicit credit.
    // Schema validation can own another typed field/key projection while
    // the decoded original remains retained. Use the same actual raw-occurrence
    // and compiled maximum slot/tree producer for that separate named phase.
    *transient = add(
        *transient,
        sum(&[parser, canonical, typed, 132, 4096], maximum)?,
        maximum,
    )?;
    Ok(())
}

fn map<K, V>(entries: usize, maximum: usize) -> Result<usize, RuntimeError> {
    let nodes = entries.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
    let tree = nodes
        .checked_mul(NodeRuntime::capture_map_node_storage::<K, V>())
        .ok_or(RuntimeError::ResourceLimit)?;
    // Future graph-derived Id clones have a checked 128-byte public Id ceiling.
    add(
        tree,
        entries
            .checked_mul(128)
            .ok_or(RuntimeError::ResourceLimit)?,
        maximum,
    )
}

fn graph_maps(ports: usize, maximum: usize) -> Result<usize, RuntimeError> {
    sum(
        &[
            map::<Id, NodeDescriptor>(4, maximum)?,
            map::<Id, NodeBinding>(4, maximum)?,
            map::<Id, OwnerBinding>(4, maximum)?,
            map::<Id, GuaranteeProfile>(4, maximum)?,
            map::<Id, Repeatability>(4, maximum)?,
            map::<(Id, Id), PortPolicy>(ports, maximum)?,
            ports.checked_mul(128).ok_or(RuntimeError::ResourceLimit)?,
            map::<Id, ConnectionPolicy>(2, maximum)?,
            map::<Id, crate::node_scheduling::ExecutionPolicy>(4, maximum)?,
            map::<Id, BTreeSet<Id>>(4, maximum)?,
            map::<Id, ()>(12, maximum)?,
        ],
        maximum,
    )
}

fn graph_working_sets(ports: usize, maximum: usize) -> Result<usize, RuntimeError> {
    // Named distinct working sets in owner/domain validation, cycle checking,
    // conflict derivation and guarantee propagation. They may retire earlier;
    // sum them conservatively, with every owned Id clone independently priced.
    let owners = map::<&Id, &OwnerBinding>(4, maximum)?;
    let domains = map::<&Id, &StateDomain>(8, maximum)?;
    let captures = map::<&Id, &OwnerCapturePolicy>(4, maximum)?;
    let expected_members = sum(
        &[
            map::<Id, BTreeSet<Id>>(4, maximum)?,
            map::<Id, ()>(4, maximum)?,
        ],
        maximum,
    )?;
    let expected_domains = sum(
        &[
            map::<Id, BTreeSet<Id>>(4, maximum)?,
            map::<Id, ()>(40, maximum)?,
        ],
        maximum,
    )?;
    let coverage = sum(
        &[map::<Id, ()>(4, maximum)?, map::<Id, ()>(8, maximum)?],
        maximum,
    )?;
    let owner_routes = map::<&Id, &Id>(4, maximum)?;
    let adjacency = sum(
        &[
            map::<Id, BTreeSet<Id>>(4, maximum)?,
            map::<Id, ()>(12, maximum)?,
        ],
        maximum,
    )?;
    let reachability = sum(
        &[
            map::<Id, ()>(4, maximum)?,
            map::<Id, ()>(4, maximum)?,
            growing_ids(16, maximum)?,
        ],
        maximum,
    )?;
    // At most four public/internal edges are admitted by the same limits.
    // Three repeatability ranks allow at most two strict changes per node;
    // initial four plus eight requeues bound the actual VecDeque growth.
    let propagation = sum(
        &[
            adjacency,
            owners,
            map::<Id, ()>(4, maximum)?,
            growing_ids(8, maximum)?,
            growing_ids(12, maximum)?,
        ],
        maximum,
    )?;
    let participants = map::<&Id, ()>(4, maximum)?;
    let object_coverage = map::<Id, ()>(8, maximum)?;
    let connection_counts = map::<(&Id, &Id, &Id), usize>(
        ports.checked_mul(4).ok_or(RuntimeError::ResourceLimit)?,
        maximum,
    )?;
    let edges = 8usize
        .checked_mul(size_of::<(Id, Id, u64)>() + 2 * 128)
        .ok_or(RuntimeError::ResourceLimit)?;
    sum(
        &[
            owners,
            domains,
            captures,
            expected_members,
            expected_domains,
            coverage,
            owner_routes,
            adjacency,
            reachability,
            propagation,
            participants,
            object_coverage,
            connection_counts,
            edges,
        ],
        maximum,
    )
}

fn growing_ids(length: usize, maximum: usize) -> Result<usize, RuntimeError> {
    let capacity = length
        .max(4)
        .checked_next_power_of_two()
        .ok_or(RuntimeError::ResourceLimit)?;
    // Sum the standard min-four doubling requests as well as copied Id children.
    capacity
        .checked_mul(2)
        .and_then(|slots| slots.checked_mul(size_of::<Id>() + 128))
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn sum(terms: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    terms
        .iter()
        .try_fold(0usize, |total, bytes| add(total, *bytes, maximum))
}

fn collect<T>(n: usize, max: usize) -> Result<usize, RuntimeError> {
    let width = size_of::<T>();
    let slots = if n == 0 { 0 } else { n.max(4) };
    let drift = if n <= 20 {
        0
    } else {
        (n - n / 2).max(n.min(8_000_000 / width)).max(48)
    };
    let sort = drift.max(n / 2);
    let heap = if sort <= 4096 / width {
        0
    } else {
        sort.checked_mul(width).ok_or(RuntimeError::ResourceLimit)?
    };
    add(
        slots
            .checked_mul(width)
            .ok_or(RuntimeError::ResourceLimit)?,
        heap,
        max,
    )
}

fn graph_collect_buffers(max: usize) -> Result<usize, RuntimeError> {
    // Actual FromIterator sites in admit_graph, owner_conflicts, ownership,
    // cycle validation and guarantee propagation. Payload children move from
    // these temporary slots into trees and are already counted independently.
    sum(
        &[
            collect::<(Id, NodeDescriptor)>(4, max)?,
            collect::<(Id, NodeBinding)>(4, max)?,
            collect::<(Id, OwnerBinding)>(4, max)?,
            collect::<(Id, BTreeSet<Id>)>(4, max)?,
            collect::<&Id>(5, max)?, // up to four execution owners plus capture
            collect::<(&Id, &OwnerBinding)>(4, max)?,
            collect::<(&Id, &StateDomain)>(8, max)?,
            4 * collect::<Id>(1, max)?,
            4 * collect::<Id>(8, max)?,
            collect::<(&Id, &OwnerCapturePolicy)>(4, max)?,
            collect::<(&Id, &Id)>(4, max)?,
            collect::<(&Id, &OwnerBinding)>(4, max)?,
            collect::<(Id, Repeatability)>(4, max)?,
            // Domain groups become Vecs after BTreeSet consumption; those slots
            // coexist with the adjacency maps. Sum all eight sequential groups.
            8 * collect::<Id>(4, max)?,
        ],
        max,
    )
}

fn graph_sort_fixed_scratch_data() -> usize {
    let width = size_of::<(Id, NodeBinding)>()
        .max(size_of::<(Id, NodeDescriptor)>())
        .max(size_of::<(Id, OwnerBinding)>())
        .max(size_of::<(Id, BTreeSet<Id>)>());
    let alignment = std::mem::align_of::<(Id, NodeBinding)>()
        .max(std::mem::align_of::<(Id, NodeDescriptor)>())
        .max(std::mem::align_of::<(Id, OwnerBinding)>());
    ((4096 + alignment - 1) & !(alignment - 1))
        + width
        + 3 * size_of::<usize>()
        + size_of::<[usize; 66]>()
        + size_of::<[u8; 66]>()
        + size_of::<Vec<(Id, NodeBinding)>>()
        + 12 * size_of::<usize>()
}
