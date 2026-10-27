//! Quotes new inactive-runtime storage for four already admitted concrete nodes.
//!
//! Existing node Boxes, their route declarations, the collecting graph and the
//! custody slot belong to the caller's earlier allocation phase. This component
//! counts the actual new runtime maps, declaration copies, barrier, scheduler
//! allocation and failed-constructor custody. It invokes no node or Source
//! callback, reauthentication, serializer or native operation.

use std::collections::BTreeSet;
use std::mem::{align_of, size_of};

use super::*;
use crate::node_admission::{AdmittedGraph, ConformanceGraph};

/// Bounds newly requested storage of one closed four-node runtime construction.
///
/// Retained alternatives conservatively sum successful runtime storage and the
/// failed-constructor capsule; neither failure nor retirement grants a refund.
/// These are requested layouts, separate from allocator, kernel and resident
/// memory. The caller admits its existing owners and callbacks independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalFixedFourRuntimeConstructionStorageData {
    /// Bounds new successful or failed-constructor retained Core allocations.
    pub retained_requested_bytes: usize,
    /// Bounds additional constructor validation collections while originals live.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Names fixed logical counter and constructor views admitted before this walk.
    pub declared_counter_scratch_bytes: usize,
}

impl OriginalFixedFourRuntimeConstructionStorageData {
    /// Adds all three simultaneous axes without granting construction authority.
    ///
    /// # Errors
    /// Refuses arithmetic overflow.
    pub fn checked_peak_data(&self) -> Result<usize, RuntimeError> {
        self.retained_requested_bytes
            .checked_add(self.maximum_simultaneous_transient_bytes)
            .and_then(|bytes| bytes.checked_add(self.declared_counter_scratch_bytes))
            .ok_or(RuntimeError::ResourceLimit)
    }
}

struct Requested {
    bytes: usize,
    maximum: usize,
}

impl Requested {
    fn new(maximum: usize) -> Self {
        Self { bytes: 0, maximum }
    }

    fn add(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn owned<T: RuntimeOwnedStorage + ?Sized>(&mut self, value: &T) -> Result<(), RuntimeError> {
        self.add(value.owned_storage()?)
    }

    fn tree<K, V>(&mut self, entries: usize) -> Result<(), RuntimeError> {
        self.add(NodeRuntime::capture_protocol_tree_storage(
            1,
            entries,
            size_of::<K>()
                .checked_add(size_of::<V>())
                .ok_or(RuntimeError::ResourceLimit)?,
            align_of::<K>().max(align_of::<V>()),
            self.maximum,
        )?)
    }

    fn collect_buffer<T>(&mut self, entries: usize) -> Result<(), RuntimeError> {
        self.add(collect_buffer_storage::<T>(entries, self.maximum)?)
    }
}

// Rust1.98 BTreeMap/BTreeSet FromIterator collects a Vec, stable-sorts it and
// moves the same elements into tree nodes. The input slot bank coexists with
// the growing tree; its payload allocations are already counted as clones.
// All called iterators have an exact remaining size_hint. max(4,len) covers
// both TrustedLen allocation and the ordinary first-item minimum-capacity path.
pub(super) fn collect_buffer_storage<T>(
    entries: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let slots = if entries == 0 { 0 } else { entries.max(4) };
    let sort = stable_sort_heap_storage::<T>(entries)?;
    let bytes = slots
        .checked_mul(size_of::<T>())
        .and_then(|bytes| bytes.checked_add(sort))
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(bytes)
}

fn stable_sort_heap_storage<T>(entries: usize) -> Result<usize, RuntimeError> {
    let width = size_of::<T>();
    if width == 0 || entries < 2 {
        return Ok(0);
    }
    // The normal stable-sort path uses insertion through20, then the exact
    // driftsort scratch rule (general small-sort scratch is32+16 slots).
    let drift = if entries <= 20 {
        0
    } else {
        (entries - entries / 2)
            .max(entries.min(8_000_000 / width))
            .max(48)
    };
    // The optimize_for_size standard-library branch uses len/2. Conservatively
    // cover either compiled branch, including a large tuple at small length.
    let slots = drift.max(entries / 2);
    if slots <= 4096 / width {
        return Ok(0);
    }
    slots.checked_mul(width).ok_or(RuntimeError::ResourceLimit)
}

pub(super) fn stable_sort_fixed_scratch_data() -> usize {
    let width = size_of::<(Id, NodeSnapshot)>()
        .max(size_of::<(Id, Box<dyn SimulationNode>)>())
        .max(size_of::<OwnerIdentity>())
        .max(size_of::<Id>());
    let alignment = align_of::<(Id, NodeSnapshot)>()
        .max(align_of::<(Id, Box<dyn SimulationNode>)>())
        .max(align_of::<OwnerIdentity>())
        .max(align_of::<Id>());
    // One sort runs at a time. AlignedStorage<T,4096> remains live even when
    // sort uses a heap buffer; insertion keeps one ManuallyDrop<T> plus its
    // CopyOnDrop{src,dst,len}. Driftsort also names66 Run(usize) and66 u8 views.
    // Recursive/compiler frames remain outside this explicit fixed-view quote.
    let aligned_bank = (4096 + alignment - 1) & !(alignment - 1);
    aligned_bank + width + 3 * size_of::<usize>()
        + size_of::<[usize; 66]>() + size_of::<[u8; 66]>()
        + size_of::<Vec<Id>>() // simultaneous stable-sort heap buffer header
        // collect slots/sort/bytes; nested width/drift/slots; this fixed-layout
        // calculator's width/alignment/aligned_bank logical scalar views.
        + 9 * size_of::<usize>()
}

struct QuoteLocals<'a> {
    routes: [&'a NodeRoute; 4],
    facets: [&'a [FacetKind]; 4],
    retained: Requested,
    transient: Requested,
}

impl NodeRuntime {
    /// Quotes the new inactive runtime phase of an original four-owner collection.
    ///
    /// The caller first authenticates the actual concrete node declarations and
    /// funds their Boxes, route allocations, graph and custody slot. This method
    /// borrows the same collecting graph and actual routes; it does not call
    /// erased observers or establish Source, plan, creator or native authority.
    /// Its separately named fixed scratch must be admitted before entry. Input
    /// owners stay charged throughout construction and every failure handoff.
    ///
    /// This closed phase has one distinct execution/capture owner per node.
    /// Slot validation, its error backing, queue storage and all native node
    /// callbacks remain independently funded caller obligations.
    ///
    /// # Errors
    /// Refuses noncollecting or incomplete membership, mismatched routes or
    /// incarnations, insufficient runtime limits, unsupported data or the bound.
    pub fn original_fixed_four_construction_storage_data(
        graph: &ConformanceGraph,
        routes: [&NodeRoute; 4],
        facets: [&[FacetKind]; 4],
        activation: &ActivationRecord,
        limits: RuntimeLimits,
        maximum: usize,
    ) -> Result<OriginalFixedFourRuntimeConstructionStorageData, RuntimeError> {
        if !graph.graph.collecting {
            return Err(RuntimeError::ForeignAuthority);
        }
        quote(&graph.graph, routes, facets, activation, limits, maximum)
    }

    /// Names fixed logical counter views used by the four-node construction quote.
    ///
    /// Includes simultaneous counter/result/borrowed views and actual constructor
    /// collection headers. Recursive/compiler frames and existing owner storage
    /// remain separate; this static DATA getter allocates nothing.
    pub fn original_fixed_four_construction_counter_scratch_data() -> usize {
        size_of::<QuoteLocals<'_>>()
            // The new dispatch loan is stack-only. Its explicit future view is
            // kept independently beside constructor views, never as heap credit.
            + OriginalRuntimeOperationDispatch::counter_scratch_data()
            + size_of::<OriginalFixedFourRuntimeConstructionStorageData>()
            + size_of::<NodeSnapshot>()
            + size_of::<ActivationBarrier>()
            + size_of::<OriginalSchedulingState>()
            + OriginalSchedulingState::construction_counter_scratch_data()
            + size_of::<Rc<()>>()
            + size_of::<BTreeMap<Id, NodeSnapshot>>()
            + size_of::<BTreeMap<Id, OwnerCustody>>()
            + size_of::<BTreeMap<Id, Box<dyn SimulationNode>>>()
            + 6 * size_of::<BTreeSet<Id>>()
            + 3 * size_of::<BTreeSet<OwnerIdentity>>()
            + size_of::<BTreeMap<Id, OwnerIdentity>>()
            + size_of::<std::slice::Iter<'static, &'static NodeRoute>>()
            + size_of::<std::slice::Iter<'static, OwnerIdentity>>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + 4 * size_of::<&()>()
            + 2 * size_of::<usize>()
            + size_of::<Option<usize>>()
            // Actual collect inputs: two map banks,16 Id sets and3 owner sets.
            // The independent payloads remain in the existing clone terms.
            + size_of::<Vec<(Id, NodeSnapshot)>>()
            + size_of::<Vec<(Id, Box<dyn SimulationNode>)>>()
            + 16 * size_of::<Vec<Id>>()
            + 3 * size_of::<Vec<OwnerIdentity>>()
            + stable_sort_fixed_scratch_data()
    }
}

fn route_matches(graph: &AdmittedGraph, route: &NodeRoute) -> Result<(), RuntimeError> {
    let descriptor = graph
        .descriptor(&route.node)
        .ok_or(RuntimeError::UnknownNode)?;
    let binding = graph
        .binding(&route.node)
        .ok_or(RuntimeError::UnknownNode)?;
    let [identity] = route.owners.as_slice() else {
        return Err(RuntimeError::UnsupportedFacet);
    };
    let owner = graph
        .owner(&identity.owner)
        .ok_or(RuntimeError::InvalidRoute)?;
    if descriptor.id != route.node
        || binding.compatibility.node_id != route.node
        || binding.compatibility.execution_owner.id != identity.owner
        || binding.compatibility.capture_owner.id != identity.owner
        || binding.authority.incarnation_id != identity.incarnation
        || binding.authority.owner_generation != identity.generation
        || identity.generation.get() == 0
        || binding.authority.activation_id.is_some()
        || binding.authority.world_generation.get() != 0
        || owner.owner.participant_ids.len() != 1
        || owner.owner.participant_ids[0] != route.node
        || owner.node_bindings.len() != 1
        || owner.node_bindings[0].node_id != route.node
    {
        return Err(RuntimeError::InvalidRoute);
    }
    Ok(())
}

fn snapshot_copies(
    graph: &AdmittedGraph,
    route: &NodeRoute,
    facets: &[FacetKind],
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    route_matches(graph, route)?;
    counter.owned(
        graph
            .descriptor(&route.node)
            .ok_or(RuntimeError::UnknownNode)?,
    )?;
    counter.owned(
        graph
            .binding(&route.node)
            .ok_or(RuntimeError::UnknownNode)?,
    )?;
    counter.owned(route)?;
    counter.add(
        facets
            .len()
            .checked_mul(size_of::<FacetKind>())
            .ok_or(RuntimeError::ResourceLimit)?,
    )
}

fn quote(
    graph: &AdmittedGraph,
    routes: [&NodeRoute; 4],
    facets: [&[FacetKind]; 4],
    activation: &ActivationRecord,
    limits: RuntimeLimits,
    maximum: usize,
) -> Result<OriginalFixedFourRuntimeConstructionStorageData, RuntimeError> {
    if limits.maximum_nodes < 4 || limits.maximum_owners < 4 {
        return Err(RuntimeError::ResourceLimit);
    }
    if graph.node_ids().take(5).count() != 4
        || graph.owners().take(5).count() != 4
        || activation.owners.len() != 4
        || activation.generation.get() == 0
        || graph.world_binding_hash() != &activation.world_binding_hash
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    for (index, route) in routes.iter().enumerate() {
        route_matches(graph, route)?;
        if routes[..index].iter().any(|previous| {
            previous.node == route.node || previous.owners[0].owner == route.owners[0].owner
        }) || !activation.owners.contains(&route.owners[0])
        {
            return Err(RuntimeError::InvalidRoute);
        }
    }

    let mut quote = QuoteLocals {
        routes,
        facets,
        retained: Requested::new(maximum),
        transient: Requested::new(maximum),
    };
    // Failed used IDs retain their reason while the original refusal is returned.
    // This independent backing row uses the same real Runtime limit as construction.
    quote.retained.add(
        OriginalRuntimeOperationDispatch::refused_reason_retained_bytes_data(
            limits.maximum_operations,
        )?,
    )?;

    quote.retained.add(size_of::<NodeRuntime>())?;
    quote
        .retained
        .add(NodeRuntime::capture_protocol_shared_header_storage(
            1,
            align_of::<()>(),
            maximum,
        )?)?;
    quote
        .retained
        .add(OriginalSchedulingState::construction_storage_data(
            &activation.world_binding_hash,
            maximum,
        )?)?;
    quote.retained.owned(activation)?; // independent barrier record clone
    quote
        .retained
        .add(NodeRuntime::capture_protocol_shared_header_storage(
            1,
            align_of::<ValidatedNodePreparation>(),
            maximum,
        )?)?; // real empty Rc slice
    quote.retained.tree::<Id, Box<dyn SimulationNode>>(4)?;
    quote.retained.tree::<Id, NodeSnapshot>(4)?;
    quote.retained.tree::<Id, OwnerCustody>(4)?;
    quote.transient.collect_buffer::<(Id, NodeSnapshot)>(4)?;
    quote
        .transient
        .collect_buffer::<(Id, Box<dyn SimulationNode>)>(4)?;

    // validate_roster retains both node sets, the owner map and four final owner
    // sets. Sum even sequential sets, and retain their independent cloned keys.
    quote.transient.tree::<Id, ()>(4)?;
    quote.transient.collect_buffer::<Id>(4)?;
    quote.transient.tree::<Id, ()>(4)?;
    quote.transient.collect_buffer::<Id>(4)?;
    quote.transient.tree::<Id, OwnerIdentity>(4)?;
    quote.transient.tree::<OwnerIdentity, ()>(4)?;
    quote.transient.collect_buffer::<OwnerIdentity>(4)?;
    quote.transient.tree::<OwnerIdentity, ()>(4)?;
    quote.transient.collect_buffer::<OwnerIdentity>(4)?;
    quote.transient.tree::<Id, ()>(4)?;
    quote.transient.collect_buffer::<Id>(4)?;
    quote.transient.tree::<Id, ()>(4)?;
    quote.transient.collect_buffer::<Id>(4)?;
    quote.transient.tree::<OwnerIdentity, ()>(4)?; // ActivationBarrier::new unique
    quote.transient.collect_buffer::<OwnerIdentity>(4)?;
    for index in 0..4 {
        let route = quote.routes[index];
        let identity = &route.owners[0];
        let owner = graph
            .owner(&identity.owner)
            .ok_or(RuntimeError::InvalidRoute)?;
        quote.retained.owned(&route.node)?; // node-map key
        quote.retained.owned(&route.node)?; // independent snapshot-map key
        snapshot_copies(graph, route, quote.facets[index], &mut quote.retained)?;
        quote.retained.owned(identity)?;
        quote.retained.owned(&identity.owner)?; // owner-map key
        quote
            .retained
            .tree::<Id, ()>(owner.owner.state_domain_ids.len())?;
        quote
            .transient
            .collect_buffer::<Id>(owner.owner.state_domain_ids.len())?;
        for domain in &owner.owner.state_domain_ids {
            quote.retained.owned(domain)?;
        }

        quote.transient.owned(&route.node)?; // expected graph node set
        quote.transient.owned(&route.node)?; // actual route node set
        quote.transient.tree::<Id, ()>(2)?; // two binding-owner clones before dedup
        quote.transient.collect_buffer::<Id>(2)?;
        quote.transient.tree::<Id, ()>(1)?; // route-owner set
        quote.transient.collect_buffer::<Id>(1)?;
        for _ in 0..3 {
            quote.transient.owned(&identity.owner)?;
        }
        quote.transient.owned(&identity.owner)?; // owner-roster key
        quote.transient.owned(identity)?; // owner-roster value, then moved into set
        quote.transient.owned(identity)?; // independent activation-owner set
        quote.transient.owned(&identity.owner)?; // graph-owner set
        quote.transient.owned(&identity.owner)?; // actual-owner-id set
        quote.transient.owned(identity)?; // barrier unique owner clone
    }

    // Partial construction may coexist with the original failed capsule. Its
    // Drop transfers a cloned activation into real WholeRuntimeCustody, which
    // creates another authority Rc and empty preparation Rc. Count these as
    // retained alternatives; only the actual owner reclamation can refund them.
    quote.retained.add(size_of::<RuntimePreparationFailure>())?;
    quote
        .retained
        .add(size_of::<crate::node_contract::WholeRuntimeCustody>())?;
    quote.retained.owned(activation)?;
    quote
        .retained
        .add(NodeRuntime::capture_protocol_shared_header_storage(
            1,
            align_of::<()>(),
            maximum,
        )?)?;
    quote
        .retained
        .add(NodeRuntime::capture_protocol_shared_header_storage(
            1,
            align_of::<ValidatedNodePreparation>(),
            maximum,
        )?)?;
    let result = OriginalFixedFourRuntimeConstructionStorageData {
        retained_requested_bytes: quote.retained.bytes,
        maximum_simultaneous_transient_bytes: quote.transient.bytes,
        declared_counter_scratch_bytes:
            NodeRuntime::original_fixed_four_construction_counter_scratch_data(),
    };
    if result.checked_peak_data()? > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::{ThreadAffinity, runtime_owned_counter::RetainedRuntimeCounter};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn declarations() -> Result<(AdmittedGraph, NodeRoute), RuntimeError> {
        let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
        let node = graph
            .node_ids()
            .next()
            .ok_or(RuntimeError::UnknownNode)?
            .clone();
        let binding = graph.binding(&node).ok_or(RuntimeError::UnknownNode)?;
        let identity = OwnerIdentity {
            owner: binding.compatibility.execution_owner.id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        };
        Ok((
            graph,
            NodeRoute {
                node,
                owners: vec![identity],
            },
        ))
    }

    #[test]
    fn actual_scheduler_allocation_and_world_clone_fit_exact_quote() -> TestResult {
        let (graph, _) = declarations()?;
        let world = graph.world_binding_hash();
        let quote = OriginalSchedulingState::construction_storage_data(world, usize::MAX)?;
        let authority = Rc::new(());
        let actual = OriginalSchedulingState::new(&authority, world.clone());
        let mut observed = RetainedRuntimeCounter::new(usize::MAX);
        actual.charge_original_retained_storage(&mut observed)?;
        assert!(quote >= observed.bytes());
        assert_eq!(
            OriginalSchedulingState::construction_storage_data(world, quote)?,
            quote
        );
        assert_eq!(
            OriginalSchedulingState::construction_storage_data(world, quote - 1),
            Err(RuntimeError::ResourceLimit)
        );
        Ok(())
    }

    #[test]
    fn actual_snapshot_clone_and_source_spare_capacity_remain_charged() -> TestResult {
        let (graph, mut route) = declarations()?;
        let facets = [FacetKind::ExactExecution];
        let mut before = Requested::new(usize::MAX);
        snapshot_copies(&graph, &route, &facets, &mut before)?;
        let old_capacity = route.owners.capacity();
        route.owners.reserve_exact(37);
        let mut quoted = Requested::new(usize::MAX);
        snapshot_copies(&graph, &route, &facets, &mut quoted)?;
        assert_eq!(
            quoted.bytes - before.bytes,
            (route.owners.capacity() - old_capacity) * size_of::<OwnerIdentity>()
        );

        let actual = NodeSnapshot {
            descriptor: graph
                .descriptor(&route.node)
                .ok_or(RuntimeError::UnknownNode)?
                .clone(),
            binding: graph
                .binding(&route.node)
                .ok_or(RuntimeError::UnknownNode)?
                .clone(),
            route: route.clone(),
            facets: facets.to_vec(),
            thread_affinity: ThreadAffinity::OwnerThread(std::thread::current().id()),
        };
        let actual_bytes = actual.descriptor.owned_storage()?
            + actual.binding.owned_storage()?
            + actual.route.owned_storage()?
            + actual.facets.capacity() * size_of::<FacetKind>();
        assert!(quoted.bytes >= actual_bytes);
        let mut exact = Requested::new(quoted.bytes);
        snapshot_copies(&graph, &route, &facets, &mut exact)?;
        assert_eq!(exact.bytes, quoted.bytes);
        let mut short = Requested::new(quoted.bytes - 1);
        assert_eq!(
            snapshot_copies(&graph, &route, &facets, &mut short),
            Err(RuntimeError::ResourceLimit)
        );
        Ok(())
    }

    #[test]
    fn foreign_or_unsupported_actual_routes_refuse_without_zero_credit() -> TestResult {
        let (graph, route) = declarations()?;
        route_matches(&graph, &route)?;
        let mut foreign = route.clone();
        foreign.owners[0].incarnation = Id::new("foreign-constructor-incarnation")?;
        assert_eq!(
            route_matches(&graph, &foreign),
            Err(RuntimeError::InvalidRoute)
        );
        let mut multiple = route.clone();
        multiple.owners.push(route.owners[0].clone());
        assert_eq!(
            route_matches(&graph, &multiple),
            Err(RuntimeError::UnsupportedFacet)
        );
        let record = ActivationRecord {
            activation_id: Id::new("data-only-construction-control")?,
            generation: crucible_node_format::U64::new(1),
            world_binding_hash: graph.world_binding_hash().clone(),
            boundary: crucible_node_format::Position {
                time_ps: crucible_node_format::U64::new(0),
                microstep: crucible_node_format::U64::new(0),
                phase: crucible_node_format::Phase::BoundaryControl,
            },
            owners: vec![route.owners[0].clone()],
        };
        assert_eq!(
            quote(
                &graph,
                [&route; 4],
                [&[]; 4],
                &record,
                RuntimeLimits::default(),
                usize::MAX
            ),
            Err(RuntimeError::UnsupportedFacet)
        );
        Ok(())
    }

    #[test]
    fn real_domain_collect_keeps_input_slots_and_large_sort_workspace() -> TestResult {
        // Actual domain cardinality is independent of the four-node roster.
        // A real512-element collect crosses the pinned4096-byte Id sort bank.
        let domains = (0..512)
            .map(|index| Id::new(format!("domain-{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        let inputs: Vec<_> = domains.iter().cloned().collect();
        let sorted: BTreeSet<_> = domains.iter().cloned().collect();
        assert_eq!(sorted.len(), domains.len());
        let quoted = collect_buffer_storage::<Id>(domains.len(), usize::MAX)?;
        let input_bytes = inputs.capacity() * size_of::<Id>();
        assert!(quoted >= input_bytes + domains.len() * size_of::<Id>());
        assert_eq!(collect_buffer_storage::<Id>(domains.len(), quoted)?, quoted);
        assert_eq!(
            collect_buffer_storage::<Id>(domains.len(), quoted - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(stable_sort_heap_storage::<Id>(20)?, 0);
        assert_eq!(stable_sort_heap_storage::<Id>(21)?, 0);
        assert!(stable_sort_heap_storage::<Id>(512)? >= 512 * size_of::<Id>());
        assert!(collect_buffer_storage::<Id>(usize::MAX, usize::MAX).is_err());
        Ok(())
    }
}
