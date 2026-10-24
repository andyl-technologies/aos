//! Quotes the new concrete Host node fields before collecting construction.
//!
//! This projection follows `HostSchedulingSource::prepare_collection_node`.
//! It performs no graph, source callback, serialization or currentness work and
//! grants no construction, attachment, Ready or scheduling permission.

use super::*;
use crate::node_admission::InstalledConformancePlan;
use crate::node_contract::NodeRuntime;
use std::{
    cell::{Ref, RefMut},
    mem::size_of,
};

/// Describes requested storage added by one original collecting Host node.
///
/// Existing Source and installed-plan backing remain separately counted by
/// the enclosing holder. Retained bytes include one destination node root
/// (inline or boxed), its new anchor and independently cloned activation/route
/// heaps. A caller whose fixed bank already includes that root may conservatively
/// count it again. This data carries no admission or executable authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostCollectionNodeConstructionStorageData {
    retained_requested_bytes: usize,
    maximum_simultaneous_transient_bytes: usize,
    declared_counter_scratch_bytes: usize,
}

impl HostCollectionNodeConstructionStorageData {
    /// Returns the future node root, anchor and independent owned metadata.
    pub fn retained_requested_bytes(&self) -> usize {
        self.retained_requested_bytes
    }

    /// Returns conservative simultaneous explicit constructor value headers.
    pub fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.maximum_simultaneous_transient_bytes
    }

    /// Returns named quote/phase-view headers required before this projection.
    pub fn declared_counter_scratch_bytes(&self) -> usize {
        self.declared_counter_scratch_bytes
    }
}

struct Counter {
    bytes: usize,
    maximum: usize,
}

impl Counter {
    fn add(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }
}

impl HostSchedulingSource {
    /// Returns fixed counter and borrowed phase-view headers before quoting.
    ///
    /// The iterator headers name the actual fixed arrays in this projection.
    /// Compiler frames, recursion and allocator bookkeeping are outside this
    /// requested-storage profile. Graph/authority/currentness callbacks and their
    /// diagnostics require a separate admitted caller construction phase.
    pub fn original_collection_node_construction_counter_scratch_data() -> usize {
        // Retained and final-conjunction counters coexist at return.
        size_of::<Counter>()
            + size_of::<Counter>()
            + size_of::<(&Rc<Self>, &ActivationRecord)>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<HostCollectionNodeConstructionStorageData>()
            + size_of::<HostCollectionNodeConstructionStorageData>()
            + size_of::<Result<HostCollectionNodeConstructionStorageData, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::array::IntoIter<usize, 7>>()
            + size_of::<std::array::IntoIter<&String, 3>>()
            + size_of::<std::slice::Iter<'_, OwnerIdentity>>()
            + size_of::<Ref<'_, Option<OriginalSchedulingSource>>>()
            + size_of::<Ref<'_, Option<Rc<capture_dependencies::OriginalHostDependencyPlan>>>>()
            + size_of::<Ref<'_, Weak<()>>>()
    }

    /// Quotes new node ownership for this original Source and activation.
    ///
    /// The same complete, unprepared Source and host owner incarnation must be
    /// present in the actual activation. The quote borrows original capacities;
    /// it allocates, clones, hashes and calls back nowhere. Clone storage is
    /// conservatively bounded by the original capacities, including spare space.
    /// `InstalledConformancePlan::retained` and the Source handle clone add no new
    /// nested allocation; their real existing backing must remain in the holder.
    ///
    /// The actual constructor's graph reauthentication, world hashing, full tuple
    /// checks and error formatting remain independently mandatory and are not
    /// priced here. Runtime attachment and readiness occur later and also need
    /// their own action. Calling this method does not change any Source flag.
    ///
    /// # Errors
    /// Refuses another creator, non-complete/historical/spent Source, busy phase
    /// loans, a foreign activation/world/host owner, overflow or a complete
    /// retained/transient/counter conjunction above `maximum`.
    pub fn original_collection_node_construction_storage_data(
        self: &Rc<Self>,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<HostCollectionNodeConstructionStorageData, RuntimeError> {
        self.authenticate_original_report_startup_data()?;
        let data = self.quote_collection_node_storage(activation, maximum)?;
        self.authenticate_original_report_startup_data()?;
        Ok(data)
    }

    pub(crate) fn original_archived_collection_node_construction_storage_data(
        self: &Rc<Self>,
        archive: &Rc<crate::node_state::CompleteOriginalSource>,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<HostCollectionNodeConstructionStorageData, RuntimeError> {
        self.authenticate_archive_report_startup_data(archive)?;
        let mut data = self.quote_collection_node_storage(activation, maximum)?;
        let mut total = Counter { bytes: 0, maximum };
        data.declared_counter_scratch_bytes = data
            .declared_counter_scratch_bytes
            .checked_add(Self::original_archived_collection_node_counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        total.add(data.retained_requested_bytes)?;
        total.add(data.maximum_simultaneous_transient_bytes)?;
        total.add(data.declared_counter_scratch_bytes)?;
        self.authenticate_archive_report_startup_data(archive)?;
        Ok(data)
    }

    pub(crate) fn original_archived_collection_node_counter_scratch_data() -> usize {
        size_of::<&Rc<Self>>()
            + size_of::<&Rc<crate::node_state::CompleteOriginalSource>>()
            + size_of::<&ActivationRecord>()
            + size_of::<HostCollectionNodeConstructionStorageData>()
            + size_of::<Result<HostCollectionNodeConstructionStorageData, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Counter>()
            + 2 * size_of::<usize>()
    }

    fn quote_collection_node_storage(
        self: &Rc<Self>,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<HostCollectionNodeConstructionStorageData, RuntimeError> {
        let selected = &self.selection;
        if activation.world_binding_hash != self.world
            || !activation.owners.iter().any(|owner| {
                owner.owner == selected.owner.owner.id
                    && owner.incarnation == selected.binding.authority.incarnation_id
                    && owner.generation == selected.binding.authority.owner_generation
            })
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        let activation_bytes = activation_clone_storage(activation, maximum)?;
        let mut retained = Counter { bytes: 0, maximum };
        // These are the actual fields created by prepare_collection_node. The
        // descriptor and binding stay borrowed in the original Source; neither
        // is cloned into this node. Ready/restoration/capture slots start empty.
        for bytes in [
            size_of::<PreparedHostSchedulingNode>(),
            NodeRuntime::capture_shared_allocation_storage::<()>(),
            activation_bytes,
            size_of::<OwnerIdentity>(),
            selected.descriptor.id.allocated_capacity(),
            selected.owner.owner.id.allocated_capacity(),
            selected
                .binding
                .authority
                .incarnation_id
                .allocated_capacity(),
        ] {
            retained.add(bytes)?;
        }
        // The constructor can hold these explicit argument/return headers while
        // moving the new nested owners into its final destination. Sum them
        // conservatively; retained heap banks above are not allocated again.
        let transient = size_of::<PreparedHostSchedulingNode>()
            + size_of::<OwnerIdentity>()
            + size_of::<NodeRoute>()
            + size_of::<ActivationRecord>()
            + size_of::<InstalledConformancePlan>()
            + size_of::<Rc<()>>()
            + size_of::<RefMut<'_, Weak<()>>>();
        let scratch = Self::original_collection_node_construction_counter_scratch_data();
        let mut total = Counter {
            bytes: retained.bytes,
            maximum,
        };
        total.add(transient)?;
        total.add(scratch)?;
        Ok(HostCollectionNodeConstructionStorageData {
            retained_requested_bytes: retained.bytes,
            maximum_simultaneous_transient_bytes: transient,
            declared_counter_scratch_bytes: scratch,
        })
    }
}

fn activation_clone_storage(
    activation: &ActivationRecord,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let ActivationRecord {
        generation: _,
        activation_id,
        world_binding_hash,
        owners,
        boundary: _,
    } = activation;
    let HashRef {
        algorithm,
        domain,
        digest,
    } = world_binding_hash;
    let mut counter = Counter { bytes: 0, maximum };
    counter.add(activation_id.allocated_capacity())?;
    for value in [algorithm, domain, digest] {
        counter.add(value.capacity())?;
    }
    counter.add(
        owners
            .capacity()
            .checked_mul(size_of::<OwnerIdentity>())
            .ok_or(RuntimeError::ResourceLimit)?,
    )?;
    for OwnerIdentity {
        owner,
        incarnation,
        generation: _,
    } in owners
    {
        counter.add(owner.allocated_capacity())?;
        counter.add(incarnation.allocated_capacity())?;
    }
    Ok(counter.bytes)
}
