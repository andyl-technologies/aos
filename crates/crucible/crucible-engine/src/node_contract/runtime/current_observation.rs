//! Quotes only the actual selected node before a separately admitted inspection.
//!
//! The immutable constructor borrows the frozen route and real live node. It
//! allocates no route clone and issues no execution or scheduling permission.

use super::*;
use crate::node_admission::OriginalRestoredSchedulingObservationConstructionData;
use crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;

impl NodeRuntime {
    pub(crate) fn quote_original_restored_scheduling_observation_data(
        &self,
        activation: &WorldActivation,
        node: &NodeId,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        ordinal: u64,
        maximum: usize,
    ) -> Result<OriginalRestoredSchedulingObservationConstructionData, RuntimeError> {
        self.validate_activation(activation)?;
        self.require_settled_capture_custody()?;
        self.scheduling_origin()?;
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        let handle = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(handle.as_ref())?;
        self.validate_owners_available(&snapshot.route)?;
        let mut row = handle.quote_original_restored_scheduling_observation(
            launch,
            canonical_launch5,
            ordinal,
            maximum,
        )?;
        let (retained, transient, scratch) =
            self.current_observation_runtime_work_data(activation, &snapshot.route, maximum)?;
        row.runtime_retained = retained;
        row.runtime_transient = transient;
        row.runtime_scratch = scratch;
        row.retained = row
            .retained
            .checked_add(retained)
            .ok_or(RuntimeError::ResourceLimit)?;
        row.transient = row
            .transient
            .checked_add(transient)
            .ok_or(RuntimeError::ResourceLimit)?;
        row.scratch = row
            .scratch
            .checked_add(scratch)
            .ok_or(RuntimeError::ResourceLimit)?;
        row.requested = row
            .retained
            .checked_add(row.transient)
            .and_then(|bytes| bytes.checked_add(row.scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        snapshot.validate_current(handle.as_ref())?;
        self.validate_activation(activation)?;
        Ok(row)
    }
}

impl NodeRuntime {
    pub(in crate::node_contract) fn current_observation_runtime_work_data(
        &self,
        activation: &WorldActivation,
        route: &NodeRoute,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        let retained = activation
            .record()
            .owned_storage()?
            .checked_add(
                crate::node_admission::OriginalRestoredSchedulingObservationClaim::RECEIPT_FAILURE
                    .len()
                    * 2,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut transient = route.owned_storage()?;
        let mut domains = 0usize;
        for (identity, owner) in &self.owners {
            transient = transient
                .checked_add(
                    identity
                        .owned_storage()?
                        .checked_mul(2)
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
            domains = domains
                .checked_add(owner.domains.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            for domain in &owner.domains {
                transient = transient
                    .checked_add(
                        domain
                            .owned_storage()?
                            .checked_mul(2)
                            .ok_or(RuntimeError::ResourceLimit)?,
                    )
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        // Existing refusal containment materializes affected/newly-contained
        // owner sets and a domain set, plus FromIterator buffers. Each bank is
        // independent of retained keys and of the successful World-record copy.
        for entries in [self.owners.len(), self.owners.len(), domains] {
            transient = transient
                .checked_add(Self::capture_protocol_tree_storage(
                    1,
                    entries,
                    std::mem::size_of::<Id>(),
                    std::mem::align_of::<Id>(),
                    maximum,
                )?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let owner_buffer =
            construction_storage::collect_buffer_storage::<Id>(self.owners.len(), maximum)?;
        let domain_buffer = construction_storage::collect_buffer_storage::<Id>(domains, maximum)?;
        transient = transient
            .checked_add(owner_buffer)
            .and_then(|bytes| bytes.checked_add(domain_buffer))
            .ok_or(RuntimeError::ResourceLimit)?;
        if retained > maximum || transient > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok((
            retained,
            transient,
            Self::original_current_scheduling_dispatch_counter_scratch_data(),
        ))
    }

    pub(crate) fn original_current_scheduling_dispatch_counter_scratch_data() -> usize {
        use std::{
            collections::{BTreeSet, btree_set},
            mem::size_of,
        };
        size_of::<NodeRoute>()
            + size_of::<WorldActivation>()
            + size_of::<crate::node_scheduling::ValidatedSchedulingObservation>()
            + size_of::<
                Result<crate::node_scheduling::ValidatedSchedulingObservation, RuntimePollFailure>,
            >()
            + size_of::<Result<crate::node_scheduling::NativeSchedulingObservation, OperationFailure>>(
            )
            + size_of::<Result<(usize, usize, usize), RuntimeError>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<BTreeSet<Id>>() * 3
            + size_of::<btree_set::IntoIter<Id>>()
            + size_of::<btree_set::Iter<'static, Id>>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + construction_storage::stable_sort_fixed_scratch_data()
    }
}

impl NodeRuntime {
    pub(in crate::node_contract) fn quote_initial_current_scheduling_work_data(
        &self,
        world: &WorldActivation,
        node: &NodeId,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.validate_activation(world)?;
        self.require_settled_capture_custody()?;
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        let handle = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(handle.as_ref())?;
        self.validate_owners_available(&snapshot.route)?;
        self.current_observation_runtime_work_data(world, &snapshot.route, maximum)
    }

    pub(in crate::node_contract) fn seed_original_installed_restored_suffix_data(
        &self,
        world: &WorldActivation,
        node: &NodeId,
    ) -> Result<(), RuntimeError> {
        self.validate_activation(world)?;
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        let handle = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(handle.as_ref())?;
        self.validate_owners_available(&snapshot.route)?;
        handle.seed_original_installed_restored_suffix(world)?;
        snapshot.validate_current(handle.as_ref())?;
        self.validate_activation(world)
    }
}
