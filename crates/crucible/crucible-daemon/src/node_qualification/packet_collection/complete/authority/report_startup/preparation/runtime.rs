//! Transfers exact original preparations into fixed admitted collecting-node slots.

use super::*;
use crucible_engine::{
    node_adapters::cnp::CnpSemanticConformanceNode, node_admission::ConformanceGraph,
};

impl PreparationOwners {
    // All actual Controller loans end before the first node constructor moves
    // its preparation. Every possible initial Seal and its parse overlap is
    // independently funded; already reserved empty Oracle slots are separate.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_native_oracle_observation_construction_storage_data(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        let mut retained = 0usize;
        let mut transient = 0usize;
        let mut scratch = Self::original_native_oracle_observation_counter_scratch_data();
        for (peer, source) in self.peers.iter().zip(sources) {
            if peer.registry.is_none() || peer.supervisor.is_none() || peer.operational.is_none() {
                return Err(RuntimeError::OwnerUnavailable);
            }
            let data = peer
                .preparation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .original_native_oracle_observation_construction_storage_data(source, maximum)?;
            retained = retained
                .checked_add(data.0)
                .ok_or(RuntimeError::ResourceLimit)?;
            transient = transient
                .checked_add(data.1)
                .ok_or(RuntimeError::ResourceLimit)?;
            scratch = scratch
                .checked_add(data.2)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok((retained, transient, scratch))
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_native_oracle_observation_counter_scratch_data()
    -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<&[Rc<PacketCompleteSemanticSource>; 3]>()
            + size_of::<
                std::iter::Zip<
                    std::slice::Iter<'static, PreparationPeer>,
                    std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>,
                >,
            >()
            + size_of::<(&PreparationPeer, &Rc<PacketCompleteSemanticSource>)>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), RuntimeError>>()
            + size_of::<[usize; 3]>()
            + size_of::<Option<usize>>()
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_runtime_node_quote_data(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        let mut retained = 0usize;
        let mut transient = 0usize;
        let mut scratch = 0usize;
        for (peer, source) in self.peers.iter().zip(sources) {
            if peer.registry.is_none() || peer.supervisor.is_none() || peer.operational.is_none() {
                return Err(RuntimeError::OwnerUnavailable);
            }
            let data = peer
                .preparation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .original_conformance_node_construction_storage_data(source, maximum)?;
            retained = retained
                .checked_add(data.retained_requested_bytes())
                .ok_or(RuntimeError::ResourceLimit)?;
            transient = transient
                .checked_add(data.maximum_simultaneous_transient_bytes())
                .ok_or(RuntimeError::ResourceLimit)?;
            scratch = scratch
                .checked_add(data.declared_counter_scratch_bytes())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok((retained, transient, scratch))
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn admit_original_runtime_node_into(
        &mut self,
        selected: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        graph: &ConformanceGraph,
        completed: &mut Option<CnpSemanticConformanceNode>,
        failure: &mut Option<crucible_engine::node_contract::OperationFailure>,
        unwind: &mut Option<Box<dyn std::any::Any + Send>>,
    ) -> Result<(), RuntimeError> {
        let peer = self
            .peers
            .get_mut(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        CnpSemanticPreparation::admit_original_conformance_node_into(
            &mut peer.preparation,
            source,
            graph,
            &mut peer.registry,
            &mut peer.supervisor,
            &mut peer.operational,
            completed,
            failure,
            unwind,
        )
    }
}
