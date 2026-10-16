//! Transfers exact original preparations into fixed admitted collecting-node slots.

use super::*;
use crucible::{node_adapters::cnp::CnpSemanticConformanceNode, node_admission::ConformanceGraph};

impl PreparationOwners {
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
        failure: &mut Option<crucible::node_contract::OperationFailure>,
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
