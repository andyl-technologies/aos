//! Follows only actual held initial nodes before the exact runtime transfer.

use super::*;
use crate::node_adapters::cnp::{CnpSemanticSource, PacketCompleteSemanticSource};
use crate::node_admission::{CompleteOriginalFreshRestoreHostWindow, InstalledConformancePlan};

impl CnpSemanticExactConformanceWorldProvider {
    /// Inspects the real held destination of an initial preparation, if present.
    ///
    /// `false` means this provider has already transferred its node bank. It
    /// cannot stand in for the caller's independently authenticated destination.
    ///
    /// # Errors
    /// Refuses retirement, partial erased transfer, a foreign original plan,
    /// absent selected node or another Source/ticket/SDK ownership occurrence.
    pub fn inspect_original_initial_preparation_data(
        &self,
        ticket: &CompleteOriginalFreshRestoreHostWindow,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
    ) -> Result<bool, RuntimeError> {
        if self.original.retirement.is_some() || !self.original.native.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let Some(nodes) = &self.original.nodes else {
            return Ok(false);
        };
        let graph = self
            .original
            .original_graph
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !graph.plan().same_original(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut selected = None;
        for node in nodes {
            if node.original_conformance_route_data().node == source.installation().descriptor.id
                && selected.replace(node).is_some()
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let node = selected.ok_or(RuntimeError::UnknownNode)?;
        node.inspect_original_initial_preparation_data(ticket, source, plan)?;
        Ok(true)
    }

    /// Counts the same held initial nodes through their actual original Sources.
    ///
    /// The ordinary provider observer keeps its strict Source walk. All existing
    /// graph, Host, queue, partial banks and independent node backing remain in
    /// this complete owning census.
    ///
    /// # Errors
    /// Refuses unknown owners, changed Source membership or the ordinary bound.
    pub fn retained_original_initial_requested_storage_precredit_data(
        &self,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if let Some(nodes) = &self.original.nodes {
            if nodes.len() != 3 {
                return Err(RuntimeError::UnsupportedFacet);
            }
            for (node, source) in nodes.iter().zip(sources) {
                node.original_conformance_facets_data(source)?;
            }
        }
        self.retained_storage_selected_precredit_data(maximum, Some(sources))
    }

    /// Names the actual initial member loans beside the existing owning counter.
    pub fn original_initial_preparation_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<&CompleteOriginalFreshRestoreHostWindow>()
            + size_of::<&InstalledConformancePlan>()
            + size_of::<&Rc<PacketCompleteSemanticSource>>()
            + size_of::<&[Rc<PacketCompleteSemanticSource>; 3]>()
            + size_of::<Option<&[Rc<PacketCompleteSemanticSource>; 3]>>()
            + size_of::<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>()
            + size_of::<std::slice::Iter<'static, CnpSemanticConformanceNode>>()
            + size_of::<
                std::iter::Zip<
                    std::slice::Iter<'static, CnpSemanticConformanceNode>,
                    std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>,
                >,
            >()
            + size_of::<Option<&CnpSemanticConformanceNode>>() * 2
            + size_of::<&CnpSemanticConformanceNode>()
            + size_of::<&crucible_node_contract::Id>()
            + size_of::<Option<&Rc<PacketCompleteSemanticSource>>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
