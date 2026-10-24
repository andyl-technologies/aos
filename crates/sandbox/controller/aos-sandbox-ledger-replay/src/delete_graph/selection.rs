//! Selects a complete dependent closure from the sole reconstructed graph.
//!
//! Selection produces comparison DATA only. It does not revoke a capability,
//! stop an execution, accept a mutation or establish physical absence.

use super::*;
use aos_sandbox_model::SandboxId;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::{
    LifecycleModelError, canonical_dependency_postorder_data_v2,
};

/// Retains one complete logical closure and its canonical removal order.
pub struct DeleteGraphSelectionDataV2 {
    /// Names the requested Sandbox at the end of the removal order.
    pub root: SandboxId,
    /// Lists every selected resource in canonical identity order.
    pub resources: Vec<Resource>,
    /// Retains all relations whose two endpoints are selected.
    pub dependencies: Vec<DeleteGraphEdgeDataV2>,
    /// Lists selected dependents before their dependencies, ending at the root.
    pub postorder: Vec<Resource>,
}

/// Reports a closed logical refusal without claiming a native disposition.
#[derive(Debug, thiserror::Error)]
pub enum DeleteGraphSelectionErrorV2 {
    /// The complete graph contains no such current Sandbox.
    #[error("the requested Sandbox is absent from the complete dependency graph")]
    MissingRoot,
    /// Default deletion would also remove a dependent logical resource.
    #[error("the Sandbox has dependent resources; cascade is required")]
    Dependents,
    /// The selected relation is cyclic, dangling or otherwise noncanonical.
    #[error(transparent)]
    Model(#[from] LifecycleModelError),
    /// A bounded, prepaid pure-work allocation failed.
    #[error("the bounded dependency selection allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
}

impl DeleteDependencyGraphDataV2 {
    /// Selects the complete dependent closure of one supplied current Sandbox.
    ///
    /// The caller pays [`Self::selection_receiving_bytes_v2`] before entry and
    /// separately proves that this graph came from its actual native originals.
    /// Cascade permits logical dependents; it does not waive a current consumer,
    /// unresolved native consumer, storage hold or later fresh preaccept check.
    ///
    /// # Errors
    /// Refuses an absent root, dependents without cascade,
    /// an invalid complete postorder or a bounded allocation failure.
    pub fn select_dependent_closure_data_v2(
        &self,
        root: SandboxId,
        cascade: bool,
    ) -> Result<DeleteGraphSelectionDataV2, DeleteGraphSelectionErrorV2> {
        let root_resource = Resource::Sandbox(root);
        if !self.projections.iter().any(|row| row.resource == root_resource) {
            return Err(DeleteGraphSelectionErrorV2::MissingRoot);
        }

        let maximum = self.projections.len()
            .checked_add(self.companions.len().checked_mul(2)
                .ok_or(LifecycleModelError::InvalidModel)?)
            .ok_or(LifecycleModelError::InvalidModel)?;
        let resources = dependent_resources_data_v2(
            &self.edges, root_resource, maximum, cascade,
        )?;

        let mut dependencies = Vec::new();
        let mut edges = Vec::new();
        dependencies.try_reserve_exact(self.edges.len())?;
        edges.try_reserve_exact(self.edges.len())?;
        for relation in &self.edges {
            if resources.binary_search(&relation.edge.dependent()).is_ok()
                && resources.binary_search(&relation.edge.dependency()).is_ok()
            {
                edges.push(relation.edge);
                dependencies.push(DeleteGraphEdgeDataV2 {
                    edge: relation.edge,
                    class: relation.class,
                });
            }
        }

        let postorder = canonical_dependency_postorder_data_v2(
            &edges, &resources, root_resource,
        )?;
        Ok(DeleteGraphSelectionDataV2 { root, resources, dependencies, postorder })
    }

    /// Bounds this exact graph's closure vectors and shared canonical walk.
    ///
    /// This byte-only recipe includes the shared map/set node suppliers. It
    /// adds no namespace entries, native admission or resource capacity.
    #[must_use]
    pub fn selection_receiving_bytes_v2(&self) -> Option<usize> {
        let vertices = self.projections.len()
            .checked_add(self.companions.len().checked_mul(2)?)?;
        let resource_planes = vertices.checked_mul(std::mem::size_of::<Resource>())?
            .checked_mul(3)?;
        let edges = self.edges.len().checked_mul(
            std::mem::size_of::<DeleteGraphEdgeDataV2>()
                .checked_add(std::mem::size_of::<Edge>())?,
        )?.checked_mul(3)?;
        let map = aos_sandbox_journal::geometry::
            conservative_btree_node_bytes_v1::<Resource, usize>(vertices)?;
        let set = aos_sandbox_journal::geometry::
            conservative_btree_node_bytes_v1::<Resource, ()>(vertices)?;
        std::mem::size_of::<Result<DeleteGraphSelectionDataV2, DeleteGraphSelectionErrorV2>>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<(
                std::collections::BTreeMap<Resource, usize>,
                std::collections::BTreeSet<Resource>,
            )>().checked_mul(3)?)?
            .checked_add(resource_planes)?
            .checked_add(edges)?
            .checked_add(map)?
            .checked_add(set)
    }
}

// Both live roles call the graph method above. This one pure fixed-point walk
// uses only complete supplied relations, with an actual prepaid vertex bound.
fn dependent_resources_data_v2(
    relations: &[DeleteGraphEdgeDataV2],
    root_resource: Resource,
    maximum: usize,
    cascade: bool,
) -> Result<Vec<Resource>, DeleteGraphSelectionErrorV2> {
    let mut resources = Vec::new();
    resources.try_reserve_exact(maximum)?;
    resources.push(root_resource);

    // Reverse reachability includes consumers in other Sandboxes. Outgoing
    // references to an unrelated owner remain read dependencies, rather
    // than broadening deletion to that owner's whole Sandbox.
    loop {
        let before = resources.len();
        for relation in relations {
            if resources.contains(&relation.edge.dependency())
                && !resources.contains(&relation.edge.dependent())
            {
                if resources.len() == maximum {
                    return Err(LifecycleModelError::InvalidModel.into());
                }
                resources.push(relation.edge.dependent());
            }
        }
        if resources.len() == before {
            break;
        }
    }

    if !cascade && resources.len() != 1 {
        return Err(DeleteGraphSelectionErrorV2::Dependents);
    }
    resources.sort_unstable();
    Ok(resources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{ExecutionId, ResourceId, ViewId};

    fn relation(dependent: Resource, dependency: Resource, class: Class) -> DeleteGraphEdgeDataV2 {
        DeleteGraphEdgeDataV2 { edge: Edge::new(dependent, dependency).unwrap(), class }
    }

    #[test]
    fn live_export_closure_includes_the_other_sandbox_consumer_but_not_its_owner() {
        let root = Resource::Sandbox(SandboxId::from_bytes([1; 16]));
        let other = Resource::Sandbox(SandboxId::from_bytes([2; 16]));
        let view = Resource::View(ViewId::from_bytes([3; 16]));
        let attachment = Resource::Attachment(ResourceId::from_bytes([4; 16]));
        let execution = Resource::Execution(ExecutionId::from_bytes([5; 16]));
        let relations = [
            relation(view, root, Class::LiveViewOwner),
            relation(attachment, view, Class::LogicalView),
            relation(attachment, other, Class::AttachmentDestination),
            relation(execution, other, Class::ExecutionOwner),
            relation(execution, attachment, Class::AssignmentAttachmentConsumer),
        ];

        assert!(matches!(dependent_resources_data_v2(&relations, root, 5, false),
            Err(DeleteGraphSelectionErrorV2::Dependents)));
        let selected = dependent_resources_data_v2(&relations, root, 5, true).unwrap();

        assert_eq!(selected.len(), 4);
        assert!([root, view, attachment, execution].iter().all(|resource| selected.contains(resource)));
        assert!(!selected.contains(&other));
        assert!(dependent_resources_data_v2(&relations, root, 3, true).is_err());
    }

}
