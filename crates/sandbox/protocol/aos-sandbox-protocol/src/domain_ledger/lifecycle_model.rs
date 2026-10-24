//! Owns passive lifecycle resource identity, dependency rules and model errors.
//!
//! Resource DATA retains the established typed identity and wire vocabulary:
//!
//! ```text
//! resource := kind:u8 (1..9) | nonzero typed-id:16
//! dependency := dependent-resource | dependency-resource
//! ```
//!
//! The original completeness rule and deterministic ready-node refinement stay
//! separate. Callers retain bounds, uniqueness, inventory and authenticated
//! graph/currentness checks; these models do not grant admission or custody.

use aos_sandbox_model::{ExecutionId, ProjectId, ResourceId, SandboxId, SnapshotId, ViewId};

/// Reports invalid lifecycle input, transition, or encoded state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LifecycleModelError {
    /// Caller data is invalid or non-canonical.
    #[error("lifecycle model is invalid or non-canonical")]
    InvalidModel,
    /// Encoded state violates schema, bounds, or digest.
    #[error("lifecycle record encoding is corrupt")]
    CorruptEncoding,
    /// A successor violates monotone progress.
    #[error("lifecycle transition is invalid")]
    InvalidTransition,
    /// Replay conflicts with immutable intent or predecessor state.
    #[error("lifecycle history conflicts with durable state")]
    Conflict,
    /// Preflighted bounded allocation failed.
    #[error("lifecycle decode allocation failed")]
    Allocation,
}

/// Selects a logical resource with a type-preserving identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LifecycleResourceV1 {
    /// A durable sandbox.
    Sandbox(SandboxId),
    /// One admitted execution.
    Execution(ExecutionId),
    /// One durable snapshot.
    Snapshot(SnapshotId),
    /// One filesystem view.
    View(ViewId),
    /// One sandbox filesystem attachment.
    Attachment(ResourceId),
    /// One delegated capability.
    Capability(ResourceId),
    /// One immutable environment generation identity.
    Environment(ResourceId),
    /// One sandbox project authority domain.
    Project(ProjectId),
    /// Another registered controller resource.
    Other(ResourceId),
}

impl LifecycleResourceV1 {
    /// Returns the established resource kind code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Sandbox(_) => 1,
            Self::Execution(_) => 2,
            Self::Snapshot(_) => 3,
            Self::View(_) => 4,
            Self::Attachment(_) => 5,
            Self::Capability(_) => 6,
            Self::Environment(_) => 7,
            Self::Project(_) => 8,
            Self::Other(_) => 9,
        }
    }

    /// Decodes the complete typed resource identity from its wire fields.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::CorruptEncoding`] for an unknown kind or
    /// an all-zero identity.
    pub fn from_code(code: u8, bytes: [u8; 16]) -> Result<Self, LifecycleModelError> {
        let resource = match code {
            1 => Self::Sandbox(SandboxId::from_bytes(bytes)),
            2 => Self::Execution(ExecutionId::from_bytes(bytes)),
            3 => Self::Snapshot(SnapshotId::from_bytes(bytes)),
            4 => Self::View(ViewId::from_bytes(bytes)),
            5 => Self::Attachment(ResourceId::from_bytes(bytes)),
            6 => Self::Capability(ResourceId::from_bytes(bytes)),
            7 => Self::Environment(ResourceId::from_bytes(bytes)),
            8 => Self::Project(ProjectId::from_bytes(bytes)),
            9 => Self::Other(ResourceId::from_bytes(bytes)),
            _ => return Err(LifecycleModelError::CorruptEncoding),
        };
        if resource.as_bytes() == &[0; 16] {
            Err(LifecycleModelError::CorruptEncoding)
        } else {
            Ok(resource)
        }
    }

    /// Borrows the stored typed identity bytes without copying them.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        match self {
            Self::Sandbox(v) => v.as_bytes(),
            Self::Execution(v) => v.as_bytes(),
            Self::Snapshot(v) => v.as_bytes(),
            Self::View(v) => v.as_bytes(),
            Self::Attachment(v) | Self::Capability(v) | Self::Environment(v) | Self::Other(v) => {
                v.as_bytes()
            }
            Self::Project(v) => v.as_bytes(),
        }
    }
}

/// Retains one dependency edge used to derive a cascade-delete postorder.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleDependencyEdgeV1 {
    dependent: LifecycleResourceV1,
    dependency: LifecycleResourceV1,
}

impl LifecycleDependencyEdgeV1 {
    /// Constructs a non-reflexive typed dependency edge.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for a self edge.
    pub fn new(
        dependent: LifecycleResourceV1,
        dependency: LifecycleResourceV1,
    ) -> Result<Self, LifecycleModelError> {
        if dependent == dependency {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                dependent,
                dependency,
            })
        }
    }

    /// Returns the resource that must be deleted first.
    #[must_use]
    pub const fn dependent(self) -> LifecycleResourceV1 {
        self.dependent
    }

    /// Returns the retained resource on which it depends.
    #[must_use]
    pub const fn dependency(self) -> LifecycleResourceV1 {
        self.dependency
    }
}

/// Checks the original dependent-before-dependency completeness rule.
///
/// Callers separately enforce bounded counts, unique resources and a closed
/// inventory. A successful topology check does not authenticate that inventory.
pub fn dependency_postorder_is_complete(
    edges: &[LifecycleDependencyEdgeV1],
    postorder: &[LifecycleResourceV1],
) -> bool {
    let Some(root) = postorder.last().copied() else {
        return false;
    };
    if edges.iter().any(|edge| {
        let dependent = postorder.iter().position(|item| *item == edge.dependent());
        let dependency = postorder.iter().position(|item| *item == edge.dependency());
        !matches!((dependent, dependency), (Some(left), Some(right)) if left < right)
    }) || postorder.iter().any(|resource| {
        let outgoing = edges
            .iter()
            .filter(|edge| edge.dependent() == *resource)
            .count();
        (*resource == root && outgoing != 0) || (*resource != root && outgoing == 0)
    }) {
        return false;
    }
    postorder.iter().all(|start| {
        let mut current = *start;
        for _ in 0..postorder.len() {
            if current == root {
                return true;
            }
            let Some(next) = edges
                .iter()
                .find(|edge| edge.dependent() == current)
                .map(|edge| edge.dependency())
            else {
                return false;
            };
            current = next;
        }
        false
    })
}

/// Adds deterministic ready-node ordering to the existing complete-graph check.
///
/// The existing Delete batch codec selects this rule. Snapshot-bound kind3
/// keeps its original postorder contract and traversal. This is a topological tie check,
/// not a second reachability or graph-inventory engine.
pub fn canonical_dependency_postorder_is_complete(
    edges: &[LifecycleDependencyEdgeV1],
    postorder: &[LifecycleResourceV1],
) -> bool {
    if !dependency_postorder_is_complete(edges, postorder) {
        return false;
    }
    let mut index = 0;
    visit_canonical_dependency_order_v2(edges, postorder, |resource| {
        let matches = postorder.get(index) == Some(&resource);
        index += 1;
        matches
    })
}

/// Derives the canonical dependent-before-dependency order from complete DATA.
///
/// The caller independently authenticates every resource and edge and admits
/// the output and same graph-validator scratch before entry. The sole ready-
/// node walk is shared with the existing canonical validator above.
///
/// # Errors
/// Refuses duplicate, cyclic, disconnected or dangling resources/edges, a root
/// that is not the terminal dependency, or a failed bounded output reservation.
pub fn canonical_dependency_postorder_data_v2(
    edges: &[LifecycleDependencyEdgeV1],
    resources: &[LifecycleResourceV1],
    root: LifecycleResourceV1,
) -> Result<Vec<LifecycleResourceV1>, LifecycleModelError> {
    let mut postorder = Vec::new();
    postorder.try_reserve_exact(resources.len()).map_err(|_| LifecycleModelError::Allocation)?;
    if !visit_canonical_dependency_order_v2(edges, resources, |resource| {
        postorder.push(resource);
        true
    }) || postorder.last() != Some(&root)
        || !dependency_postorder_is_complete(edges, &postorder)
    {
        return Err(LifecycleModelError::InvalidModel);
    }
    Ok(postorder)
}

// This pure visitor emits only typed resource DATA. It has no native owner,
// financial borrower, writer capability or error/IO callback.
fn visit_canonical_dependency_order_v2(
    edges: &[LifecycleDependencyEdgeV1],
    resources: &[LifecycleResourceV1],
    mut visit: impl FnMut(LifecycleResourceV1) -> bool,
) -> bool {
    use std::collections::{BTreeMap, BTreeSet};

    let mut incoming: BTreeMap<_, usize> = resources.iter().map(|item| (*item, 0)).collect();
    if incoming.len() != resources.len() { return false; }
    for edge in edges {
        if !incoming.contains_key(&edge.dependent()) { return false; }
        let Some(count) = incoming.get_mut(&edge.dependency()) else {
            return false;
        };
        *count += 1;
    }
    let mut ready: BTreeSet<_> = incoming
        .iter()
        .filter_map(|(item, count)| (*count == 0).then_some(*item))
        .collect();

    for _ in resources {
        let Some(actual) = ready.pop_first() else { return false; };
        if !visit(actual) { return false; }
        for edge in edges.iter().filter(|edge| edge.dependent() == actual) {
            let Some(count) = incoming.get_mut(&edge.dependency()) else {
                return false;
            };
            let Some(next) = count.checked_sub(1) else {
                return false;
            };
            *count = next;
            if next == 0 {
                ready.insert(edge.dependency());
            }
        }
    }
    ready.is_empty()
}

#[cfg(test)]
mod canonical_order_tests {
    use super::*;

    #[test]
    fn producer_uses_the_existing_canonical_tie_rule_and_rejects_partial_graphs() {
        let resource = |byte| LifecycleResourceV1::Sandbox(SandboxId::from_bytes([byte; 16]));
        let first = resource(1);
        let second = resource(2);
        let root = resource(3);
        let edges = [LifecycleDependencyEdgeV1::new(first, root).unwrap(),
            LifecycleDependencyEdgeV1::new(second, root).unwrap()];

        let order = canonical_dependency_postorder_data_v2(&edges, &[root, second, first], root).unwrap();
        assert_eq!(order, [first, second, root]);
        assert!(canonical_dependency_postorder_is_complete(&edges, &order));
        assert!(canonical_dependency_postorder_data_v2(&edges, &[root, first], root).is_err());
        assert!(canonical_dependency_postorder_data_v2(&edges, &[root, second, first, first], root).is_err());
        assert!(canonical_dependency_postorder_data_v2(&edges, &[root, second, first, resource(4)], root).is_err());
        let cycle = [LifecycleDependencyEdgeV1::new(first, second).unwrap(),
            LifecycleDependencyEdgeV1::new(second, first).unwrap()];
        assert!(canonical_dependency_postorder_data_v2(&cycle, &[first, second], root).is_err());
    }
}

/// Bounds the established complete lifecycle expectation and inventory rosters.
pub const MAXIMUM_LIFECYCLE_EXPECTATIONS: usize = 4_096;

/// Carries one historical resource and its complete row commitment.
///
/// These fields are comparison DATA. They authenticate no inventory and retain
/// no native owner or effect grant. Actual inventory owners independently
/// verify protected provenance, completeness and currentness before use.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleBootDomainEntryDataV1 {
    /// Identifies the logical resource represented by this historical row.
    pub resource: LifecycleResourceV1,
    /// Commits the complete protected row bytes used for stable ordering.
    pub identity: aos_sandbox_model::ObjectDigest,
}

impl LifecycleBootDomainEntryDataV1 {
    /// Checks the established nonzero resource and row identity constraints.
    ///
    /// # Errors
    /// Refuses the same sentinel resource or zero row commitment as before.
    pub fn from_fields_data_v1(
        resource: LifecycleResourceV1,
        identity: aos_sandbox_model::ObjectDigest,
    ) -> Result<Self, LifecycleModelError> {
        if resource.as_bytes() == &[0; 16] || identity.as_bytes() == &[0; 32] {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self { resource, identity })
    }

    /// Returns the logical resource represented by this historical row.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the complete row commitment used for stable order.
    #[must_use]
    pub const fn identity(self) -> aos_sandbox_model::ObjectDigest {
        self.identity
    }
}
