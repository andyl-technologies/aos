//! Shared passive Lifecycle resources, dependency rules and model errors.

use aos_sandbox_core::{ExecutionId, ProjectId, ResourceId, SandboxId, SnapshotId, ViewId};

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
/// Only the new batch codec selects this rule. Snapshot-bound kind3 keeps its
/// original postorder contract and traversal. This is a topological tie check,
/// not a second reachability or graph-inventory engine.
pub fn canonical_dependency_postorder_is_complete(
    edges: &[LifecycleDependencyEdgeV1],
    postorder: &[LifecycleResourceV1],
) -> bool {
    use std::collections::{BTreeMap, BTreeSet};

    if !dependency_postorder_is_complete(edges, postorder) {
        return false;
    }

    let mut incoming: BTreeMap<_, usize> = postorder.iter().map(|item| (*item, 0)).collect();
    for edge in edges {
        let Some(count) = incoming.get_mut(&edge.dependency()) else {
            return false;
        };
        *count += 1;
    }
    let mut ready: BTreeSet<_> = incoming
        .iter()
        .filter_map(|(item, count)| (*count == 0).then_some(*item))
        .collect();

    for actual in postorder {
        if ready.pop_first() != Some(*actual) {
            return false;
        }
        for edge in edges.iter().filter(|edge| edge.dependent() == *actual) {
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
