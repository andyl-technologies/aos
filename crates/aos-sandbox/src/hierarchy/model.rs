//! Shared identities, limits, and records for the sandbox ancestry tree.

use aos_sandbox_core::{DesiredGeneration, IncarnationId, ProjectId, SandboxId};

/// Hard implementation ceiling for one validated project tree.
pub const MAXIMUM_TREE_SANDBOXES: usize = 65_536;

/// Configures the independently enforced shape limits for one project tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeLimitsV1 {
    maximum_project_roots: usize,
    maximum_project_sandboxes: usize,
    maximum_project_live_sandboxes: usize,
    maximum_depth: usize,
    maximum_children_per_parent: usize,
    maximum_descendants: usize,
    maximum_live_descendants: usize,
}

impl TreeLimitsV1 {
    /// Constructs internally consistent limits bounded by the implementation ceiling.
    ///
    /// # Errors
    ///
    /// Zero is accepted for a ceiling that intentionally disables that class.
    /// Returns [`HierarchyModelError::InvalidLimits`] when a limit exceeds
    /// [`MAXIMUM_TREE_SANDBOXES`] or is internally inconsistent.
    pub fn new(
        maximum_project_roots: usize,
        maximum_project_sandboxes: usize,
        maximum_project_live_sandboxes: usize,
        maximum_depth: usize,
        maximum_children_per_parent: usize,
        maximum_descendants: usize,
        maximum_live_descendants: usize,
    ) -> Result<Self, HierarchyModelError> {
        let maximum_strict_descendants = maximum_project_sandboxes.saturating_sub(1);
        if maximum_project_roots > maximum_project_sandboxes
            || maximum_project_live_sandboxes > maximum_project_sandboxes
            || maximum_project_sandboxes > MAXIMUM_TREE_SANDBOXES
            || maximum_depth > maximum_strict_descendants
            || maximum_children_per_parent > maximum_strict_descendants
            || maximum_descendants > maximum_strict_descendants
            || maximum_live_descendants > maximum_descendants
            || maximum_live_descendants > maximum_project_live_sandboxes
        {
            return Err(HierarchyModelError::InvalidLimits);
        }

        Ok(Self {
            maximum_project_roots,
            maximum_project_sandboxes,
            maximum_project_live_sandboxes,
            maximum_depth,
            maximum_children_per_parent,
            maximum_descendants,
            maximum_live_descendants,
        })
    }

    /// Returns the maximum independent sandbox roots in the project.
    #[must_use]
    pub const fn maximum_project_roots(self) -> usize {
        self.maximum_project_roots
    }

    /// Returns the maximum logical sandboxes in the complete project forest.
    #[must_use]
    pub const fn maximum_project_sandboxes(self) -> usize {
        self.maximum_project_sandboxes
    }

    /// Returns the maximum live runtime incarnations in the complete project.
    #[must_use]
    pub const fn maximum_project_live_sandboxes(self) -> usize {
        self.maximum_project_live_sandboxes
    }

    /// Returns the maximum number of parent edges from a project root.
    #[must_use]
    pub const fn maximum_depth(self) -> usize {
        self.maximum_depth
    }

    /// Returns the maximum direct children of one sandbox.
    #[must_use]
    pub const fn maximum_children_per_parent(self) -> usize {
        self.maximum_children_per_parent
    }

    /// Returns the maximum strict descendants of one sandbox.
    #[must_use]
    pub const fn maximum_descendants(self) -> usize {
        self.maximum_descendants
    }

    /// Returns the maximum live strict descendants of one sandbox.
    #[must_use]
    pub const fn maximum_live_descendants(self) -> usize {
        self.maximum_live_descendants
    }
}

/// Stores one generation-fenced logical sandbox in a project ancestry graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxTreeRecordV1 {
    project: ProjectId,
    sandbox: SandboxId,
    parent: Option<SandboxId>,
    desired_generation: DesiredGeneration,
    incarnation: Option<IncarnationId>,
}

impl SandboxTreeRecordV1 {
    /// Constructs one specified logical tree record.
    ///
    /// A present incarnation marks the record live. Absence is a durable
    /// logical sandbox, not evidence that it was deleted.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyModelError::UnspecifiedIdentity`] for a zero
    /// identity or generation, or [`HierarchyModelError::SelfParent`] when the
    /// parent is the sandbox itself.
    pub fn new(
        project: ProjectId,
        sandbox: SandboxId,
        parent: Option<SandboxId>,
        desired_generation: DesiredGeneration,
        incarnation: Option<IncarnationId>,
    ) -> Result<Self, HierarchyModelError> {
        if project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || parent.is_some_and(|value| value.as_bytes() == &[0; 16])
            || desired_generation.get() == 0
            || incarnation.is_some_and(|value| value.as_bytes() == &[0; 16])
        {
            return Err(HierarchyModelError::UnspecifiedIdentity);
        }
        if parent == Some(sandbox) {
            return Err(HierarchyModelError::SelfParent);
        }

        Ok(Self {
            project,
            sandbox,
            parent,
            desired_generation,
            incarnation,
        })
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the durable sandbox identity.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the immediate logical parent, if any.
    #[must_use]
    pub const fn parent(self) -> Option<SandboxId> {
        self.parent
    }

    /// Returns the compare-and-swap generation.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the current runtime incarnation, if this sandbox is live.
    #[must_use]
    pub const fn incarnation(self) -> Option<IncarnationId> {
        self.incarnation
    }

    /// Reports whether the sandbox currently has a runtime incarnation.
    #[must_use]
    pub const fn is_live(self) -> bool {
        self.incarnation.is_some()
    }
}

/// Reports malformed or stale hierarchy model input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HierarchyModelError {
    /// A configured tree bound is excessive or internally inconsistent.
    #[error("sandbox tree limits are invalid")]
    InvalidLimits,
    /// A required identity or generation uses its zero sentinel.
    #[error("sandbox hierarchy contains an unspecified identity")]
    UnspecifiedIdentity,
    /// A sandbox names itself as its parent.
    #[error("a sandbox cannot be its own parent")]
    SelfParent,
}
