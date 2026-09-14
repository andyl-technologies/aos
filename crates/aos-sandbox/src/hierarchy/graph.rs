//! Bounded validation and reduction of project-local ancestry graphs.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{DesiredGeneration, IncarnationId, ProjectId, Revision, SandboxId};

use super::model::{MAXIMUM_TREE_SANDBOXES, SandboxTreeRecordV1, TreeLimitsV1};

/// Maximum durable deleted identities retained by one project tree.
pub const MAXIMUM_TREE_TOMBSTONES: usize = 262_144;

/// Owns one validated project-local forest in canonical sandbox order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxTreeV1 {
    project: ProjectId,
    tree_generation: Revision,
    limits: TreeLimitsV1,
    records: BTreeMap<SandboxId, SandboxTreeRecordV1>,
    tombstones: BTreeSet<SandboxId>,
    depths: BTreeMap<SandboxId, usize>,
}

impl SandboxTreeV1 {
    /// Validates canonical records and all tree-wide shape limits.
    ///
    /// Project roots have no parent. Multiple roots are allowed because the
    /// project, rather than an artificial sandbox, is their common parent.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError`] for unordered or duplicate records,
    /// cross-project or missing parents, cycles, or any exceeded bound.
    pub fn from_records(
        project: ProjectId,
        tree_generation: Revision,
        limits: TreeLimitsV1,
        records: Vec<SandboxTreeRecordV1>,
    ) -> Result<Self, SandboxTreeError> {
        Self::from_records_and_tombstones(project, tree_generation, limits, records, Vec::new())
    }

    /// Validates canonical live records and durable never-reuse tombstones.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError`] for malformed records or tombstones,
    /// identity overlap, or any invalid graph invariant.
    pub fn from_records_and_tombstones(
        project: ProjectId,
        tree_generation: Revision,
        limits: TreeLimitsV1,
        records: Vec<SandboxTreeRecordV1>,
        tombstones: Vec<SandboxId>,
    ) -> Result<Self, SandboxTreeError> {
        if project.as_bytes() == &[0; 16]
            || tree_generation.get() == 0
            || records.len() > MAXIMUM_TREE_SANDBOXES
            || tombstones.len() > MAXIMUM_TREE_TOMBSTONES
        {
            return Err(SandboxTreeError::Capacity);
        }
        if !records
            .windows(2)
            .all(|pair| pair[0].sandbox() < pair[1].sandbox())
        {
            return Err(SandboxTreeError::RecordsNotCanonical);
        }
        if records.iter().any(|record| record.project() != project) {
            return Err(SandboxTreeError::ProjectMismatch);
        }
        if tombstones
            .iter()
            .any(|sandbox| sandbox.as_bytes() == &[0; 16])
            || !tombstones.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(SandboxTreeError::TombstonesNotCanonical);
        }

        let records: BTreeMap<_, _> = records
            .into_iter()
            .map(|record| (record.sandbox(), record))
            .collect();
        let tombstones: BTreeSet<_> = tombstones.into_iter().collect();
        if records.keys().any(|sandbox| tombstones.contains(sandbox)) {
            return Err(SandboxTreeError::RetiredSandbox);
        }
        let depths = validate_graph(&records, limits)?;

        Ok(Self {
            project,
            tree_generation,
            limits,
            records,
            tombstones,
            depths,
        })
    }

    /// Returns the project-level compare-and-swap generation.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the project shared by every record.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the enforced shape limits.
    #[must_use]
    pub const fn limits(&self) -> TreeLimitsV1 {
        self.limits
    }

    /// Returns records in canonical sandbox order.
    #[must_use]
    pub fn records(&self) -> impl ExactSizeIterator<Item = &SandboxTreeRecordV1> {
        self.records.values()
    }

    /// Returns durable deleted identities in canonical order.
    #[must_use]
    pub fn tombstones(&self) -> impl ExactSizeIterator<Item = SandboxId> + '_ {
        self.tombstones.iter().copied()
    }

    /// Returns one record by durable identity.
    #[must_use]
    pub fn record(&self, sandbox: SandboxId) -> Option<&SandboxTreeRecordV1> {
        self.records.get(&sandbox)
    }

    /// Returns the number of parent edges from the project root.
    #[must_use]
    pub fn depth(&self, sandbox: SandboxId) -> Option<usize> {
        self.depths.get(&sandbox).copied()
    }

    /// Reports whether `candidate` is `root` or one of its descendants.
    #[must_use]
    pub fn contains_in_subtree(&self, root: SandboxId, candidate: SandboxId) -> bool {
        if !self.records.contains_key(&root) || !self.records.contains_key(&candidate) {
            return false;
        }

        let mut cursor = Some(candidate);
        while let Some(current) = cursor {
            if current == root {
                return true;
            }
            cursor = self
                .records
                .get(&current)
                .and_then(|record| record.parent());
        }
        false
    }

    /// Returns the complete subtree as a canonical sandbox set.
    ///
    /// The implementation walks records once in depth order. Callers that
    /// classify many records or edges should retain this set instead of
    /// repeatedly following parent chains.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError::UnknownSandbox`] when the root is absent,
    /// or [`SandboxTreeError::Capacity`] when bounded allocation fails.
    pub fn subtree_members(
        &self,
        root: SandboxId,
    ) -> Result<BTreeSet<SandboxId>, SandboxTreeError> {
        let root_depth = self.depth(root).ok_or(SandboxTreeError::UnknownSandbox)?;
        let mut by_depth = Vec::new();
        by_depth
            .try_reserve_exact(self.records.len())
            .map_err(|_| SandboxTreeError::Capacity)?;
        by_depth.extend(
            self.depths
                .iter()
                .map(|(sandbox, depth)| (*depth, *sandbox)),
        );
        by_depth.sort_unstable();

        let mut members = BTreeSet::new();
        members.insert(root);
        for (depth, sandbox) in by_depth {
            if depth <= root_depth || sandbox == root {
                continue;
            }
            let parent = self
                .records
                .get(&sandbox)
                .and_then(SandboxTreeRecordV1::parent)
                .ok_or(SandboxTreeError::MissingParent)?;
            if members.contains(&parent) {
                members.insert(sandbox);
            }
        }

        Ok(members)
    }

    /// Returns a root-to-parent chain for the subject.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError::UnknownSandbox`] when the subject is absent.
    pub fn ancestry(&self, sandbox: SandboxId) -> Result<Vec<SandboxId>, SandboxTreeError> {
        let record = self
            .records
            .get(&sandbox)
            .ok_or(SandboxTreeError::UnknownSandbox)?;
        let depth = self
            .depth(sandbox)
            .ok_or(SandboxTreeError::UnknownSandbox)?;
        let mut reversed = Vec::new();
        reversed
            .try_reserve_exact(depth)
            .map_err(|_| SandboxTreeError::Capacity)?;
        let mut cursor = record.parent();

        while let Some(parent) = cursor {
            reversed.push(parent);
            cursor = self.records.get(&parent).and_then(|entry| entry.parent());
        }
        reversed.reverse();
        Ok(reversed)
    }

    /// Produces a validated successor after inserting a new sandbox.
    ///
    /// The parent generation is checked before graph validation. This reducer
    /// creates no storage, runtime, capability, or journal effect.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError`] for identity reuse, a stale parent, or a
    /// resulting graph that violates a project limit.
    pub fn insert(
        &self,
        record: SandboxTreeRecordV1,
        expected_tree_generation: Revision,
        expected_parent_generation: Option<DesiredGeneration>,
    ) -> Result<Self, SandboxTreeError> {
        if expected_tree_generation != self.tree_generation {
            return Err(SandboxTreeError::StaleTreeGeneration);
        }
        if record.project() != self.project {
            return Err(SandboxTreeError::ProjectMismatch);
        }
        if self.records.contains_key(&record.sandbox()) {
            return Err(SandboxTreeError::DuplicateSandbox);
        }
        if self.tombstones.contains(&record.sandbox()) {
            return Err(SandboxTreeError::RetiredSandbox);
        }
        if record.desired_generation().get() != 1 {
            return Err(SandboxTreeError::InvalidInitialGeneration);
        }
        match (record.parent(), expected_parent_generation) {
            (None, None) => {}
            (Some(parent), Some(expected)) => {
                let parent = self
                    .records
                    .get(&parent)
                    .ok_or(SandboxTreeError::MissingParent)?;
                if parent.desired_generation() != expected {
                    return Err(SandboxTreeError::StaleGeneration);
                }
            }
            _ => return Err(SandboxTreeError::StaleGeneration),
        }

        let mut records = self.records.clone();
        records.insert(record.sandbox(), record);
        let depths = validate_graph(&records, self.limits)?;
        let tree_generation = self
            .tree_generation
            .checked_next()
            .map_err(|_| SandboxTreeError::Capacity)?;
        Ok(Self {
            project: self.project,
            tree_generation,
            limits: self.limits,
            records,
            tombstones: self.tombstones.clone(),
            depths,
        })
    }

    /// Produces a successor after an exact generation-CAS record replacement.
    ///
    /// This reducer supports desired-state updates, reparenting, and explicit
    /// incarnation changes. Full graph validation prevents cycles and ensures
    /// every project and descendant limit still holds.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError`] for stale generations, identity changes,
    /// skipped successor generations, or an invalid resulting graph.
    fn replace(
        &self,
        replacement: SandboxTreeRecordV1,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
    ) -> Result<Self, SandboxTreeError> {
        if expected_tree_generation != self.tree_generation {
            return Err(SandboxTreeError::StaleTreeGeneration);
        }
        let current = self
            .records
            .get(&replacement.sandbox())
            .ok_or(SandboxTreeError::UnknownSandbox)?;
        let next_generation = expected_sandbox_generation
            .checked_next()
            .map_err(|_| SandboxTreeError::Capacity)?;
        if replacement.project() != self.project
            || current.desired_generation() != expected_sandbox_generation
            || replacement.desired_generation() != next_generation
        {
            return Err(SandboxTreeError::StaleGeneration);
        }

        let mut records = self.records.clone();
        records.insert(replacement.sandbox(), replacement);
        let depths = validate_graph(&records, self.limits)?;
        Ok(Self {
            project: self.project,
            tree_generation: self
                .tree_generation
                .checked_next()
                .map_err(|_| SandboxTreeError::Capacity)?,
            limits: self.limits,
            records,
            tombstones: self.tombstones.clone(),
            depths,
        })
    }

    /// Advances one sandbox desired generation without changing topology or incarnation.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError`] for stale input or an invalid successor.
    pub fn advance_sandbox_generation(
        &self,
        sandbox: SandboxId,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
    ) -> Result<Self, SandboxTreeError> {
        let current = self
            .record(sandbox)
            .ok_or(SandboxTreeError::UnknownSandbox)?;
        let replacement = SandboxTreeRecordV1::new(
            current.project(),
            current.sandbox(),
            current.parent(),
            expected_sandbox_generation
                .checked_next()
                .map_err(|_| SandboxTreeError::Capacity)?,
            current.incarnation(),
        )
        .map_err(|_| SandboxTreeError::InvalidRecord)?;
        self.replace(
            replacement,
            expected_tree_generation,
            expected_sandbox_generation,
        )
    }

    /// Reparents one sandbox after subject, project-tree, and new-parent CAS checks.
    ///
    /// Full successor validation prevents cycles and re-evaluates depth, fanout,
    /// total-descendant, and live-descendant bounds for both ancestry branches.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError`] for stale fences, a missing parent, or an
    /// invalid resulting graph.
    pub fn reparent(
        &self,
        sandbox: SandboxId,
        new_parent: Option<SandboxId>,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
        expected_new_parent_generation: Option<DesiredGeneration>,
    ) -> Result<Self, SandboxTreeError> {
        match (new_parent, expected_new_parent_generation) {
            (None, None) => {}
            (Some(parent), Some(expected)) => {
                let parent = self.record(parent).ok_or(SandboxTreeError::MissingParent)?;
                if parent.desired_generation() != expected {
                    return Err(SandboxTreeError::StaleGeneration);
                }
            }
            _ => return Err(SandboxTreeError::StaleGeneration),
        }
        let current = self
            .record(sandbox)
            .ok_or(SandboxTreeError::UnknownSandbox)?;
        let subtree = self.subtree_members(current.sandbox())?;
        if self
            .records
            .values()
            .any(|record| record.is_live() && subtree.contains(&record.sandbox()))
        {
            return Err(SandboxTreeError::LiveReparent);
        }
        if current.parent() == new_parent {
            return Err(SandboxTreeError::NoStateChange);
        }
        let replacement = SandboxTreeRecordV1::new(
            current.project(),
            current.sandbox(),
            new_parent,
            expected_sandbox_generation
                .checked_next()
                .map_err(|_| SandboxTreeError::Capacity)?,
            current.incarnation(),
        )
        .map_err(|_| SandboxTreeError::InvalidRecord)?;
        self.replace(
            replacement,
            expected_tree_generation,
            expected_sandbox_generation,
        )
    }

    /// Produces a successor that changes only one sandbox incarnation.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError`] for stale input or an invalid successor.
    pub fn set_incarnation(
        &self,
        sandbox: SandboxId,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
        incarnation: Option<IncarnationId>,
    ) -> Result<Self, SandboxTreeError> {
        let current = self
            .record(sandbox)
            .ok_or(SandboxTreeError::UnknownSandbox)?;
        if current.incarnation().is_some() && incarnation.is_some() {
            return Err(SandboxTreeError::IncarnationReplacementRequiresStop);
        }
        if current.incarnation() == incarnation {
            return Err(SandboxTreeError::NoStateChange);
        }
        let replacement = SandboxTreeRecordV1::new(
            current.project(),
            current.sandbox(),
            current.parent(),
            expected_sandbox_generation
                .checked_next()
                .map_err(|_| SandboxTreeError::Capacity)?,
            incarnation,
        )
        .map_err(|_| SandboxTreeError::InvalidRecord)?;
        self.replace(
            replacement,
            expected_tree_generation,
            expected_sandbox_generation,
        )
    }

    /// Produces a successor after deleting one generation-fenced leaf.
    ///
    /// Deleting a sandbox with any direct child fails; cascade planning must
    /// submit separate leaf deletions in postorder.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxTreeError`] for stale input, an unknown sandbox, or a
    /// sandbox that still has children.
    pub fn delete_leaf(
        &self,
        sandbox: SandboxId,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
    ) -> Result<Self, SandboxTreeError> {
        if expected_tree_generation != self.tree_generation {
            return Err(SandboxTreeError::StaleTreeGeneration);
        }
        let current = self
            .record(sandbox)
            .ok_or(SandboxTreeError::UnknownSandbox)?;
        if current.desired_generation() != expected_sandbox_generation {
            return Err(SandboxTreeError::StaleGeneration);
        }
        if current.is_live() {
            return Err(SandboxTreeError::LiveDelete);
        }
        if self
            .records
            .values()
            .any(|record| record.parent() == Some(sandbox))
        {
            return Err(SandboxTreeError::NotLeaf);
        }
        if self.tombstones.len() >= MAXIMUM_TREE_TOMBSTONES {
            return Err(SandboxTreeError::Capacity);
        }
        let mut records = self.records.clone();
        records.remove(&sandbox);
        let mut tombstones = self.tombstones.clone();
        tombstones.insert(sandbox);
        let depths = validate_graph(&records, self.limits)?;
        Ok(Self {
            project: self.project,
            tree_generation: self
                .tree_generation
                .checked_next()
                .map_err(|_| SandboxTreeError::Capacity)?,
            limits: self.limits,
            records,
            tombstones,
            depths,
        })
    }
}

fn validate_graph(
    records: &BTreeMap<SandboxId, SandboxTreeRecordV1>,
    limits: TreeLimitsV1,
) -> Result<BTreeMap<SandboxId, usize>, SandboxTreeError> {
    if records.len() > limits.maximum_project_sandboxes() {
        return Err(SandboxTreeError::TooManyProjectSandboxes);
    }
    let root_count = records
        .values()
        .filter(|record| record.parent().is_none())
        .count();
    let live_count = records.values().filter(|record| record.is_live()).count();
    if root_count > limits.maximum_project_roots() {
        return Err(SandboxTreeError::TooManyProjectRoots);
    }
    if live_count > limits.maximum_project_live_sandboxes() {
        return Err(SandboxTreeError::TooManyProjectLiveSandboxes);
    }
    let mut live_incarnations = BTreeSet::new();
    for incarnation in records
        .values()
        .filter_map(SandboxTreeRecordV1::incarnation)
    {
        if !live_incarnations.insert(incarnation) {
            return Err(SandboxTreeError::DuplicateIncarnation);
        }
    }
    let mut child_counts = BTreeMap::<SandboxId, usize>::new();
    for record in records.values() {
        if let Some(parent) = record.parent() {
            if !records.contains_key(&parent) {
                return Err(SandboxTreeError::MissingParent);
            }
            let count = child_counts.entry(parent).or_default();
            *count = count.checked_add(1).ok_or(SandboxTreeError::Capacity)?;
            if *count > limits.maximum_children_per_parent() {
                return Err(SandboxTreeError::TooManyChildren);
            }
        }
    }

    let mut depths = BTreeMap::<SandboxId, usize>::new();
    for sandbox in records.keys().copied() {
        if depths.contains_key(&sandbox) {
            continue;
        }
        let mut path_set = BTreeSet::new();
        let mut path = Vec::new();
        let mut cursor = Some(sandbox);
        let mut known_parent_depth = None;
        while let Some(current) = cursor {
            if let Some(depth) = depths.get(&current).copied() {
                known_parent_depth = Some(depth);
                break;
            }
            if !path_set.insert(current) {
                return Err(SandboxTreeError::Cycle);
            }
            path.push(current);
            cursor = records.get(&current).and_then(|record| record.parent());
        }

        let mut next_depth = known_parent_depth;
        for current in path.into_iter().rev() {
            let depth = match next_depth {
                Some(parent_depth) => parent_depth
                    .checked_add(1)
                    .ok_or(SandboxTreeError::Capacity)?,
                None => 0,
            };
            if depth > limits.maximum_depth() {
                return Err(SandboxTreeError::TooDeep);
            }
            depths.insert(current, depth);
            next_depth = Some(depth);
        }
    }

    let mut descendants = BTreeMap::<SandboxId, usize>::new();
    let mut live_descendants = BTreeMap::<SandboxId, usize>::new();
    let mut deepest_first: Vec<_> = depths
        .iter()
        .map(|(sandbox, depth)| (*depth, *sandbox))
        .collect();
    deepest_first.sort_unstable_by(|left, right| right.cmp(left));
    for (_, sandbox) in deepest_first {
        let descendant_count = descendants.get(&sandbox).copied().unwrap_or(0);
        let live_descendant_count = live_descendants.get(&sandbox).copied().unwrap_or(0);
        if descendant_count > limits.maximum_descendants() {
            return Err(SandboxTreeError::TooManyDescendants);
        }
        if live_descendant_count > limits.maximum_live_descendants() {
            return Err(SandboxTreeError::TooManyLiveDescendants);
        }
        let record = records
            .get(&sandbox)
            .ok_or(SandboxTreeError::UnknownSandbox)?;
        if let Some(parent) = record.parent() {
            let subtree_count = descendant_count
                .checked_add(1)
                .ok_or(SandboxTreeError::Capacity)?;
            let subtree_live_count = live_descendant_count
                .checked_add(usize::from(record.is_live()))
                .ok_or(SandboxTreeError::Capacity)?;
            let parent_descendants = descendants.get(&parent).copied().unwrap_or(0);
            let parent_live_descendants = live_descendants.get(&parent).copied().unwrap_or(0);
            descendants.insert(
                parent,
                parent_descendants
                    .checked_add(subtree_count)
                    .ok_or(SandboxTreeError::Capacity)?,
            );
            live_descendants.insert(
                parent,
                parent_live_descendants
                    .checked_add(subtree_live_count)
                    .ok_or(SandboxTreeError::Capacity)?,
            );
        }
    }
    Ok(depths)
}

/// Reports an invalid project ancestry graph or stale mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SandboxTreeError {
    /// The bounded record input is not strictly ordered by sandbox identity.
    #[error("sandbox tree records are not canonical")]
    RecordsNotCanonical,
    /// A record belongs to a different project.
    #[error("sandbox tree record belongs to another project")]
    ProjectMismatch,
    /// A sandbox identity appears more than once.
    #[error("sandbox identity already exists")]
    DuplicateSandbox,
    /// Deleted identities are duplicated, unordered, zero, or overlap live state.
    #[error("sandbox tombstones are not a canonical disjoint set")]
    TombstonesNotCanonical,
    /// A deleted sandbox identity cannot be reused.
    #[error("sandbox identity was durably retired and cannot be reused")]
    RetiredSandbox,
    /// A runtime incarnation is assigned to more than one logical sandbox.
    #[error("runtime incarnation is already assigned in this project")]
    DuplicateIncarnation,
    /// A named sandbox does not exist.
    #[error("sandbox is absent from the project tree")]
    UnknownSandbox,
    /// A parent link names an absent sandbox.
    #[error("sandbox parent is absent from the project tree")]
    MissingParent,
    /// Parent links contain a cycle.
    #[error("sandbox ancestry contains a cycle")]
    Cycle,
    /// A parent compare-and-swap generation is stale or omitted.
    #[error("sandbox parent generation is stale")]
    StaleGeneration,
    /// A newly created sandbox does not start at generation one.
    #[error("new sandbox generation must be one")]
    InvalidInitialGeneration,
    /// The project forest compare-and-swap generation is stale.
    #[error("sandbox tree generation is stale")]
    StaleTreeGeneration,
    /// A record constructor rejected a generated successor.
    #[error("sandbox tree successor record is invalid")]
    InvalidRecord,
    /// A delete target still has direct children.
    #[error("sandbox tree deletion target is not a leaf")]
    NotLeaf,
    /// A delete target still has a runtime incarnation.
    #[error("sandbox tree deletion target is still live")]
    LiveDelete,
    /// A subtree containing a live sandbox cannot change ancestry.
    #[error("sandbox subtree must stop before reparenting")]
    LiveReparent,
    /// A live incarnation cannot be replaced without an observed stopped state.
    #[error("sandbox incarnation replacement requires an intermediate stopped state")]
    IncarnationReplacementRequiresStop,
    /// A specialized mutation would leave its selected state unchanged.
    #[error("sandbox tree mutation does not change state")]
    NoStateChange,
    /// The project contains too many independent roots.
    #[error("sandbox project exceeds its configured root count")]
    TooManyProjectRoots,
    /// The project contains too many logical sandboxes.
    #[error("sandbox project exceeds its configured sandbox count")]
    TooManyProjectSandboxes,
    /// The project contains too many live incarnations.
    #[error("sandbox project exceeds its configured live-sandbox count")]
    TooManyProjectLiveSandboxes,
    /// The depth limit would be exceeded.
    #[error("sandbox ancestry exceeds the configured depth")]
    TooDeep,
    /// A direct-child fanout limit would be exceeded.
    #[error("sandbox parent exceeds its configured child fanout")]
    TooManyChildren,
    /// A total-descendant limit would be exceeded.
    #[error("sandbox exceeds its configured descendant count")]
    TooManyDescendants,
    /// A live-descendant limit would be exceeded.
    #[error("sandbox exceeds its configured live-descendant count")]
    TooManyLiveDescendants,
    /// Input size or checked arithmetic exceeds an implementation ceiling.
    #[error("sandbox tree capacity is exhausted")]
    Capacity,
}
