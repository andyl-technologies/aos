//! Named sandbox exports and complete subtree-export dependency closure.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{
    DesiredGeneration, ExportId, IncarnationId, ObjectDigest, ProjectId, Revision, SandboxId,
    ViewId,
};
use sha2::{Digest as _, Sha256};

use super::graph::SandboxTreeV1;

/// Maximum UTF-8 bytes in one logical export name.
pub const MAXIMUM_EXPORT_NAME_BYTES: usize = 128;
/// Maximum export definitions in one closure input.
pub const MAXIMUM_EXPORT_DEFINITIONS: usize = 65_536;
/// Maximum export-reference edges in one closure input.
pub const MAXIMUM_EXPORT_REFERENCES: usize = 262_144;

/// Stores one canonical lowercase-ASCII export name rather than a host path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExportNameV1(Vec<u8>);

impl ExportNameV1 {
    /// Constructs one nonempty path-free canonical byte name.
    ///
    /// # Errors
    ///
    /// Returns [`ExportClosureError::InvalidName`] for excessive length,
    /// non-lowercase-ASCII bytes, separators, or dot path components.
    pub fn new(name: Vec<u8>) -> Result<Self, ExportClosureError> {
        if name.is_empty()
            || name.len() > MAXIMUM_EXPORT_NAME_BYTES
            || name == b"."
            || name == b".."
            || !name[0].is_ascii_lowercase() && !name[0].is_ascii_digit()
            || name.iter().any(|byte| {
                !byte.is_ascii_lowercase()
                    && !byte.is_ascii_digit()
                    && !matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(ExportClosureError::InvalidName);
        }
        Ok(Self(name))
    }

    /// Returns the exact canonical name bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Selects the exact immutable or explicitly live source of one export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportSourceV1 {
    /// Names an immutable view revision and its content commitment.
    Immutable {
        /// Logical view identity.
        view: ViewId,
        /// Immutable revision number.
        revision: Revision,
        /// Commitment to the revision semantics.
        commitment: ObjectDigest,
    },
    /// Names a local live generation with kernel-coupled semantics.
    LiveKernelCoupled {
        /// Exact source incarnation.
        incarnation: IncarnationId,
        /// Source desired generation.
        generation: DesiredGeneration,
        /// Commitment to the closed export semantics.
        commitment: ObjectDigest,
    },
}

impl ExportSourceV1 {
    fn validate(self) -> Result<(), ExportClosureError> {
        match self {
            Self::Immutable {
                view,
                revision,
                commitment,
            } => {
                if view.as_bytes() == &[0; 16]
                    || revision.get() == 0
                    || commitment.as_bytes() == &[0; 32]
                {
                    return Err(ExportClosureError::UnspecifiedIdentity);
                }
            }
            Self::LiveKernelCoupled {
                incarnation,
                generation,
                commitment,
            } => {
                if incarnation.as_bytes() == &[0; 16]
                    || generation.get() == 0
                    || commitment.as_bytes() == &[0; 32]
                {
                    return Err(ExportClosureError::UnspecifiedIdentity);
                }
            }
        }
        Ok(())
    }

    fn generation(self) -> Option<DesiredGeneration> {
        match self {
            Self::Immutable { .. } => None,
            Self::LiveKernelCoupled { generation, .. } => Some(generation),
        }
    }

    fn commitment(self) -> ObjectDigest {
        match self {
            Self::Immutable { commitment, .. } | Self::LiveKernelCoupled { commitment, .. } => {
                commitment
            }
        }
    }
}

/// Defines one named export owned by an exact sandbox generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxExportV1 {
    export: ExportId,
    sandbox: SandboxId,
    sandbox_generation: DesiredGeneration,
    name: ExportNameV1,
    source: ExportSourceV1,
    dependencies: Vec<ExportId>,
}

impl SandboxExportV1 {
    /// Constructs one specified logical export.
    ///
    /// # Errors
    ///
    /// Returns [`ExportClosureError`] when identities or source fields are zero,
    /// or dependencies are excessive, self-referential, or noncanonical.
    pub fn new(
        export: ExportId,
        sandbox: SandboxId,
        sandbox_generation: DesiredGeneration,
        name: ExportNameV1,
        source: ExportSourceV1,
        dependencies: Vec<ExportId>,
    ) -> Result<Self, ExportClosureError> {
        if export.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || sandbox_generation.get() == 0
        {
            return Err(ExportClosureError::UnspecifiedIdentity);
        }
        source.validate()?;
        if dependencies.len() > MAXIMUM_EXPORT_REFERENCES
            || dependencies
                .iter()
                .any(|dependency| dependency.as_bytes() == &[0; 16] || *dependency == export)
            || !dependencies.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ExportClosureError::InputsNotCanonical);
        }
        Ok(Self {
            export,
            sandbox,
            sandbox_generation,
            name,
            source,
            dependencies,
        })
    }

    /// Returns the export identity.
    #[must_use]
    pub const fn export(&self) -> ExportId {
        self.export
    }

    /// Returns the owning sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the owning sandbox generation.
    #[must_use]
    pub const fn sandbox_generation(&self) -> DesiredGeneration {
        self.sandbox_generation
    }

    /// Returns the path-free export name.
    #[must_use]
    pub const fn name(&self) -> &ExportNameV1 {
        &self.name
    }

    /// Returns the exact export source.
    #[must_use]
    pub const fn source(&self) -> ExportSourceV1 {
        self.source
    }

    /// Returns the complete canonical outbound export references.
    #[must_use]
    pub fn dependencies(&self) -> &[ExportId] {
        &self.dependencies
    }
}

/// Records one directed export dependency.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExportReferenceV1 {
    from: ExportId,
    to: ExportId,
}

impl ExportReferenceV1 {
    /// Constructs one non-self export reference.
    ///
    /// # Errors
    ///
    /// Returns [`ExportClosureError`] for zero or identical endpoints.
    pub fn new(from: ExportId, to: ExportId) -> Result<Self, ExportClosureError> {
        if from.as_bytes() == &[0; 16] || to.as_bytes() == &[0; 16] {
            return Err(ExportClosureError::UnspecifiedIdentity);
        }
        if from == to {
            return Err(ExportClosureError::ReferenceCycle);
        }
        Ok(Self { from, to })
    }

    /// Returns the referencing export.
    #[must_use]
    pub const fn from(self) -> ExportId {
        self.from
    }

    /// Returns the referenced export.
    #[must_use]
    pub const fn to(self) -> ExportId {
        self.to
    }
}

/// Declares one exact dependency root outside the exported subtree.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExternalExportRootV1 {
    export: ExportId,
    source_generation: Option<DesiredGeneration>,
    source_commitment: ObjectDigest,
}

impl ExternalExportRootV1 {
    /// Constructs one explicit external dependency root.
    ///
    /// # Errors
    ///
    /// Returns [`ExportClosureError::UnspecifiedIdentity`] for zero fields.
    pub fn new(
        export: ExportId,
        source_generation: Option<DesiredGeneration>,
        source_commitment: ObjectDigest,
    ) -> Result<Self, ExportClosureError> {
        if export.as_bytes() == &[0; 16]
            || source_generation.is_some_and(|generation| generation.get() == 0)
            || source_commitment.as_bytes() == &[0; 32]
        {
            return Err(ExportClosureError::UnspecifiedIdentity);
        }
        Ok(Self {
            export,
            source_generation,
            source_commitment,
        })
    }

    /// Returns the external export identity.
    #[must_use]
    pub const fn export(self) -> ExportId {
        self.export
    }

    /// Returns the live generation when the external source is mutable.
    #[must_use]
    pub const fn source_generation(self) -> Option<DesiredGeneration> {
        self.source_generation
    }

    /// Returns the exact external source commitment.
    #[must_use]
    pub const fn source_commitment(self) -> ObjectDigest {
        self.source_commitment
    }
}

/// Contains a complete bounded export graph for one sandbox subtree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubtreeExportClosureV1 {
    project: ProjectId,
    tree_generation: Revision,
    root: SandboxId,
    subtree_exports: Vec<ExportId>,
    reachable_definitions: Vec<SandboxExportV1>,
    external_roots: Vec<ExternalExportRootV1>,
    references: Vec<ExportReferenceV1>,
    commitment: ObjectDigest,
}

impl SubtreeExportClosureV1 {
    /// Computes complete reachable exports and exact external crossings.
    ///
    /// Definitions declare canonical dependencies, and the reference set must
    /// exactly reproduce them. Every edge
    /// leaving the sandbox subtree must have exactly one matching external-root
    /// declaration, while unused declarations are rejected. Dependencies of an
    /// external root are also traversed so the returned reference graph is
    /// closed and cycle-free.
    ///
    /// # Errors
    ///
    /// Returns [`ExportClosureError`] for stale definitions, absent targets,
    /// cycles, or incomplete/conflicting external-root facts.
    pub fn build(
        tree: &SandboxTreeV1,
        root: SandboxId,
        definitions: &[SandboxExportV1],
        references: &[ExportReferenceV1],
        external_roots: &[ExternalExportRootV1],
    ) -> Result<Self, ExportClosureError> {
        validate_inputs(tree, definitions, references, external_roots)?;
        if tree.record(root).is_none() {
            return Err(ExportClosureError::UnknownSandbox);
        }
        let subtree_members = tree
            .subtree_members(root)
            .map_err(|_| ExportClosureError::UnknownSandbox)?;

        let definitions_by_id: BTreeMap<_, _> = definitions
            .iter()
            .map(|definition| (definition.export(), definition))
            .collect();
        let mut edges = BTreeMap::<ExportId, Vec<ExportId>>::new();
        for reference in references {
            edges
                .entry(reference.from())
                .or_default()
                .push(reference.to());
        }

        let mut subtree_exports = Vec::new();
        subtree_exports
            .try_reserve_exact(definitions.len())
            .map_err(|_| ExportClosureError::Capacity)?;
        subtree_exports.extend(
            definitions
                .iter()
                .filter(|definition| subtree_members.contains(&definition.sandbox()))
                .map(SandboxExportV1::export),
        );
        let mut reachable = BTreeSet::new();
        let maximum_pending = subtree_exports
            .len()
            .checked_add(references.len())
            .ok_or(ExportClosureError::InputsNotCanonical)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(maximum_pending)
            .map_err(|_| ExportClosureError::Capacity)?;
        pending.extend(subtree_exports.iter().copied());
        while let Some(export) = pending.pop() {
            if !definitions_by_id.contains_key(&export) {
                return Err(ExportClosureError::MissingDefinition);
            }
            if !reachable.insert(export) {
                continue;
            }
            if let Some(targets) = edges.get(&export) {
                pending.extend(targets.iter().copied());
            }
        }
        reject_reachable_cycle(&reachable, &edges)?;

        let mut required_external = BTreeSet::new();
        for reference in references {
            let from = definitions_by_id
                .get(&reference.from())
                .ok_or(ExportClosureError::MissingDefinition)?;
            let to = definitions_by_id
                .get(&reference.to())
                .ok_or(ExportClosureError::MissingDefinition)?;
            if reachable.contains(&reference.from())
                && subtree_members.contains(&from.sandbox())
                && !subtree_members.contains(&to.sandbox())
            {
                required_external.insert(reference.to());
            }
        }
        let declared_external: BTreeSet<_> =
            external_roots.iter().map(|root| root.export).collect();
        if required_external != declared_external {
            return Err(ExportClosureError::ExternalRootsIncomplete);
        }
        for external in external_roots {
            let definition = definitions_by_id
                .get(&external.export)
                .ok_or(ExportClosureError::MissingDefinition)?;
            if definition.source().generation() != external.source_generation
                || definition.source().commitment() != external.source_commitment
            {
                return Err(ExportClosureError::ExternalRootConflict);
            }
        }

        let reachable_definitions: Vec<_> = definitions
            .iter()
            .filter(|definition| reachable.contains(&definition.export()))
            .cloned()
            .collect();
        let references: Vec<ExportReferenceV1> = references
            .iter()
            .copied()
            .filter(|reference| {
                reachable.contains(&reference.from()) && reachable.contains(&reference.to())
            })
            .collect();
        let commitment = commit_closure(
            tree.project(),
            tree.tree_generation(),
            root,
            &subtree_exports,
            &reachable_definitions,
            external_roots,
            &references,
        )?;
        Ok(Self {
            project: tree.project(),
            tree_generation: tree.tree_generation(),
            root,
            subtree_exports,
            reachable_definitions,
            external_roots: external_roots.to_vec(),
            references,
            commitment,
        })
    }

    /// Returns the project against which the closure was validated.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the exact tree generation used to validate export ownership.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the sandbox subtree root.
    #[must_use]
    pub const fn root(&self) -> SandboxId {
        self.root
    }

    /// Returns all exports owned inside the subtree in canonical order.
    #[must_use]
    pub fn subtree_exports(&self) -> &[ExportId] {
        &self.subtree_exports
    }

    /// Returns complete reachable definitions in canonical export order.
    #[must_use]
    pub fn reachable_definitions(&self) -> &[SandboxExportV1] {
        &self.reachable_definitions
    }

    /// Returns exact external crossings in canonical order.
    #[must_use]
    pub fn external_roots(&self) -> &[ExternalExportRootV1] {
        &self.external_roots
    }

    /// Returns all reachable dependency edges in canonical order.
    #[must_use]
    pub fn references(&self) -> &[ExportReferenceV1] {
        &self.references
    }

    /// Reports whether every reachable source is an immutable revision.
    #[must_use]
    pub fn is_fully_immutable(&self) -> bool {
        self.reachable_definitions
            .iter()
            .all(|definition| matches!(definition.source(), ExportSourceV1::Immutable { .. }))
    }

    /// Returns the canonical domain-separated closure commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

fn validate_inputs(
    tree: &SandboxTreeV1,
    definitions: &[SandboxExportV1],
    references: &[ExportReferenceV1],
    external_roots: &[ExternalExportRootV1],
) -> Result<(), ExportClosureError> {
    if definitions.len() > MAXIMUM_EXPORT_DEFINITIONS
        || references.len() > MAXIMUM_EXPORT_REFERENCES
        || external_roots.len() > MAXIMUM_EXPORT_DEFINITIONS
        || !definitions
            .windows(2)
            .all(|pair| pair[0].export() < pair[1].export())
        || !references.windows(2).all(|pair| pair[0] < pair[1])
        || !external_roots.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(ExportClosureError::InputsNotCanonical);
    }

    let mut names = BTreeSet::new();
    let mut reference_index = 0_usize;
    for definition in definitions {
        let record = tree
            .record(definition.sandbox())
            .ok_or(ExportClosureError::UnknownSandbox)?;
        if record.desired_generation() != definition.sandbox_generation() {
            return Err(ExportClosureError::StaleGeneration);
        }
        match definition.source() {
            ExportSourceV1::LiveKernelCoupled {
                incarnation,
                generation,
                ..
            } if generation != definition.sandbox_generation()
                || record.incarnation() != Some(incarnation) =>
            {
                return Err(ExportClosureError::StaleGeneration);
            }
            _ => {}
        }
        if !names.insert((definition.sandbox(), definition.name().clone())) {
            return Err(ExportClosureError::DuplicateName);
        }
        for dependency in definition.dependencies() {
            let expected = ExportReferenceV1 {
                from: definition.export(),
                to: *dependency,
            };
            if references.get(reference_index).copied() != Some(expected) {
                return Err(ExportClosureError::ReferencesIncomplete);
            }
            reference_index = reference_index
                .checked_add(1)
                .ok_or(ExportClosureError::InputsNotCanonical)?;
        }
    }
    if reference_index != references.len() {
        return Err(ExportClosureError::ReferencesIncomplete);
    }
    Ok(())
}

fn reject_reachable_cycle(
    reachable: &BTreeSet<ExportId>,
    edges: &BTreeMap<ExportId, Vec<ExportId>>,
) -> Result<(), ExportClosureError> {
    let mut indegrees: BTreeMap<_, usize> = reachable.iter().map(|export| (*export, 0)).collect();
    for from in reachable {
        if let Some(targets) = edges.get(from) {
            for target in targets {
                if reachable.contains(target) {
                    let count = indegrees
                        .get_mut(target)
                        .ok_or(ExportClosureError::MissingDefinition)?;
                    *count = count
                        .checked_add(1)
                        .ok_or(ExportClosureError::InputsNotCanonical)?;
                }
            }
        }
    }
    let mut ready: BTreeSet<_> = indegrees
        .iter()
        .filter_map(|(export, count)| (*count == 0).then_some(*export))
        .collect();
    let mut visited = 0_usize;
    while let Some(export) = ready.pop_first() {
        visited = visited
            .checked_add(1)
            .ok_or(ExportClosureError::InputsNotCanonical)?;
        if let Some(targets) = edges.get(&export) {
            for target in targets {
                if !reachable.contains(target) {
                    continue;
                }
                let count = indegrees
                    .get_mut(target)
                    .ok_or(ExportClosureError::MissingDefinition)?;
                *count = count
                    .checked_sub(1)
                    .ok_or(ExportClosureError::ReferenceCycle)?;
                if *count == 0 {
                    ready.insert(*target);
                }
            }
        }
    }
    if visited != reachable.len() {
        return Err(ExportClosureError::ReferenceCycle);
    }
    Ok(())
}

fn commit_closure(
    project: ProjectId,
    tree_generation: Revision,
    root: SandboxId,
    subtree_exports: &[ExportId],
    definitions: &[SandboxExportV1],
    external_roots: &[ExternalExportRootV1],
    references: &[ExportReferenceV1],
) -> Result<ObjectDigest, ExportClosureError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.subtree-export-closure.v1\0");
    hasher.update(project.as_bytes());
    hasher.update(tree_generation.get().to_be_bytes());
    hasher.update(root.as_bytes());
    hash_len(&mut hasher, subtree_exports.len())?;
    for export in subtree_exports {
        hasher.update(export.as_bytes());
    }
    hash_len(&mut hasher, definitions.len())?;
    for definition in definitions {
        hasher.update(definition.export().as_bytes());
        hasher.update(definition.sandbox().as_bytes());
        hasher.update(definition.sandbox_generation().get().to_be_bytes());
        hash_len(&mut hasher, definition.name().as_bytes().len())?;
        hasher.update(definition.name().as_bytes());
        match definition.source() {
            ExportSourceV1::Immutable {
                view,
                revision,
                commitment,
            } => {
                hasher.update([0]);
                hasher.update(view.as_bytes());
                hasher.update(revision.get().to_be_bytes());
                hasher.update(commitment.as_bytes());
            }
            ExportSourceV1::LiveKernelCoupled {
                incarnation,
                generation,
                commitment,
            } => {
                hasher.update([1]);
                hasher.update(incarnation.as_bytes());
                hasher.update(generation.get().to_be_bytes());
                hasher.update(commitment.as_bytes());
            }
        }
        hash_len(&mut hasher, definition.dependencies().len())?;
        for dependency in definition.dependencies() {
            hasher.update(dependency.as_bytes());
        }
    }
    hash_len(&mut hasher, external_roots.len())?;
    for external in external_roots {
        hasher.update(external.export().as_bytes());
        match external.source_generation() {
            Some(generation) => {
                hasher.update([1]);
                hasher.update(generation.get().to_be_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update(external.source_commitment().as_bytes());
    }
    hash_len(&mut hasher, references.len())?;
    for reference in references {
        hasher.update(reference.from().as_bytes());
        hasher.update(reference.to().as_bytes());
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn hash_len(hasher: &mut Sha256, length: usize) -> Result<(), ExportClosureError> {
    let length = u32::try_from(length).map_err(|_| ExportClosureError::InputsNotCanonical)?;
    hasher.update(length.to_be_bytes());
    Ok(())
}

/// Reports malformed or incomplete subtree-export closure input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExportClosureError {
    /// An identity, generation, revision, or commitment is zero.
    #[error("export closure contains an unspecified identity")]
    UnspecifiedIdentity,
    /// An export name is empty, unsafe, or oversized.
    #[error("export name is not a bounded path-free name")]
    InvalidName,
    /// Definitions, references, or roots are oversized or noncanonical.
    #[error("export closure inputs are not canonical bounded sets")]
    InputsNotCanonical,
    /// An export's owning sandbox is absent.
    #[error("export owner is absent from the sandbox tree")]
    UnknownSandbox,
    /// An export names an obsolete sandbox generation.
    #[error("export names a stale sandbox generation")]
    StaleGeneration,
    /// Two exports in one sandbox share a logical name.
    #[error("sandbox export names must be unique")]
    DuplicateName,
    /// A reference endpoint has no definition.
    #[error("export reference has no complete definition")]
    MissingDefinition,
    /// Supplied references do not exactly reproduce definition dependencies.
    #[error("export references are incomplete or contain undeclared edges")]
    ReferencesIncomplete,
    /// Export references contain a cycle.
    #[error("export dependency graph contains a cycle")]
    ReferenceCycle,
    /// External-root declarations do not exactly cover subtree crossings.
    #[error("external export roots are incomplete or contain unused entries")]
    ExternalRootsIncomplete,
    /// An external-root generation or commitment differs from its definition.
    #[error("external export root conflicts with its source definition")]
    ExternalRootConflict,
    /// Bounded closure working-memory allocation failed.
    #[error("export closure capacity is exhausted")]
    Capacity,
}
