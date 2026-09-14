//! Exact immutable environment-generation identity model.

use std::collections::BTreeMap;

use aos_sandbox_core::format::{descriptor_for_bytes, try_encode_environment};
use aos_sandbox_core::model::{CacheDomain, Environment};
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId, Revision, SandboxId,
    ViewId,
};
use sha2::{Digest as _, Sha256};

use super::format::{
    decode_environment_generation_v1, encode_environment_generation_v1,
    environment_manifest_digest_v1,
};

/// Maximum typed input descriptors in one generation.
pub const MAXIMUM_ENVIRONMENT_INPUTS: usize = 4_096;
/// Maximum canonical inline Environment v1 bytes.
pub const MAXIMUM_INLINE_ENVIRONMENT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum selected-output bytes.
pub const MAXIMUM_SELECTED_OUTPUT_BYTES: usize = 4_096;
/// Maximum target-system bytes.
pub const MAXIMUM_TARGET_SYSTEM_BYTES: usize = 255;

/// Commits a predecessor generation manifest in a purpose-specific domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentManifestDigestV1(ObjectDigest);

impl EnvironmentManifestDigestV1 {
    /// Commits exact prior manifest bytes.
    #[must_use]
    pub fn commit(bytes: &[u8]) -> Self {
        Self(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.environment-generation.manifest.v1\0")
                .chain_update(bytes)
                .finalize()
                .into(),
        ))
    }

    /// Returns the underlying SHA-256 commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, EnvironmentModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(EnvironmentModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}

/// Names the exact predecessor generation and its canonical manifest digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvironmentPredecessorV1 {
    generation: Revision,
    manifest: EnvironmentManifestDigestV1,
}

impl EnvironmentPredecessorV1 {
    /// Constructs an exact predecessor lineage edge.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for zero or MAX generation.
    pub fn new(
        generation: Revision,
        manifest: EnvironmentManifestDigestV1,
    ) -> Result<Self, EnvironmentModelError> {
        if generation.get() == 0 || generation.get() == u64::MAX {
            Err(EnvironmentModelError::InvalidModel)
        } else {
            Ok(Self {
                generation,
                manifest,
            })
        }
    }

    /// Returns the exact predecessor generation.
    #[must_use]
    pub const fn generation(self) -> Revision {
        self.generation
    }

    /// Returns the canonical predecessor manifest commitment.
    #[must_use]
    pub const fn manifest(self) -> EnvironmentManifestDigestV1 {
        self.manifest
    }
}

/// Selects the semantic role of an immutable generation input descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EnvironmentDescriptorRoleV1 {
    /// Complete project or flake source tree.
    ProjectSource = 1,
    /// Exact lock-file content.
    LockFile = 2,
    /// Additional evaluator input.
    EvaluationInput = 3,
    /// Toolchain closure input.
    Toolchain = 4,
    /// Other declared immutable dependency.
    Dependency = 5,
}

/// Binds an immutable descriptor to one closed environment-input role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentInputCommitmentV1 {
    role: EnvironmentDescriptorRoleV1,
    descriptor: ObjectDescriptor,
}

impl Ord for EnvironmentInputCommitmentV1 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.role
            .cmp(&other.role)
            .then_with(|| self.descriptor.cmp(&other.descriptor))
    }
}

impl PartialOrd for EnvironmentInputCommitmentV1 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl EnvironmentInputCommitmentV1 {
    /// Constructs a role-checked immutable input commitment.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidDescriptorRole`] when the media
    /// type is not admitted for the selected role or the digest is sentinel.
    pub fn new(
        role: EnvironmentDescriptorRoleV1,
        descriptor: ObjectDescriptor,
    ) -> Result<Self, EnvironmentModelError> {
        if descriptor.digest().as_bytes() == &[0; 32]
            || !input_role_accepts(role, descriptor.media_type().as_str())
        {
            return Err(EnvironmentModelError::InvalidDescriptorRole);
        }
        Ok(Self { role, descriptor })
    }

    /// Returns the input role.
    #[must_use]
    pub const fn role(&self) -> EnvironmentDescriptorRoleV1 {
        self.role
    }
    /// Borrows the exact descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
}

/// Stores a validated, byte-exact selected output attribute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedEnvironmentOutputV1(String);

impl SelectedEnvironmentOutputV1 {
    /// Validates a bounded dotted attribute path.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidSelectedOutput`] for empty
    /// components or bytes outside ASCII alphanumeric, `_`, `-`, and `.`.
    pub fn new(value: String) -> Result<Self, EnvironmentModelError> {
        let bytes_valid = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
        let components_valid = value.split('.').all(|component| !component.is_empty());
        if value.is_empty()
            || value.len() > MAXIMUM_SELECTED_OUTPUT_BYTES
            || !bytes_valid
            || !components_valid
        {
            return Err(EnvironmentModelError::InvalidSelectedOutput);
        }
        Ok(Self(value))
    }

    /// Returns the exact selected attribute path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stores a normalized target-system identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentTargetSystemV1(String);

impl EnvironmentTargetSystemV1 {
    /// Validates a bounded lowercase target tuple.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidTargetSystem`] for unsupported
    /// bytes, empty tuple components, or a value outside the fixed bound.
    pub fn new(value: String) -> Result<Self, EnvironmentModelError> {
        let bytes_valid = value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        });
        let components_valid = value.split('-').all(|component| !component.is_empty());
        if value.is_empty()
            || value.len() > MAXIMUM_TARGET_SYSTEM_BYTES
            || !bytes_valid
            || !components_valid
        {
            return Err(EnvironmentModelError::InvalidTargetSystem);
        }
        Ok(Self(value))
    }

    /// Returns the exact normalized target tuple.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Binds the generated facade to an exact immutable View revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentFacadeV1 {
    view: ViewId,
    revision: Revision,
    descriptor: ObjectDescriptor,
}

impl EnvironmentFacadeV1 {
    /// Constructs an exact facade view revision commitment.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidDescriptorRole`] for sentinel
    /// fields or a descriptor other than portable View v1.
    pub fn new(
        view: ViewId,
        revision: Revision,
        descriptor: ObjectDescriptor,
    ) -> Result<Self, EnvironmentModelError> {
        if view.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
            || descriptor.digest().as_bytes() == &[0; 32]
            || descriptor.media_type().as_str() != PortableMediaType::View.as_str()
        {
            return Err(EnvironmentModelError::InvalidDescriptorRole);
        }
        Ok(Self {
            view,
            revision,
            descriptor,
        })
    }

    /// Returns the facade View identity.
    #[must_use]
    pub const fn view(&self) -> ViewId {
        self.view
    }
    /// Returns the immutable View revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    /// Borrows the exact portable View descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
}

/// Commits every semantic input to one immutable environment realization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentGenerationManifestV1 {
    project: ProjectId,
    sandbox: SandboxId,
    generation: Revision,
    predecessor: Option<EnvironmentPredecessorV1>,
    environment: Environment,
    environment_descriptor: ObjectDescriptor,
    selected_output: SelectedEnvironmentOutputV1,
    target_system: EnvironmentTargetSystemV1,
    facade: EnvironmentFacadeV1,
    effective_policy: ObjectDescriptor,
    disclosure: CacheDomain,
    inputs: Vec<EnvironmentInputCommitmentV1>,
}

impl EnvironmentGenerationManifestV1 {
    /// Constructs one exact, non-authorizing environment identity.
    ///
    /// Generation one has no predecessor; later generations commit the exact
    /// prior manifest. Inputs are strictly ordered and contain exactly one
    /// project source and one lock file. The supplied inline Environment
    /// descriptor must match its canonical CBOR bytes exactly.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] for invalid ancestry, descriptor roles,
    /// non-canonical inputs, a mismatched inline descriptor, or encoder ceilings.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectId,
        sandbox: SandboxId,
        generation: Revision,
        predecessor: Option<EnvironmentPredecessorV1>,
        environment: Environment,
        environment_descriptor: ObjectDescriptor,
        selected_output: SelectedEnvironmentOutputV1,
        target_system: EnvironmentTargetSystemV1,
        facade: EnvironmentFacadeV1,
        effective_policy: ObjectDescriptor,
        disclosure: CacheDomain,
        inputs: Vec<EnvironmentInputCommitmentV1>,
    ) -> Result<Self, EnvironmentModelError> {
        preflight_environment_encoding(&environment)?;
        let environment_bytes =
            try_encode_environment(&environment).map_err(|_| EnvironmentModelError::Allocation)?;
        let media_type = MediaType::new(PortableMediaType::Environment.as_str().to_owned())
            .map_err(|_| EnvironmentModelError::InvalidInlineEnvironment)?;
        let expected_descriptor = descriptor_for_bytes(media_type, &environment_bytes);
        let ancestry_valid = match (generation.get(), predecessor) {
            (1, None) => true,
            (2.., Some(value)) => value
                .generation()
                .checked_next()
                .is_ok_and(|next| next == generation),
            _ => false,
        };
        let inputs_canonical = inputs.windows(2).all(|pair| pair[0] < pair[1]);
        let project_sources = inputs
            .iter()
            .filter(|input| input.role() == EnvironmentDescriptorRoleV1::ProjectSource)
            .count();
        let lock_files = inputs
            .iter()
            .filter(|input| input.role() == EnvironmentDescriptorRoleV1::LockFile)
            .count();
        if project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || generation.get() == u64::MAX
            || !ancestry_valid
            || environment.closure().is_empty()
            || environment_bytes.len() > MAXIMUM_INLINE_ENVIRONMENT_BYTES
            || environment_descriptor != expected_descriptor
            || effective_policy.digest().as_bytes() == &[0; 32]
            || effective_policy.media_type().as_str() != PortableMediaType::Policy.as_str()
            || disclosure.domain_id().as_bytes() == &[0; 16]
            || inputs.is_empty()
            || inputs.len() > MAXIMUM_ENVIRONMENT_INPUTS
            || !inputs_canonical
            || project_sources != 1
            || lock_files != 1
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(Self {
            project,
            sandbox,
            generation,
            predecessor,
            environment,
            environment_descriptor,
            selected_output,
            target_system,
            facade,
            effective_policy,
            disclosure,
            inputs,
        })
    }

    /// Returns project identity.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }
    /// Returns sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }
    /// Returns immutable generation.
    #[must_use]
    pub const fn generation(&self) -> Revision {
        self.generation
    }
    /// Returns exact predecessor-manifest commitment.
    #[must_use]
    pub const fn predecessor(&self) -> Option<EnvironmentPredecessorV1> {
        self.predecessor
    }
    /// Borrows inline portable Environment semantics.
    #[must_use]
    pub const fn environment(&self) -> &Environment {
        &self.environment
    }
    /// Borrows canonical inline Environment descriptor.
    #[must_use]
    pub const fn environment_descriptor(&self) -> &ObjectDescriptor {
        &self.environment_descriptor
    }
    /// Borrows typed selected output.
    #[must_use]
    pub const fn selected_output(&self) -> &SelectedEnvironmentOutputV1 {
        &self.selected_output
    }
    /// Borrows typed target system.
    #[must_use]
    pub const fn target_system(&self) -> &EnvironmentTargetSystemV1 {
        &self.target_system
    }
    /// Borrows exact facade View revision.
    #[must_use]
    pub const fn facade(&self) -> &EnvironmentFacadeV1 {
        &self.facade
    }
    /// Borrows effective portable policy descriptor.
    #[must_use]
    pub const fn effective_policy(&self) -> &ObjectDescriptor {
        &self.effective_policy
    }
    /// Returns disclosure domain.
    #[must_use]
    pub const fn disclosure(&self) -> CacheDomain {
        self.disclosure
    }
    /// Returns strictly ordered typed input commitments.
    #[must_use]
    pub fn inputs(&self) -> &[EnvironmentInputCommitmentV1] {
        &self.inputs
    }
}

fn preflight_environment_encoding(environment: &Environment) -> Result<(), EnvironmentModelError> {
    // Each CBOR container/scalar contributes at most nine prefix bytes. This
    // checked upper bound rejects oversized values before the exact fallible
    // core encoder reserves its output.
    let mut bound = 64_usize;
    for descriptor in environment.closure() {
        bound = bound
            .checked_add(64)
            .and_then(|value| value.checked_add(descriptor.media_type().as_str().len()))
            .ok_or(EnvironmentModelError::InvalidInlineEnvironment)?;
    }
    for variable in environment.variables() {
        bound = bound
            .checked_add(32)
            .and_then(|value| value.checked_add(variable.name().len()))
            .and_then(|value| value.checked_add(variable.value().len()))
            .ok_or(EnvironmentModelError::InvalidInlineEnvironment)?;
    }
    for path in environment.command_search_path() {
        bound = bound
            .checked_add(16)
            .ok_or(EnvironmentModelError::InvalidInlineEnvironment)?;
        for component in path.components() {
            bound = bound
                .checked_add(9)
                .and_then(|value| value.checked_add(component.as_bytes().len()))
                .ok_or(EnvironmentModelError::InvalidInlineEnvironment)?;
        }
    }
    for feature in environment.required_features() {
        bound = bound
            .checked_add(40)
            .and_then(|value| value.checked_add(feature.namespace().len()))
            .ok_or(EnvironmentModelError::InvalidInlineEnvironment)?;
    }
    if bound > MAXIMUM_INLINE_ENVIRONMENT_BYTES {
        Err(EnvironmentModelError::InvalidInlineEnvironment)
    } else {
        Ok(())
    }
}

fn input_role_accepts(role: EnvironmentDescriptorRoleV1, media_type: &str) -> bool {
    match role {
        EnvironmentDescriptorRoleV1::ProjectSource => {
            media_type == PortableMediaType::Tree.as_str()
        }
        EnvironmentDescriptorRoleV1::LockFile => media_type == PortableMediaType::Content.as_str(),
        EnvironmentDescriptorRoleV1::EvaluationInput
        | EnvironmentDescriptorRoleV1::Toolchain
        | EnvironmentDescriptorRoleV1::Dependency => {
            matches!(media_type, value if value == PortableMediaType::Content.as_str() || value == PortableMediaType::Tree.as_str())
        }
    }
}

/// Reports invalid environment input or corrupt canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EnvironmentModelError {
    /// Model state is invalid or non-canonical.
    #[error("environment generation is invalid or non-canonical")]
    InvalidModel,
    /// A descriptor does not match its closed semantic role.
    #[error("environment descriptor role is invalid")]
    InvalidDescriptorRole,
    /// Inline Environment bytes and descriptor do not match.
    #[error("inline portable environment descriptor is invalid")]
    InvalidInlineEnvironment,
    /// Selected output is invalid.
    #[error("selected environment output is invalid")]
    InvalidSelectedOutput,
    /// Target system is invalid.
    #[error("environment target system is invalid")]
    InvalidTargetSystem,
    /// Encoded state violates schema, bounds, or digest.
    #[error("environment generation encoding is corrupt")]
    CorruptEncoding,
    /// Preflighted bounded allocation failed.
    #[error("environment decode allocation failed")]
    Allocation,
}

/// Maximum manifests accepted by one history replay.
pub const MAXIMUM_ENVIRONMENT_HISTORY_RECORDS: usize = 262_144;
/// Maximum aggregate canonical bytes accepted by one history replay.
pub const MAXIMUM_ENVIRONMENT_HISTORY_BYTES: usize = 256 * 1024 * 1024;

/// Retains the latest fully validated immutable generation for each sandbox.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentGenerationHistoryV1 {
    pub(super) latest:
        BTreeMap<SandboxId, (EnvironmentGenerationManifestV1, EnvironmentManifestDigestV1)>,
    pub(super) generations: BTreeMap<
        (SandboxId, Revision),
        (EnvironmentGenerationManifestV1, EnvironmentManifestDigestV1),
    >,
    pub(super) floors: BTreeMap<SandboxId, Revision>,
    pub(super) retained_bytes: usize,
}

/// Stores a fully validated environment-history compaction floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentGenerationCheckpointV1 {
    pub(super) history: EnvironmentGenerationHistoryV1,
    pub(super) digest: ObjectDigest,
    pub(super) accepted_record: Option<ObjectDigest>,
}

impl EnvironmentGenerationHistoryV1 {
    /// Replays canonical manifests under exact lineage and aggregate ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentHistoryError`] for malformed bytes, exhausted
    /// bounds, a fork, a skipped generation, or changed project identity.
    pub fn replay(
        records: super::EnvironmentAcceptedRecordSetV1,
    ) -> Result<Self, EnvironmentHistoryError> {
        let mut history = Self::default();
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        for accepted in
            records.into_kind(super::EnvironmentJournalRecordKindV1::Generation, None)?
        {
            let encoded = accepted.payload();
            count = count
                .checked_add(1)
                .ok_or(EnvironmentHistoryError::Capacity)?;
            bytes = bytes
                .checked_add(encoded.len())
                .ok_or(EnvironmentHistoryError::Capacity)?;
            if count > MAXIMUM_ENVIRONMENT_HISTORY_RECORDS
                || bytes > MAXIMUM_ENVIRONMENT_HISTORY_BYTES
            {
                return Err(EnvironmentHistoryError::Capacity);
            }
            let manifest = decode_environment_generation_v1(encoded)?;
            let ownership = accepted.ownership();
            if ownership.project() != manifest.project()
                || ownership.sandbox() != manifest.sandbox()
                || ownership.revision() != manifest.generation()
            {
                return Err(EnvironmentHistoryError::Conflict);
            }
            let digest = environment_manifest_digest_v1(&manifest)?;
            history.apply(manifest, digest)?;
        }
        Ok(history)
    }

    /// Replays a bounded suffix after a trusted materialized checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentHistoryError`] under the same conditions as
    /// [`Self::replay`], including a suffix that forks checkpointed lineage.
    pub fn replay_after(
        checkpoint: &EnvironmentGenerationCheckpointV1,
        records: super::EnvironmentAcceptedRecordSetV1,
        verifier: &super::EnvironmentJournalVerifierV1,
    ) -> Result<Self, EnvironmentHistoryError> {
        if checkpoint.digest != environment_history_digest(&checkpoint.history) {
            return Err(EnvironmentHistoryError::Conflict);
        }
        let accepted = checkpoint
            .accepted_record
            .filter(|digest| verifier.accepts_checkpoint(*digest))
            .ok_or(EnvironmentHistoryError::Conflict)?;
        if accepted.as_bytes() == &[0; 32] {
            return Err(EnvironmentHistoryError::Conflict);
        }
        let mut history = checkpoint.history.clone();
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        for accepted in records.into_kind(
            super::EnvironmentJournalRecordKindV1::Generation,
            Some(verifier.authority()),
        )? {
            let encoded = accepted.payload();
            count = count
                .checked_add(1)
                .ok_or(EnvironmentHistoryError::Capacity)?;
            bytes = bytes
                .checked_add(encoded.len())
                .ok_or(EnvironmentHistoryError::Capacity)?;
            if count > MAXIMUM_ENVIRONMENT_HISTORY_RECORDS
                || bytes > MAXIMUM_ENVIRONMENT_HISTORY_BYTES
            {
                return Err(EnvironmentHistoryError::Capacity);
            }
            let manifest = decode_environment_generation_v1(encoded)?;
            let ownership = accepted.ownership();
            if ownership.project() != manifest.project()
                || ownership.sandbox() != manifest.sandbox()
                || ownership.revision() != manifest.generation()
            {
                return Err(EnvironmentHistoryError::Conflict);
            }
            let digest = environment_manifest_digest_v1(&manifest)?;
            history.apply(manifest, digest)?;
        }
        Ok(history)
    }

    /// Captures a trusted checkpoint for bounded suffix replay.
    #[must_use]
    pub fn checkpoint(&self) -> EnvironmentGenerationCheckpointV1 {
        EnvironmentGenerationCheckpointV1 {
            history: self.clone(),
            digest: environment_history_digest(self),
            accepted_record: None,
        }
    }

    /// Compacts one sandbox through its exact current immutable generation.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentHistoryError::Conflict`] for an unknown, stale,
    /// non-current, or regressing floor.
    pub(super) fn compact_through(
        &mut self,
        sandbox: SandboxId,
        floor: Revision,
        activations: &super::lifecycle::EnvironmentActivationHistoryV1,
    ) -> Result<(), EnvironmentHistoryError> {
        if self
            .latest
            .get(&sandbox)
            .is_none_or(|(manifest, _)| manifest.generation() != floor)
            || self
                .floors
                .get(&sandbox)
                .is_some_and(|previous| floor <= *previous)
        {
            return Err(EnvironmentHistoryError::Conflict);
        }
        let retained = activations
            .retained_manifest_selectors(sandbox)?
            .ok_or(EnvironmentHistoryError::Conflict)?;
        for selector in &retained {
            if self.selector_exact(sandbox, selector.generation(), selector.manifest())?
                != Some((**selector).clone())
            {
                return Err(EnvironmentHistoryError::Conflict);
            }
        }
        self.generations.retain(|(owner, generation), _| {
            *owner != sandbox
                || *generation == floor
                || retained
                    .binary_search_by_key(generation, |selector| selector.generation())
                    .is_ok()
        });
        self.retained_bytes =
            self.generations
                .values()
                .try_fold(0_usize, |total, (manifest, _)| {
                    total
                        .checked_add(encode_environment_generation_v1(manifest)?.len())
                        .filter(|value| *value <= MAXIMUM_ENVIRONMENT_HISTORY_BYTES)
                        .ok_or(EnvironmentHistoryError::Capacity)
                })?;
        self.floors.insert(sandbox, floor);
        Ok(())
    }

    /// Returns the latest validated manifest for a sandbox.
    #[must_use]
    pub fn latest(&self, sandbox: SandboxId) -> Option<&EnvironmentGenerationManifestV1> {
        self.latest.get(&sandbox).map(|(manifest, _)| manifest)
    }

    /// Derives the current selector only from the validated manifest history.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] if canonical manifest digest encoding
    /// cannot be allocated within its fixed ceiling.
    pub fn selector(
        &self,
        sandbox: SandboxId,
    ) -> Result<Option<super::lifecycle::EnvironmentSelectorV1>, EnvironmentModelError> {
        self.latest(sandbox)
            .map(super::lifecycle::EnvironmentSelectorV1::from_manifest)
            .transpose()
    }

    /// Resolves an exact retained generation into a manifest-derived selector.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] if canonical manifest digest encoding
    /// cannot be allocated within its fixed ceiling.
    pub fn selector_exact(
        &self,
        sandbox: SandboxId,
        generation: Revision,
        digest: EnvironmentManifestDigestV1,
    ) -> Result<Option<super::lifecycle::EnvironmentSelectorV1>, EnvironmentModelError> {
        self.generations
            .get(&(sandbox, generation))
            .filter(|(_, stored_digest)| *stored_digest == digest)
            .map(|(manifest, _)| super::lifecycle::EnvironmentSelectorV1::from_manifest(manifest))
            .transpose()
    }

    fn apply(
        &mut self,
        manifest: EnvironmentGenerationManifestV1,
        digest: EnvironmentManifestDigestV1,
    ) -> Result<(), EnvironmentHistoryError> {
        let sandbox = manifest.sandbox();
        let encoded_length = encode_environment_generation_v1(&manifest)?.len();
        let retained_bytes = self
            .retained_bytes
            .checked_add(encoded_length)
            .ok_or(EnvironmentHistoryError::Capacity)?;
        if self.generations.len() >= MAXIMUM_ENVIRONMENT_HISTORY_RECORDS
            || retained_bytes > MAXIMUM_ENVIRONMENT_HISTORY_BYTES
        {
            return Err(EnvironmentHistoryError::Capacity);
        }
        match self.latest.get(&sandbox) {
            None if manifest.generation().get() == 1 && manifest.predecessor().is_none() => {}
            Some((previous, previous_digest))
                if previous.project() == manifest.project()
                    && manifest.predecessor().is_some_and(|predecessor| {
                        predecessor.generation() == previous.generation()
                            && predecessor.manifest() == *previous_digest
                    }) => {}
            _ => return Err(EnvironmentHistoryError::Conflict),
        }
        self.generations
            .insert((sandbox, manifest.generation()), (manifest.clone(), digest));
        self.latest.insert(sandbox, (manifest, digest));
        self.retained_bytes = retained_bytes;
        Ok(())
    }
}

impl EnvironmentGenerationCheckpointV1 {
    /// Returns the complete materialized checkpoint commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

pub(super) fn environment_history_digest(history: &EnvironmentGenerationHistoryV1) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.environment-generation-checkpoint.v1\0")
        .chain_update((history.retained_bytes as u64).to_be_bytes());
    for (sandbox, floor) in &history.floors {
        hasher = hasher
            .chain_update(sandbox.as_bytes())
            .chain_update(floor.get().to_be_bytes());
    }
    for ((sandbox, generation), (_, digest)) in &history.generations {
        hasher = hasher
            .chain_update(sandbox.as_bytes())
            .chain_update(generation.get().to_be_bytes())
            .chain_update(digest.digest().as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Reports bounded environment lineage replay failure.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentHistoryError {
    /// Replay exceeds the fixed record or byte ceiling.
    #[error("environment history exceeds fixed replay capacity")]
    Capacity,
    /// A record forks, skips, or changes an immutable lineage.
    #[error("environment history contains a conflicting lineage")]
    Conflict,
    /// A manifest is malformed or non-canonical.
    #[error(transparent)]
    Model(#[from] EnvironmentModelError),
}
