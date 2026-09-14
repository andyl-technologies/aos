//! Path-free Git repository, object graph, export, and pack commitments.

use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{
    ObjectDescriptor, ObjectDigest, ProjectId, ResourceId, Revision, SandboxId,
};
use sha2::{Digest as _, Sha256};

/// Maximum fully qualified Git ref-name bytes.
pub const MAXIMUM_GIT_REF_BYTES: usize = 1_024;
/// Maximum refs or graph roots in one control record.
pub const MAXIMUM_GIT_GRAPH_ROOTS: usize = 65_536;
/// Maximum accepted object count; the sentinel maximum is rejected.
pub const MAXIMUM_GIT_OBJECTS: u64 = u64::MAX - 1;

macro_rules! define_git_commitment {
    ($name:ident, $summary:literal, $domain:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(ObjectDigest);
        impl $name {
            /// Commits exact bytes in this value's purpose-specific domain.
            #[must_use]
            pub fn commit(bytes: &[u8]) -> Self {
                Self(ObjectDigest::from_bytes(
                    Sha256::new()
                        .chain_update($domain)
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
            pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, GitModelError> {
                if value.as_bytes() == &[0; 32] {
                    Err(GitModelError::CorruptEncoding)
                } else {
                    Ok(Self(value))
                }
            }
        }
    };
}

define_git_commitment!(
    GitObjectDatabaseDigestV1,
    "Commits one complete Git object database.",
    b"aos.sandbox.git.object-database.v1\0"
);
define_git_commitment!(
    GitGraphProofDigestV1,
    "Commits the validator evidence for complete Git graph traversal.",
    b"aos.sandbox.git.graph-proof.v1\0"
);
define_git_commitment!(
    GitObjectInventoryDigestV1,
    "Commits the canonical physical enumeration of every ODB object.",
    b"aos.sandbox.git.object-inventory.v1\0"
);
define_git_commitment!(
    GitPackIndexSetDigestV1,
    "Commits the canonical complete set of physical pack indexes.",
    b"aos.sandbox.git.pack-index-set.v1\0"
);
define_git_commitment!(
    GitRefMapDigestV1,
    "Commits one complete canonical Git ref map.",
    b"aos.sandbox.git.ref-map.v1\0"
);
define_git_commitment!(
    GitAudienceDigestV1,
    "Commits whole-object-database read authorization.",
    b"aos.sandbox.git.audience.v1\0"
);
define_git_commitment!(
    GitExportGenerationDigestV1,
    "Commits one immutable export generation and all of its bounded evidence.",
    b"aos.sandbox.git.export-generation.v1\0"
);
define_git_commitment!(
    GitValidationPolicyDigestV1,
    "Commits the receive quarantine validation policy.",
    b"aos.sandbox.git.validation-policy.v1\0"
);
define_git_commitment!(
    GitQuarantineDigestV1,
    "Commits one sealed receive quarantine.",
    b"aos.sandbox.git.quarantine.v1\0"
);
define_git_commitment!(
    GitAtomicCasDigestV1,
    "Commits the exact repository/ref/ODB atomic compare-and-swap.",
    b"aos.sandbox.git.atomic-cas.v1\0"
);
define_git_commitment!(
    GitAncestryProofDigestV1,
    "Commits validator evidence that one ref update is a fast-forward.",
    b"aos.sandbox.git.ancestry-proof.v1\0"
);
define_git_commitment!(
    GitChannelBindingDigestV1,
    "Commits the authenticated Git transport channel.",
    b"aos.sandbox.git.channel-binding.v1\0"
);
define_git_commitment!(
    GitPackGenerationDigestV1,
    "Commits one exact immutable pack generation.",
    b"aos.sandbox.git.pack-generation.v1\0"
);
/// References an opaque trust-boundary attestation for a validator report.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitValidatorTrustDigestV1(ObjectDigest);

impl GitValidatorTrustDigestV1 {
    /// Returns the opaque external attestation commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, GitModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(GitModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}

/// Brands validator evidence that crossed the crate-internal trust boundary.
///
/// The brand has no public scalar constructor. Canonical decoders require a
/// matching instance, so attacker-controlled bytes cannot mint trusted ODB
/// completeness evidence by naming an arbitrary attestation digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitTrustedValidatorV1 {
    pub(super) attestation: GitValidatorTrustDigestV1,
    pub(super) accepted_graphs: Vec<ObjectDigest>,
    pub(super) accepted_ancestry: Vec<ObjectDigest>,
    pub(super) accepted_validation_reports: Vec<ObjectDigest>,
}

/// Retains a validator-issued fast-forward ancestry report and its exact inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitAncestryReportV1 {
    trust: GitValidatorTrustDigestV1,
    reference: GitRefNameV1,
    old: GitObjectIdV1,
    new: GitObjectIdV1,
    object_database: GitObjectDatabaseDigestV1,
    report: GitAncestryProofDigestV1,
}

impl GitAncestryReportV1 {
    pub(super) fn from_validator(
        validator: &GitTrustedValidatorV1,
        reference: GitRefNameV1,
        old: GitObjectIdV1,
        new: GitObjectIdV1,
        object_database: GitObjectDatabaseDigestV1,
        report: ObjectDigest,
    ) -> Result<Self, GitModelError> {
        if old == new || old.format() != new.format() || report.as_bytes() == &[0; 32] {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            trust: validator.attestation(),
            reference,
            old,
            new,
            object_database,
            report: GitAncestryProofDigestV1::from_stored(report)?,
        })
    }

    /// Rehydrates a report only under the matching already-trusted validator.
    pub(super) fn from_stored(
        trusted: &GitTrustedValidatorV1,
        reference: GitRefNameV1,
        old: GitObjectIdV1,
        new: GitObjectIdV1,
        object_database: GitObjectDatabaseDigestV1,
        report: ObjectDigest,
        stored_trust: GitValidatorTrustDigestV1,
    ) -> Result<Self, GitModelError> {
        if stored_trust != trusted.attestation() {
            return Err(GitModelError::CorruptEncoding);
        }
        trusted.accept_ancestry_report(reference, old, new, object_database, report)
    }

    /// Returns the validator trust identity.
    #[must_use]
    pub const fn trust(&self) -> GitValidatorTrustDigestV1 {
        self.trust
    }

    /// Borrows the exact ref checked by the validator.
    #[must_use]
    pub const fn reference(&self) -> &GitRefNameV1 {
        &self.reference
    }

    /// Returns the checked predecessor object.
    #[must_use]
    pub const fn old(&self) -> GitObjectIdV1 {
        self.old
    }

    /// Returns the checked successor object.
    #[must_use]
    pub const fn new(&self) -> GitObjectIdV1 {
        self.new
    }

    /// Returns the complete object database used for ancestry traversal.
    #[must_use]
    pub const fn object_database(&self) -> GitObjectDatabaseDigestV1 {
        self.object_database
    }

    /// Returns the opaque validator report commitment.
    #[must_use]
    pub const fn report(&self) -> GitAncestryProofDigestV1 {
        self.report
    }
}

/// Selects the object identifier format of one repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GitObjectFormatV1 {
    /// Uses 20-byte SHA-1 object identifiers.
    Sha1 = 1,
    /// Uses 32-byte SHA-256 object identifiers.
    Sha256 = 2,
}

impl GitObjectFormatV1 {
    pub(super) const fn byte_length(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

/// Stores one exact binary Git object identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GitObjectIdV1 {
    /// A 20-byte SHA-1 object identifier.
    Sha1([u8; 20]),
    /// A 32-byte SHA-256 object identifier.
    Sha256([u8; 32]),
}

impl GitObjectIdV1 {
    /// Constructs an identifier matching the repository format.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for wrong length or all-zero ID.
    pub fn from_bytes(format: GitObjectFormatV1, bytes: &[u8]) -> Result<Self, GitModelError> {
        if bytes.len() != format.byte_length() || bytes.iter().all(|byte| *byte == 0) {
            return Err(GitModelError::InvalidModel);
        }
        match format {
            GitObjectFormatV1::Sha1 => bytes
                .try_into()
                .map(Self::Sha1)
                .map_err(|_| GitModelError::InvalidModel),
            GitObjectFormatV1::Sha256 => bytes
                .try_into()
                .map(Self::Sha256)
                .map_err(|_| GitModelError::InvalidModel),
        }
    }
    /// Returns object format.
    #[must_use]
    pub const fn format(self) -> GitObjectFormatV1 {
        match self {
            Self::Sha1(_) => GitObjectFormatV1::Sha1,
            Self::Sha256(_) => GitObjectFormatV1::Sha256,
        }
    }
    /// Borrows exact binary bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha1(v) => v,
            Self::Sha256(v) => v,
        }
    }
}

/// Stores one validated byte-exact fully qualified ref name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitRefNameV1(Vec<u8>);

impl GitRefNameV1 {
    /// Validates Git's portable fully qualified ref-name restrictions.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidRefName`] for forbidden names or bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, GitModelError> {
        let forbidden = bytes.iter().any(|byte| {
            byte.is_ascii_control()
                || *byte == b' '
                || matches!(*byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        });
        let invalid_component = bytes.split(|byte| *byte == b'/').any(|part| {
            part.is_empty()
                || part.starts_with(b".")
                || part.ends_with(b".")
                || part.ends_with(b".lock")
        });
        if bytes.is_empty()
            || bytes.len() > MAXIMUM_GIT_REF_BYTES
            || !bytes.starts_with(b"refs/")
            || bytes.ends_with(b"/")
            || bytes.windows(2).any(|pair| pair == b".." || pair == b"@{")
            || forbidden
            || invalid_component
        {
            return Err(GitModelError::InvalidRefName);
        }
        Ok(Self(bytes))
    }
    /// Borrows exact ref bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Stores one canonical advertised ref-map entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitAdvertisedRefV1 {
    name: GitRefNameV1,
    object: GitObjectIdV1,
}

impl GitAdvertisedRefV1 {
    /// Constructs one advertised ref entry.
    #[must_use]
    pub const fn new(name: GitRefNameV1, object: GitObjectIdV1) -> Self {
        Self { name, object }
    }
    /// Borrows ref name.
    #[must_use]
    pub const fn name(&self) -> &GitRefNameV1 {
        &self.name
    }
    /// Returns target object.
    #[must_use]
    pub const fn object(&self) -> GitObjectIdV1 {
        self.object
    }
}

/// Validates and commits a complete canonical advertised ref map.
///
/// # Errors
///
/// Returns [`GitModelError::InvalidModel`] for oversized, unordered, or
/// mixed-format maps. An empty map is the canonical state of an unborn or
/// fully deleted ref namespace.
pub fn git_ref_map_digest_v1(
    format: GitObjectFormatV1,
    refs: &[GitAdvertisedRefV1],
) -> Result<GitRefMapDigestV1, GitModelError> {
    if refs.len() > MAXIMUM_GIT_GRAPH_ROOTS
        || !refs.windows(2).all(|pair| pair[0].name() < pair[1].name())
        || refs.iter().any(|entry| entry.object().format() != format)
    {
        return Err(GitModelError::InvalidModel);
    }
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.ref-map.v1\0")
        .chain_update([format as u8]);
    for entry in refs {
        let length = entry.name().as_bytes().len().to_be_bytes();
        hasher = hasher
            .chain_update(&length[length.len() - 2..])
            .chain_update(entry.name().as_bytes())
            .chain_update(entry.object().as_bytes());
    }
    Ok(GitRefMapDigestV1(ObjectDigest::from_bytes(
        hasher.finalize().into(),
    )))
}

/// Selects the proof profile used for object-graph completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GitGraphCompletenessV1 {
    /// Every object reachable from the advertised immutable export was checked.
    AdvertisedClosure = 1,
    /// Every object reachable after applying a quarantined receive was checked.
    ValidatedQuarantineClosure = 2,
}

/// Commits exact format, bounds, roots, and completeness of one object graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitObjectGraphEvidenceV1 {
    format: GitObjectFormatV1,
    completeness: GitGraphCompletenessV1,
    object_count: u64,
    total_object_bytes: u64,
    roots: Vec<GitObjectIdV1>,
    object_database: GitObjectDatabaseDigestV1,
    graph_proof: GitGraphProofDigestV1,
}

impl GitObjectGraphEvidenceV1 {
    /// Constructs complete bounded graph evidence.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidObjectGraph`] for inconsistent/MAX
    /// counters, mixed formats, or roots not strictly ordered and unique. The
    /// all-empty graph is canonical for an empty object database.
    pub(super) fn new(
        format: GitObjectFormatV1,
        completeness: GitGraphCompletenessV1,
        object_count: u64,
        total_object_bytes: u64,
        roots: Vec<GitObjectIdV1>,
        object_database: GitObjectDatabaseDigestV1,
        graph_proof: GitGraphProofDigestV1,
    ) -> Result<Self, GitModelError> {
        let root_count =
            u64::try_from(roots.len()).map_err(|_| GitModelError::InvalidObjectGraph)?;
        if object_count > MAXIMUM_GIT_OBJECTS
            || total_object_bytes == u64::MAX
            || (object_count == 0) != (total_object_bytes == 0)
            || roots.len() > MAXIMUM_GIT_GRAPH_ROOTS
            || root_count > object_count
            || roots.iter().any(|object| object.format() != format)
            || !roots.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(GitModelError::InvalidObjectGraph);
        }
        Ok(Self {
            format,
            completeness,
            object_count,
            total_object_bytes,
            roots,
            object_database,
            graph_proof,
        })
    }
    /// Returns object format.
    #[must_use]
    pub const fn format(&self) -> GitObjectFormatV1 {
        self.format
    }
    /// Returns completeness profile.
    #[must_use]
    pub const fn completeness(&self) -> GitGraphCompletenessV1 {
        self.completeness
    }
    /// Returns checked object count.
    #[must_use]
    pub const fn object_count(&self) -> u64 {
        self.object_count
    }
    /// Returns checked aggregate object bytes.
    #[must_use]
    pub const fn total_object_bytes(&self) -> u64 {
        self.total_object_bytes
    }
    /// Returns sorted complete root set.
    #[must_use]
    pub fn roots(&self) -> &[GitObjectIdV1] {
        &self.roots
    }
    /// Returns complete ODB commitment.
    #[must_use]
    pub const fn object_database(&self) -> GitObjectDatabaseDigestV1 {
        self.object_database
    }

    /// Returns validator evidence for the complete traversal.
    #[must_use]
    pub const fn graph_proof(&self) -> GitGraphProofDigestV1 {
        self.graph_proof
    }
}

/// Retains bounded evidence from physical enumeration of a complete ODB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitPhysicalObjectEnumerationV1 {
    format: GitObjectFormatV1,
    object_database: GitObjectDatabaseDigestV1,
    loose_object_count: u64,
    pack_count: u64,
    pack_indexes: GitPackIndexSetDigestV1,
    inventory: GitObjectInventoryDigestV1,
}

impl GitPhysicalObjectEnumerationV1 {
    /// Constructs physical enumeration evidence for one complete ODB.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidObjectGraph`] for MAX counters or a
    /// physical count inconsistent with the graph's complete object count.
    pub fn new(
        graph: &GitObjectGraphEvidenceV1,
        loose_object_count: u64,
        pack_count: u64,
        pack_indexes: GitPackIndexSetDigestV1,
        inventory: GitObjectInventoryDigestV1,
    ) -> Result<Self, GitModelError> {
        if loose_object_count == u64::MAX
            || pack_count == u64::MAX
            || loose_object_count > graph.object_count()
            || (graph.object_count() == 0 && (loose_object_count != 0 || pack_count != 0))
            || (graph.object_count() != 0 && loose_object_count == 0 && pack_count == 0)
        {
            return Err(GitModelError::InvalidObjectGraph);
        }
        Ok(Self {
            format: graph.format(),
            object_database: graph.object_database(),
            loose_object_count,
            pack_count,
            pack_indexes,
            inventory,
        })
    }

    /// Returns the enumerated object format.
    #[must_use]
    pub const fn format(self) -> GitObjectFormatV1 {
        self.format
    }

    /// Returns the exact enumerated ODB commitment.
    #[must_use]
    pub const fn object_database(self) -> GitObjectDatabaseDigestV1 {
        self.object_database
    }

    /// Returns the exact loose-object count.
    #[must_use]
    pub const fn loose_object_count(self) -> u64 {
        self.loose_object_count
    }

    /// Returns the exact physical pack count.
    #[must_use]
    pub const fn pack_count(self) -> u64 {
        self.pack_count
    }

    /// Returns the complete pack-index-set commitment.
    #[must_use]
    pub const fn pack_indexes(self) -> GitPackIndexSetDigestV1 {
        self.pack_indexes
    }

    /// Returns the complete physical object inventory commitment.
    #[must_use]
    pub const fn inventory(self) -> GitObjectInventoryDigestV1 {
        self.inventory
    }
}

/// Binds complete logical and physical ODB evidence to one exact audience.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitWholeObjectDatabaseV1 {
    graph: GitObjectGraphEvidenceV1,
    physical: GitPhysicalObjectEnumerationV1,
    validator: GitGraphValidatorEvidenceV1,
    audience: GitReadAudienceV1,
    audience_commitment: GitAudienceDigestV1,
}

impl GitWholeObjectDatabaseV1 {
    /// Constructs whole-ODB evidence for one physical disclosure audience.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidObjectGraph`] when physical enumeration
    /// was produced for a different format or object database.
    pub fn new(
        graph: GitObjectGraphEvidenceV1,
        physical: GitPhysicalObjectEnumerationV1,
        validator: GitGraphValidatorEvidenceV1,
        audience: GitReadAudienceV1,
        trusted_validator: &GitTrustedValidatorV1,
    ) -> Result<Self, GitModelError> {
        if physical.format() != graph.format()
            || physical.object_database() != graph.object_database()
            || validator.graph_proof() != graph.graph_proof()
            || validator.trust() != trusted_validator.attestation()
        {
            return Err(GitModelError::InvalidObjectGraph);
        }
        let audience_commitment = audience.complete_commitment();
        Ok(Self {
            graph,
            physical,
            validator,
            audience,
            audience_commitment,
        })
    }

    /// Borrows complete logical reachability evidence.
    #[must_use]
    pub const fn graph(&self) -> &GitObjectGraphEvidenceV1 {
        &self.graph
    }

    /// Returns complete physical enumeration evidence.
    #[must_use]
    pub const fn physical(&self) -> GitPhysicalObjectEnumerationV1 {
        self.physical
    }

    /// Borrows the closed validator report and policy evidence.
    #[must_use]
    pub const fn validator(&self) -> &GitGraphValidatorEvidenceV1 {
        &self.validator
    }

    /// Borrows the exact physical disclosure audience.
    #[must_use]
    pub const fn audience(&self) -> &GitReadAudienceV1 {
        &self.audience
    }

    /// Returns the complete audience/disclosure commitment.
    #[must_use]
    pub const fn audience_commitment(&self) -> GitAudienceDigestV1 {
        self.audience_commitment
    }
}

/// Selects one closed Git object descriptor role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GitDescriptorRoleV1 {
    /// Complete immutable bare repository export.
    BareExport = 1,
    /// Sealed receive quarantine.
    ReceiveQuarantine = 2,
    /// Immutable Git pack.
    Pack = 3,
    /// Immutable Git pack index.
    PackIndex = 4,
    /// Immutable Git multi-pack index.
    MultiPackIndex = 5,
    /// Immutable complete graph-validator report.
    GraphValidationReport = 6,
}

/// Binds a closed validator report to an exact proof and validation policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitGraphValidatorEvidenceV1 {
    report: GitDescriptorV1,
    graph_proof: GitGraphProofDigestV1,
    policy: GitValidationPolicyDigestV1,
    trust: GitValidatorTrustDigestV1,
}

impl GitGraphValidatorEvidenceV1 {
    /// Constructs evidence carrying a crate-internal trusted-validator brand.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidDescriptorRole`] for a wrong report role.
    pub(crate) fn from_trusted(
        report: GitDescriptorV1,
        graph_proof: GitGraphProofDigestV1,
        policy: GitValidationPolicyDigestV1,
        trusted: &GitTrustedValidatorV1,
    ) -> Result<Self, GitModelError> {
        if !trusted.accepts_validation_report(&report, graph_proof, policy) {
            return Err(GitModelError::InvalidDescriptorRole);
        }
        Self::new(report, graph_proof, policy, trusted.attestation())
    }

    /// Constructs exact immutable graph-validation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidDescriptorRole`] for a wrong report role.
    pub(super) fn new(
        report: GitDescriptorV1,
        graph_proof: GitGraphProofDigestV1,
        policy: GitValidationPolicyDigestV1,
        trust: GitValidatorTrustDigestV1,
    ) -> Result<Self, GitModelError> {
        if report.role() != GitDescriptorRoleV1::GraphValidationReport {
            return Err(GitModelError::InvalidDescriptorRole);
        }
        Ok(Self {
            report,
            graph_proof,
            policy,
            trust,
        })
    }
    /// Borrows the immutable validator report descriptor.
    #[must_use]
    pub const fn report(&self) -> &GitDescriptorV1 {
        &self.report
    }
    /// Returns the exact complete-traversal proof commitment.
    #[must_use]
    pub const fn graph_proof(&self) -> GitGraphProofDigestV1 {
        self.graph_proof
    }
    /// Returns the closed validation-policy commitment.
    #[must_use]
    pub const fn policy(&self) -> GitValidationPolicyDigestV1 {
        self.policy
    }
    /// Returns the opaque external trust-boundary attestation commitment.
    #[must_use]
    pub const fn trust(&self) -> GitValidatorTrustDigestV1 {
        self.trust
    }
}

/// Binds an immutable object descriptor to a closed Git role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDescriptorV1 {
    role: GitDescriptorRoleV1,
    descriptor: ObjectDescriptor,
}

impl GitDescriptorV1 {
    /// Constructs a descriptor with exact role-specific media type.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidDescriptorRole`] for mismatch or sentinel.
    pub fn new(
        role: GitDescriptorRoleV1,
        descriptor: ObjectDescriptor,
    ) -> Result<Self, GitModelError> {
        if descriptor.digest().as_bytes() == &[0; 32]
            || descriptor.media_type().as_str() != descriptor_media_type(role)
        {
            return Err(GitModelError::InvalidDescriptorRole);
        }
        Ok(Self { role, descriptor })
    }
    /// Returns role.
    #[must_use]
    pub const fn role(&self) -> GitDescriptorRoleV1 {
        self.role
    }
    /// Borrows exact descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
}

/// Identifies one private mutable repository without exposing a path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitRepositoryV1 {
    repository: ResourceId,
    project: ProjectId,
    sandbox: SandboxId,
    workspace: ResourceId,
    format: GitObjectFormatV1,
    revision: Revision,
}

impl GitRepositoryV1 {
    /// Constructs a path-free repository identity at an exact revision.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for sentinel fields or MAX revision.
    pub fn new(
        repository: ResourceId,
        project: ProjectId,
        sandbox: SandboxId,
        workspace: ResourceId,
        format: GitObjectFormatV1,
        revision: Revision,
    ) -> Result<Self, GitModelError> {
        if repository.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || workspace.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            repository,
            project,
            sandbox,
            workspace,
            format,
            revision,
        })
    }
    /// Returns repository identity.
    #[must_use]
    pub const fn repository(&self) -> ResourceId {
        self.repository
    }
    /// Returns project identity.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }
    /// Returns owning sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }
    /// Returns workspace handle.
    #[must_use]
    pub const fn workspace(&self) -> ResourceId {
        self.workspace
    }
    /// Returns object format.
    #[must_use]
    pub const fn format(&self) -> GitObjectFormatV1 {
        self.format
    }
    /// Returns repository revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

/// Binds whole-ODB read authorization to physical disclosure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitReadAudienceV1 {
    disclosure: CacheDomain,
    authorization: GitAudienceDigestV1,
}

impl GitReadAudienceV1 {
    /// Constructs a whole-object-database audience.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for sentinel disclosure identity.
    pub fn new(
        disclosure: CacheDomain,
        authorization: GitAudienceDigestV1,
    ) -> Result<Self, GitModelError> {
        if disclosure.domain_id().as_bytes() == &[0; 16] {
            Err(GitModelError::InvalidModel)
        } else {
            Ok(Self {
                disclosure,
                authorization,
            })
        }
    }
    /// Returns disclosure domain.
    #[must_use]
    pub const fn disclosure(&self) -> CacheDomain {
        self.disclosure
    }
    /// Returns authorization commitment.
    #[must_use]
    pub const fn authorization(&self) -> GitAudienceDigestV1 {
        self.authorization
    }
    /// Returns a canonical domain-separated commitment including disclosure.
    #[must_use]
    pub fn complete_commitment(&self) -> GitAudienceDigestV1 {
        let mut bytes = [0_u8; 49];
        bytes[0] = cache_kind_code(self.disclosure.kind());
        bytes[1..17].copy_from_slice(self.disclosure.domain_id().as_bytes());
        bytes[17..49].copy_from_slice(self.authorization.digest().as_bytes());
        GitAudienceDigestV1::commit(&bytes)
    }
}

/// Commits one immutable bare export and complete advertised graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitExportGenerationV1 {
    export: ResourceId,
    generation: Revision,
    generation_digest: GitExportGenerationDigestV1,
    project: ProjectId,
    repository: ResourceId,
    repository_revision: Revision,
    bare_export: GitDescriptorV1,
    refs: Vec<GitAdvertisedRefV1>,
    ref_map: GitRefMapDigestV1,
    database: GitWholeObjectDatabaseV1,
}

impl GitExportGenerationV1 {
    /// Constructs an immutable whole-audience export generation.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] for sentinel/MAX fields, wrong descriptor or
    /// graph role, invalid ref map, or advertised targets absent from roots.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        export: ResourceId,
        generation: Revision,
        project: ProjectId,
        repository: ResourceId,
        repository_revision: Revision,
        bare_export: GitDescriptorV1,
        refs: Vec<GitAdvertisedRefV1>,
        database: GitWholeObjectDatabaseV1,
    ) -> Result<Self, GitModelError> {
        let graph = database.graph();
        let ref_map = git_ref_map_digest_v1(graph.format(), &refs)?;
        let roots_cover_refs = refs
            .iter()
            .all(|entry| graph.roots().binary_search(&entry.object()).is_ok());
        if export.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || repository.as_bytes() == &[0; 16]
            || generation.get() == 0
            || generation.get() == u64::MAX
            || repository_revision.get() == 0
            || repository_revision.get() == u64::MAX
            || bare_export.role() != GitDescriptorRoleV1::BareExport
            || graph.completeness() != GitGraphCompletenessV1::AdvertisedClosure
            || !roots_cover_refs
        {
            return Err(GitModelError::InvalidModel);
        }
        let generation_digest = export_generation_digest(
            export,
            generation,
            project,
            repository,
            repository_revision,
            &bare_export,
            ref_map,
            &database,
        );
        Ok(Self {
            export,
            generation,
            generation_digest,
            project,
            repository,
            repository_revision,
            bare_export,
            refs,
            ref_map,
            database,
        })
    }
    /// Returns export identity.
    #[must_use]
    pub const fn export(&self) -> ResourceId {
        self.export
    }
    /// Returns immutable export generation.
    #[must_use]
    pub const fn generation(&self) -> Revision {
        self.generation
    }
    /// Returns the commitment to this exact immutable export generation.
    #[must_use]
    pub const fn generation_digest(&self) -> GitExportGenerationDigestV1 {
        self.generation_digest
    }
    /// Returns the project owning the source repository.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }
    /// Returns source repository.
    #[must_use]
    pub const fn repository(&self) -> ResourceId {
        self.repository
    }
    /// Returns source repository revision.
    #[must_use]
    pub const fn repository_revision(&self) -> Revision {
        self.repository_revision
    }
    /// Borrows bare-export descriptor.
    #[must_use]
    pub const fn bare_export(&self) -> &GitDescriptorV1 {
        &self.bare_export
    }
    /// Returns complete advertised refs.
    #[must_use]
    pub fn refs(&self) -> &[GitAdvertisedRefV1] {
        &self.refs
    }
    /// Returns canonical ref-map commitment.
    #[must_use]
    pub const fn ref_map(&self) -> GitRefMapDigestV1 {
        self.ref_map
    }
    /// Borrows complete object graph evidence.
    #[must_use]
    pub const fn graph(&self) -> &GitObjectGraphEvidenceV1 {
        self.database.graph()
    }
    /// Borrows whole-ODB audience.
    #[must_use]
    pub const fn audience(&self) -> &GitReadAudienceV1 {
        self.database.audience()
    }
    /// Borrows whole-ODB logical, physical, and audience evidence.
    #[must_use]
    pub const fn database(&self) -> &GitWholeObjectDatabaseV1 {
        &self.database
    }
}

#[allow(clippy::too_many_arguments)]
fn export_generation_digest(
    export: ResourceId,
    generation: Revision,
    project: ProjectId,
    repository: ResourceId,
    repository_revision: Revision,
    bare_export: &GitDescriptorV1,
    ref_map: GitRefMapDigestV1,
    database: &GitWholeObjectDatabaseV1,
) -> GitExportGenerationDigestV1 {
    let graph = database.graph();
    let audience = database.audience();
    let media = bare_export.descriptor().media_type().as_str().as_bytes();
    let media_length = media.len().to_be_bytes();
    let validator_media = database
        .validator()
        .report()
        .descriptor()
        .media_type()
        .as_str()
        .as_bytes();
    let validator_media_length = validator_media.len().to_be_bytes();
    let root_count = graph.roots().len().to_be_bytes();
    let disclosure = audience.disclosure();
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.export-generation.v1\0")
        .chain_update(export.as_bytes())
        .chain_update(generation.get().to_be_bytes())
        .chain_update(project.as_bytes())
        .chain_update(repository.as_bytes())
        .chain_update(repository_revision.get().to_be_bytes())
        .chain_update([bare_export.role() as u8])
        .chain_update(&media_length[media_length.len() - 2..])
        .chain_update(media)
        .chain_update(bare_export.descriptor().digest().as_bytes())
        .chain_update(bare_export.descriptor().encoded_size().to_be_bytes())
        .chain_update(ref_map.digest().as_bytes())
        .chain_update([graph.format() as u8, graph.completeness() as u8])
        .chain_update(graph.object_count().to_be_bytes())
        .chain_update(graph.total_object_bytes().to_be_bytes())
        .chain_update(graph.object_database().digest().as_bytes())
        .chain_update(graph.graph_proof().digest().as_bytes())
        .chain_update(database.physical().loose_object_count().to_be_bytes())
        .chain_update(database.physical().pack_count().to_be_bytes())
        .chain_update(database.physical().pack_indexes().digest().as_bytes())
        .chain_update(database.physical().inventory().digest().as_bytes())
        .chain_update([database.validator().report().role() as u8])
        .chain_update(&validator_media_length[validator_media_length.len() - 2..])
        .chain_update(validator_media)
        .chain_update(
            database
                .validator()
                .report()
                .descriptor()
                .digest()
                .as_bytes(),
        )
        .chain_update(
            database
                .validator()
                .report()
                .descriptor()
                .encoded_size()
                .to_be_bytes(),
        )
        .chain_update(database.validator().policy().digest().as_bytes())
        .chain_update(database.validator().trust().digest().as_bytes())
        .chain_update(&root_count[root_count.len() - 4..]);
    for root in graph.roots() {
        hasher = hasher.chain_update(root.as_bytes());
    }
    hasher = hasher
        .chain_update([cache_kind_code(disclosure.kind())])
        .chain_update(disclosure.domain_id().as_bytes())
        .chain_update(audience.authorization().digest().as_bytes());
    GitExportGenerationDigestV1(ObjectDigest::from_bytes(hasher.finalize().into()))
}

/// Commits one immutable complete pack set eligible for an alternate lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutablePackGenerationV1 {
    pack_generation: ResourceId,
    generation: Revision,
    predecessor: Option<GitPackGenerationPredecessorV1>,
    generation_digest: GitPackGenerationDigestV1,
    project: ProjectId,
    repository: ResourceId,
    export: ResourceId,
    export_generation: Revision,
    export_digest: GitExportGenerationDigestV1,
    pack: GitDescriptorV1,
    index: GitDescriptorV1,
    multi_pack_index: Option<GitDescriptorV1>,
    database: GitWholeObjectDatabaseV1,
}

/// Names the exact predecessor of an immutable pack generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitPackGenerationPredecessorV1 {
    generation: Revision,
    digest: GitPackGenerationDigestV1,
}

impl GitPackGenerationPredecessorV1 {
    /// Constructs one non-sentinel pack lineage edge.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for zero or MAX generation.
    pub fn new(
        generation: Revision,
        digest: GitPackGenerationDigestV1,
    ) -> Result<Self, GitModelError> {
        if generation.get() == 0 || generation.get() == u64::MAX {
            Err(GitModelError::InvalidModel)
        } else {
            Ok(Self { generation, digest })
        }
    }

    /// Returns the predecessor generation.
    #[must_use]
    pub const fn generation(self) -> Revision {
        self.generation
    }

    /// Returns the exact predecessor commitment.
    #[must_use]
    pub const fn digest(self) -> GitPackGenerationDigestV1 {
        self.digest
    }
}

impl ImmutablePackGenerationV1 {
    /// Constructs a role-checked complete immutable pack set.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for role or sentinel mismatch.
    pub fn new(
        pack_generation: ResourceId,
        generation: Revision,
        predecessor: Option<GitPackGenerationPredecessorV1>,
        export: &GitExportGenerationV1,
        pack: GitDescriptorV1,
        index: GitDescriptorV1,
        multi_pack_index: Option<GitDescriptorV1>,
        database: GitWholeObjectDatabaseV1,
    ) -> Result<Self, GitModelError> {
        if database != *export.database() {
            return Err(GitModelError::InvalidModel);
        }
        Self::from_parts(
            pack_generation,
            generation,
            predecessor,
            export.project(),
            export.repository(),
            export.export(),
            export.generation(),
            export.generation_digest(),
            pack,
            index,
            multi_pack_index,
            database,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_parts(
        pack_generation: ResourceId,
        generation: Revision,
        predecessor: Option<GitPackGenerationPredecessorV1>,
        project: ProjectId,
        repository: ResourceId,
        export: ResourceId,
        export_generation: Revision,
        export_digest: GitExportGenerationDigestV1,
        pack: GitDescriptorV1,
        index: GitDescriptorV1,
        multi_pack_index: Option<GitDescriptorV1>,
        database: GitWholeObjectDatabaseV1,
    ) -> Result<Self, GitModelError> {
        let realized_pack_indexes =
            git_pack_index_set_digest_v1(&pack, &index, multi_pack_index.as_ref());
        let lineage_valid = match (generation.get(), predecessor) {
            (1, None) => true,
            (2.., Some(previous)) => previous
                .generation()
                .checked_next()
                .is_ok_and(|next| next == generation),
            _ => false,
        };
        if pack_generation.as_bytes() == &[0; 16]
            || !lineage_valid
            || project.as_bytes() == &[0; 16]
            || repository.as_bytes() == &[0; 16]
            || pack.role() != GitDescriptorRoleV1::Pack
            || index.role() != GitDescriptorRoleV1::PackIndex
            || multi_pack_index
                .as_ref()
                .is_some_and(|value| value.role() != GitDescriptorRoleV1::MultiPackIndex)
            || database.physical().pack_indexes() != realized_pack_indexes
            || export.as_bytes() == &[0; 16]
            || export_generation.get() == 0
            || export_generation.get() == u64::MAX
        {
            return Err(GitModelError::InvalidModel);
        }
        let generation_digest = pack_generation_digest(
            pack_generation,
            generation,
            predecessor,
            project,
            repository,
            export_digest,
            &pack,
            &index,
            multi_pack_index.as_ref(),
            &database,
        );
        let value = Self {
            pack_generation,
            generation,
            predecessor,
            generation_digest,
            project,
            repository,
            export,
            export_generation,
            export_digest,
            pack,
            index,
            multi_pack_index,
            database,
        };
        super::pack_format::validate_pack_record_size(&value)?;
        Ok(value)
    }
    /// Returns pack generation identity.
    #[must_use]
    pub const fn pack_generation(&self) -> ResourceId {
        self.pack_generation
    }
    /// Returns the monotone immutable pack generation.
    #[must_use]
    pub const fn generation(&self) -> Revision {
        self.generation
    }
    /// Returns the exact predecessor lineage edge.
    #[must_use]
    pub const fn predecessor(&self) -> Option<GitPackGenerationPredecessorV1> {
        self.predecessor
    }
    /// Returns the canonical generation commitment.
    #[must_use]
    pub const fn generation_digest(&self) -> GitPackGenerationDigestV1 {
        self.generation_digest
    }
    /// Returns the project owning the pack's source repository.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }
    /// Returns the exact source repository.
    #[must_use]
    pub const fn repository(&self) -> ResourceId {
        self.repository
    }
    /// Returns source export identity.
    #[must_use]
    pub const fn export(&self) -> ResourceId {
        self.export
    }
    /// Returns the exact source export generation.
    #[must_use]
    pub const fn export_generation(&self) -> Revision {
        self.export_generation
    }
    /// Returns the commitment to the exact source export generation.
    #[must_use]
    pub const fn export_digest(&self) -> GitExportGenerationDigestV1 {
        self.export_digest
    }
    /// Borrows pack descriptor.
    #[must_use]
    pub const fn pack(&self) -> &GitDescriptorV1 {
        &self.pack
    }
    /// Borrows index descriptor.
    #[must_use]
    pub const fn index(&self) -> &GitDescriptorV1 {
        &self.index
    }
    /// Borrows optional multi-pack index.
    #[must_use]
    pub const fn multi_pack_index(&self) -> Option<&GitDescriptorV1> {
        self.multi_pack_index.as_ref()
    }
    /// Borrows graph evidence.
    #[must_use]
    pub const fn graph(&self) -> &GitObjectGraphEvidenceV1 {
        self.database.graph()
    }
    /// Borrows audience.
    #[must_use]
    pub const fn audience(&self) -> &GitReadAudienceV1 {
        self.database.audience()
    }
    /// Borrows whole-ODB logical, physical, and audience evidence.
    #[must_use]
    pub const fn database(&self) -> &GitWholeObjectDatabaseV1 {
        &self.database
    }
}

/// Derives the physical pack-index-set commitment from exact descriptors.
#[must_use]
pub fn git_pack_index_set_digest_v1(
    pack: &GitDescriptorV1,
    index: &GitDescriptorV1,
    multi_pack_index: Option<&GitDescriptorV1>,
) -> GitPackIndexSetDigestV1 {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.realized-pack-index-set.v1\0")
        .chain_update(pack.descriptor().digest().as_bytes())
        .chain_update(pack.descriptor().encoded_size().to_be_bytes())
        .chain_update(index.descriptor().digest().as_bytes())
        .chain_update(index.descriptor().encoded_size().to_be_bytes())
        .chain_update([u8::from(multi_pack_index.is_some())]);
    if let Some(descriptor) = multi_pack_index {
        hasher = hasher
            .chain_update(descriptor.descriptor().digest().as_bytes())
            .chain_update(descriptor.descriptor().encoded_size().to_be_bytes());
    }
    GitPackIndexSetDigestV1::commit(&hasher.finalize())
}

fn pack_generation_digest(
    identity: ResourceId,
    generation: Revision,
    predecessor: Option<GitPackGenerationPredecessorV1>,
    project: ProjectId,
    repository: ResourceId,
    export: GitExportGenerationDigestV1,
    pack: &GitDescriptorV1,
    index: &GitDescriptorV1,
    multi_pack_index: Option<&GitDescriptorV1>,
    database: &GitWholeObjectDatabaseV1,
) -> GitPackGenerationDigestV1 {
    let zero_digest = ObjectDigest::from_bytes([0; 32]);
    let predecessor_generation = predecessor.map_or(0, |value| value.generation().get());
    let predecessor_digest = predecessor.map_or(zero_digest, |value| value.digest().digest());
    let multi_pack_index_digest =
        multi_pack_index.map_or(zero_digest, |value| value.descriptor().digest());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.git.pack-generation.v1\0")
        .chain_update(identity.as_bytes())
        .chain_update(generation.get().to_be_bytes())
        .chain_update(predecessor_generation.to_be_bytes())
        .chain_update(predecessor_digest.as_bytes())
        .chain_update(project.as_bytes())
        .chain_update(repository.as_bytes())
        .chain_update(export.digest().as_bytes())
        .chain_update(pack.descriptor().digest().as_bytes())
        .chain_update(index.descriptor().digest().as_bytes())
        .chain_update(multi_pack_index_digest.as_bytes())
        .chain_update(database.graph().object_database().digest().as_bytes())
        .chain_update(database.graph().graph_proof().digest().as_bytes())
        .chain_update(database.physical().inventory().digest().as_bytes())
        .chain_update(database.audience_commitment().digest().as_bytes())
        .chain_update(database.validator().policy().digest().as_bytes())
        .chain_update(database.validator().trust().digest().as_bytes())
        .finalize();
    GitPackGenerationDigestV1(ObjectDigest::from_bytes(digest.into()))
}

pub(super) const fn descriptor_media_type(role: GitDescriptorRoleV1) -> &'static str {
    match role {
        GitDescriptorRoleV1::BareExport => "application/vnd.aos.git.bare-export.v1",
        GitDescriptorRoleV1::ReceiveQuarantine => "application/vnd.aos.git.receive-quarantine.v1",
        GitDescriptorRoleV1::Pack => "application/vnd.aos.git.pack.v1",
        GitDescriptorRoleV1::PackIndex => "application/vnd.aos.git.pack-index.v1",
        GitDescriptorRoleV1::MultiPackIndex => "application/vnd.aos.git.multi-pack-index.v1",
        GitDescriptorRoleV1::GraphValidationReport => {
            "application/vnd.aos.git.graph-validation-report.v1"
        }
    }
}
pub(super) const fn cache_kind_code(kind: CacheDomainKind) -> u8 {
    match kind {
        CacheDomainKind::Private => 1,
        CacheDomainKind::Project => 2,
        CacheDomainKind::TrustDomain => 3,
        CacheDomainKind::Public => 4,
    }
}

/// Reports invalid Git control input or corrupt canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GitModelError {
    /// Model data is invalid or non-canonical.
    #[error("Git model is invalid or non-canonical")]
    InvalidModel,
    /// Ref name violates closed byte profile.
    #[error("Git ref name is invalid")]
    InvalidRefName,
    /// Object graph evidence is incomplete or invalid.
    #[error("Git object graph evidence is invalid")]
    InvalidObjectGraph,
    /// Descriptor does not match closed role.
    #[error("Git descriptor role is invalid")]
    InvalidDescriptorRole,
    /// Receive would be a no-op.
    #[error("Git receive plan must change refs or object database")]
    NoOpReceive,
    /// Encoded bytes violate schema, bounds, or digest.
    #[error("Git control encoding is corrupt")]
    CorruptEncoding,
    /// Preflighted bounded allocation failed.
    #[error("Git decode allocation failed")]
    Allocation,
}
