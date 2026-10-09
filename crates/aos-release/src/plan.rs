//! Frozen release intent evaluated before build or signing effects.
//!
//! A plan closes package eligibility across all four targets and closes image
//! intent across both Linux targets. There is no implicit missing cell.
//!
//! The plan embeds the shared [`QualificationContract`], names its two
//! [`PlannedSurface`]s (staging and production), and freezes every
//! [`PlannedDestination`] with the gates, soak, and rollout rings its profile
//! selected. The release class is derived from the version string.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::RELEASE_PLAN;
use crate::artifact::{require_identifier, require_store_path};
use crate::digest::Sha256Digest;
use crate::evidence::GateRequirement;
use crate::inventory::PackagePublicationMetadata;
use crate::platform::{
    MatrixCell, Platform, require_complete_image_platforms, require_complete_package_platforms,
};
use crate::qualification::QualificationContract;
use crate::qualification::change_scope::ChangeScope;
use crate::registry::registry_policy;
use crate::signing::{SignerRequirement, SignerRole};

pub mod destinations;
mod request;

pub use crate::qualification::profiles::RolloutRing;
pub use destinations::{
    PlannedDestination, PlannedSurface, ProfileOverrideRef, RequestedDestination, SurfaceKind,
    SurfaceRole, class_allows_channel_kind, parse_destination_name,
};
pub use request::{ReleasePlanRequest, planned_destinations};

/// Exact schema for planner inputs with surfaces and destinations.
pub const PLAN_REQUEST: &str = "aos.release.plan-request/v1";

/// Reserved release-id prefix for a retained, non-public qualification snapshot.
pub const QUALIFICATION_SNAPSHOT_RELEASE_PREFIX: &str = "qualification-snapshot-";

/// Reserved source-tag prefix for a retained, non-public qualification snapshot.
pub const QUALIFICATION_SNAPSHOT_TAG_PREFIX: &str = "qualification-snapshot/";

/// Release maturity derived from the version format; selects the TUF role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseClass {
    /// Changed-business-day integration snapshot (`-dev.YYYYMMDD.N`).
    Edge,
    /// Weekly release candidate (`-rc.N`).
    Candidate,
    /// Supported production release (no prerelease component).
    Stable,
}

impl ReleaseClass {
    /// Derives the class from a calendar version string.
    ///
    /// # Errors
    /// Returns an error for a `v` prefix, a non-SemVer version, a version
    /// outside the `YYYY.M.P` calendar form, or an unknown prerelease format.
    pub fn from_version(value: &str) -> Result<Self> {
        if value.starts_with('v') {
            bail!("release version must not have a v prefix");
        }
        let version = Version::parse(value).context("parsing release version")?;
        if version.major < 2026 || !(1..=12).contains(&version.minor) {
            bail!("release version must use YYYY.M.P calendar components");
        }
        let prerelease = version.pre.as_str();
        if prerelease.is_empty() {
            Ok(Self::Stable)
        } else if prerelease.starts_with("dev.") {
            Ok(Self::Edge)
        } else if prerelease.starts_with("rc.") {
            Ok(Self::Candidate)
        } else {
            bail!("release version prerelease must be -dev.YYYYMMDD.N or -rc.N: {value}")
        }
    }

    /// Returns the exact public spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::Candidate => "candidate",
            Self::Stable => "stable",
        }
    }

    /// Returns the TUF delegated role required to authorize this class.
    #[must_use]
    pub const fn tuf_role(self) -> SignerRole {
        match self {
            Self::Edge => SignerRole::TufEdge,
            Self::Candidate => SignerRole::TufCandidate,
            Self::Stable => SignerRole::TufStable,
        }
    }
}

impl std::fmt::Display for ReleaseClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One platform decision in a package or image matrix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformCell<T> {
    /// Exact target identity.
    pub platform: Platform,
    /// Explicit artifact, inapplicability, or blocker decision.
    pub decision: MatrixCell<T>,
}

/// Logical artifacts expected when a planned matrix cell succeeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedArtifactSet {
    /// Exact planned artifacts the final manifest must resolve.
    pub artifacts: Vec<PlannedArtifact>,
}

/// Frozen Nix identity for one planned output or non-Nix final artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedArtifact {
    /// Stable logical artifact id.
    pub id: String,
    /// Exact derivation path, when the artifact is produced by Nix.
    pub derivation: Option<String>,
    /// Exact named derivation output.
    pub output: Option<String>,
    /// Evaluated output store path.
    pub store_path: Option<String>,
    /// Exact source and dependency-source store roots needed to rebuild it.
    pub source_store_paths: Vec<String>,
}

impl PlannedArtifactSet {
    fn validate(&self) -> Result<()> {
        if self.artifacts.is_empty() {
            bail!("planned artifact set cannot be empty");
        }
        for artifact in &self.artifacts {
            require_identifier(&artifact.id, "planned artifact id")?;
            if artifact.derivation.is_some() != artifact.output.is_some() {
                bail!("planned derivation and output identities must be present together");
            }
            if artifact.derivation.is_some() && artifact.store_path.is_none() {
                bail!("planned derivation artifacts must have an evaluated store path");
            }
            if let (Some(derivation), Some(output)) = (&artifact.derivation, &artifact.output) {
                require_store_path(derivation, true)?;
                require_identifier(output, "planned output name")?;
            }
            if let Some(store_path) = &artifact.store_path {
                require_store_path(store_path, false)?;
            }
            if artifact
                .source_store_paths
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                bail!("planned source store paths must be unique and sorted");
            }
            for source in &artifact.source_store_paths {
                require_store_path(source, false)?;
            }
        }

        require_unique_by(
            &self.artifacts,
            |artifact| &artifact.id,
            "planned artifact id",
        )
    }
}

/// Complete target decisions for one publishable package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePlan {
    /// Canonical package name.
    pub name: String,
    /// Nix-derived distribution metadata, absent only for a blocked package.
    pub publication: Option<PackagePublicationMetadata>,
    /// Exact versions for targets whose source port differs from the default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub platform_versions: BTreeMap<Platform, String>,
    /// One explicit decision for each of the four platforms.
    pub platforms: Vec<PlatformCell<PlannedArtifactSet>>,
}

impl PackagePlan {
    /// Returns the published source version for the selected target.
    #[must_use]
    pub fn version_for(&self, platform: Platform) -> Option<&str> {
        self.publication.as_ref().map(|publication| {
            self.platform_versions
                .get(&platform)
                .map_or(publication.version.as_str(), String::as_str)
        })
    }
}

/// Complete Linux target decisions for one public system variant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePlan {
    /// Canonical system variant.
    pub system_variant: String,
    /// One explicit decision for each Linux architecture.
    pub platforms: Vec<PlatformCell<PlannedArtifactSet>>,
}

/// Authenticated source identity frozen by release planning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Exact lowercase commit id in the source repository's SHA-1 or SHA-256
    /// object format.
    pub commit: String,
    /// SHA-256 of the domain-separated, full recursive Git tree listing.
    pub tree_digest: Sha256Digest,
    /// Protected branch whose reachability was checked.
    pub protected_branch: String,
    /// Immutable source tag reserved for this release.
    pub source_tag: String,
    /// Digest of public contributor-authorization evidence.
    pub contributor_authorization_digest: Sha256Digest,
}

/// Source policy supplied before Git identities are derived locally.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningSource {
    /// Protected branch that must contain the checked-out commit.
    pub protected_branch: String,
    /// Immutable source tag that must not already exist.
    pub source_tag: String,
    /// Digest of public contributor-authorization evidence.
    pub contributor_authorization_digest: Sha256Digest,
}

/// Retention requirements frozen before publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    /// Versioned public retention policy id.
    pub policy_id: String,
    /// Exact public retention policy digest.
    pub policy_digest: Sha256Digest,
    /// Whether every distributed binary requires corresponding source.
    pub require_corresponding_source: bool,
}

/// Versioned release intent that authorizes all later effects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlan {
    /// Exact plan schema identifier.
    pub schema_version: String,
    /// Shared qualification contract.
    pub qualification: QualificationContract,
    /// Frozen preceding snapshot for the required update/recovery cycle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_predecessor: Option<crate::qualification_evidence::QualificationPredecessor>,
    /// Immutable release identity.
    pub release_id: String,
    /// SemVer-compatible calendar release version.
    pub version: String,
    /// Maturity class; must equal the class derived from `version`.
    pub release_class: ReleaseClass,
    /// Canonical public registry identity.
    pub registry: String,
    /// Exact registry commit on which authoring must begin.
    pub registry_base_commit: String,
    /// Exact compare-and-swap registry generation.
    pub registry_base_generation: u64,
    /// Authenticated source identity.
    pub source: SourceIdentity,
    /// Complete package eligibility matrix.
    pub packages: Vec<PackagePlan>,
    /// Complete Linux system-image matrix.
    pub images: Vec<ImagePlan>,
    /// Role-separated signer thresholds and public key ids.
    pub signers: Vec<SignerRequirement>,
    /// Staging and production publication surfaces.
    pub surfaces: Vec<PlannedSurface>,
    /// Publication destinations and their bound obligations; empty for snapshots.
    pub destinations: Vec<PlannedDestination>,
    /// Recorded change scope; required when any destination profile is change-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_scope: Option<ChangeScope>,
    /// Accepted signed profile overrides bound into this plan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_overrides: Vec<ProfileOverrideRef>,
    /// Retention and corresponding-source policy.
    pub retention: RetentionPolicy,
    /// Digest of the public evidence policy.
    pub public_evidence_policy_digest: Sha256Digest,
    /// Digest of the restricted operator policy, without private contents.
    pub restricted_operator_policy_digest: Sha256Digest,
}

impl ReleasePlan {
    /// Returns whether this plan is the reserved non-public predecessor snapshot.
    #[must_use]
    pub fn is_qualification_snapshot(&self) -> bool {
        self.qualification_predecessor.is_none()
            && self.release_id == format!("{QUALIFICATION_SNAPSHOT_RELEASE_PREFIX}{}", self.version)
            && self.source.source_tag
                == format!("{QUALIFICATION_SNAPSHOT_TAG_PREFIX}{}", self.version)
            && self.destinations.is_empty()
    }

    /// Returns the planned surface with one role.
    ///
    /// # Errors
    /// Returns an error when the plan declares no such surface.
    pub fn surface(&self, role: SurfaceRole) -> Result<&PlannedSurface> {
        self.surfaces
            .iter()
            .find(|surface| surface.role == role)
            .ok_or_else(|| anyhow::anyhow!("release plan has no {role} surface"))
    }

    /// Returns the planned destination with one name, such as `production/stable`.
    ///
    /// # Errors
    /// Returns an error when the plan has no such destination.
    pub fn destination(&self, name: &str) -> Result<&PlannedDestination> {
        self.destinations
            .iter()
            .find(|destination| destination.name == name)
            .ok_or_else(|| anyhow::anyhow!("release plan has no destination {name}"))
    }

    /// Returns the planned destination for a surface role and channel name.
    ///
    /// # Errors
    /// Returns an error when the plan has no such destination.
    pub fn destination_for(
        &self,
        surface: SurfaceRole,
        channel: &str,
    ) -> Result<&PlannedDestination> {
        self.destinations
            .iter()
            .find(|destination| destination.surface == surface && destination.channel == channel)
            .ok_or_else(|| anyhow::anyhow!("release plan has no destination {surface}/{channel}"))
    }

    /// Returns the union of every destination's gates.
    #[must_use]
    pub fn all_gates(&self) -> BTreeSet<GateRequirement> {
        self.destinations
            .iter()
            .flat_map(|destination| destination.gates.iter())
            .cloned()
            .collect()
    }

    /// Returns whether any destination profile rejects blocked matrix cells.
    ///
    /// An unresolvable profile is treated as requiring completeness (fail
    /// closed).
    #[must_use]
    pub fn requires_complete_matrix(&self) -> bool {
        self.qualification
            .requires_complete_matrix(self)
            .unwrap_or(true)
    }

    /// Requires a valid plan that is authorized to cross a publication boundary.
    ///
    /// Qualification snapshots deliberately use the ordinary build and signing
    /// pipeline, but remain local inputs to predecessor testing. They cannot be
    /// published to any destination or assigned to a channel.
    ///
    /// # Errors
    /// Returns an error for an invalid plan or shared contract, or a
    /// non-public qualification snapshot.
    pub fn require_publishable_qualification(&self) -> Result<()> {
        self.validate()?;
        if self.is_qualification_snapshot() {
            bail!("qualification snapshots cannot cross a publication boundary");
        }
        Ok(())
    }

    /// Validates the complete frozen release contract.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong schema or registry, a class that differs
    /// from the version format, malformed source identity, duplicate or
    /// incomplete matrix entries, blocked cells where completeness is required,
    /// malformed gates/signers/channels/surfaces/destinations, or absent
    /// mandatory signer roles.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RELEASE_PLAN {
            bail!("unsupported release plan schema: {}", self.schema_version);
        }
        let registry_policy = registry_policy(&self.registry)?;
        require_identifier(&self.release_id, "release id")?;
        validate_version(&self.version, self.release_class)?;
        validate_sha256_git_oid(&self.registry_base_commit, "registry base commit")?;
        validate_source_git_oid(&self.source.commit)?;
        require_identifier(&self.source.protected_branch, "protected branch")?;
        require_identifier(&self.source.source_tag, "source tag")?;
        self.qualification.validate_plan(self)?;
        // Matrix, image, and signer completeness follow the destination profiles.
        let complete = self.requires_complete_matrix();

        if self.packages.is_empty() {
            bail!("release plan must classify at least one package");
        }
        require_unique_by(&self.packages, |package| &package.name, "package")?;
        for package in &self.packages {
            require_identifier(&package.name, "package name")?;
            if let Some(publication) = &package.publication {
                publication.validate()?;
            }
            for (platform, version) in &package.platform_versions {
                aos_registry_surface::package_version::validate_package_version(version)
                    .context("validating target package publication version")?;
                let publication = package
                    .publication
                    .as_ref()
                    .context("target version lacks package publication metadata")?;
                if version == &publication.version
                    || !package.platforms.iter().any(|cell| {
                        cell.platform == *platform
                            && matches!(cell.decision, MatrixCell::Artifact { .. })
                    })
                {
                    bail!("target version must override a publishable package cell");
                }
            }
            if package.publication.is_none()
                && package
                    .platforms
                    .iter()
                    .any(|cell| matches!(cell.decision, MatrixCell::Artifact { .. }))
            {
                bail!("publishable package lacks distribution metadata");
            }
            validate_cells(&package.platforms, false, complete)?;
        }

        require_unique_by(
            &self.images,
            |image| &image.system_variant,
            "system image variant",
        )?;
        for image in &self.images {
            require_identifier(&image.system_variant, "system variant")?;
            validate_cells(&image.platforms, true, complete)?;
        }
        if complete && self.images.is_empty() {
            bail!("complete-matrix releases require the Linux image matrix");
        }

        self.validate_signers(complete)?;

        let channels: Vec<String> = self
            .destinations
            .iter()
            .map(|destination| destination.channel.clone())
            .collect();
        registry_policy.require_release(&channels)?;
        require_identifier(&self.retention.policy_id, "retention policy id")?;
        if !self.retention.require_corresponding_source {
            bail!("canonical releases must retain corresponding source");
        }
        Ok(())
    }

    fn validate_signers(&self, complete: bool) -> Result<()> {
        let mut roles = BTreeSet::new();
        let mut signer_key_roles = BTreeMap::new();
        for signer in &self.signers {
            signer.validate()?;
            if !roles.insert(signer.role) {
                bail!("release plan contains duplicate signer role policy");
            }
            for key_id in &signer.key_ids {
                if let Some(previous_role) = signer_key_roles.insert(key_id, signer.role) {
                    bail!(
                        "release signer key id {key_id} is shared by {previous_role:?} and {:?}",
                        signer.role
                    );
                }
            }
        }
        for required in [
            SignerRole::Registry,
            SignerRole::Cache,
            SignerRole::Provenance,
            SignerRole::ReleaseEvidence,
            SignerRole::Qualification,
            SignerRole::TufRoot,
            SignerRole::TufTargets,
            self.release_class.tuf_role(),
            SignerRole::TufSnapshot,
            SignerRole::TufTimestamp,
        ] {
            if !roles.contains(&required) {
                bail!("release plan lacks mandatory signer role {required:?}");
            }
        }
        if !self.destinations.is_empty() && !roles.contains(&SignerRole::Channel) {
            bail!("planned channel operation requires a channel signer policy");
        }
        if self
            .surfaces
            .iter()
            .any(|surface| surface.kind == SurfaceKind::Static)
            && !roles.contains(&SignerRole::SurfaceReceipt)
        {
            bail!("static publication surfaces require a surface-receipt signer policy");
        }
        if complete {
            for required in [
                SignerRole::SecureBootDb,
                SignerRole::KernelModule,
                SignerRole::PcrPolicy,
            ] {
                if !roles.contains(&required) {
                    bail!("complete-matrix plan lacks mandatory image signer role {required:?}");
                }
            }
        }
        Ok(())
    }
}

fn validate_cells(
    cells: &[PlatformCell<PlannedArtifactSet>],
    image: bool,
    complete: bool,
) -> Result<()> {
    if image {
        require_complete_image_platforms(cells.iter().map(|cell| &cell.platform))?;
    } else {
        require_complete_package_platforms(cells.iter().map(|cell| &cell.platform))?;
    }
    if cells.len() != if image { 2 } else { 4 } {
        bail!("matrix contains a duplicate platform cell");
    }
    for cell in cells {
        cell.decision.validate()?;
        if let MatrixCell::Artifact { artifact } = &cell.decision {
            artifact.validate()?;
        }
        if complete && cell.decision.is_blocked() {
            bail!("complete-matrix release contains a blocked matrix cell");
        }
    }
    Ok(())
}

fn validate_version(value: &str, release_class: ReleaseClass) -> Result<()> {
    let derived = ReleaseClass::from_version(value)?;
    if derived != release_class {
        bail!("release class {release_class} differs from the {derived} version format: {value}");
    }
    Ok(())
}

fn validate_sha256_git_oid(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be a lowercase SHA-256 Git object id");
    }
    Ok(())
}

fn validate_source_git_oid(value: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("source commit must be a lowercase SHA-1 or SHA-256 Git object id");
    }
    Ok(())
}

fn require_unique_by<'a, T, F>(values: &'a [T], key: F, label: &str) -> Result<()>
where
    F: Fn(&'a T) -> &'a String,
{
    let mut keys: Vec<_> = values.iter().map(key).collect();
    keys.sort();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("duplicate {label}");
    }
    Ok(())
}
