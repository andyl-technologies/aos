//! Frozen release intent evaluated before build or signing effects.
//!
//! A plan closes package eligibility across all four targets and closes image
//! intent across both Linux targets. There is no implicit missing cell.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::evidence::GateRequirement;
use crate::platform::{
    MatrixCell, Platform, require_complete_image_platforms, require_complete_package_platforms,
};
use crate::signing::{SignerRequirement, SignerRole};
use crate::{CANONICAL_REGISTRY, RELEASE_PLAN_V1};

/// Release maturity and authorization class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseClass {
    /// Changed-business-day integration snapshot.
    Edge,
    /// Weekly release candidate.
    Candidate,
    /// Supported monthly production release.
    Stable,
    /// Fix-forward security or availability release.
    Emergency,
}

impl ReleaseClass {
    /// Returns whether this release class must contain no blocked matrix cell.
    #[must_use]
    pub const fn requires_complete_matrix(self) -> bool {
        matches!(self, Self::Stable | Self::Emergency)
    }

    /// Returns the TUF delegated role required to authorize this class.
    #[must_use]
    pub const fn tuf_role(self) -> SignerRole {
        match self {
            Self::Edge => SignerRole::TufEdge,
            Self::Candidate => SignerRole::TufCandidate,
            Self::Stable | Self::Emergency => SignerRole::TufStable,
        }
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
    /// Stable logical artifact ids the final manifest must resolve.
    pub artifact_ids: Vec<String>,
}

impl PlannedArtifactSet {
    fn validate(&self) -> Result<()> {
        if self.artifact_ids.is_empty() {
            bail!("planned artifact set cannot be empty");
        }
        for id in &self.artifact_ids {
            require_identifier(id, "planned artifact id")?;
        }
        require_unique(&self.artifact_ids, "planned artifact id")
    }
}

/// Complete target decisions for one publishable package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePlan {
    /// Canonical package name.
    pub name: String,
    /// One explicit decision for each of the four platforms.
    pub platforms: Vec<PlatformCell<PlannedArtifactSet>>,
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
    /// Exact lowercase SHA-256 Git commit object id.
    pub commit: String,
    /// Digest of the source tree represented by the commit.
    pub tree_digest: Sha256Digest,
    /// Protected branch whose reachability was checked.
    pub protected_branch: String,
    /// Immutable source tag reserved for this release.
    pub source_tag: String,
    /// Digest of public contributor-authorization evidence.
    pub contributor_authorization_digest: Sha256Digest,
}

/// Intended later channel operation; it is not part of release authoring.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelIntent {
    /// `edge`, `candidate`, or `stable`.
    pub channel: String,
    /// Inclusive first partition intended for the rollout.
    pub first_partition: u16,
    /// Inclusive final partition intended for the rollout.
    pub last_partition: u16,
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
pub struct ReleasePlanV1 {
    /// Exact plan schema identifier.
    pub schema_version: String,
    /// Immutable release identity.
    pub release_id: String,
    /// SemVer-compatible calendar release version.
    pub version: String,
    /// Maturity and authorization class.
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
    /// Versioned qualification and release gates.
    pub gates: Vec<GateRequirement>,
    /// Staging Hub deployment identity.
    pub staging_deployment_id: String,
    /// Production Hub deployment identity.
    pub production_deployment_id: String,
    /// Role-separated signer thresholds and public key ids.
    pub signers: Vec<SignerRequirement>,
    /// Reviewed future channel operations.
    pub intended_channels: Vec<ChannelIntent>,
    /// Retention and corresponding-source policy.
    pub retention: RetentionPolicy,
    /// Digest of the public evidence policy.
    pub public_evidence_policy_digest: Sha256Digest,
    /// Digest of the restricted operator policy, without private contents.
    pub restricted_operator_policy_digest: Sha256Digest,
}

impl ReleasePlanV1 {
    /// Validates the complete frozen release contract.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong schema or registry, invalid versioning,
    /// malformed source identity, duplicate or incomplete matrix entries,
    /// stable blockers, malformed gates/signers/channels, or absent mandatory
    /// signer roles.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RELEASE_PLAN_V1 {
            bail!("unsupported release plan schema: {}", self.schema_version);
        }
        if self.registry != CANONICAL_REGISTRY {
            bail!("canonical releases require registry {CANONICAL_REGISTRY}");
        }
        require_identifier(&self.release_id, "release id")?;
        validate_version(&self.version, self.release_class)?;
        validate_git_oid(&self.registry_base_commit, "registry base commit")?;
        validate_git_oid(&self.source.commit, "source commit")?;
        require_identifier(&self.source.protected_branch, "protected branch")?;
        require_identifier(&self.source.source_tag, "source tag")?;
        require_identifier(&self.staging_deployment_id, "staging deployment id")?;
        require_identifier(&self.production_deployment_id, "production deployment id")?;
        if self.staging_deployment_id == self.production_deployment_id {
            bail!("staging and production deployment identities must differ");
        }

        if self.packages.is_empty() {
            bail!("release plan must classify at least one package");
        }
        require_unique_by(&self.packages, |package| &package.name, "package")?;
        for package in &self.packages {
            require_identifier(&package.name, "package name")?;
            validate_cells(&package.platforms, false, self.release_class)?;
        }

        require_unique_by(
            &self.images,
            |image| &image.system_variant,
            "system image variant",
        )?;
        for image in &self.images {
            require_identifier(&image.system_variant, "system variant")?;
            validate_cells(&image.platforms, true, self.release_class)?;
        }
        if self.release_class.requires_complete_matrix() && self.images.is_empty() {
            bail!("stable and emergency releases require the Linux image matrix");
        }

        require_unique_by(&self.gates, |gate| &gate.policy_id, "gate policy")?;
        for gate in &self.gates {
            require_identifier(&gate.policy_id, "gate policy id")?;
        }
        if self.release_class.requires_complete_matrix()
            && self.gates.iter().any(|gate| !gate.required_for_stable)
        {
            bail!("stable plans cannot select advisory-only release gates");
        }

        let mut roles = BTreeSet::new();
        for signer in &self.signers {
            signer.validate()?;
            if !roles.insert(signer.role) {
                bail!("release plan contains duplicate signer role policy");
            }
        }
        for required in [
            SignerRole::Registry,
            SignerRole::Cache,
            SignerRole::Provenance,
            SignerRole::ReleaseEvidence,
            self.release_class.tuf_role(),
        ] {
            if !roles.contains(&required) {
                bail!("release plan lacks mandatory signer role {required:?}");
            }
        }
        if !self.intended_channels.is_empty() && !roles.contains(&SignerRole::Channel) {
            bail!("planned channel operation requires a channel signer policy");
        }
        if self.release_class.requires_complete_matrix() {
            for required in [
                SignerRole::SecureBootDb,
                SignerRole::KernelModule,
                SignerRole::PcrPolicy,
            ] {
                if !roles.contains(&required) {
                    bail!("stable plan lacks mandatory image signer role {required:?}");
                }
            }
        }

        require_unique_by(
            &self.intended_channels,
            |intent| &intent.channel,
            "channel intent",
        )?;
        for intent in &self.intended_channels {
            if !matches!(intent.channel.as_str(), "edge" | "candidate" | "stable") {
                bail!("unknown release channel: {}", intent.channel);
            }
            if intent.first_partition > intent.last_partition || intent.last_partition > 255 {
                bail!("channel partition range must be within 0..=255");
            }
            match self.release_class {
                ReleaseClass::Edge if intent.channel != "edge" => {
                    bail!("edge releases can target only the edge channel")
                }
                ReleaseClass::Candidate if intent.channel == "stable" => {
                    bail!("candidate releases cannot target stable")
                }
                _ => {}
            }
        }
        require_identifier(&self.retention.policy_id, "retention policy id")?;
        if !self.retention.require_corresponding_source {
            bail!("canonical releases must retain corresponding source");
        }
        Ok(())
    }
}

fn validate_cells(
    cells: &[PlatformCell<PlannedArtifactSet>],
    image: bool,
    release_class: ReleaseClass,
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
        if release_class.requires_complete_matrix() && cell.decision.is_blocked() {
            bail!("stable or emergency release contains a blocked matrix cell");
        }
    }
    Ok(())
}

fn validate_version(value: &str, release_class: ReleaseClass) -> Result<()> {
    if value.starts_with('v') {
        bail!("release version must not have a v prefix");
    }
    let version = Version::parse(value).context("parsing release version")?;
    if version.major < 2026 || !(1..=12).contains(&version.minor) {
        bail!("release version must use YYYY.M.P calendar components");
    }
    let prerelease = version.pre.as_str();
    match release_class {
        ReleaseClass::Edge if !prerelease.starts_with("dev.") => {
            bail!("edge release version must use -dev.YYYYMMDD.N")
        }
        ReleaseClass::Candidate if !prerelease.starts_with("rc.") => {
            bail!("candidate release version must use -rc.N")
        }
        ReleaseClass::Stable | ReleaseClass::Emergency if !prerelease.is_empty() => {
            bail!("stable and emergency release versions cannot have prerelease components")
        }
        _ => {}
    }
    Ok(())
}

fn validate_git_oid(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be a lowercase SHA-256 Git object id");
    }
    Ok(())
}

fn require_unique<T>(values: &[T], label: &str) -> Result<()>
where
    T: Ord + Clone,
{
    let mut values = values.to_vec();
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("duplicate {label}");
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
