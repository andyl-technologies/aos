//! Closed package-maintenance inventory and structural validation.
//!
//! The canonical JSON shape is rooted at `aos.maintenance-inventory/v1` and
//! contains only primitive policy data. It cannot contain executable hooks,
//! derivations, filesystem paths outside the repository, or ambient state.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};

use crate::MAINTENANCE_INVENTORY_V1;
use crate::identity::{ArtifactSlotId, ComponentId, FamilyId, MemberId, SourceSlotId, UnitId};

/// Resource limits for one canonical maintenance inventory.
pub const INVENTORY_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 16 * 1024 * 1024,
    max_depth: 32,
    max_items: 250_000,
    max_string_bytes: 64 * 1024,
};

/// Contains every maintenance unit emitted by pure Nix evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaintenanceInventoryV1 {
    /// Selects the exact closed inventory schema.
    pub schema: String,
    /// Lists update units in canonical identifier order.
    pub units: Vec<UpdateUnit>,
}

impl MaintenanceInventoryV1 {
    /// Decodes and validates a bounded inventory document.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, ambiguous, oversized, incompatible, or
    /// structurally invalid inventory data.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let inventory: Self = INVENTORY_LIMITS.decode(bytes, "maintenance inventory")?;
        inventory.validate()?;
        Ok(inventory)
    }

    /// Validates schema identity, ordering, uniqueness, and unit references.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema is incompatible or any unit violates
    /// the closed structural contract.
    pub fn validate(&self) -> Result<()> {
        if self.schema != MAINTENANCE_INVENTORY_V1 {
            bail!("unsupported maintenance inventory schema: {}", self.schema);
        }
        if self.units.len() > 10_000 {
            bail!("maintenance inventory exceeds 10000 units");
        }

        let mut unit_ids = BTreeSet::new();
        let mut family_streams = BTreeSet::new();
        let mut previous: Option<&UnitId> = None;
        for unit in &self.units {
            if previous.is_some_and(|prior| prior >= &unit.unit_id) {
                bail!("maintenance units must be strictly ordered by unitId");
            }
            previous = Some(&unit.unit_id);
            if !unit_ids.insert(&unit.unit_id) {
                bail!("duplicate update unit: {}", unit.unit_id);
            }
            if !family_streams.insert((&unit.family, unit.stream.as_str())) {
                bail!(
                    "duplicate maintained family/stream: {}/{}",
                    unit.family,
                    unit.stream
                );
            }
            unit.validate()?;
        }
        for unit in &self.units {
            if let Some(successor) = &unit.policy.successor_unit {
                let successor = self
                    .units
                    .iter()
                    .find(|candidate| &candidate.unit_id == successor)
                    .ok_or_else(|| {
                        anyhow::anyhow!("unit {} names missing successor {successor}", unit.unit_id)
                    })?;
                if successor.family != unit.family {
                    bail!("unit {} successor belongs to another family", unit.unit_id);
                }
            }
            if let Some(owner_unit_id) = &unit.owner_unit {
                let owner_unit = self
                    .units
                    .iter()
                    .find(|candidate| &candidate.unit_id == owner_unit_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "unit {} names missing owner unit {owner_unit_id}",
                            unit.unit_id
                        )
                    })?;
                if unit.owner_member.as_ref().is_some_and(|member| {
                    !owner_unit
                        .members
                        .iter()
                        .any(|candidate| candidate == member)
                }) {
                    bail!(
                        "unit {} names a member absent from its owner unit",
                        unit.unit_id
                    );
                }
            }
        }
        Ok(())
    }
}

/// Describes one independently scheduled update unit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateUnit {
    /// Stable unit identity, including a concurrent stream suffix when needed.
    pub unit_id: UnitId,
    /// Stable upstream family identity shared by concurrent streams.
    pub family: FamilyId,
    /// Maintained major, minor, LTS, channel, or VCS lineage.
    pub stream: String,
    /// Determines whether and how the controller may schedule the unit.
    pub classification: Classification,
    /// Maps component versions to the package version exposed by AOS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackageProjection>,
    /// Independently versioned upstream components keyed by stable identity.
    pub components: BTreeMap<ComponentId, Component>,
    /// Generated fixed-output artifacts updated after their declared inputs.
    #[serde(default)]
    pub artifacts: BTreeMap<ArtifactSlotId, ArtifactSlot>,
    /// Normalized repository-relative source file owning the contract.
    pub owner: String,
    /// AOS package outputs updated atomically by this unit.
    pub members: Vec<MemberId>,
    /// Explicit supported Nix platforms.
    pub platforms: Vec<String>,
    /// Lifecycle and minimum-risk policy.
    pub policy: UnitPolicy,
    /// Human reason required for manual and frozen units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Owning update unit required for generated and alias roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_unit: Option<UnitId>,
    /// Owning package member required for generated and alias roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_member: Option<MemberId>,
    /// Review date required for an intentionally frozen unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_after: Option<String>,
}

impl UpdateUnit {
    fn validate(&self) -> Result<()> {
        validate_owner(&self.owner)?;
        if self.stream.is_empty() || self.stream.len() > 96 {
            bail!("unit {} has an invalid stream", self.unit_id);
        }
        if self.members.is_empty() {
            bail!("unit {} has no package members", self.unit_id);
        }
        if self.platforms.is_empty() {
            bail!("unit {} has no supported platforms", self.unit_id);
        }
        require_strict_order(&self.members, "member", &self.unit_id)?;
        require_strict_strings(&self.platforms, "platform", &self.unit_id)?;

        let upstream = matches!(
            self.classification,
            Classification::Automatic
                | Classification::Assisted
                | Classification::Manual
                | Classification::Frozen
        );
        if upstream && (self.components.is_empty() || self.package.is_none()) {
            bail!(
                "upstream unit {} lacks components or package projection",
                self.unit_id
            );
        }
        if matches!(
            self.classification,
            Classification::Manual | Classification::Frozen
        ) && self.reason.as_deref().is_none_or(str::is_empty)
        {
            bail!("manual or frozen unit {} requires a reason", self.unit_id);
        }
        if self.classification == Classification::Frozen
            && self.review_after.as_deref().is_none_or(str::is_empty)
        {
            bail!("frozen unit {} requires a review date", self.unit_id);
        }
        let owned = matches!(
            self.classification,
            Classification::Generated | Classification::Alias
        );
        if owned && (self.owner_unit.is_none() || self.owner_member.is_none()) {
            bail!(
                "generated or alias unit {} requires an owner unit and member",
                self.unit_id
            );
        }
        if !upstream && (!self.components.is_empty() || self.package.is_some()) {
            bail!(
                "non-upstream unit {} cannot declare upstream components",
                self.unit_id
            );
        }

        if let Some(package) = &self.package {
            package.validate(&self.components, &self.unit_id)?;
        }
        for (component_id, component) in &self.components {
            component.validate(
                component_id,
                &self.classification,
                &self.unit_id,
                &self.components,
            )?;
        }
        validate_artifacts(&self.artifacts, &self.components, &self.unit_id)?;
        Ok(())
    }
}

/// Classifies the controller authority available for an update unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Classification {
    /// Deterministic materialization may proceed within the approved contract.
    Automatic,
    /// Deterministic work may proceed but repair or review is expected.
    Assisted,
    /// The controller reports the unit but does not schedule writes.
    Manual,
    /// The unit intentionally remains pinned until an explicit review.
    Frozen,
    /// The package is generated by another declared owner unit.
    Generated,
    /// The package is an alias of another declared owner unit.
    Alias,
    /// The package is AOS-owned without an independent upstream release.
    Local,
}

/// Projects a complete component vector to one AOS package version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageProjection {
    /// Current AOS derivation and registry version.
    pub current_version: String,
    /// Closed projection rule for candidate component vectors.
    pub version_projection: VersionProjection,
}

impl PackageProjection {
    fn validate(
        &self,
        components: &BTreeMap<ComponentId, Component>,
        unit_id: &UnitId,
    ) -> Result<()> {
        if self.current_version.is_empty() || self.current_version.len() > 256 {
            bail!("unit {unit_id} has an invalid package version");
        }
        let VersionProjection::ComponentField { component, .. } = &self.version_projection;
        if !components.contains_key(component) {
            bail!("unit {unit_id} projects from unknown component {component}");
        }
        Ok(())
    }
}

/// Selects the component field used as the package version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VersionProjection {
    /// Copies one component's comparison or upstream identity field.
    ComponentField {
        /// Component providing the projected value.
        component: ComponentId,
        /// Exact component field selected for projection.
        field: ProjectionField,
    },
}

/// Names a component value that may become the package version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionField {
    /// Uses the normalized value consumed by version ordering.
    ComparisonVersion,
    /// Uses the exact provider release, tag, or ref identity.
    UpstreamId,
}

/// Describes one independently discovered and selected upstream component.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Component {
    /// Current exact and comparison identities.
    pub current: ComponentVersion,
    /// Authoritative direct-provider discovery adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<DiscoveryProvider>,
    /// Non-authoritative advisory provider adapters.
    #[serde(default)]
    pub advisors: Vec<DiscoveryProvider>,
    /// Candidate selection and ordering policy.
    pub release_policy: ReleasePolicy,
    /// Source slots updated atomically for this component.
    pub sources: BTreeMap<SourceSlotId, SourceSlot>,
}

impl Component {
    fn validate(
        &self,
        component_id: &ComponentId,
        classification: &Classification,
        unit_id: &UnitId,
        components: &BTreeMap<ComponentId, Component>,
    ) -> Result<()> {
        self.current.validate(unit_id, component_id)?;
        if matches!(
            classification,
            Classification::Automatic | Classification::Assisted
        ) && self.primary.is_none()
        {
            bail!("unit {unit_id} component {component_id} lacks primary discovery");
        }
        if matches!(
            classification,
            Classification::Automatic | Classification::Assisted
        ) && self.sources.is_empty()
        {
            bail!("unit {unit_id} component {component_id} has no source slots");
        }
        for (slot_id, slot) in &self.sources {
            slot.validate(slot_id, unit_id, component_id, components)?;
        }
        Ok(())
    }
}

/// Preserves exact and normalized forms of one upstream version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ComponentVersion {
    /// Exact release, tag, revision, or ref identity supplied by upstream.
    pub upstream_id: String,
    /// Normalized value interpreted by the declared version scheme.
    pub comparison_version: String,
}

impl ComponentVersion {
    fn validate(&self, unit_id: &UnitId, component_id: &ComponentId) -> Result<()> {
        if self.upstream_id.is_empty() || self.comparison_version.is_empty() {
            bail!("unit {unit_id} component {component_id} has an empty current identity");
        }
        if self.upstream_id.len() > 512 || self.comparison_version.len() > 256 {
            bail!("unit {unit_id} component {component_id} identity is oversized");
        }
        Ok(())
    }
}

/// Selects a deterministic upstream discovery adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "provider",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DiscoveryProvider {
    /// Enumerates tags from one GitHub repository with pagination proof.
    GithubTags {
        /// Repository in `owner/name` form.
        repository: String,
        /// Literal prefix removed before version normalization.
        #[serde(default)]
        tag_prefix: String,
    },
    /// Advises using an explicitly mapped Repology project.
    Repology {
        /// Exact Repology project identifier.
        project: String,
    },
}

/// Determines how a newer component candidate is selected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReleasePolicy {
    /// Stream selection strategy.
    pub strategy: ReleaseStrategy,
    /// Version parser and ordering scheme.
    pub version_scheme: VersionScheme,
    /// Optional required major series for concurrent streams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_major: Option<u64>,
    /// Allows prerelease candidates when true.
    #[serde(default)]
    pub allow_prerelease: bool,
    /// Minimum elapsed days since first observation.
    #[serde(default)]
    pub minimum_age_days: u32,
}

/// Selects the release window applied to provider records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseStrategy {
    /// Selects the newest accepted version within the declared series.
    LatestInSeries,
    /// Selects the newest accepted version from an exact provider channel.
    Channel,
    /// Selects a descendant revision within a pinned VCS lineage.
    VcsLineage,
}

/// Selects the parser and ordering semantics for comparison versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionScheme {
    /// Uses Semantic Versioning precedence.
    Semver,
    /// Uses dotted numeric component ordering without SemVer metadata.
    Numeric,
    /// Uses an adapter-defined opaque channel order.
    Provider,
}

/// Describes one source input whose location and hash may change atomically.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceSlot {
    /// AOS-local fixed-output fetcher kind.
    pub fetcher: SourceFetcher,
    /// Exact evaluated fixed-output derivation identity.
    pub derivation: String,
    /// Structured candidate URL templates in preference order.
    pub url_templates: Vec<UrlTemplate>,
    /// Current SRI hash literal.
    pub hash: String,
    /// Flat-file or recursive content hash semantics.
    pub hash_mode: HashMode,
    /// Complete redirect-host allowlist.
    pub allowed_redirect_hosts: Vec<String>,
}

impl SourceSlot {
    fn validate(
        &self,
        slot_id: &SourceSlotId,
        unit_id: &UnitId,
        component_id: &ComponentId,
        components: &BTreeMap<ComponentId, Component>,
    ) -> Result<()> {
        if self.url_templates.is_empty() {
            bail!("unit {unit_id} component {component_id} source {slot_id} has no URLs");
        }
        if !self.derivation.starts_with("/nix/store/") || !self.derivation.ends_with(".drv") {
            bail!(
                "unit {unit_id} component {component_id} source {slot_id} has invalid derivation identity"
            );
        }
        if !self.hash.starts_with("sha256-") || self.hash.len() > 128 {
            bail!("unit {unit_id} component {component_id} source {slot_id} has invalid SRI hash");
        }
        require_strict_strings(&self.allowed_redirect_hosts, "redirect host", unit_id)?;
        for template in &self.url_templates {
            template.validate(unit_id, component_id, slot_id, components)?;
        }
        Ok(())
    }
}

/// Selects the AOS-local source fetcher used by a slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceFetcher {
    /// Fetches one URL as a fixed-output file or archive.
    Fetchurl,
}

/// Selects fixed-output hashing semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashMode {
    /// Hashes exact downloaded bytes.
    Flat,
    /// Hashes a recursively serialized source tree.
    Recursive,
}

/// Describes one generated fixed-output dependency artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactSlot {
    /// Ordered source or artifact edges consumed by this materializer.
    pub inputs: Vec<ArtifactInput>,
    /// Current recursive SRI hash literal.
    pub hash: String,
    /// Exact evaluated artifact derivation identity.
    pub derivation: String,
    /// Closed kind-specific builder parameters.
    pub materializer: ArtifactMaterializer,
    /// Optional repository outputs a materializer may replace.
    #[serde(default)]
    pub outputs: Vec<ArtifactOutput>,
}

/// Selects one declared input edge in an artifact dependency graph.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ArtifactInput {
    /// Reads one source slot from an upstream component.
    Source {
        /// Component owning the source slot.
        component: ComponentId,
        /// Stable source-slot identity.
        slot: SourceSlotId,
    },
    /// Reads a previously materialized artifact.
    Artifact {
        /// Stable dependency artifact identity.
        artifact: ArtifactSlotId,
    },
}

/// Freezes all output-affecting parameters for a supported materializer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ArtifactMaterializer {
    /// Vendors dependencies using the legacy `cargo vendor` builder.
    CargoDeps {
        /// Source-relative Cargo package root.
        source_root: String,
        /// Repository-relative patches applied before vendoring.
        patches: Vec<String>,
        /// Frozen AOS builder contract identity.
        builder: String,
    },
    /// Vendors lockfile-resolved Cargo dependencies, including Git sources.
    CargoVendor {
        /// Source-relative Cargo package root.
        source_root: String,
        /// Repository-relative patches applied before vendoring.
        patches: Vec<String>,
        /// Frozen AOS builder contract identity.
        builder: String,
    },
    /// Downloads one or several Go module graphs.
    GoModules {
        /// Source-relative extraction root.
        source_root: String,
        /// Strictly ordered module roots within the source.
        module_roots: Vec<String>,
        /// Frozen AOS builder contract identity.
        builder: String,
    },
    /// Installs an npm lockfile without lifecycle scripts.
    NpmDeps {
        /// Source-relative npm package root.
        source_root: String,
        /// Repository-relative package manifest path.
        manifest: String,
        /// Repository-relative npm lockfile path.
        lockfile: String,
        /// Must remain false; dependency acquisition cannot run scripts.
        lifecycle_scripts: bool,
        /// Frozen AOS builder contract identity.
        builder: String,
    },
    /// Evaluates Bazel repository rules inside the full confinement boundary.
    BazelDeps {
        /// Source-relative Bazel workspace root.
        source_root: String,
        /// Exact Bazel target used to populate external repositories.
        target: String,
        /// Ordered Bazel fetch flags.
        flags: Vec<String>,
        /// Repository-relative patches applied before fetching.
        patches: Vec<String>,
        /// Frozen AOS builder contract identity.
        builder: String,
    },
}

/// Declares one repository file a materializer may replace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactOutput {
    /// Normalized repository-relative output path.
    pub path: String,
    /// Parsed format required before and after transformation.
    pub format: ArtifactOutputFormat,
    /// Exact preimage digest required before writing.
    pub expected_preimage: String,
    /// Closed transformation performed by the controller.
    pub transformation: ArtifactTransformation,
}

/// Selects the parser used to validate a generated repository output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactOutputFormat {
    /// Parses canonical JSON data.
    Json,
    /// Parses TOML data.
    Toml,
}

/// Selects a reviewed generated-output transformation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactTransformation {
    /// Regenerates a Cargo lockfile without executing package code.
    CargoLock,
    /// Regenerates an npm lockfile without executing lifecycle scripts.
    NpmLock,
}

/// Defines one URL without allowing candidate text to alter its origin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UrlTemplate {
    /// Fixed URL scheme; version substitution cannot change it.
    pub scheme: UrlScheme,
    /// Fixed ASCII hostname; version substitution cannot change it.
    pub authority: String,
    /// Path segments encoded independently after substitution.
    pub path: Vec<UrlSegment>,
}

impl UrlTemplate {
    fn validate(
        &self,
        unit_id: &UnitId,
        component_id: &ComponentId,
        slot_id: &SourceSlotId,
        components: &BTreeMap<ComponentId, Component>,
    ) -> Result<()> {
        if self.authority.is_empty()
            || !self.authority.is_ascii()
            || self.authority.bytes().any(|byte| {
                byte.is_ascii_control() || matches!(byte, b'/' | b'?' | b'#' | b'@' | b':')
            })
        {
            bail!("unit {unit_id} component {component_id} source {slot_id} has invalid authority");
        }
        if self.path.is_empty() {
            bail!("unit {unit_id} component {component_id} source {slot_id} has an empty URL path");
        }
        for segment in &self.path {
            if let UrlSegment::Parts { parts } = segment {
                if parts.is_empty() {
                    bail!(
                        "unit {unit_id} component {component_id} source {slot_id} has empty URL parts"
                    );
                }
                for part in parts {
                    if let UrlPart::ComponentField { component, .. } = part
                        && !components.contains_key(component)
                    {
                        bail!(
                            "unit {unit_id} component {component_id} source {slot_id} references unknown URL component {component}"
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Selects the fixed transport scheme for a source URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlScheme {
    /// Requires authenticated HTTPS transport.
    Https,
}

/// Defines one URL path segment from typed literal and component parts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum UrlSegment {
    /// Uses one fixed literal path segment.
    Literal {
        /// Exact literal segment before percent encoding.
        value: String,
    },
    /// Concatenates typed parts into one independently encoded path segment.
    Parts {
        /// Ordered literal and component-field values.
        parts: Vec<UrlPart>,
    },
}

/// Supplies one typed value inside a URL path segment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum UrlPart {
    /// Supplies fixed text.
    Literal {
        /// Exact literal text.
        value: String,
    },
    /// Supplies one field from the selected component target.
    ComponentField {
        /// Component owning the target field.
        component: ComponentId,
        /// Exact target field to substitute.
        field: ProjectionField,
    },
}

/// Defines lifecycle and minimum risk for one unit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnitPolicy {
    /// Current maintenance lifecycle.
    pub lifecycle: Lifecycle,
    /// Minimum risk classification before derived escalation.
    pub risk_floor: RiskLevel,
    /// Optional succeeding unit for concurrent-stream reporting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_unit: Option<UnitId>,
}

/// Describes the supported lifetime of an update stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifecycle {
    /// Receives normal upstream updates.
    Supported,
    /// Receives only security-relevant updates.
    SecurityOnly,
    /// Is pinned pending an explicit review.
    Frozen,
    /// Is being removed through a human-planned migration.
    Retiring,
}

/// Orders minimum review and validation scrutiny.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    /// Conventional leaf update with limited impact.
    Low,
    /// Ordinary update requiring standard review and gates.
    Normal,
    /// Broad or sensitive update requiring expanded gates.
    High,
    /// Exceptional update requiring named specialist review.
    Critical,
}

fn validate_artifacts(
    artifacts: &BTreeMap<ArtifactSlotId, ArtifactSlot>,
    components: &BTreeMap<ComponentId, Component>,
    unit_id: &UnitId,
) -> Result<()> {
    if artifacts.len() > 128 {
        bail!("unit {unit_id} has too many artifact slots");
    }
    for (artifact_id, artifact) in artifacts {
        if artifact.inputs.is_empty() || artifact.inputs.len() > 128 {
            bail!("unit {unit_id} artifact {artifact_id} has an invalid input set");
        }
        if !artifact.hash.starts_with("sha256-") || artifact.hash.len() > 128 {
            bail!("unit {unit_id} artifact {artifact_id} has an invalid SRI hash");
        }
        if !artifact.derivation.starts_with("/nix/store/") || !artifact.derivation.ends_with(".drv")
        {
            bail!("unit {unit_id} artifact {artifact_id} has an invalid derivation identity");
        }
        let mut previous = None;
        for input in &artifact.inputs {
            if previous.is_some_and(|prior| prior >= input) {
                bail!("unit {unit_id} artifact {artifact_id} inputs must be strictly ordered");
            }
            previous = Some(input);
            match input {
                ArtifactInput::Source { component, slot } => {
                    if !components
                        .get(component)
                        .is_some_and(|value| value.sources.contains_key(slot))
                    {
                        bail!(
                            "unit {unit_id} artifact {artifact_id} references missing source {component}/{slot}"
                        );
                    }
                }
                ArtifactInput::Artifact {
                    artifact: dependency,
                } => {
                    if !artifacts.contains_key(dependency) {
                        bail!(
                            "unit {unit_id} artifact {artifact_id} references missing artifact {dependency}"
                        );
                    }
                }
            }
        }
        validate_materializer(&artifact.materializer, unit_id, artifact_id)?;
        if artifact.outputs.len() > 32 {
            bail!("unit {unit_id} artifact {artifact_id} has too many outputs");
        }
        let mut output_paths = BTreeSet::new();
        for output in &artifact.outputs {
            validate_repository_path(&output.path, "artifact output")?;
            if !output_paths.insert(&output.path) {
                bail!("unit {unit_id} artifact {artifact_id} repeats an output path");
            }
            if !output.expected_preimage.starts_with("sha256:")
                || output.expected_preimage.len() != 71
            {
                bail!(
                    "unit {unit_id} artifact {artifact_id} has an invalid output preimage digest"
                );
            }
        }
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for artifact_id in artifacts.keys() {
        visit_artifact(artifact_id, artifacts, unit_id, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit_artifact<'a>(
    artifact_id: &'a ArtifactSlotId,
    artifacts: &'a BTreeMap<ArtifactSlotId, ArtifactSlot>,
    unit_id: &UnitId,
    visiting: &mut BTreeSet<&'a ArtifactSlotId>,
    visited: &mut BTreeSet<&'a ArtifactSlotId>,
) -> Result<()> {
    if visited.contains(artifact_id) {
        return Ok(());
    }
    if !visiting.insert(artifact_id) {
        bail!("unit {unit_id} artifact graph contains a cycle at {artifact_id}");
    }
    for input in &artifacts[artifact_id].inputs {
        if let ArtifactInput::Artifact {
            artifact: dependency,
        } = input
        {
            visit_artifact(dependency, artifacts, unit_id, visiting, visited)?;
        }
    }
    visiting.remove(artifact_id);
    visited.insert(artifact_id);
    Ok(())
}

fn validate_materializer(
    materializer: &ArtifactMaterializer,
    unit_id: &UnitId,
    artifact_id: &ArtifactSlotId,
) -> Result<()> {
    let (source_root, builder) = match materializer {
        ArtifactMaterializer::CargoDeps {
            source_root,
            patches,
            builder,
        }
        | ArtifactMaterializer::CargoVendor {
            source_root,
            patches,
            builder,
        } => {
            for patch in patches {
                validate_repository_path(patch, "artifact patch")?;
            }
            (source_root, builder)
        }
        ArtifactMaterializer::GoModules {
            source_root,
            module_roots,
            builder,
        } => {
            if module_roots.is_empty() {
                bail!("unit {unit_id} artifact {artifact_id} has no Go module roots");
            }
            require_strict_strings(module_roots, "Go module root", unit_id)?;
            for root in module_roots {
                validate_relative_path(root, "Go module root")?;
            }
            (source_root, builder)
        }
        ArtifactMaterializer::NpmDeps {
            source_root,
            manifest,
            lockfile,
            lifecycle_scripts,
            builder,
        } => {
            if *lifecycle_scripts {
                bail!("unit {unit_id} artifact {artifact_id} enables npm lifecycle scripts");
            }
            validate_repository_path(manifest, "npm manifest")?;
            validate_repository_path(lockfile, "npm lockfile")?;
            (source_root, builder)
        }
        ArtifactMaterializer::BazelDeps {
            source_root,
            target,
            flags,
            patches,
            builder,
        } => {
            if target.is_empty()
                || target.len() > 512
                || target.bytes().any(|byte| byte.is_ascii_control())
            {
                bail!("unit {unit_id} artifact {artifact_id} has an invalid Bazel target");
            }
            for value in flags {
                if value.is_empty()
                    || value.len() > 512
                    || value.bytes().any(|byte| byte.is_ascii_control())
                {
                    bail!("unit {unit_id} artifact {artifact_id} has an invalid Bazel flag");
                }
            }
            for patch in patches {
                validate_repository_path(patch, "artifact patch")?;
            }
            (source_root, builder)
        }
    };
    validate_relative_path(source_root, "artifact source root")?;
    if builder.is_empty()
        || builder.len() > 128
        || !builder.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
    {
        bail!("unit {unit_id} artifact {artifact_id} has an invalid builder identity");
    }
    Ok(())
}

fn validate_relative_path(path: &str, label: &str) -> Result<()> {
    if path == "." {
        return Ok(());
    }
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("invalid {label}: {path}");
    }
    Ok(())
}

fn validate_repository_path(path: &str, label: &str) -> Result<()> {
    validate_relative_path(path, label)?;
    if path.len() > 1024 || path.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("invalid {label}: {path}");
    }
    Ok(())
}

fn validate_owner(owner: &str) -> Result<()> {
    if owner.is_empty()
        || owner.starts_with('/')
        || owner.ends_with('/')
        || owner
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !owner.starts_with("pkgs/")
        || !owner.ends_with(".nix")
    {
        bail!("invalid maintenance owner path: {owner}");
    }
    Ok(())
}

fn require_strict_order<T>(values: &[T], label: &str, unit_id: &UnitId) -> Result<()>
where
    T: Ord + std::fmt::Display,
{
    for pair in values.windows(2) {
        if pair[0] >= pair[1] {
            bail!("unit {unit_id} {label} values must be unique and strictly ordered");
        }
    }
    Ok(())
}

fn require_strict_strings(values: &[String], label: &str, unit_id: &UnitId) -> Result<()> {
    for value in values {
        if value.is_empty()
            || value.len() > 256
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            bail!("unit {unit_id} has an invalid {label}");
        }
    }
    for pair in values.windows(2) {
        if pair[0] >= pair[1] {
            bail!("unit {unit_id} {label} values must be unique and strictly ordered");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_contract::canonical;
    use serde_json::json;

    use super::*;

    fn canary() -> serde_json::Value {
        json!({
            "schema": MAINTENANCE_INVENTORY_V1,
            "units": [{
                "unitId": "zlib-1",
                "family": "zlib",
                "stream": "1",
                "classification": "automatic",
                "package": {
                    "currentVersion": "1.3.1",
                    "versionProjection": {
                        "kind": "component-field",
                        "component": "main",
                        "field": "comparisonVersion"
                    }
                },
                "components": {
                    "main": {
                        "current": {"upstreamId": "v1.3.1", "comparisonVersion": "1.3.1"},
                        "primary": {"provider": "github-tags", "repository": "madler/zlib", "tagPrefix": "v"},
                        "advisors": [{"provider": "repology", "project": "zlib"}],
                        "releasePolicy": {
                            "strategy": "latest-in-series",
                            "versionScheme": "semver",
                            "seriesMajor": 1,
                            "allowPrerelease": false,
                            "minimumAgeDays": 3
                        },
                        "sources": {
                            "source": {
                                "fetcher": "fetchurl",
                                "derivation": "/nix/store/00000000000000000000000000000000-source.drv",
                                "urlTemplates": [{
                                    "scheme": "https",
                                    "authority": "zlib.net",
                                    "path": [
                                        {"kind": "literal", "value": "fossils"},
                                        {"kind": "parts", "parts": [
                                            {"kind": "literal", "value": "zlib-"},
                                            {"kind": "component-field", "component": "main", "field": "comparisonVersion"},
                                            {"kind": "literal", "value": ".tar.gz"}
                                        ]}
                                    ]
                                }],
                                "hash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                "hashMode": "flat",
                                "allowedRedirectHosts": ["zlib.net"]
                            }
                        }
                    }
                },
                "artifacts": {},
                "owner": "pkgs/compression/zlib.nix",
                "members": ["zlib"],
                "platforms": ["aarch64-linux", "x86_64-linux"],
                "policy": {"lifecycle": "supported", "riskFloor": "normal"}
            }]
        })
    }

    #[test]
    fn conventional_inventory_round_trips_canonically() -> Result<()> {
        let bytes = canonical::canonical_json(&canary())?;
        let inventory = MaintenanceInventoryV1::from_slice(&bytes)?;
        assert_eq!(canonical::to_vec(&inventory)?, bytes);
        Ok(())
    }

    #[test]
    fn inventory_rejects_unknown_fields_and_incompatible_schema() -> Result<()> {
        let mut unknown = canary();
        unknown["extra"] = json!(true);
        assert!(MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&unknown)?).is_err());

        let mut incompatible = canary();
        incompatible["schema"] = json!("aos.maintenance-inventory/v2");
        assert!(
            MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&incompatible)?).is_err()
        );
        Ok(())
    }

    #[test]
    fn concurrent_streams_are_distinct_but_duplicate_streams_fail() -> Result<()> {
        let mut inventory = canary();
        let mut second = inventory["units"][0].clone();
        second["unitId"] = json!("zlib-2");
        second["stream"] = json!("2");
        inventory["units"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("units fixture"))?
            .push(second.clone());
        assert!(
            MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&inventory)?).is_ok()
        );

        second["unitId"] = json!("zlib-3");
        second["stream"] = json!("1");
        inventory["units"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("units fixture"))?[1] = second;
        assert!(
            MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&inventory)?).is_err()
        );
        Ok(())
    }

    #[test]
    fn automatic_units_require_primary_source_and_safe_owner() -> Result<()> {
        let mut missing = canary();
        missing["units"][0]["components"]["main"]
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("component fixture"))?
            .remove("primary");
        assert!(MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&missing)?).is_err());

        let mut escaped = canary();
        escaped["units"][0]["owner"] = json!("pkgs/../secrets.nix");
        assert!(MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&escaped)?).is_err());
        Ok(())
    }

    #[test]
    fn artifact_graph_is_closed_acyclic_and_script_safe() -> Result<()> {
        let mut inventory = canary();
        inventory["units"][0]["artifacts"] = json!({
            "goModules": {
                "inputs": [{"kind": "source", "component": "main", "slot": "source"}],
                "hash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "derivation": "/nix/store/11111111111111111111111111111111-go-modules.drv",
                "materializer": {
                    "kind": "go-modules",
                    "sourceRoot": ".",
                    "moduleRoots": ["."],
                    "builder": "fetchGoModules/v1"
                },
                "outputs": []
            },
            "npmModules": {
                "inputs": [{"kind": "artifact", "artifact": "goModules"}],
                "hash": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "derivation": "/nix/store/22222222222222222222222222222222-npm-modules.drv",
                "materializer": {
                    "kind": "npm-deps",
                    "sourceRoot": ".",
                    "manifest": "pkgs/example/package.json",
                    "lockfile": "pkgs/example/package-lock.json",
                    "lifecycleScripts": false,
                    "builder": "fetchNpmDeps/v1"
                },
                "outputs": []
            }
        });
        assert!(
            MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&inventory)?).is_ok()
        );

        inventory["units"][0]["artifacts"]["goModules"]["inputs"] =
            json!([{"kind": "artifact", "artifact": "npmModules"}]);
        assert!(
            MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&inventory)?).is_err()
        );

        inventory["units"][0]["artifacts"]["goModules"]["inputs"] =
            json!([{"kind": "source", "component": "main", "slot": "source"}]);
        inventory["units"][0]["artifacts"]["npmModules"]["materializer"]["lifecycleScripts"] =
            json!(true);
        assert!(
            MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&inventory)?).is_err()
        );
        Ok(())
    }

    #[test]
    fn frozen_local_and_alias_roles_are_explicit() -> Result<()> {
        let mut frozen = canary();
        frozen["units"][0]["classification"] = json!("frozen");
        frozen["units"][0]["reason"] = json!("bootstrap compatibility");
        assert!(MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&frozen)?).is_err());
        frozen["units"][0]["reviewAfter"] = json!("2027-01-01");
        assert!(MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&frozen)?).is_ok());

        let mut local = canary();
        local["units"][0]["classification"] = json!("local");
        local["units"][0]
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("unit fixture"))?
            .remove("package");
        local["units"][0]["components"] = json!({});
        assert!(MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&local)?).is_ok());

        let mut alias_inventory = canary();
        let mut alias = alias_inventory["units"][0].clone();
        alias["unitId"] = json!("zlib-alias");
        alias["stream"] = json!("alias-default");
        alias["classification"] = json!("alias");
        alias["members"] = json!(["zlib-default"]);
        alias["ownerUnit"] = json!("zlib-1");
        alias["ownerMember"] = json!("zlib");
        alias["components"] = json!({});
        alias
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("alias fixture"))?
            .remove("package");
        alias_inventory["units"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("units fixture"))?
            .push(alias);
        assert!(
            MaintenanceInventoryV1::from_slice(&canonical::canonical_json(&alias_inventory)?)
                .is_ok()
        );
        Ok(())
    }
}
