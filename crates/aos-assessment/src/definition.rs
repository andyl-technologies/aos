//! Immutable package-authored scan definitions, independent of execution mode.
//!
//! The `aos.package-scan-definition/v1` record reuses maintenance component
//! policy and adds declarative security identities. It contains no credentials,
//! schedule state, checkout paths, or executable provider code.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::identity::{CohortId, ComponentId, FamilyId, MemberId, UnitId};
use crate::inventory::{
    Classification, ComponentVersion, DiscoveryProvider, Lifecycle, ReleasePolicy,
    VersionProjection,
};
use crate::security::SecurityDeclaration;
use crate::time::Timestamp;
use crate::validation::{decode, digest, sorted, text};

/// Identifies the closed package scan declaration.
pub const PACKAGE_SCAN_DEFINITION_V1: &str = "aos.package-scan-definition/v1";

/// Binds a generated/alias definition to one admitted upstream owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanOwnerRef {
    /// Exact owner update unit.
    pub unit_id: UnitId,
    /// Exact output/member under that unit.
    pub member_id: MemberId,
    /// Immutable admitted owner definition; not an ambient name lookup.
    pub definition_digest: Sha256Digest,
}

/// Preserves primary and advisory providers from package maintenance metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanDiscovery {
    /// Primary selection authority, absent for intentionally manual components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<DiscoveryProvider>,
    /// Non-authoritative version/license/vulnerability signals.
    pub advisors: Vec<DiscoveryProvider>,
}

/// Declares one upstream component and its shared assessment policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanComponent {
    /// Stable identity within the update unit.
    pub component_id: ComponentId,
    /// Exact current upstream and comparison versions.
    pub current: ComponentVersion,
    /// Supported provider declaration; not an arbitrary HTTP request.
    pub discovery: ScanDiscovery,
    /// Shared maintained-stream and candidate eligibility policy.
    pub release_policy: ReleasePolicy,
    /// Advisory identity and dependency-coverage declaration.
    pub security: SecurityDeclaration,
}

/// Binds package metadata to the complete versioned scan declaration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageScanDefinitionV1 {
    /// Exact schema identity.
    pub schema: String,
    /// Compatible update-unit identity.
    pub unit_id: UnitId,
    /// Cross-stream upstream family.
    pub family: FamilyId,
    /// Explicit maintained upstream stream.
    pub stream: String,
    /// Preserved maintenance controller authority.
    pub classification: Classification,
    /// Preserved maintenance support posture.
    pub lifecycle: Lifecycle,
    /// Components sorted by stable component ID.
    pub components: Vec<ScanComponent>,
    /// Version derivation required only for independent upstream units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_projection: Option<VersionProjection>,
    /// Generated/alias owner binding, absent for independent units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<ScanOwnerRef>,
    /// Required explanation for manual/frozen authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Exact frozen-unit review boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_after: Option<Timestamp>,
    /// Explicit compatible multi-unit association.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort: Option<CohortId>,
    /// Sorted admitted provenance identities; signatures are verified separately.
    pub metadata_origins: Vec<String>,
}

impl PackageScanDefinitionV1 {
    /// Decodes a bounded closed definition without executing package code.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous/oversized JSON, unsupported schemas,
    /// invalid classification rules, identities, providers, or ordering.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let definition: Self = decode(bytes, "package scan definition")?;
        definition.validate()?;
        Ok(definition)
    }

    /// Validates package scan structure without conferring publication authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, inconsistent ownership or
    /// projection, missing reason/review boundary, invalid identities or bounds.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_SCAN_DEFINITION_V1 {
            bail!("unsupported package scan definition schema");
        }
        text(&self.stream, 96, "maintained stream")?;
        if self.components.len() > 128 || self.metadata_origins.len() > 128 {
            bail!("package scan definition exceeds scope limits");
        }
        sorted(&self.metadata_origins, "metadata origins")?;
        for origin in &self.metadata_origins {
            text(origin, 128, "metadata origin")?;
        }

        let upstream = matches!(
            self.classification,
            Classification::Automatic
                | Classification::Assisted
                | Classification::Manual
                | Classification::Frozen
        );
        if upstream != self.version_projection.is_some() || upstream != !self.components.is_empty()
        {
            bail!("scan components/projection disagree with maintenance classification");
        }
        let owned = matches!(
            self.classification,
            Classification::Generated | Classification::Alias
        );
        if owned != self.owner_ref.is_some() {
            bail!("scan owner binding disagrees with maintenance classification");
        }
        if self
            .owner_ref
            .as_ref()
            .is_some_and(|owner| owner.unit_id == self.unit_id)
        {
            bail!("scan definition cannot own itself");
        }
        if matches!(
            self.classification,
            Classification::Manual | Classification::Frozen
        ) && self.reason.is_none()
        {
            bail!("manual/frozen scan definition requires a reason");
        }
        if self.classification == Classification::Frozen && self.review_after.is_none() {
            bail!("frozen scan definition requires an exact review boundary");
        }
        if let Some(reason) = &self.reason {
            text(reason, 4096, "maintenance reason")?;
        }
        for pair in self.components.windows(2) {
            if pair[0].component_id >= pair[1].component_id {
                bail!("scan components must be sorted and unique");
            }
        }

        for component in &self.components {
            text(&component.current.upstream_id, 512, "upstream identity")?;
            text(
                &component.current.comparison_version,
                256,
                "comparison version",
            )?;
            component.security.validate()?;
            if matches!(
                self.classification,
                Classification::Automatic | Classification::Assisted
            ) && component.discovery.primary.is_none()
            {
                bail!("automatic/assisted component requires primary discovery");
            }
            if component.discovery.advisors.len() > 16 {
                bail!("component advisor set exceeds limit");
            }
            let policy = &component.release_policy;
            if policy.series_minor.is_some() && policy.series_major.is_none() {
                bail!("component minor stream requires an explicit major stream");
            }
        }
        if let Some(VersionProjection::ComponentField { component, .. }) = &self.version_projection
            && !self
                .components
                .iter()
                .any(|item| &item.component_id == component)
        {
            bail!("scan version projection references a missing component");
        }
        Ok(())
    }

    /// Computes the immutable domain-separated identity after validation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid definition or noncanonical/oversized data.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(PACKAGE_SCAN_DEFINITION_V1, self)
    }
}
