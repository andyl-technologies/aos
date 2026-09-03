//! Bounded upstream observations and deterministic version selection.
//!
//! Provider adapters preserve raw identities in [`UpstreamObservationV1`].
//! Selection consumes those immutable records, an explicit evaluation time,
//! and package-authored policy; this module never reads a clock or network.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::inventory::{Component, ComponentVersion, UpdateUnit, VersionScheme};
use crate::workflow::DiscoveryDecision;
use crate::{DISCOVERY_SNAPSHOT_V1, UPSTREAM_OBSERVATION_V1};

const MAX_CANDIDATES: usize = 2_000;
const MAX_TEXT: usize = 2_048;

/// Describes whether an adapter proved its candidate set complete enough.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ObservationCoverage {
    /// The provider proved that the returned set is complete.
    Complete,
    /// Newest-first enumeration reached the current immutable identity.
    ThroughCurrent {
        /// Current identity that terminated bounded pagination.
        identity: String,
    },
    /// A safety limit prevented a completeness proof.
    Truncated {
        /// Stable explanation of the bound that stopped enumeration.
        reason: String,
    },
}

impl ObservationCoverage {
    fn is_sufficient(&self, current: &str) -> bool {
        matches!(self, Self::Complete)
            || matches!(self, Self::ThroughCurrent { identity } if identity == current)
    }
}

/// Preserves one provider-native release or tag candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationCandidate {
    /// Immutable provider-native identity, such as an exact tag.
    pub raw_id: String,
    /// Provider version text before AOS normalization.
    pub raw_version: String,
    /// Provider publication time in Unix seconds, when authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at_unix: Option<u64>,
    /// First durable local observation time in Unix seconds.
    pub first_observed_at_unix: u64,
    /// Marks a provider-declared prerelease.
    #[serde(default)]
    pub prerelease: bool,
    /// Marks a provider-declared withdrawn or yanked record.
    #[serde(default)]
    pub yanked: bool,
    /// Sanitized public release URL, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_url: Option<String>,
}

/// Records one immutable, bounded provider response and its parsed candidates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpstreamObservationV1 {
    /// Selects the exact closed observation schema.
    pub schema: String,
    /// Stable provider adapter name.
    pub provider: String,
    /// Provider-native project identity.
    pub project: String,
    /// Retrieval time supplied by the effect layer in Unix seconds.
    pub retrieved_at_unix: u64,
    /// Sanitized request URL without credentials or secret query values.
    pub request_url: String,
    /// Adapter and parser contract version.
    pub adapter_version: String,
    /// Completeness proof produced by the adapter.
    pub coverage: ObservationCoverage,
    /// Digest of the exact bounded response bytes.
    pub response_digest: Sha256Digest,
    /// Provider-native candidates in deterministic order.
    pub candidates: Vec<ObservationCandidate>,
}

impl UpstreamObservationV1 {
    /// Validates bounds, identity, ordering, and completeness metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, unsafe strings, duplicate
    /// identities, an empty adapter version, or an oversized candidate set.
    pub fn validate(&self) -> Result<()> {
        if self.schema != UPSTREAM_OBSERVATION_V1 {
            bail!("unsupported upstream observation schema");
        }
        for (label, value) in [
            ("provider", self.provider.as_str()),
            ("project", self.project.as_str()),
            ("request URL", self.request_url.as_str()),
            ("adapter version", self.adapter_version.as_str()),
        ] {
            validate_text(label, value)?;
        }
        if !self.request_url.starts_with("https://") || self.request_url.contains('@') {
            bail!("upstream observation request URL is unsafe");
        }
        if self.candidates.len() > MAX_CANDIDATES {
            bail!("upstream observation candidate set is oversized");
        }

        let mut prior: Option<&str> = None;
        for candidate in &self.candidates {
            validate_text("candidate identity", &candidate.raw_id)?;
            validate_text("candidate version", &candidate.raw_version)?;
            if candidate.first_observed_at_unix > self.retrieved_at_unix {
                bail!("candidate first-observed time is after retrieval time");
            }
            if prior.is_some_and(|value| value >= candidate.raw_id.as_str()) {
                bail!("candidate identities must be unique and strictly ordered");
            }
            prior = Some(&candidate.raw_id);
        }
        Ok(())
    }
}

/// Explains why one provider record was not selectable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CandidateRejection {
    /// Exact rejected provider identity.
    pub raw_id: String,
    /// Stable policy reason.
    pub reason: String,
}

/// Contains one component's deterministic discovery result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ComponentDiscovery {
    /// Component identity inside its update unit.
    pub component: String,
    /// Evidence decision for this component.
    pub decision: DiscoveryDecision,
    /// Greatest acceptable newer identity, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<ComponentVersion>,
    /// Every examined record rejected by policy.
    #[serde(default)]
    pub rejected: Vec<CandidateRejection>,
}

/// Contains one unit's complete component-vector discovery decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnitDiscovery {
    /// Exact update-unit identity.
    pub unit_id: String,
    /// Aggregate evidence decision.
    pub decision: DiscoveryDecision,
    /// Component results in component identity order.
    pub components: Vec<ComponentDiscovery>,
}

/// Freezes repository-bound observations and their pure decisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DiscoverySnapshotV1 {
    /// Selects the exact closed discovery snapshot schema.
    pub schema: String,
    /// Digest of the repository-bound inventory envelope.
    pub inventory_envelope_digest: Sha256Digest,
    /// Immutable observations keyed by their canonical request identity.
    pub observations: BTreeMap<String, UpstreamObservationV1>,
    /// Unit decisions in update-unit order.
    pub units: Vec<UnitDiscovery>,
    /// Policy evaluation time supplied by the effect layer.
    pub evaluated_at_unix: u64,
}

impl DiscoverySnapshotV1 {
    /// Validates the snapshot's schema, observations, and deterministic order.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible schema, invalid embedded evidence,
    /// or duplicate/out-of-order unit identities.
    pub fn validate(&self) -> Result<()> {
        if self.schema != DISCOVERY_SNAPSHOT_V1 {
            bail!("unsupported discovery snapshot schema");
        }
        for observation in self.observations.values() {
            observation.validate()?;
        }
        for pair in self.units.windows(2) {
            if pair[0].unit_id >= pair[1].unit_id {
                bail!("discovery snapshot units must be unique and ordered");
            }
        }
        Ok(())
    }
}

/// Selects one complete unit result from component-keyed primary evidence.
///
/// `now_unix` and `observation_max_age_seconds` are explicit so selection is
/// deterministic and independently testable.
///
/// # Errors
///
/// Returns an error when an observation is malformed or version policy cannot
/// interpret the unit's current version.
pub fn select_unit(
    unit: &UpdateUnit,
    observations: &BTreeMap<String, UpstreamObservationV1>,
    now_unix: u64,
    observation_max_age_seconds: u64,
) -> Result<UnitDiscovery> {
    let mut components = Vec::with_capacity(unit.components.len());
    for (component_id, component) in &unit.components {
        let result = match observations.get(component_id.as_str()) {
            Some(observation) => select_component(
                component_id.as_str(),
                component,
                observation,
                now_unix,
                observation_max_age_seconds,
            )?,
            None => ComponentDiscovery {
                component: component_id.to_string(),
                decision: DiscoveryDecision::Unknown,
                selected: None,
                rejected: Vec::new(),
            },
        };
        components.push(result);
    }

    let decision = if components
        .iter()
        .any(|component| component.decision == DiscoveryDecision::Quarantined)
    {
        DiscoveryDecision::Quarantined
    } else if components
        .iter()
        .any(|component| component.decision == DiscoveryDecision::Unknown)
    {
        DiscoveryDecision::Unknown
    } else if components
        .iter()
        .any(|component| component.decision == DiscoveryDecision::UpdateAvailable)
    {
        DiscoveryDecision::UpdateAvailable
    } else {
        DiscoveryDecision::Current
    };

    Ok(UnitDiscovery {
        unit_id: unit.unit_id.to_string(),
        decision,
        components,
    })
}

fn select_component(
    component_id: &str,
    component: &Component,
    observation: &UpstreamObservationV1,
    now_unix: u64,
    observation_max_age_seconds: u64,
) -> Result<ComponentDiscovery> {
    observation.validate()?;
    if now_unix < observation.retrieved_at_unix
        || now_unix.saturating_sub(observation.retrieved_at_unix) > observation_max_age_seconds
        || !observation
            .coverage
            .is_sufficient(&component.current.upstream_id)
    {
        return Ok(component_result(component_id, DiscoveryDecision::Unknown));
    }

    let current = version_key(
        component.release_policy.version_scheme,
        &component.current.comparison_version,
    )?;
    let minimum_age = u64::from(component.release_policy.minimum_age_days) * 86_400;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for candidate in &observation.candidates {
        let rejection = if candidate.yanked {
            Some("yanked")
        } else if candidate.prerelease && !component.release_policy.allow_prerelease {
            Some("prerelease-disallowed")
        } else if now_unix < candidate.first_observed_at_unix
            || now_unix.saturating_sub(candidate.first_observed_at_unix) < minimum_age
        {
            Some("stabilizing")
        } else {
            None
        };
        if let Some(reason) = rejection {
            rejected.push(reject(candidate, reason));
            continue;
        }

        let key = match version_key(
            component.release_policy.version_scheme,
            &candidate.raw_version,
        ) {
            Ok(key) => key,
            Err(_) => {
                rejected.push(reject(candidate, "unorderable-version"));
                continue;
            }
        };
        if key.is_prerelease() && !component.release_policy.allow_prerelease {
            rejected.push(reject(candidate, "prerelease-disallowed"));
            continue;
        }
        if let Some(major) = component.release_policy.series_major
            && key.major() != Some(major)
        {
            rejected.push(reject(candidate, "outside-maintained-stream"));
            continue;
        }
        if key.cmp(&current) != Ordering::Greater {
            rejected.push(reject(candidate, "not-newer"));
            continue;
        }
        accepted.push((key, candidate));
    }

    accepted.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.raw_id.cmp(&right.1.raw_id))
    });
    if accepted
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].1.raw_id != pair[1].1.raw_id)
    {
        return Ok(ComponentDiscovery {
            component: component_id.to_string(),
            decision: DiscoveryDecision::Quarantined,
            selected: None,
            rejected,
        });
    }
    let selected = accepted.last().map(|(_, candidate)| ComponentVersion {
        upstream_id: candidate.raw_id.clone(),
        comparison_version: candidate.raw_version.clone(),
    });
    Ok(ComponentDiscovery {
        component: component_id.to_string(),
        decision: if selected.is_some() {
            DiscoveryDecision::UpdateAvailable
        } else {
            DiscoveryDecision::Current
        },
        selected,
        rejected,
    })
}

fn component_result(component: &str, decision: DiscoveryDecision) -> ComponentDiscovery {
    ComponentDiscovery {
        component: component.to_string(),
        decision,
        selected: None,
        rejected: Vec::new(),
    }
}

fn reject(candidate: &ObservationCandidate, reason: &str) -> CandidateRejection {
    CandidateRejection {
        raw_id: candidate.raw_id.clone(),
        reason: reason.to_string(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum VersionKey {
    Semver(Version),
    Numeric(Vec<u64>),
    Provider(String),
}

impl VersionKey {
    fn major(&self) -> Option<u64> {
        match self {
            Self::Semver(version) => Some(version.major),
            Self::Numeric(parts) => parts.first().copied(),
            Self::Provider(_) => None,
        }
    }

    fn is_prerelease(&self) -> bool {
        matches!(self, Self::Semver(version) if !version.pre.is_empty())
    }
}

impl Ord for VersionKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Semver(left), Self::Semver(right)) => left.cmp(right),
            (Self::Numeric(left), Self::Numeric(right)) => numeric_cmp(left, right),
            (Self::Provider(left), Self::Provider(right)) => left.cmp(right),
            _ => Ordering::Equal,
        }
    }
}

impl PartialOrd for VersionKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn version_key(scheme: VersionScheme, value: &str) -> Result<VersionKey> {
    match scheme {
        VersionScheme::Semver => Ok(VersionKey::Semver(
            Version::parse(value).map_err(|error| anyhow::anyhow!("invalid SemVer: {error}"))?,
        )),
        VersionScheme::Numeric => {
            let parts = value
                .split('.')
                .map(|part| {
                    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                        bail!("invalid numeric version")
                    }
                    part.parse::<u64>()
                        .map_err(|error| anyhow::anyhow!("invalid numeric version: {error}"))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(VersionKey::Numeric(parts))
        }
        VersionScheme::Provider => Ok(VersionKey::Provider(value.to_string())),
    }
}

fn numeric_cmp(left: &[u64], right: &[u64]) -> Ordering {
    let length = left.len().max(right.len());
    (0..length)
        .map(|index| {
            left.get(index)
                .copied()
                .unwrap_or(0)
                .cmp(&right.get(index).copied().unwrap_or(0))
        })
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        bail!("{label} is empty, oversized, or contains controls");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::identity::{ComponentId, FamilyId, MemberId, SourceSlotId, UnitId};
    use crate::inventory::{
        Classification, HashMode, Lifecycle, PackageProjection, ProjectionField, ReleasePolicy,
        ReleaseStrategy, RiskLevel, SourceFetcher, SourceSlot, UnitPolicy, UrlScheme, UrlSegment,
        UrlTemplate, VersionProjection,
    };

    use super::*;

    fn unit(minimum_age_days: u32) -> Result<UpdateUnit> {
        let component_id = ComponentId::parse("main")?;
        Ok(UpdateUnit {
            cohort: None,
            unit_id: UnitId::parse("zlib-1")?,
            family: FamilyId::parse("zlib")?,
            stream: "1".to_string(),
            classification: Classification::Automatic,
            package: Some(PackageProjection {
                current_version: "1.3.1".to_string(),
                version_projection: VersionProjection::ComponentField {
                    component: component_id.clone(),
                    field: ProjectionField::ComparisonVersion,
                },
            }),
            components: BTreeMap::from([(
                component_id,
                Component {
                    current: ComponentVersion {
                        upstream_id: "v1.3.1".to_string(),
                        comparison_version: "1.3.1".to_string(),
                    },
                    primary: Some(crate::inventory::DiscoveryProvider::GithubTags {
                        repository: "madler/zlib".to_string(),
                        tag_prefix: "v".to_string(),
                    }),
                    advisors: Vec::new(),
                    release_policy: ReleasePolicy {
                        strategy: ReleaseStrategy::LatestInSeries,
                        version_scheme: VersionScheme::Semver,
                        series_major: Some(1),
                        allow_prerelease: false,
                        minimum_age_days,
                    },
                    sources: BTreeMap::from([(
                        SourceSlotId::parse("source")?,
                        SourceSlot {
                            fetcher: SourceFetcher::Fetchurl,
                            derivation: "/nix/store/00000000000000000000000000000000-source.drv"
                                .to_string(),
                            url_templates: vec![UrlTemplate {
                                scheme: UrlScheme::Https,
                                authority: "zlib.net".to_string(),
                                path: vec![UrlSegment::Literal {
                                    value: "archive".to_string(),
                                }],
                            }],
                            hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                            hash_mode: HashMode::Flat,
                            allowed_redirect_hosts: vec!["zlib.net".to_string()],
                        },
                    )]),
                },
            )]),
            artifacts: BTreeMap::new(),
            owner: "pkgs/compression/zlib.nix".to_string(),
            members: vec![MemberId::parse("zlib")?],
            platforms: vec!["x86_64-linux".to_string()],
            policy: UnitPolicy {
                lifecycle: Lifecycle::Supported,
                risk_floor: RiskLevel::Normal,
                successor_unit: None,
            },
            reason: None,
            owner_unit: None,
            owner_member: None,
            review_after: None,
        })
    }

    fn candidate(id: &str, version: &str, first_observed: u64) -> ObservationCandidate {
        ObservationCandidate {
            raw_id: id.to_string(),
            raw_version: version.to_string(),
            published_at_unix: None,
            first_observed_at_unix: first_observed,
            prerelease: false,
            yanked: false,
            release_url: None,
        }
    }

    fn observation(candidates: Vec<ObservationCandidate>) -> UpstreamObservationV1 {
        UpstreamObservationV1 {
            schema: UPSTREAM_OBSERVATION_V1.to_string(),
            provider: "github-tags".to_string(),
            project: "madler/zlib".to_string(),
            retrieved_at_unix: 1_000_000,
            request_url: "https://api.github.com/repos/madler/zlib/tags".to_string(),
            adapter_version: "github-tags/v1".to_string(),
            coverage: ObservationCoverage::ThroughCurrent {
                identity: "v1.3.1".to_string(),
            },
            response_digest: Sha256Digest::of_bytes("fixture"),
            candidates,
        }
    }

    #[test]
    fn selects_latest_stable_candidate_inside_major_stream() -> Result<()> {
        let evidence = observation(vec![
            candidate("v1.3.1", "1.3.1", 1),
            candidate("v1.3.2", "1.3.2", 1),
            candidate("v2.0.0", "2.0.0", 1),
        ]);
        let selected = select_unit(
            &unit(0)?,
            &BTreeMap::from([("main".to_string(), evidence)]),
            1_000_100,
            3_600,
        )?;

        assert_eq!(selected.decision, DiscoveryDecision::UpdateAvailable);
        assert_eq!(
            selected.components[0]
                .selected
                .as_ref()
                .map(|version| version.upstream_id.as_str()),
            Some("v1.3.2")
        );
        assert!(
            selected.components[0]
                .rejected
                .iter()
                .any(|item| item.reason == "outside-maintained-stream")
        );
        Ok(())
    }

    #[test]
    fn stale_truncated_and_stabilizing_evidence_fail_closed() -> Result<()> {
        let mut truncated = observation(vec![candidate("v1.3.2", "1.3.2", 999_999)]);
        truncated.coverage = ObservationCoverage::Truncated {
            reason: "page-limit".to_string(),
        };
        let result = select_unit(
            &unit(3)?,
            &BTreeMap::from([("main".to_string(), truncated)]),
            1_000_100,
            3_600,
        )?;
        assert_eq!(result.decision, DiscoveryDecision::Unknown);

        let stabilizing = observation(vec![candidate("v1.3.2", "1.3.2", 999_999)]);
        let result = select_unit(
            &unit(3)?,
            &BTreeMap::from([("main".to_string(), stabilizing)]),
            1_000_100,
            3_600,
        )?;
        assert_eq!(result.decision, DiscoveryDecision::Current);
        assert_eq!(result.components[0].rejected[0].reason, "stabilizing");
        Ok(())
    }

    #[test]
    fn normalization_collisions_quarantine() -> Result<()> {
        let evidence = observation(vec![
            candidate("release-1.3.2", "1.3.2", 1),
            candidate("v1.3.2", "1.3.2", 1),
        ]);
        let result = select_unit(
            &unit(0)?,
            &BTreeMap::from([("main".to_string(), evidence)]),
            1_000_100,
            3_600,
        )?;

        assert_eq!(result.decision, DiscoveryDecision::Quarantined);
        Ok(())
    }

    #[test]
    fn observation_rejects_duplicates_and_future_first_seen() {
        let duplicate = observation(vec![
            candidate("v1.3.2", "1.3.2", 1),
            candidate("v1.3.2", "1.3.2", 1),
        ]);
        assert!(duplicate.validate().is_err());

        let future = observation(vec![candidate("v1.3.2", "1.3.2", 1_000_001)]);
        assert!(future.validate().is_err());
    }
}
