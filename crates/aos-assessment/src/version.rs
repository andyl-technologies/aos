//! Portable version reporting through the existing shared maintenance selector.

use std::cmp::Ordering;

use anyhow::Result;
use aos_contract::Sha256Digest;

use crate::definition::PackageScanDefinitionV1;
use crate::discovery::{
    ObservationCoverage, select_component_validated_policy, version_is_newer_in_stream,
};
use crate::evaluator::declaration;
use crate::input::{EvaluationData, ScanInputV1, UpstreamBinding};
use crate::inventory::{Classification, ComponentVersion, ReleaseStrategy, VersionScheme};
use crate::ranges::compare_versions;
use crate::result::{VersionDecision, VersionResult};
use crate::scan_inventory::ComponentInstance;
use crate::security::AdvisoryVersionScheme;

pub(crate) fn evaluate(
    component: &ComponentInstance,
    definition: &PackageScanDefinitionV1,
    input: &ScanInputV1,
    data: &EvaluationData,
    upstream: Option<&UpstreamBinding>,
) -> Result<(VersionResult, Vec<String>)> {
    let declared = declaration(component, definition)?;
    let mut result = VersionResult {
        component_ref: component.component_ref.clone(),
        current: component.current.clone(),
        decision: VersionDecision::Unknown,
        latest_known: None,
        latest_known_provisional: true,
        eligible: None,
        observation_digests: vec![],
        rejected: vec![],
    };
    let mut reasons = Vec::new();
    if let Some(binding) = upstream {
        let observation = &binding.observation;
        result.observation_digests.push(Sha256Digest::of_canonical(
            crate::UPSTREAM_OBSERVATION_V1,
            observation,
        )?);
        result.latest_known_provisional = !match &observation.coverage {
            ObservationCoverage::Complete => true,
            ObservationCoverage::ThroughCurrent { identity } => {
                identity == &component.current.upstream_id
            }
            ObservationCoverage::Truncated { .. } => false,
        };
        let comparator = match declared.release_policy.version_scheme {
            VersionScheme::Semver => AdvisoryVersionScheme::Semver,
            VersionScheme::Numeric => AdvisoryVersionScheme::DottedNumeric,
            VersionScheme::Provider => AdvisoryVersionScheme::Unsupported,
        };
        for candidate in &observation.candidates {
            let greatest = match &result.latest_known {
                None => matches!(
                    compare_versions(comparator, &candidate.raw_version, &candidate.raw_version),
                    Ok(Some(_))
                ),
                Some(previous) => matches!(
                    compare_versions(
                        comparator,
                        &candidate.raw_version,
                        &previous.comparison_version
                    ),
                    Ok(Some(Ordering::Greater))
                ),
            };
            if greatest {
                result.latest_known = Some(ComponentVersion {
                    upstream_id: candidate.raw_id.clone(),
                    comparison_version: candidate.raw_version.clone(),
                });
            }
        }
        if declared.release_policy.version_scheme == VersionScheme::Provider
            || declared.release_policy.strategy != ReleaseStrategy::LatestInSeries
        {
            reasons.push("version-unsupported".into());
        } else {
            match select_component_validated_policy(
                component.component_id.as_str(),
                &component.current,
                &declared.release_policy,
                observation,
                binding.validated_at_unix(),
                input.evaluated_at.unix_seconds(),
                data.policy.upstream_max_age_seconds,
            ) {
                Ok(selected) => {
                    result.decision = selected.decision.into();
                    result.eligible = selected.selected;
                    result.rejected = selected.rejected;
                    if result.decision == VersionDecision::Current
                        && result
                            .rejected
                            .iter()
                            .filter(|rejected| rejected.reason == "stabilizing")
                            .any(|rejected| {
                                observation
                                    .candidates
                                    .iter()
                                    .find(|candidate| candidate.raw_id == rejected.raw_id)
                                    .is_some_and(|candidate| {
                                        version_is_newer_in_stream(
                                            &declared.release_policy,
                                            &component.current.comparison_version,
                                            &candidate.raw_version,
                                        )
                                        .unwrap_or(false)
                                    })
                            })
                    {
                        result.decision = VersionDecision::Stabilizing;
                    }
                }
                Err(_) => reasons.push("version-unsupported".into()),
            }
        }
        if input
            .evaluated_at
            .unix_seconds()
            .saturating_sub(binding.validated_at_unix())
            > data.policy.upstream_max_age_seconds
            || (!binding.page_observations.is_empty()
                && input
                    .evaluated_at
                    .unix_seconds()
                    .saturating_sub(binding.validated_at_unix())
                    == data.policy.upstream_max_age_seconds)
            || binding
                .expires_at_unix()
                .is_some_and(|expires| input.evaluated_at.unix_seconds() >= expires)
        {
            result.decision = VersionDecision::Unknown;
            result.eligible = None;
            reasons.push("snapshot-stale".into());
        }
        if result.latest_known_provisional {
            reasons.push("coverage-truncated".into());
        }
        if result.decision == VersionDecision::Quarantined {
            reasons.push("identity-quarantined".into());
        }
    } else {
        reasons.push("provider-unavailable".into());
    }
    match definition.classification {
        Classification::Manual => {
            result.decision = VersionDecision::Manual;
            result.eligible = None;
        }
        Classification::Frozen => {
            result.decision = VersionDecision::Frozen;
            result.eligible = None;
        }
        _ => {}
    }
    reasons.sort();
    reasons.dedup();
    Ok((result, reasons))
}
