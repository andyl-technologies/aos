//! Clock-explicit freshness projection for immutable profile results.
//!
//! A result remains immutable as time passes. This projection bounds its useful
//! lifetime by both the pinned decision policy and retained observation expiry.
//! Missing or partial coverage never becomes fresh merely because a scan ran.

use anyhow::{Context as _, Result, bail};
use aos_assessment::input::{EvaluationData, Profile, ScanInputV1};
use aos_assessment::inventory::{Classification, ReleaseStrategy};
use aos_assessment::result::ProfileCoverage;
use aos_assessment::security::CoverageState;
use aos_assessment::time::Timestamp;

/// Computes a conservative exclusive freshness deadline for a complete profile.
///
/// Incomplete coverage has no freshness deadline for a clean/current conclusion.
/// All supplied profile observations constrain the deadline, so unrelated old
/// evidence may shorten freshness but can never extend it. The function does
/// not grant custody, source or publication authority. Update results also expire
/// at an earlier retained candidate stabilization boundary, so a current decision
/// cannot remain effectively fresh after its eligibility policy changes with time.
///
/// # Errors
/// Returns an error for an unrequested profile, invalid policy, timestamp
/// overflow or unavailable pinned advisory snapshot.
pub fn profile_freshness_deadline(
    input: &ScanInputV1,
    data: &EvaluationData,
    coverage: &ProfileCoverage,
) -> Result<Option<Timestamp>> {
    input.validate()?;
    data.policy.validate()?;
    let profile = coverage.profile;
    if !input.profiles.contains(&profile) || data.policy.digest()? != input.policy_digest {
        bail!("freshness projection differs from the frozen profile or policy");
    }
    if coverage.state != CoverageState::Complete {
        return Ok(None);
    }
    if !coverage.reasons.is_empty() || coverage.counts.evaluated != coverage.counts.declared {
        bail!("complete freshness coverage has unresolved limitations");
    }
    let age = match profile {
        Profile::Updates => data.policy.upstream_max_age_seconds,
        Profile::Vulnerabilities => data.policy.advisory_max_age_seconds,
        Profile::LicenseSignals => {
            bail!("license signal freshness requires admitted license observations")
        }
    };
    let mut deadline = input
        .evaluated_at
        .unix_seconds()
        .checked_add(age)
        .ok_or_else(|| anyhow::anyhow!("profile freshness timestamp overflows"))?;
    match profile {
        Profile::Updates => {
            let definitions = data
                .definitions
                .iter()
                .map(|definition| Ok((definition.digest()?, definition)))
                .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
            let components = data
                .inventory
                .components
                .iter()
                .map(|component| (component.component_ref.as_str(), component))
                .collect::<std::collections::BTreeMap<_, _>>();
            for binding in &data.upstream {
                deadline =
                    deadline.min(binding.validated_at_unix().checked_add(age).ok_or_else(
                        || anyhow::anyhow!("upstream freshness timestamp overflows"),
                    )?);
                if let Some(expires) = binding.expires_at_unix() {
                    deadline = deadline.min(expires);
                }
                let component = components
                    .get(binding.component_ref.as_str())
                    .context("stabilization binding lacks its admitted component")?;
                let definition = definitions
                    .get(&component.scan_definition_digest)
                    .context("stabilization component lacks its admitted definition")?;
                if matches!(
                    definition.classification,
                    Classification::Manual | Classification::Frozen
                ) {
                    continue;
                }
                let declared = definition
                    .components
                    .iter()
                    .find(|declared| declared.component_id == component.component_id)
                    .context("stabilization component is absent from its definition")?;
                if declared.release_policy.strategy == ReleaseStrategy::LatestInSeries
                    && let Some(eligible_at) =
                        aos_assessment::discovery::next_stabilization_deadline(
                            &declared.release_policy,
                            &component.current,
                            &binding.observation,
                            binding.validated_at_unix(),
                            input.evaluated_at.unix_seconds(),
                            age,
                        )?
                {
                    deadline = deadline.min(eligible_at);
                }
            }
        }
        Profile::Vulnerabilities => {
            let snapshot = data.advisory_snapshot.as_ref().ok_or_else(|| {
                anyhow::anyhow!("vulnerability freshness lacks its pinned snapshot")
            })?;
            for source in &snapshot.sources {
                deadline = deadline.min(source.observation.expires_at.unix_seconds());
                deadline = deadline.min(
                    source
                        .observation
                        .validated_at
                        .unix_seconds()
                        .checked_add(age)
                        .ok_or_else(|| anyhow::anyhow!("advisory freshness timestamp overflows"))?,
                );
            }
        }
        Profile::LicenseSignals => {
            bail!("license signal freshness requires admitted license observations")
        }
    }
    Ok(Some(Timestamp::from_unix_seconds(deadline)?))
}
