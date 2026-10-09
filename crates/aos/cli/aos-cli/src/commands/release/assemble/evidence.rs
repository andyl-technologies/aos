//! Build-phase qualification evidence derived from validated assembly inputs.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use aos_release_format::build::BuildReportV1;
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::evidence::{EvidenceRecord, GateResult};
use aos_release_format::manifest::ReleaseManifestV1;
use aos_release_format::plan::ReleasePlan;
use aos_release_format::qualification::{QualificationMethod, QualificationPhase};
use aos_release_format::qualification_evidence::{
    CheckObservation, QualificationCase, QualificationObservation,
};
use aos_release_format::registry::{RegistryTier, registry_policy};
use serde::Serialize;

use super::{ArtifactKind, PayloadBuilder};

const BUILD_INTEGRITY_REPORT_V1: &str = "aos.release.build-integrity-report/v1";

#[derive(Serialize)]
struct BuildIntegrityReportV1<'a> {
    schema_version: &'static str,
    case: &'a QualificationCase,
    build_report_digest: Sha256Digest,
    sbom_digest: Sha256Digest,
    advisory_disposition_digest: Sha256Digest,
    license_inventory_digest: Sha256Digest,
    contributor_authorization_digest: Sha256Digest,
    artifact_count: usize,
    checks: BTreeMap<String, String>,
    completed_at: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    report: &BuildReportV1,
    sbom: &[u8],
    advisory: &[u8],
    unresolved_advisories: usize,
    licenses: &[u8],
    authorization: &[u8],
    completed_at: &str,
    payload: &mut PayloadBuilder,
) -> Result<Vec<EvidenceRecord>> {
    let start = super::require_utc(&report.completed_at, "build completion time")?;
    let finish = super::require_utc(completed_at, "assembly completion time")?;
    if start > finish {
        bail!("assembly completed before its build report");
    }
    let cases = aos_release_format::qualification_evidence::cases(
        plan,
        manifest,
        None,
        QualificationPhase::Build,
    )?;
    let tier = registry_policy(&plan.registry)?.tier();
    let executor_digest = Sha256Digest::of_canonical(
        "aos.release.build-integrity-executor/v1",
        &(plan.source.commit.as_str(), BUILD_INTEGRITY_REPORT_V1),
    )?;
    let mut records = Vec::with_capacity(cases.len());
    for case in cases {
        if case.method != QualificationMethod::Automated || case.target.is_some() {
            bail!("build assembly cannot synthesize an operator or target qualification case");
        }
        let details = check_details(
            &case,
            report,
            tier,
            manifest.artifacts.len(),
            unresolved_advisories,
        )?;
        let report_value = BuildIntegrityReportV1 {
            schema_version: BUILD_INTEGRITY_REPORT_V1,
            case: &case,
            build_report_digest: Sha256Digest::of_bytes(canonical::to_vec(report)?),
            sbom_digest: Sha256Digest::of_bytes(sbom),
            advisory_disposition_digest: Sha256Digest::of_bytes(advisory),
            license_inventory_digest: Sha256Digest::of_bytes(licenses),
            contributor_authorization_digest: Sha256Digest::of_bytes(authorization),
            artifact_count: manifest.artifacts.len(),
            checks: details.clone(),
            completed_at,
        };
        let bytes = canonical::to_vec(&report_value)?;
        let report_digest = Sha256Digest::of_bytes(&bytes);
        let artifact_id = format!("evidence/qualification/{}", case.id);
        payload.write(
            &bytes,
            artifact_id,
            ArtifactKind::Evidence,
            format!("evidence/qualification/{}.json", case.id),
            "application/vnd.aos.release.build-integrity-report.v1+json",
        )?;

        let checks = details
            .into_iter()
            .map(|(name, detail)| {
                (
                    name,
                    CheckObservation {
                        passed: true,
                        detail,
                    },
                )
            })
            .collect();
        records.push(EvidenceRecord {
            qualification: Some(QualificationObservation {
                capabilities: None,
                environment: None,
                assessment: None,
                native_adapter_matrix: None,
                case_digest: case.digest()?,
                executor_digest,
                environment_digest: Sha256Digest::separated(
                    "aos.release.build-integrity-environment/v1",
                    report.plan_digest.to_string(),
                ),
                checks,
                observed_seconds: 0,
                operations: BTreeMap::new(),
                predecessor: case.predecessor.clone(),
            }),
            id: format!("qualification/{}", case.id),
            policy_id: case.requirement_id,
            policy_digest: case.policy_digest,
            platform: case.platform,
            subjects: case.subjects,
            result: GateResult::Passed,
            report_digest,
            authority_id: "aos-release-assembler".to_owned(),
            nonce: None,
            started_at: report.completed_at.clone(),
            finished_at: completed_at.to_owned(),
        });
    }
    records.sort_by(|left, right| left.id.cmp(&right.id));

    let mut candidate = manifest.clone();
    candidate
        .artifacts
        .extend(payload.artifacts.iter().cloned());
    candidate
        .artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    candidate.evidence = records.clone();
    aos_release_format::qualification_evidence::validate_observations(
        plan,
        &candidate,
        None,
        QualificationPhase::Build,
        &records,
        completed_at,
        None,
    )?;
    Ok(records)
}

fn check_details(
    case: &QualificationCase,
    report: &BuildReportV1,
    tier: RegistryTier,
    artifact_count: usize,
    unresolved_advisories: usize,
) -> Result<BTreeMap<String, String>> {
    case.checks
        .iter()
        .map(|check| {
            let detail = match check.as_str() {
                "source-and-contributor-authorization" => format!(
                    "The plan-bound contributor summary and {} retained source NARs were captured.",
                    report.sources.len()
                ),
                "hermetic-build" => format!(
                    "The validated Nix build report binds {} planned outputs to the frozen source commit.",
                    report.outputs.len()
                ),
                "repeat-build" => repeat_build_detail(report, tier)?,
                "complete-closure" => format!(
                    "Every signed narinfo reference resolved inside the {}-artifact closed payload.",
                    artifact_count
                ),
                "sbom-and-advisory-dispositions" => advisory_detail(tier, unresolved_advisories)?,
                "licenses-and-corresponding-source" => format!(
                    "Every planned output is linked to declared license inventory and corresponding source; {} source NARs are retained.",
                    report.sources.len()
                ),
                other => bail!("unsupported automated build-integrity check {other}"),
            };
            Ok((check.clone(), detail))
        })
        .collect::<Result<BTreeMap<_, _>>>()
        .context("deriving build-integrity check details")
}

/// Describes the advisory-disposition check under the registry tier's policy.
///
/// Like the repeat-build detail, a testing-tier release with unresolved
/// advisories states how many remain, so the passing observation never
/// claims a clean review it did not get.
fn advisory_detail(tier: RegistryTier, unresolved: usize) -> Result<String> {
    if unresolved == 0 {
        return Ok(
            "The exact SPDX inventory has a reviewed disposition with no unresolved advisories."
                .to_owned(),
        );
    }
    if !tier.accepts_unresolved_advisories() {
        bail!("the {tier} registry tier refuses unresolved advisories");
    }
    Ok(format!(
        "The exact SPDX inventory has a reviewed disposition; {unresolved} advisories remain \
         unresolved, which the {tier} registry tier accepts."
    ))
}

/// Describes the repeat-build check under the registry tier's policy.
///
/// The check passes only when the tier accepts every recorded result. A
/// testing-tier release with unreproduced outputs states how many were
/// recorded, so the passing observation never claims more than Nix proved.
fn repeat_build_detail(report: &BuildReportV1, tier: RegistryTier) -> Result<String> {
    report.require_reproducibility_policy(tier)?;

    let total = report.outputs.len();
    let not_checked = report.not_checked().count();
    if not_checked == total && total > 0 {
        return Ok(format!(
            "The {tier} registry tier does not run Nix --check repeat builds; \
             all {total} planned outputs are recorded as not checked."
        ));
    }
    if not_checked > 0 {
        bail!("build report mixes skipped and executed repeat builds");
    }

    let unreproduced = report.not_reproduced().collect::<Vec<_>>();
    if unreproduced.is_empty() {
        return Ok(format!(
            "All {total} planned outputs carry the reproduced result from Nix --check."
        ));
    }

    let derivations = unreproduced
        .iter()
        .map(|output| output.derivation.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    Ok(format!(
        "{} of {total} planned outputs carry the reproduced result from Nix --check; \
         {} outputs of {derivations} derivations are recorded as not reproduced, \
         which the {tier} registry tier accepts.",
        total - unreproduced.len(),
        unreproduced.len(),
    ))
}

#[cfg(test)]
mod tests {
    use aos_release::build::{BUILD_REPORT_V1, BuildOutputEvidence, ReproducibilityResult};
    use aos_release::platform::Platform;

    use super::*;

    fn output(id: &str, derivation: &str, result: ReproducibilityResult) -> BuildOutputEvidence {
        BuildOutputEvidence {
            id: id.to_owned(),
            package: "example".to_owned(),
            version: "1.0.0".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            source_store_paths: vec![],
            platform: Platform::X86_64Linux,
            derivation: derivation.to_owned(),
            output: "out".to_owned(),
            store_path: format!("/nix/store/{id}"),
            nar_hash: format!("sha256:{}", "a".repeat(64)),
            nar_size: 1,
            closure_size: 1,
            references: vec![],
            reproducibility: result,
        }
    }

    fn report(outputs: Vec<BuildOutputEvidence>) -> BuildReportV1 {
        BuildReportV1 {
            schema_version: BUILD_REPORT_V1.to_owned(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            source_commit: "0".repeat(40),
            outputs,
            sources: vec![],
            completed_at: "2026-10-04T00:00:00Z".to_owned(),
        }
    }

    fn partly_reproduced() -> BuildReportV1 {
        report(vec![
            output(
                "a-out",
                "/nix/store/a.drv",
                ReproducibilityResult::Reproduced,
            ),
            output(
                "b-dev",
                "/nix/store/b.drv",
                ReproducibilityResult::NotReproduced,
            ),
            output(
                "b-out",
                "/nix/store/b.drv",
                ReproducibilityResult::NotReproduced,
            ),
        ])
    }

    #[test]
    fn fully_reproduced_builds_keep_the_original_claim_on_every_tier() -> Result<()> {
        let reproduced = report(vec![output(
            "a-out",
            "/nix/store/a.drv",
            ReproducibilityResult::Reproduced,
        )]);

        for tier in [RegistryTier::Production, RegistryTier::Testing] {
            assert_eq!(
                repeat_build_detail(&reproduced, tier)?,
                "All 1 planned outputs carry the reproduced result from Nix --check."
            );
        }
        Ok(())
    }

    #[test]
    fn testing_tier_claim_states_the_recorded_unreproduced_outputs() -> Result<()> {
        let detail = repeat_build_detail(&partly_reproduced(), RegistryTier::Testing)?;

        assert_eq!(
            detail,
            "1 of 3 planned outputs carry the reproduced result from Nix --check; \
             2 outputs of 1 derivations are recorded as not reproduced, \
             which the testing registry tier accepts."
        );
        Ok(())
    }

    #[test]
    fn advisory_claim_without_unresolved_advisories_is_unchanged_on_every_tier() -> Result<()> {
        for tier in [RegistryTier::Testing, RegistryTier::Production] {
            assert_eq!(
                advisory_detail(tier, 0)?,
                "The exact SPDX inventory has a reviewed disposition with no unresolved advisories."
            );
        }
        Ok(())
    }

    #[test]
    fn testing_tier_advisory_claim_states_the_unresolved_count() -> Result<()> {
        let detail = advisory_detail(RegistryTier::Testing, 147)?;

        assert!(detail.contains("147 advisories remain unresolved"));
        assert!(detail.contains("testing registry tier accepts"));
        Ok(())
    }

    #[test]
    fn production_tier_cannot_claim_unresolved_advisories() {
        assert!(advisory_detail(RegistryTier::Production, 1).is_err());
    }

    #[test]
    fn testing_tier_claim_states_that_no_repeat_build_ran() -> Result<()> {
        let skipped = report(vec![
            output(
                "package/a/x86_64-linux",
                "/nix/store/a.drv",
                ReproducibilityResult::NotChecked,
            ),
            output(
                "package/b/x86_64-linux",
                "/nix/store/b.drv",
                ReproducibilityResult::NotChecked,
            ),
        ]);

        let detail = repeat_build_detail(&skipped, RegistryTier::Testing)?;
        assert!(detail.contains("does not run Nix --check repeat builds"));
        assert!(detail.contains("all 2 planned outputs are recorded as not checked"));
        assert!(repeat_build_detail(&skipped, RegistryTier::Production).is_err());
        Ok(())
    }

    #[test]
    fn production_tier_cannot_claim_a_partly_reproduced_build() {
        assert!(repeat_build_detail(&partly_reproduced(), RegistryTier::Production).is_err());
    }
}
