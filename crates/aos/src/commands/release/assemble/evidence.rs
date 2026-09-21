//! Build-phase qualification evidence derived from validated assembly inputs.

use std::collections::BTreeMap;

use anyhow::{bail, Context as _, Result};
use aos_release::build::BuildReportV1;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::evidence::{EvidenceRecord, GateResult};
use aos_release::manifest::ReleaseManifestV1;
use aos_release::plan::ReleasePlanV1;
use aos_release::qualification::{QualificationMethod, QualificationPhase};
use aos_release::qualification_evidence::{
    CheckObservation, QualificationCase, QualificationObservation,
};
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
    plan: &ReleasePlanV1,
    manifest: &ReleaseManifestV1,
    report: &BuildReportV1,
    sbom: &[u8],
    advisory: &[u8],
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
    let cases =
        aos_release::qualification_evidence::cases(plan, manifest, QualificationPhase::Build)?;
    let executor_digest = Sha256Digest::of_canonical(
        "aos.release.build-integrity-executor/v1",
        &(plan.source.commit.as_str(), BUILD_INTEGRITY_REPORT_V1),
    )?;
    let mut records = Vec::with_capacity(cases.len());
    for case in cases {
        if case.method != QualificationMethod::Automated || case.target.is_some() {
            bail!("build assembly cannot synthesize an operator or target qualification case");
        }
        let details = check_details(&case, report, manifest.artifacts.len())?;
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
    aos_release::qualification_evidence::validate_observations(
        plan,
        &candidate,
        QualificationPhase::Build,
        &records,
        completed_at,
    )?;
    Ok(records)
}

fn check_details(
    case: &QualificationCase,
    report: &BuildReportV1,
    artifact_count: usize,
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
                "repeat-build" => format!(
                    "All {} planned outputs carry the reproduced result from Nix --check.",
                    report.outputs.len()
                ),
                "complete-closure" => format!(
                    "Every signed narinfo reference resolved inside the {}-artifact closed payload.",
                    artifact_count
                ),
                "sbom-and-advisory-dispositions" => {
                    "The exact SPDX inventory has a reviewed disposition with no unresolved advisories."
                        .to_owned()
                }
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
