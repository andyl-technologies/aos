//! Public release evidence and target qualification results.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::manifest::ReleaseManifestV1;
use crate::plan::ReleasePlanV1;
use crate::platform::{MatrixCell, Platform};

/// Schema for a complete staging qualification report.
pub const QUALIFICATION_REPORT_V1: &str = "aos.release.qualification-report/v1";

/// Closed result of a release gate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateResult {
    /// The selected policy passed.
    Passed,
    /// The selected policy failed and blocks the relevant transition.
    Failed,
}

/// Public, non-sensitive result of one versioned release gate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    /// Stable evidence identity unique within the release.
    pub id: String,
    /// Versioned gate or qualification policy identifier.
    pub policy_id: String,
    /// Digest of the exact policy bytes.
    pub policy_digest: Sha256Digest,
    /// Platform qualified by this evidence, when target-specific.
    pub platform: Option<Platform>,
    /// Artifact identities covered by the result.
    pub subjects: Vec<String>,
    /// Closed gate result.
    pub result: GateResult,
    /// Digest of the public report file in the release bundle.
    pub report_digest: Sha256Digest,
    /// Public executor or authority identity.
    pub authority_id: String,
    /// Nonce binding remote qualification to the release request.
    pub nonce: Option<String>,
    /// RFC 3339 UTC start time supplied by the executor.
    pub started_at: String,
    /// RFC 3339 UTC finish time supplied by the executor.
    pub finished_at: String,
}

impl EvidenceRecord {
    /// Validates stable identifiers and nonempty subject/time fields.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers, an empty or duplicate
    /// subject set, an empty time, or an empty nonce when present.
    pub fn validate(&self) -> Result<()> {
        require_identifier(&self.id, "evidence id")?;
        require_identifier(&self.policy_id, "evidence policy id")?;
        require_identifier(&self.authority_id, "evidence authority id")?;
        if self.subjects.is_empty() {
            bail!("evidence {} must cover at least one subject", self.id);
        }
        for subject in &self.subjects {
            require_identifier(subject, "evidence subject")?;
        }
        let mut subjects = self.subjects.clone();
        subjects.sort();
        if subjects.windows(2).any(|pair| pair[0] == pair[1]) {
            bail!("evidence {} contains a duplicate subject", self.id);
        }
        if self.started_at.trim().is_empty() || self.finished_at.trim().is_empty() {
            bail!("evidence {} has an empty time", self.id);
        }
        if self.nonce.as_ref().is_some_and(|nonce| nonce.is_empty()) {
            bail!("evidence {} has an empty nonce", self.id);
        }
        Ok(())
    }
}

/// Complete gate and platform evidence over exact staged release bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReportV1 {
    /// Exact report schema identifier.
    pub schema_version: String,
    /// Digest of the signed staging publication receipt.
    pub staging_receipt_digest: Sha256Digest,
    /// Final release-manifest payload digest.
    pub manifest_digest: Sha256Digest,
    /// Public executor records in stable evidence-id order.
    pub evidence: Vec<EvidenceRecord>,
}

impl QualificationReportV1 {
    /// Validates full planned-gate coverage across every artifact platform.
    ///
    /// A target-independent record covers all platforms for its gate. When a
    /// gate emits target-specific records, it must cover every platform that
    /// has at least one package or image artifact in the final manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for identity drift, failed/duplicate/unknown evidence,
    /// missing artifact subjects, or incomplete gate/platform coverage.
    pub fn validate(
        &self,
        plan: &ReleasePlanV1,
        manifest: &ReleaseManifestV1,
        staging_receipt_digest: Sha256Digest,
        manifest_digest: Sha256Digest,
    ) -> Result<()> {
        if self.schema_version != QUALIFICATION_REPORT_V1
            || self.staging_receipt_digest != staging_receipt_digest
            || self.manifest_digest != manifest_digest
        {
            bail!("qualification report identity differs from staged release bytes");
        }
        if self.evidence.is_empty()
            || self
                .evidence
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            bail!("qualification evidence must be nonempty, unique, and sorted by id");
        }
        let artifact_ids = manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let mut required_platforms = std::collections::BTreeSet::new();
        for package in &manifest.packages {
            for cell in &package.platforms {
                if matches!(cell.decision, MatrixCell::Artifact { .. }) {
                    required_platforms.insert(cell.platform);
                }
            }
        }
        for image in &manifest.images {
            for cell in &image.platforms {
                if matches!(cell.decision, MatrixCell::Artifact { .. }) {
                    required_platforms.insert(cell.platform);
                }
            }
        }
        for record in &self.evidence {
            record.validate()?;
            if record.result != GateResult::Passed
                || record
                    .subjects
                    .iter()
                    .any(|subject| !artifact_ids.contains(subject.as_str()))
            {
                bail!(
                    "qualification evidence {} is failed or names an unknown artifact",
                    record.id
                );
            }
        }
        for gate in &plan.gates {
            let records = self
                .evidence
                .iter()
                .filter(|record| {
                    record.policy_id == gate.policy_id && record.policy_digest == gate.policy_digest
                })
                .collect::<Vec<_>>();
            if records.is_empty() {
                bail!("qualification report lacks planned gate {}", gate.policy_id);
            }
            if !records.iter().any(|record| record.platform.is_none()) {
                let covered = records
                    .iter()
                    .filter_map(|record| record.platform)
                    .collect::<std::collections::BTreeSet<_>>();
                if covered != required_platforms {
                    bail!(
                        "qualification gate {} lacks full platform coverage",
                        gate.policy_id
                    );
                }
            }
        }
        if self.evidence.iter().any(|record| {
            !plan.gates.iter().any(|gate| {
                gate.policy_id == record.policy_id && gate.policy_digest == record.policy_digest
            })
        }) {
            bail!("qualification report contains evidence outside the release plan");
        }
        Ok(())
    }
}

/// Frozen requirement for one versioned gate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateRequirement {
    /// Stable gate identifier.
    pub policy_id: String,
    /// Digest of exact gate policy bytes.
    pub policy_digest: Sha256Digest,
    /// Whether this gate is required before stable authorization.
    pub required_for_stable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{ArtifactKind, ArtifactRecord, BundlePath, Compression};
    use crate::manifest::{FinalArtifactSet, PackageResult};
    use crate::plan::{
        PackagePlan, PlannedArtifactSet, PlatformCell, ReleaseClass, RetentionPolicy,
        SourceIdentity,
    };
    use crate::platform::Platform;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(label.as_bytes())
    }

    fn artifact_id(platform: Platform) -> String {
        format!("package/example/{platform}")
    }

    fn fixture() -> (ReleasePlanV1, ReleaseManifestV1, Sha256Digest, Sha256Digest) {
        let platforms = Platform::ALL
            .into_iter()
            .map(|platform| PlatformCell {
                platform,
                decision: MatrixCell::Artifact {
                    artifact: PlannedArtifactSet {
                        artifacts: Vec::new(),
                    },
                },
            })
            .collect::<Vec<_>>();
        let gate_digest = digest("gate");
        let plan = ReleasePlanV1 {
            schema_version: crate::RELEASE_PLAN_V1.to_owned(),
            release_id: "release-2026.9.0".to_owned(),
            version: "2026.9.0".to_owned(),
            release_class: ReleaseClass::Stable,
            registry: crate::CANONICAL_REGISTRY.to_owned(),
            registry_base_commit: "0123456789012345678901234567890123456789".to_owned(),
            registry_base_generation: 1,
            source: SourceIdentity {
                commit: "0123456789012345678901234567890123456789".to_owned(),
                tree_digest: digest("tree"),
                protected_branch: "main".to_owned(),
                source_tag: "release/2026.9.0".to_owned(),
                contributor_authorization_digest: digest("authorization"),
            },
            packages: vec![PackagePlan {
                name: "example".to_owned(),
                publication: None,
                platforms: platforms.clone(),
            }],
            images: Vec::new(),
            gates: vec![GateRequirement {
                policy_id: "package-install-v1".to_owned(),
                policy_digest: gate_digest,
                required_for_stable: true,
            }],
            staging_deployment_id: "staging-v1".to_owned(),
            production_deployment_id: "production-v1".to_owned(),
            signers: Vec::new(),
            intended_channels: Vec::new(),
            retention: RetentionPolicy {
                policy_id: "retention-v1".to_owned(),
                policy_digest: digest("retention"),
                require_corresponding_source: true,
            },
            public_evidence_policy_digest: digest("public-evidence"),
            restricted_operator_policy_digest: digest("operator"),
        };
        let artifacts = Platform::ALL
            .into_iter()
            .map(|platform| ArtifactRecord {
                id: artifact_id(platform),
                kind: ArtifactKind::PackageNar,
                platform: Some(platform),
                system_variant: None,
                path: BundlePath::parse(format!("packages/{platform}.nar")).unwrap(),
                size_bytes: 1,
                sha256: digest(platform.as_str()),
                media_type: "application/x-nix-nar".to_owned(),
                compression: Compression::None,
                derivation: None,
                output: None,
                store_path: None,
                nar_hash: None,
                relationships: Vec::new(),
            })
            .collect();
        let manifest = ReleaseManifestV1 {
            schema_version: crate::RELEASE_MANIFEST_V1.to_owned(),
            release_id: plan.release_id.clone(),
            version: plan.version.clone(),
            release_class: plan.release_class,
            registry: plan.registry.clone(),
            plan_digest: digest("plan"),
            source_commit: plan.source.commit.clone(),
            packages: vec![PackageResult {
                name: "example".to_owned(),
                platforms: platforms
                    .into_iter()
                    .map(|cell| PlatformCell {
                        platform: cell.platform,
                        decision: MatrixCell::Artifact {
                            artifact: FinalArtifactSet {
                                artifact_ids: vec![artifact_id(cell.platform)],
                            },
                        },
                    })
                    .collect(),
            }],
            images: Vec::new(),
            artifacts,
            evidence: Vec::new(),
        };
        (plan, manifest, digest("staging"), digest("manifest"))
    }

    fn record(platform: Option<Platform>, policy_digest: Sha256Digest) -> EvidenceRecord {
        let suffix = platform.map_or("all", Platform::as_str);
        EvidenceRecord {
            id: format!("package-install-{suffix}"),
            policy_id: "package-install-v1".to_owned(),
            policy_digest,
            platform,
            subjects: platform.map_or_else(
                || Platform::ALL.into_iter().map(artifact_id).collect(),
                |value| vec![artifact_id(value)],
            ),
            result: GateResult::Passed,
            report_digest: digest(suffix),
            authority_id: "qualification-executor".to_owned(),
            nonce: Some(format!("nonce-{suffix}")),
            started_at: "2026-09-03T00:00:00Z".to_owned(),
            finished_at: "2026-09-03T00:01:00Z".to_owned(),
        }
    }

    #[test]
    fn qualification_requires_all_artifact_platforms() {
        let (plan, manifest, staging, manifest_digest) = fixture();
        let gate_digest = plan.gates[0].policy_digest;
        let mut evidence = Platform::ALL
            .into_iter()
            .map(|platform| record(Some(platform), gate_digest))
            .collect::<Vec<_>>();
        evidence.sort_by(|left, right| left.id.cmp(&right.id));
        let report = QualificationReportV1 {
            schema_version: QUALIFICATION_REPORT_V1.to_owned(),
            staging_receipt_digest: staging,
            manifest_digest,
            evidence,
        };

        assert!(
            report
                .validate(&plan, &manifest, staging, manifest_digest)
                .is_ok()
        );
        let mut incomplete = report.clone();
        incomplete
            .evidence
            .retain(|value| value.platform != Some(Platform::Aarch64Darwin));
        assert!(
            incomplete
                .validate(&plan, &manifest, staging, manifest_digest)
                .is_err()
        );
    }

    #[test]
    fn target_independent_evidence_covers_the_matrix() {
        let (plan, manifest, staging, manifest_digest) = fixture();
        let report = QualificationReportV1 {
            schema_version: QUALIFICATION_REPORT_V1.to_owned(),
            staging_receipt_digest: staging,
            manifest_digest,
            evidence: vec![record(None, plan.gates[0].policy_digest)],
        };

        assert!(
            report
                .validate(&plan, &manifest, staging, manifest_digest)
                .is_ok()
        );
    }

    #[test]
    fn qualification_rejects_unknown_gate_and_subject() {
        let (plan, manifest, staging, manifest_digest) = fixture();
        let mut unknown_gate = record(None, digest("different-gate"));
        unknown_gate.policy_id = "different-gate-v1".to_owned();
        let report = QualificationReportV1 {
            schema_version: QUALIFICATION_REPORT_V1.to_owned(),
            staging_receipt_digest: staging,
            manifest_digest,
            evidence: vec![unknown_gate],
        };
        assert!(
            report
                .validate(&plan, &manifest, staging, manifest_digest)
                .is_err()
        );

        let mut unknown_subject = record(None, plan.gates[0].policy_digest);
        unknown_subject.subjects = vec!["package/not-in-manifest".to_owned()];
        let report = QualificationReportV1 {
            schema_version: QUALIFICATION_REPORT_V1.to_owned(),
            staging_receipt_digest: staging,
            manifest_digest,
            evidence: vec![unknown_subject],
        };
        assert!(
            report
                .validate(&plan, &manifest, staging, manifest_digest)
                .is_err()
        );
    }
}
