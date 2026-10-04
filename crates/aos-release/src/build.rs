//! Exact Nix realization and repeat-build evidence.
//!
//! The build report binds every planned Nix output to the observed NAR
//! identity, closure size, references, and the result of a Nix `--check`
//! repeat build of its derivation.
//!
//! Production-tier registries require every output to be reproduced. The
//! testing tier records outputs whose repeat build did not prove a
//! byte-identical result as [`ReproducibilityResult::NotReproduced`] and lets
//! the release proceed, so nondeterministic packages can be fixed without
//! blocking the experimental pipeline.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;
use crate::plan::ReleasePlan;
use crate::platform::Platform;
use crate::registry::{RegistryTier, registry_policy};

/// Schema identifier for a complete build report.
pub const BUILD_REPORT_V1: &str = "aos.release.build-report/v1";

/// Result of rebuilding an already realized derivation with Nix `--check`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReproducibilityResult {
    /// Nix proved the repeat output byte-identical.
    Reproduced,
    /// The derivation's Nix `--check` repeat build did not prove a
    /// byte-identical output: the repeat output differed, or the repeat
    /// build itself failed.
    ///
    /// Only registry tiers whose policy accepts unreproduced outputs (see
    /// [`RegistryTier::accepts_not_reproduced_outputs`]) may carry it.
    NotReproduced,
}

/// Observed identity and closure facts for one planned output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildOutputEvidence {
    /// Planned logical artifact id.
    pub id: String,
    /// Canonical package name from the plan.
    pub package: String,
    /// Public package version from Nix distribution metadata.
    pub version: String,
    /// SPDX-compatible declared license expression.
    pub license_expression: String,
    /// Exact source and dependency-source store roots needed to rebuild it.
    pub source_store_paths: Vec<String>,
    /// Planned target platform.
    pub platform: Platform,
    /// Exact planned derivation path.
    pub derivation: String,
    /// Exact planned named output.
    pub output: String,
    /// Exact planned and realized output path.
    pub store_path: String,
    /// Nix NAR hash reported for the output.
    pub nar_hash: String,
    /// NAR byte size reported by Nix.
    pub nar_size: u64,
    /// Recursive closure size reported by Nix.
    pub closure_size: u64,
    /// Direct store references, sorted bytewise.
    pub references: Vec<String>,
    /// Repeat-build result for the owning derivation.
    pub reproducibility: ReproducibilityResult,
}

/// Exact Nix identity of one retained upstream source input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSourceEvidence {
    /// Exact source store path.
    pub store_path: String,
    /// Nix NAR hash reported for the source.
    pub nar_hash: String,
    /// Exact NAR byte size.
    pub nar_size: u64,
}

/// Closed report produced by `aos maintain release step build`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildReportV1 {
    /// Exact build-report schema.
    pub schema_version: String,
    /// Digest of the exact canonical release plan.
    pub plan_digest: Sha256Digest,
    /// Source commit inherited from the plan.
    pub source_commit: String,
    /// Every planned Nix output in stable artifact-id order.
    pub outputs: Vec<BuildOutputEvidence>,
    /// Every distinct retained upstream source in store-path order.
    pub sources: Vec<BuildSourceEvidence>,
    /// RFC 3339 UTC completion time supplied by the coordinator.
    pub completed_at: String,
}

impl BuildReportV1 {
    /// Validates the report as an exact realization of the plan.
    ///
    /// # Errors
    ///
    /// Returns an error for identity drift, missing, extra, reordered, or
    /// duplicate outputs, a planned Nix identity mismatch, malformed NAR
    /// facts, unsorted references, an empty completion time, an unsupported
    /// plan registry, or an unreproduced output that the plan's registry
    /// tier does not accept.
    pub fn validate(&self, plan: &ReleasePlan, plan_digest: Sha256Digest) -> Result<()> {
        if self.schema_version != BUILD_REPORT_V1
            || self.plan_digest != plan_digest
            || self.source_commit != plan.source.commit
            || self.completed_at.trim().is_empty()
        {
            bail!("build report identity differs from its release plan");
        }

        let expected = planned_nix_outputs(plan)?;
        if self.outputs.len() != expected.len()
            || self.outputs.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            bail!("build report outputs must exactly match and sort the plan");
        }
        for output in &self.outputs {
            let Some(planned) = expected.get(output.id.as_str()) else {
                bail!("build report contains unplanned output {}", output.id);
            };
            if output.platform != planned.platform
                || output.package != planned.package
                || output.version != planned.version
                || output.license_expression != planned.license_expression
                || output.source_store_paths != planned.source_store_paths
                || output.derivation != planned.derivation
                || output.output != planned.output
                || output.store_path != planned.store_path
            {
                bail!(
                    "build output {} differs from its planned Nix identity",
                    output.id
                );
            }
            if !(output.nar_hash.starts_with("sha256:") || output.nar_hash.starts_with("sha256-"))
                || output.nar_hash.len() <= 7
                || output.nar_size == 0
                || output.closure_size < output.nar_size
                || output.references.windows(2).any(|pair| pair[0] >= pair[1])
                || output
                    .references
                    .iter()
                    .any(|reference| !reference.starts_with("/nix/store/"))
            {
                bail!(
                    "build output {} has invalid Nix closure evidence",
                    output.id
                );
            }
        }
        let expected_sources = expected
            .values()
            .flat_map(|output| output.source_store_paths)
            .collect::<BTreeSet<_>>();
        if self.sources.len() != expected_sources.len()
            || self
                .sources
                .windows(2)
                .any(|pair| pair[0].store_path >= pair[1].store_path)
        {
            bail!("build report sources must exactly match and sort the plan");
        }
        for (source, expected_path) in self.sources.iter().zip(expected_sources) {
            if source.store_path != *expected_path
                || !(source.nar_hash.starts_with("sha256:")
                    || source.nar_hash.starts_with("sha256-"))
                || source.nar_size == 0
            {
                bail!("build report contains invalid source evidence");
            }
        }

        // Every reader validates against the plan, so a production report
        // with an unreproduced output is rejected wherever it is consumed.
        let tier = registry_policy(&plan.registry)?.tier();
        self.require_reproducibility_policy(tier)
    }

    /// Returns every output whose repeat build did not reproduce it.
    pub fn not_reproduced(&self) -> impl Iterator<Item = &BuildOutputEvidence> {
        self.outputs
            .iter()
            .filter(|output| output.reproducibility == ReproducibilityResult::NotReproduced)
    }

    /// Requires the recorded repeat-build results to satisfy a registry tier.
    ///
    /// A tier that does not accept unreproduced outputs fails closed on any
    /// output other than [`ReproducibilityResult::Reproduced`].
    ///
    /// # Errors
    ///
    /// Returns an error naming every unreproduced output when `tier` does not
    /// accept them.
    pub fn require_reproducibility_policy(&self, tier: RegistryTier) -> Result<()> {
        if tier.accepts_not_reproduced_outputs() {
            return Ok(());
        }

        let rejected = self
            .outputs
            .iter()
            .filter(|output| output.reproducibility != ReproducibilityResult::Reproduced)
            .map(|output| output.id.as_str())
            .collect::<Vec<_>>();
        if !rejected.is_empty() {
            bail!(
                "build report contains {} outputs without a successful repeat build, \
                 which the {tier} registry tier does not accept: {}",
                rejected.len(),
                rejected.join(", ")
            );
        }
        Ok(())
    }
}

/// Borrowed exact Nix output selected by a release plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedNixOutput<'a> {
    /// Canonical package name.
    pub package: &'a str,
    /// Public package version.
    pub version: &'a str,
    /// SPDX-compatible declared license expression.
    pub license_expression: &'a str,
    /// Exact source and dependency-source store roots.
    pub source_store_paths: &'a [String],
    /// Planned target platform.
    pub platform: Platform,
    /// Exact derivation path.
    pub derivation: &'a str,
    /// Exact named output.
    pub output: &'a str,
    /// Exact evaluated output store path.
    pub store_path: &'a str,
}

/// Returns every exact Nix output in stable artifact-id order.
///
/// # Errors
///
/// Returns an error when the plan repeats an artifact id or contains no Nix
/// outputs.
pub fn planned_nix_outputs(plan: &ReleasePlan) -> Result<BTreeMap<&str, PlannedNixOutput<'_>>> {
    let mut expected = BTreeMap::new();
    for package in &plan.packages {
        let Some(publication) = package.publication.as_ref() else {
            continue;
        };
        for cell in &package.platforms {
            let crate::platform::MatrixCell::Artifact { artifact } = &cell.decision else {
                continue;
            };
            let version = package
                .version_for(cell.platform)
                .context("planned output lacks its target package version")?;
            for planned in &artifact.artifacts {
                let (Some(derivation), Some(output), Some(store_path)) = (
                    planned.derivation.as_deref(),
                    planned.output.as_deref(),
                    planned.store_path.as_deref(),
                ) else {
                    continue;
                };
                if expected
                    .insert(
                        planned.id.as_str(),
                        PlannedNixOutput {
                            package: &package.name,
                            version,
                            license_expression: &publication.license_expression,
                            source_store_paths: &planned.source_store_paths,
                            platform: cell.platform,
                            derivation,
                            output,
                            store_path,
                        },
                    )
                    .is_some()
                {
                    bail!("release plan repeats a Nix artifact id");
                }
            }
        }
    }
    let unique_derivations = expected
        .values()
        .map(|output| output.derivation)
        .collect::<BTreeSet<_>>();
    if unique_derivations.is_empty() {
        bail!("release plan has no Nix outputs to build");
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::MatrixCell;
    use crate::registry::{EXPERIMENTAL_REGISTRY, MAIN_REGISTRY};

    fn evidence(id: &str, reproducibility: ReproducibilityResult) -> BuildOutputEvidence {
        BuildOutputEvidence {
            id: id.to_owned(),
            package: "example".to_owned(),
            version: "1.0.0".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            source_store_paths: vec![],
            platform: Platform::X86_64Linux,
            derivation: "/nix/store/22222222222222222222222222222222-example.drv".to_owned(),
            output: "out".to_owned(),
            store_path: "/nix/store/11111111111111111111111111111111-example".to_owned(),
            nar_hash: format!("sha256:{}", "a".repeat(64)),
            nar_size: 1,
            closure_size: 1,
            references: vec![],
            reproducibility,
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

    /// Returns the release fixture plan with one exact planned Nix output and
    /// a build report that realizes it with `reproducibility`.
    fn planned_report(
        registry: &str,
        reproducibility: ReproducibilityResult,
    ) -> Result<(ReleasePlan, BuildReportV1)> {
        let (mut plan, _) = crate::verify::tests::qualification_fixture()?;
        plan.registry = registry.to_owned();

        let cell = plan.packages[0]
            .platforms
            .iter_mut()
            .find(|cell| cell.platform == Platform::X86_64Linux)
            .context("fixture lacks an x86_64 Linux package cell")?;
        let MatrixCell::Artifact { artifact } = &mut cell.decision else {
            bail!("fixture requires a published x86_64 Linux package");
        };
        artifact.artifacts[0].derivation =
            Some("/nix/store/22222222222222222222222222222222-example.drv".into());
        artifact.artifacts[0].output = Some("out".into());
        artifact.artifacts[0].store_path =
            Some("/nix/store/11111111111111111111111111111111-example".into());

        let outputs = planned_nix_outputs(&plan)?
            .into_iter()
            .map(|(id, planned)| BuildOutputEvidence {
                package: planned.package.to_owned(),
                platform: planned.platform,
                version: planned.version.to_owned(),
                license_expression: planned.license_expression.to_owned(),
                ..evidence(id, reproducibility)
            })
            .collect();
        let mut report = report(outputs);
        report.source_commit = plan.source.commit.clone();
        Ok((plan, report))
    }

    #[test]
    fn not_reproduced_round_trips_with_its_kebab_case_spelling() -> Result<()> {
        let encoded = serde_json::to_string(&ReproducibilityResult::NotReproduced)?;
        assert_eq!(encoded, "\"not-reproduced\"");

        let decoded: ReproducibilityResult = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, ReproducibilityResult::NotReproduced);

        let output = evidence("package/example/x86_64-linux", decoded);
        let bytes = crate::canonical::to_vec(&output)?;
        let parsed: BuildOutputEvidence = crate::canonical::from_slice(&bytes, "test output")?;
        assert_eq!(parsed, output);
        Ok(())
    }

    #[test]
    fn production_tier_rejects_every_not_reproduced_output() {
        let report = report(vec![
            evidence("package/a/x86_64-linux", ReproducibilityResult::Reproduced),
            evidence(
                "package/b/x86_64-linux",
                ReproducibilityResult::NotReproduced,
            ),
        ]);

        let error = report
            .require_reproducibility_policy(RegistryTier::Production)
            .expect_err("production must fail closed");

        let message = error.to_string();
        assert!(message.contains("production registry tier"));
        assert!(message.contains("package/b/x86_64-linux"));
        assert!(!message.contains("package/a/x86_64-linux"));
    }

    #[test]
    fn testing_tier_records_not_reproduced_outputs() -> Result<()> {
        let report = report(vec![
            evidence("package/a/x86_64-linux", ReproducibilityResult::Reproduced),
            evidence(
                "package/b/x86_64-linux",
                ReproducibilityResult::NotReproduced,
            ),
        ]);

        report.require_reproducibility_policy(RegistryTier::Testing)?;
        let unreproduced = report
            .not_reproduced()
            .map(|output| output.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(unreproduced, ["package/b/x86_64-linux"]);
        Ok(())
    }

    #[test]
    fn validation_applies_the_plan_registry_tier() -> Result<()> {
        let digest = Sha256Digest::of_bytes("plan");

        let (plan, reproduced) = planned_report(MAIN_REGISTRY, ReproducibilityResult::Reproduced)?;
        reproduced.validate(&plan, digest)?;

        let (plan, unreproduced) =
            planned_report(MAIN_REGISTRY, ReproducibilityResult::NotReproduced)?;
        assert!(unreproduced.validate(&plan, digest).is_err());

        let (plan, unreproduced) =
            planned_report(EXPERIMENTAL_REGISTRY, ReproducibilityResult::NotReproduced)?;
        unreproduced.validate(&plan, digest)?;
        Ok(())
    }
}
