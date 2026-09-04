//! Exact Nix realization and repeat-build evidence.
//!
//! The build report binds every planned Nix output to the observed NAR
//! identity, closure size, references, and a successful Nix check rebuild.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;
use crate::plan::ReleasePlanV1;
use crate::platform::Platform;

/// Schema identifier for a complete build report.
pub const BUILD_REPORT_V1: &str = "aos.release.build-report/v1";

/// Result of rebuilding an already realized derivation with Nix `--check`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReproducibilityResult {
    /// Nix proved the repeat output byte-identical.
    Reproduced,
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
    /// Exact upstream source store paths, or empty for repository source.
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

/// Closed report produced by `aos release build`.
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
    /// facts, unsorted references, or an empty completion time.
    pub fn validate(&self, plan: &ReleasePlanV1, plan_digest: Sha256Digest) -> Result<()> {
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
    /// Exact upstream source store paths.
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
pub fn planned_nix_outputs(plan: &ReleasePlanV1) -> Result<BTreeMap<&str, PlannedNixOutput<'_>>> {
    let mut expected = BTreeMap::new();
    for package in &plan.packages {
        let Some(publication) = package.publication.as_ref() else {
            continue;
        };
        for cell in &package.platforms {
            let crate::platform::MatrixCell::Artifact { artifact } = &cell.decision else {
                continue;
            };
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
                            version: &publication.version,
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
