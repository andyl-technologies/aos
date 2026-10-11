//! Checked standalone fixtures for realized artifact-consumption gates.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_doc_model::artifact_consumption::CheckedArtifactConsumptionEvidence;

/// Retains the exact checked evidence bytes without inventing a graph join.
///
/// # Errors
/// Returns an error for invalid arguments, malformed realized evidence, or I/O.
pub(super) fn generate(arguments: &[String]) -> Result<()> {
    let [evidence_path, output_path] = arguments else {
        bail!("usage: aos-release-fleet-fixture artifact-consumption-evidence EVIDENCE OUTPUT");
    };
    let bytes = fs::read(evidence_path)
        .with_context(|| format!("reading artifact evidence {evidence_path}"))?;
    CheckedArtifactConsumptionEvidence::decode(&bytes)
        .context("checking realized artifact-consumption evidence")?;
    fs::write(Path::new(output_path), bytes)
        .with_context(|| format!("retaining artifact evidence {output_path}"))
}
