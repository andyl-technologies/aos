//! Checked ability-graph fixtures for realized artifact-consumption gates.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_ability_inspect::{CheckedArtifactConsumptionEvidence, InspectionBundle};
use aos_ability_validate::test_support::plan_fixture;

/// Writes a canonical checked inspection bundle containing both evidence artifacts.
pub(super) fn generate(arguments: &[String]) -> Result<()> {
    let [evidence_path, output_path] = arguments else {
        bail!("usage: aos-release-fleet-fixture artifact-consumption-bundle EVIDENCE OUTPUT");
    };
    let evidence_bytes = fs::read(evidence_path)
        .with_context(|| format!("reading artifact evidence {evidence_path}"))?;
    let evidence = CheckedArtifactConsumptionEvidence::decode(&evidence_bytes)
        .context("checking artifact evidence before graph construction")?;
    let document = evidence.document();

    let mut fixture = plan_fixture();
    let provider = document.provider.artifact.clone();
    fixture.binding_inputs.environment.providers[0]
        .implementation
        .artifact = provider.clone();
    fixture.binding_plan.bindings[0].implementation.artifact = provider.clone();
    fixture.effect_plan.artifacts = vec![document.consumer.artifact.clone(), provider];
    fixture.effect_plan.artifacts.sort_by(|left, right| {
        left.content
            .cmp(&right.content)
            .then_with(|| left.store_path.cmp(&right.store_path))
    });
    fixture.effect_plan.artifacts.dedup();
    fixture.refresh_commitments();

    let checked = fixture
        .validate()
        .context("validating artifact-consumption ability graph")?;
    let bundle = InspectionBundle::from_checked(&checked)
        .context("constructing artifact-consumption inspection bundle")?
        .with_artifact_consumption_edges(vec![(*document).clone()])
        .context("attaching the exact artifact-consumption graph edge")?;
    let bytes = bundle
        .canonical_bytes()
        .context("encoding artifact-consumption inspection bundle")?;
    fs::write(Path::new(output_path), bytes)
        .with_context(|| format!("writing artifact inspection bundle {output_path}"))
}
