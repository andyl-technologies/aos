//! Campaign creation, mutation, publication, and authoritative-ref transactions.

use super::projection::PlannerCandidateProjectionCache;
use super::*;

mod publication;

mod creation;
mod discovery;
mod mutation;
mod planner;
mod query;

fn validate_creation_artifact_basis(
    lineage: &CampaignLineage,
    scenario: &ScenarioArtifact,
    genesis: &ConfigurationArtifact,
) -> Result<(), CampaignRepositoryError> {
    // The genesis ID authenticates its complete configuration payload,
    // including that payload's version. `exact_closure_schema` instead names
    // executor checkpoint closures; the two formats evolve independently.
    if scenario.id()? != lineage.scenario_content()
        || scenario.scenario() != lineage.scenario()
        || scenario.payload_schema() != lineage.scenario_schema()
        || genesis.id()? != lineage.genesis_content()
        || genesis.scenario() != lineage.scenario()
        || genesis.scenario_artifact() != lineage.scenario_content()
        || genesis.configuration() != lineage.genesis()
    {
        return Err(integrity("lineage-execution-model-artifact-mismatch"));
    }
    Ok(())
}

fn push_retained_planner_input(
    retained: &mut Vec<ObjectEnvelope>,
    retained_bytes: &mut usize,
    envelope: ObjectEnvelope,
) -> Result<(), CampaignRepositoryError> {
    if retained.len() >= crate::MAX_RETAINED_PLANNER_REQUEST_BUNDLE_OBJECTS {
        return Err(integrity("retained-planner-request-bundle-object-count"));
    }
    *retained_bytes = retained_bytes
        .checked_add(envelope.canonical_bytes().len())
        .filter(|bytes| *bytes <= crate::MAX_RETAINED_PLANNER_REQUEST_BYTES)
        .ok_or_else(|| integrity("retained-planner-request-encoded-bytes"))?;
    retained.push(envelope);
    Ok(())
}

pub(super) fn charge_creation_generator_bytes(
    total: &mut usize,
    next: usize,
) -> Result<(), CampaignRepositoryError> {
    *total = (*total)
        .checked_add(next)
        .filter(|bytes| *bytes <= crate::MAX_CREATE_CAMPAIGN_GENERATOR_BYTES)
        .ok_or_else(|| integrity("campaign-generator-byte-limit"))?;
    Ok(())
}

fn validate_creation_generator_closure(
    policy: &CampaignPolicy,
    generators: &BTreeMap<CandidateGeneratorSpecId, CandidateGeneratorSpec>,
) -> Result<(), CampaignRepositoryError> {
    if generators.len() > crate::MAX_CREATE_CAMPAIGN_GENERATORS {
        return Err(integrity("campaign-generator-count-limit"));
    }
    let mut canonical_bytes = 0_usize;
    for (expected, generator) in generators {
        charge_creation_generator_bytes(&mut canonical_bytes, generator.canonical_bytes().len())?;
        if generator.id()? != *expected {
            return Err(integrity("candidate-generator-map-key-mismatch"));
        }
    }

    let mut pending: Vec<_> = policy
        .content_children()
        .into_iter()
        .map(|(_, child)| CandidateGeneratorSpecId::from_content_id(child))
        .collect::<Result<_, _>>()?;
    let mut reachable = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let generator = generators
            .get(&id)
            .ok_or_else(|| integrity("campaign-policy-generator-was-not-supplied"))?;
        for (_, child) in generator.content_children() {
            pending.push(CandidateGeneratorSpecId::from_content_id(child)?);
        }
    }
    if reachable.len() != generators.len() {
        return Err(integrity("campaign-generator-map-has-unreachable-record"));
    }
    Ok(())
}
