//! Candidate eligibility horizons without network effects or evidence mutation.

use anyhow::{Context as _, Result};
use aos_assessment::input::{EvaluationData, Profile};
use aos_assessment::inventory::Classification;
use aos_assessment::result::VersionDecision;
use aos_assessment::security::CoverageState;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::status::profile_freshness_deadline;

#[path = "../../aos-assessment/tests/common/mod.rs"]
mod common;

fn fixture(after: u64) -> Result<EvaluationData> {
    let now = common::evaluated_at()?;
    let mut data = common::updates::data(now.clone())?;
    let first = now.unix_seconds() - 3 * 86_400 + after;
    data.history[0].first_observed_at = Timestamp::from_unix_seconds(first)?;
    data.upstream[0].observation.candidates[0].first_observed_at_unix = first;
    Ok(data)
}

fn update_deadline(data: &EvaluationData, now: Timestamp) -> Result<Option<Timestamp>> {
    let input = data.freeze(vec![Profile::Updates], now)?;
    let result = aos_assessment::evaluator::evaluate(&input, data)?;
    profile_freshness_deadline(&input, data, &result.subject_results[0].coverage[0])
}

#[test]
fn stabilization_boundary_reassesses_retained_bytes_without_mutating_history() -> Result<()> {
    let now = common::evaluated_at()?;
    let data = fixture(10)?;
    let original = data.clone();
    let input = data.freeze(vec![Profile::Updates], now.clone())?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert_eq!(
        result.subject_results[0].versions[0].decision,
        VersionDecision::Stabilizing
    );
    let digest = result.digest()?;
    let deadline =
        profile_freshness_deadline(&input, &data, &result.subject_results[0].coverage[0])?
            .context("stabilization deadline")?;
    assert_eq!(deadline.unix_seconds(), now.unix_seconds() + 10);

    let before = data.freeze(
        vec![Profile::Updates],
        Timestamp::from_unix_seconds(deadline.unix_seconds() - 1)?,
    )?;
    assert_eq!(
        aos_assessment::evaluator::evaluate(&before, &data)?.subject_results[0].versions[0]
            .decision,
        VersionDecision::Stabilizing
    );
    let at = data.freeze(vec![Profile::Updates], deadline)?;
    let matured = aos_assessment::evaluator::evaluate(&at, &data)?;
    assert_eq!(
        matured.subject_results[0].versions[0].decision,
        VersionDecision::UpdateAvailable
    );
    assert_eq!(
        matured.subject_results[0].versions[0]
            .eligible
            .as_ref()
            .context("mature candidate")?
            .comparison_version,
        "1.3.0"
    );
    assert_eq!(data, original);
    assert_eq!(result.digest()?, digest);
    assert_eq!(
        update_deadline(&data, at.evaluated_at)?
            .context("mature source lifetime")?
            .unix_seconds(),
        now.unix_seconds() + 86_400
    );
    Ok(())
}

#[test]
fn new_source_validation_preserves_the_original_stabilization_age() -> Result<()> {
    let now = common::evaluated_at()?;
    let mut data = fixture(10)?;
    let history = data.history.clone();
    let first = data.upstream[0].observation.candidates[0].first_observed_at_unix;
    let later = Timestamp::from_unix_seconds(now.unix_seconds() + 4)?;
    data.upstream[0].observation.retrieved_at_unix = later.unix_seconds();
    assert_eq!(
        update_deadline(&data, later)?
            .context("retained age")?
            .unix_seconds(),
        now.unix_seconds() + 10
    );
    assert_eq!(data.history, history);
    assert_eq!(
        data.upstream[0].observation.candidates[0].first_observed_at_unix,
        first
    );
    Ok(())
}

#[test]
fn publication_time_owns_eligibility_when_first_observation_is_newer() -> Result<()> {
    let now = common::evaluated_at()?;
    let mut data = fixture(10)?;
    data.history[0].first_observed_at = now.clone();
    let candidate = &mut data.upstream[0].observation.candidates[0];
    candidate.first_observed_at_unix = now.unix_seconds();
    candidate.published_at_unix = Some(now.unix_seconds() - 3 * 86_400 + 30);
    assert_eq!(
        update_deadline(&data, now.clone())?
            .context("publication deadline")?
            .unix_seconds(),
        now.unix_seconds() + 30
    );
    Ok(())
}

#[test]
fn source_expiry_wins_and_excluded_candidates_never_extend_coverage() -> Result<()> {
    let now = common::evaluated_at()?;
    let data = fixture(2 * 86_400)?;
    assert_eq!(
        update_deadline(&data, now.clone())?
            .context("source deadline")?
            .unix_seconds(),
        now.unix_seconds() + 86_400
    );
    for change in 0..4 {
        let mut data = fixture(10)?;
        let candidate = &mut data.upstream[0].observation.candidates[0];
        match change {
            0 => candidate.yanked = true,
            1 => {
                candidate.prerelease = true;
                candidate.raw_version = "1.3.0-rc.1".into();
            }
            2 => candidate.raw_version = "2.0.0".into(),
            _ => candidate.raw_version = "1.0.0".into(),
        }
        assert_eq!(
            update_deadline(&data, now.clone())?
                .context("excluded candidate source lifetime")?
                .unix_seconds(),
            now.unix_seconds() + 86_400
        );
    }
    let mut stale = fixture(10)?;
    stale.upstream[0].observation.retrieved_at_unix -= 86_401;
    let input = stale.freeze(vec![Profile::Updates], now.clone())?;
    let result = aos_assessment::evaluator::evaluate(&input, &stale)?;
    assert_ne!(
        result.subject_results[0].coverage[0].state,
        CoverageState::Complete
    );
    assert_eq!(update_deadline(&stale, now)?, None);
    Ok(())
}

#[test]
fn vulnerability_lifetime_is_independent_of_candidate_maturation() -> Result<()> {
    let now = common::evaluated_at()?;
    let data = fixture(10)?;
    let input = data.freeze(
        vec![Profile::Updates, Profile::Vulnerabilities],
        now.clone(),
    )?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    let coverage = &result.subject_results[0].coverage[1];
    assert_eq!(coverage.state, CoverageState::Complete);
    let deadline = profile_freshness_deadline(&input, &data, coverage)?;
    let mut without_candidate = data.clone();
    without_candidate.upstream.clear();
    without_candidate.history.clear();
    let input = without_candidate.freeze(vec![Profile::Vulnerabilities], now)?;
    let result = aos_assessment::evaluator::evaluate(&input, &without_candidate)?;
    assert_eq!(
        deadline,
        profile_freshness_deadline(
            &input,
            &without_candidate,
            &result.subject_results[0].coverage[0]
        )?
    );
    Ok(())
}

#[test]
fn manual_and_frozen_policy_keep_source_lifetimes_and_missing_definitions_fail() -> Result<()> {
    let now = common::evaluated_at()?;
    for classification in [Classification::Manual, Classification::Frozen] {
        let mut data = fixture(10)?;
        let definition = &mut data.definitions[0];
        definition.classification = classification;
        definition.reason = Some("Reviewed fixture maintenance policy".into());
        if classification == Classification::Frozen {
            definition.review_after =
                Some(Timestamp::from_unix_seconds(now.unix_seconds() + 86_400)?);
        }
        let definition_digest = definition.digest()?;
        data.inventory.components[0].scan_definition_digest = definition_digest;
        data.inventory.subjects[0].scan_definition_digest = definition_digest;
        data.inventory.subjects[0].component_inventory_digest =
            data.inventory.components[0].digest()?;
        assert_eq!(
            update_deadline(&data, now.clone())?
                .context("reviewed source lifetime")?
                .unix_seconds(),
            now.unix_seconds() + 86_400
        );
    }
    let mut data = fixture(10)?;
    let input = data.freeze(vec![Profile::Updates], now)?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    data.definitions.clear();
    assert!(
        profile_freshness_deadline(&input, &data, &result.subject_results[0].coverage[0]).is_err()
    );
    Ok(())
}
