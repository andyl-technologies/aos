//! Frozen replay, incomplete-source retention and exact finding conformance.

mod common;

use anyhow::{Context as _, Result};
use aos_assessment::evaluator::evaluate;
use aos_assessment::input::{EvaluationData, Profile, ScanInputV1};
use aos_assessment::observation::ProviderCoverage;
use aos_assessment::result::Applicability;
use aos_assessment::security::CoverageState;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;

#[test]
fn selected_subjects_are_frozen_without_rewriting_inventory_or_evaluating_other_subjects()
-> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    let mut additional = data.inventory.subjects[0].clone();
    additional.subject_ref = "subject-extra".into();
    data.inventory.subjects.push(additional);
    let inventory_digest = data.inventory.digest()?;
    let input = data.freeze_selected(
        vec![Profile::Vulnerabilities],
        vec!["subject".into()],
        common::evaluated_at()?,
    )?;
    let assessment = evaluate(&input, &data)?;
    assert_eq!(input.inventory_digest, inventory_digest);
    assert_eq!(input.subject_refs, ["subject"]);
    assert_eq!(assessment.subject_results.len(), 1);
    assert_eq!(assessment.subject_results[0].subject_ref, "subject");
    assert_eq!(assessment.subject_results[0].findings.len(), 1);
    let all = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    assert_ne!(input.digest()?, all.digest()?);
    assert!(
        data.freeze_selected(vec![Profile::Updates], vec![], common::evaluated_at()?)
            .is_err()
    );
    assert!(
        data.freeze_selected(
            vec![Profile::Updates],
            vec!["absent".into()],
            common::evaluated_at()?
        )
        .is_err()
    );
    assert!(
        data.freeze_selected(
            vec![Profile::Updates],
            vec!["subject".into(), "subject".into()],
            common::evaluated_at()?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn frozen_inputs_and_canonical_results_reproduce_after_portable_round_trip() -> Result<()> {
    let data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let assessment = evaluate(&input, &data)?;
    assert_eq!(assessment.coverage, CoverageState::Complete);
    let finding = &assessment.subject_results[0].findings[0];
    assert_eq!(finding.applicability, Applicability::Affected);
    assert_eq!(finding.advisory_ids, ["CVE-2026-10001", "GHSA-fixture-one"]);
    assert_eq!(finding.fixes[0].version, "1.3.0");
    assert_eq!(
        finding.advisory_record_digests,
        [data.advisories[0].digest()?]
    );

    let portable = aos_contract::canonical::to_vec(&data)?;
    let replay_data = EvaluationData::from_slice(&portable)?;
    let replay_input: ScanInputV1 =
        serde_json::from_slice(&aos_contract::canonical::to_vec(&input)?)?;
    assert_eq!(
        evaluate(&replay_input, &replay_data)?.digest()?,
        assessment.digest()?
    );
    Ok(())
}

#[test]
fn stale_or_partial_refresh_retains_known_findings_without_freshness_laundering() -> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    let observation = &mut data
        .advisory_snapshot
        .as_mut()
        .context("fixture snapshot")?
        .sources[0]
        .observation;
    observation.coverage = ProviderCoverage::Partial {
        reason: "provider-unavailable".into(),
        continuation: None,
    };
    let original_validation = observation.validated_at.clone();
    let input = data.freeze(
        vec![Profile::Vulnerabilities],
        Timestamp::parse("2026-10-11T12:00:00Z")?,
    )?;
    let assessment = evaluate(&input, &data)?;
    assert_eq!(assessment.subject_results[0].findings.len(), 1);
    assert_eq!(assessment.coverage, CoverageState::Partial);
    assert_eq!(assessment.subject_results[0].coverage[0].counts.stale, 1);
    assert_eq!(
        data.advisory_snapshot
            .as_ref()
            .context("fixture snapshot")?
            .sources[0]
            .observation
            .validated_at,
        original_validation
    );
    Ok(())
}

#[test]
fn fixed_version_has_no_known_findings_only_with_complete_required_evidence() -> Result<()> {
    let mut data = common::fixture("1.3.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let assessment = evaluate(&input, &data)?;
    assert!(assessment.subject_results[0].findings.is_empty());
    assert_eq!(assessment.coverage, CoverageState::Complete);

    data.advisory_snapshot
        .as_mut()
        .context("fixture snapshot")?
        .sources
        .clear();
    data.advisories.clear();
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let missing = evaluate(&input, &data)?;
    assert!(missing.subject_results[0].findings.is_empty());
    assert_eq!(missing.coverage, CoverageState::Unknown);
    assert_eq!(missing.subject_results[0].coverage[0].counts.failed, 1);
    Ok(())
}

#[test]
fn tampered_metadata_and_missing_referenced_records_fail_before_evaluation() -> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    data.inventory.components[0].current.comparison_version = "1.3.0".into();
    assert!(evaluate(&input, &data).is_err());

    data = common::fixture("1.2.0")?;
    data.advisories.clear();
    assert!(
        data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)
            .is_err()
    );
    data = common::fixture("1.2.0")?;
    let mut changed = input;
    changed.engine_digest = Sha256Digest::of_bytes("different engine");
    assert!(evaluate(&changed, &data).is_err());
    assert!(
        data.freeze(
            vec![Profile::Vulnerabilities, Profile::Updates],
            common::evaluated_at()?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn updates_only_never_fabricates_or_clears_a_vulnerability_result() -> Result<()> {
    let data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Updates], common::evaluated_at()?)?;
    let assessment = evaluate(&input, &data)?;
    assert!(assessment.subject_results[0].findings.is_empty());
    assert_eq!(assessment.subject_results[0].coverage.len(), 1);
    assert_eq!(
        assessment.subject_results[0].coverage[0].profile,
        Profile::Updates
    );
    assert_eq!(assessment.coverage, CoverageState::Unknown);
    Ok(())
}

#[test]
fn reviewed_backports_preserve_raw_findings_and_expire_on_exact_patch_scope() -> Result<()> {
    use aos_assessment::disposition::{SECURITY_DISPOSITION_V1, SecurityDispositionV1};
    let mut data = common::fixture("1.2.0")?;
    let statement: SecurityDispositionV1 = serde_json::from_value(serde_json::json!({
        "schema":SECURITY_DISPOSITION_V1, "componentInstanceDigest":data.inventory.components[0].digest()?,
        "advisoryRecordDigests":[data.advisories[0].digest()?], "status":"fixed",
        "justification":"reviewed-backport", "explanation":"Exact fixture patch reviewed against the source claim",
        "evidenceDigests":[Sha256Digest::of_bytes("reviewed patch evidence")], "issuer":"fixture-issuer", "reviewer":"fixture-reviewer",
        "authorizationDigest":Sha256Digest::of_bytes("external review authorization"),
        "validFrom":"2026-10-09T00:00:00Z", "expiresAt":"2026-10-10T00:00:00Z"
    }))?;
    data.dispositions.push(statement.clone());
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let result = evaluate(&input, &data)?;
    assert_eq!(
        result.subject_results[0].findings[0].disposition_refs,
        [statement.digest()?]
    );
    assert_eq!(
        result.subject_results[0].findings[0].applicability,
        Applicability::Affected
    );
    let expiry = Timestamp::parse("2026-10-10T00:00:00Z")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], expiry)?;
    assert!(
        evaluate(&input, &data)?.subject_results[0].findings[0]
            .disposition_refs
            .is_empty()
    );
    data.inventory.components[0].patch_set_digest = Some(Sha256Digest::of_bytes("different patch"));
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    assert!(
        evaluate(&input, &data)?.subject_results[0].findings[0]
            .disposition_refs
            .is_empty()
    );
    Ok(())
}

#[test]
fn kev_enrichment_matches_equivalent_cves_and_never_related_or_upstream_ids() -> Result<()> {
    use aos_assessment::advisory::{ExploitCatalog, KnownExploit};
    use aos_assessment::observation::SourceEvidenceRef;
    let mut data = common::fixture("1.2.0")?;
    let raw = b"retained KEV catalog";
    let digest = Sha256Digest::of_bytes(raw);
    let mut observation = data
        .advisory_snapshot
        .as_ref()
        .context("fixture snapshot")?
        .sources[0]
        .observation
        .clone();
    observation.provider = "cisa-kev".into();
    observation.project = "catalog".into();
    observation.adapter_version = "aos-cisa-kev/v1".into();
    observation.response_digest = digest;
    observation.source_refs = vec![SourceEvidenceRef {
        digest,
        byte_length: raw.len() as u64,
        origin: "cisa-kev".into(),
    }];
    let records = vec![
        KnownExploit {
            cve_id: "CVE-2026-10001".into(),
            catalog_version: "2026.10.09".into(),
            date_added: "2026-10-08".into(),
            source_digest: digest,
        },
        KnownExploit {
            cve_id: "CVE-2026-10002".into(),
            catalog_version: "2026.10.09".into(),
            date_added: "2026-10-08".into(),
            source_digest: digest,
        },
    ];
    observation.payload_digest =
        Sha256Digest::of_canonical("aos.known-exploitation-set/v1", &records)?;
    data.advisory_snapshot
        .as_mut()
        .context("fixture snapshot")?
        .exploit_catalog = Some(ExploitCatalog {
        observation,
        records,
    });
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let result = evaluate(&input, &data)?;
    assert_eq!(
        result.subject_results[0].findings[0].exploit_signals.len(),
        1
    );
    assert_eq!(
        result.subject_results[0].findings[0].exploit_signals[0].cve_id,
        "CVE-2026-10001"
    );
    Ok(())
}

#[test]
fn version_selection_preserves_history_age_stream_and_frozen_authority() -> Result<()> {
    use aos_assessment::discovery::{
        ObservationCandidate, ObservationCoverage, UpstreamObservationV1,
    };
    use aos_assessment::input::{CandidateHistory, UpstreamBinding};
    use aos_assessment::inventory::Classification;
    use aos_assessment::result::VersionDecision;
    let mut data = common::fixture("1.2.0")?;
    let evaluated = common::evaluated_at()?;
    let published = evaluated.unix_seconds() - 4 * 86400;
    let candidate = ObservationCandidate {
        raw_id: "v1.3.0".into(),
        raw_version: "1.3.0".into(),
        published_at_unix: None,
        first_observed_at_unix: published,
        prerelease: false,
        yanked: false,
        release_url: None,
        status: None,
        vulnerable: None,
        licenses: vec![],
    };
    data.history.push(CandidateHistory {
        provider: "github-releases".into(),
        project: "example/fixture".into(),
        raw_id: candidate.raw_id.clone(),
        first_observed_at: Timestamp::from_unix_seconds(published)?,
    });
    data.upstream.push(UpstreamBinding {
        source_refs: vec![],
        component_ref: "component".into(),
        response_byte_length: 3,
        observation: UpstreamObservationV1 {
            schema: aos_assessment::UPSTREAM_OBSERVATION_V1.into(),
            provider: "github-releases".into(),
            project: "example/fixture".into(),
            retrieved_at_unix: evaluated.unix_seconds(),
            request_url: "https://api.github.com/repos/example/fixture/releases".into(),
            adapter_version: "fixture-v1".into(),
            coverage: ObservationCoverage::Complete,
            response_digest: Sha256Digest::of_bytes("raw"),
            candidates: vec![candidate],
        },
    });
    let input = data.freeze(vec![Profile::Updates], evaluated.clone())?;
    let result = evaluate(&input, &data)?;
    assert_eq!(
        result.subject_results[0].versions[0].decision,
        VersionDecision::UpdateAvailable
    );
    assert_eq!(
        result.subject_results[0].versions[0]
            .eligible
            .as_ref()
            .context("eligible fixture version")?
            .comparison_version,
        "1.3.0"
    );
    assert_eq!(result.coverage, CoverageState::Complete);
    data.upstream[0].observation.candidates[0].first_observed_at_unix += 1;
    assert!(
        data.freeze(vec![Profile::Updates], evaluated.clone())
            .is_err()
    );
    data.upstream[0].observation.candidates[0].first_observed_at_unix = published;
    data.definitions[0].classification = Classification::Frozen;
    data.definitions[0].reason = Some("Pinned fixture stream".into());
    data.definitions[0].review_after = Some(Timestamp::parse("2027-01-01T00:00:00Z")?);
    let definition = data.definitions[0].digest()?;
    data.inventory.subjects[0].scan_definition_digest = definition;
    data.inventory.components[0].scan_definition_digest = definition;
    let input = data.freeze(vec![Profile::Updates], evaluated)?;
    let result = evaluate(&input, &data)?;
    assert_eq!(
        result.subject_results[0].versions[0].decision,
        VersionDecision::Frozen
    );
    assert!(result.subject_results[0].versions[0].eligible.is_none());
    Ok(())
}
