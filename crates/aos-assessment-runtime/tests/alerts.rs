//! Episode continuity, exact resolution scope and alias merge/split audit retention.

use anyhow::{Context as _, Result};
use aos_assessment::input::Profile;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::alerts::*;
use aos_contract::Sha256Digest;

fn at() -> Result<Timestamp> {
    Timestamp::parse("2026-10-09T12:00:00Z")
}
fn assessment() -> Sha256Digest {
    Sha256Digest::of_bytes("exact assessment")
}
fn observation(ids: &[&str]) -> Result<IssueObservation> {
    let mut ids = ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
    ids.sort();
    Ok(IssueObservation {
        issue_key: Sha256Digest::of_canonical("fixture-issue", &ids)?,
        context_digest: Sha256Digest::of_bytes("exact artifact component"),
        family: IssueFamily::Vulnerability,
        profile: Profile::Vulnerabilities,
        lineage_ids: ids,
        source_keys: vec![Sha256Digest::of_bytes(
            "exact OSV query identity and product/version",
        )],
        material_digest: Sha256Digest::of_bytes("critical severity"),
        uncertain: false,
    })
}
fn opened(issue: &IssueObservation) -> Result<AssessmentAlertV1> {
    Ok(
        reduce(&[], std::slice::from_ref(issue), &[], assessment(), &at()?)?
            .remove(0)
            .alert,
    )
}

#[test]
fn equivalent_scans_preserve_episode_and_do_not_repeat_opening_events() -> Result<()> {
    let issue = observation(&["CVE-2026-10001"])?;
    let previous = opened(&issue)?;
    let result = reduce(
        std::slice::from_ref(&previous),
        &[issue],
        &[],
        assessment(),
        &at()?,
    )?;
    assert_eq!(result[0].event, None);
    assert_eq!(result[0].alert.episode, 1);
    assert_eq!(result[0].previous_sequence, Some(previous.sequence));
    assert_eq!(result[0].alert.sequence, previous.sequence + 1);
    Ok(())
}

#[test]
fn missing_unrelated_or_updates_only_evidence_retains_unresolved_security_issue() -> Result<()> {
    let issue = observation(&["CVE-2026-10001"])?;
    let previous = opened(&issue)?;
    let irrelevant = ResolutionProof {
        context_digest: issue.context_digest,
        profile: Profile::Updates,
        checked_source_keys: issue.source_keys.clone(),
    };
    let changes = reduce(
        std::slice::from_ref(&previous),
        &[],
        &[irrelevant],
        assessment(),
        &at()?,
    )?;
    assert_eq!(changes[0].alert.state, AttentionState::Open);
    assert!(changes[0].alert.issue.uncertain);
    assert_eq!(changes[0].event, Some(AlertTransitionKind::Unconfirmed));
    let unrelated = ResolutionProof {
        context_digest: issue.context_digest,
        profile: issue.profile,
        checked_source_keys: vec![Sha256Digest::of_bytes("unrelated query")],
    };
    let changes = reduce(&[previous], &[], &[unrelated], assessment(), &at()?)?;
    assert_eq!(changes[0].alert.state, AttentionState::Open);
    let repeated = reduce(&[changes[0].alert.clone()], &[], &[], assessment(), &at()?)?;
    assert_eq!(repeated[0].event, None);
    Ok(())
}

#[test]
fn exact_complete_resolution_then_reopening_creates_a_new_unacknowledged_episode() -> Result<()> {
    let issue = observation(&["CVE-2026-10001"])?;
    let previous = opened(&issue)?;
    let acknowledged = previous.acknowledge(
        previous.sequence,
        Acknowledgement {
            idempotency_key: None,
            issue_key: previous.issue_key,
            episode: 1,
            actor_ref: "authorized-reviewer".into(),
            acknowledged_at: at()?,
            reason: None,
        },
    )?;
    assert_eq!(acknowledged.state, AttentionState::Open);
    let proof = ResolutionProof {
        context_digest: issue.context_digest,
        profile: issue.profile,
        checked_source_keys: issue.source_keys.clone(),
    };
    let resolved = reduce(&[acknowledged], &[], &[proof], assessment(), &at()?)?
        .remove(0)
        .alert;
    assert_eq!(resolved.state, AttentionState::Resolved);
    let reopened = reduce(&[resolved], &[issue], &[], assessment(), &at()?)?.remove(0);
    assert_eq!(reopened.event, Some(AlertTransitionKind::Reopened));
    assert_eq!(reopened.alert.episode, 2);
    assert_eq!(reopened.alert.acknowledgements[0].episode, 1);
    assert!(
        reopened
            .alert
            .acknowledge(
                reopened.alert.sequence,
                Acknowledgement {
                    idempotency_key: None,
                    issue_key: reopened.alert.issue_key,
                    episode: 1,
                    actor_ref: "reviewer".into(),
                    acknowledged_at: at()?,
                    reason: None,
                }
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn aliases_merge_into_one_open_issue_without_losing_acknowledgement_history() -> Result<()> {
    let one = observation(&["CVE-2026-10001"])?;
    let two = observation(&["GHSA-fixture-one"])?;
    let mut previous = vec![opened(&one)?, opened(&two)?];
    for alert in &mut previous {
        *alert = alert.acknowledge(
            alert.sequence,
            Acknowledgement {
                idempotency_key: None,
                issue_key: alert.issue_key,
                episode: alert.episode,
                actor_ref: "reviewer".into(),
                acknowledged_at: at()?,
                reason: None,
            },
        )?;
    }
    let merged = observation(&["CVE-2026-10001", "GHSA-fixture-one"])?;
    let changes = reduce(&previous, &[merged], &[], assessment(), &at()?)?;
    let open = changes
        .iter()
        .find(|change| change.alert.state == AttentionState::Open)
        .context("merged open lineage")?;
    assert_eq!(open.event, Some(AlertTransitionKind::Merged));
    assert_eq!(open.alert.acknowledgements.len(), 2);
    assert_eq!(open.alert.episode, 1);
    assert_eq!(
        changes
            .iter()
            .filter(|change| change.alert.state == AttentionState::Retired)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn alias_split_retains_parent_lineage_and_does_not_extend_old_acknowledgements() -> Result<()> {
    let merged = observation(&["CVE-2026-10001", "GHSA-fixture-one"])?;
    let parent = opened(&merged)?;
    let parent = parent.acknowledge(
        parent.sequence,
        Acknowledgement {
            idempotency_key: None,
            issue_key: parent.issue_key,
            episode: 1,
            actor_ref: "reviewer".into(),
            acknowledged_at: at()?,
            reason: None,
        },
    )?;
    let mut split = vec![
        observation(&["CVE-2026-10001"])?,
        observation(&["GHSA-fixture-one"])?,
    ];
    split.sort_by_key(|issue| issue.issue_key);
    let changes = reduce(
        std::slice::from_ref(&parent),
        &split,
        &[],
        assessment(),
        &at()?,
    )?;
    assert_eq!(changes.len(), 2);
    let branch = changes
        .iter()
        .find(|change| change.previous_sequence.is_none())
        .context("new split branch")?;
    assert!(branch.alert.acknowledgements.is_empty());
    assert!(branch.alert.lineage_keys.contains(&parent.issue_key));
    Ok(())
}

#[test]
fn source_identity_removal_cannot_resolve_old_artifact_and_stale_acknowledgements_fail()
-> Result<()> {
    let issue = observation(&["CVE-2026-10001"])?;
    let previous = opened(&issue)?;
    let changed_context = ResolutionProof {
        context_digest: Sha256Digest::of_bytes("same name different identity or patches"),
        profile: issue.profile,
        checked_source_keys: issue.source_keys.clone(),
    };
    assert_eq!(
        reduce(
            std::slice::from_ref(&previous),
            &[],
            &[changed_context],
            assessment(),
            &at()?
        )?[0]
            .alert
            .state,
        AttentionState::Open
    );
    assert!(
        previous
            .acknowledge(
                previous.sequence + 1,
                Acknowledgement {
                    idempotency_key: None,
                    issue_key: previous.issue_key,
                    episode: 1,
                    actor_ref: "reviewer".into(),
                    acknowledged_at: at()?,
                    reason: None
                }
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn alert_revisions_use_canonical_decimal_strings_on_the_wire() -> Result<()> {
    let alert = opened(&observation(&["CVE-2026-10001"])?)?;
    let mut encoded = serde_json::to_value(&alert)?;
    assert_eq!(encoded["episode"], serde_json::json!("1"));
    assert_eq!(encoded["sequence"], serde_json::json!("1"));
    encoded["sequence"] = serde_json::json!("01");
    assert!(serde_json::from_value::<AssessmentAlertV1>(encoded.clone()).is_err());
    encoded["sequence"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AssessmentAlertV1>(encoded).is_err());
    Ok(())
}
