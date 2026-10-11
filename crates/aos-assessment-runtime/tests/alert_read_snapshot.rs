//! Original episode custody, exact continuations and finite attention capture tests.

use anyhow::Result;
use aos_assessment::{input::Profile, time::Timestamp};
use aos_assessment_runtime::alerts::{
    AssessmentAlertV1, AttentionState, IssueFamily, IssueObservation,
};
use aos_assessment_runtime::attention_control::{AlertPageV1, AlertQueryV1};
use aos_assessment_runtime::read_snapshot::{ScanPageError, alerts::*};
use aos_contract::Sha256Digest;

fn capture() -> Result<AlertReadSnapshotV1> {
    let mut alerts = ["first", "second", "third"]
        .into_iter()
        .map(|id| {
            let key = Sha256Digest::of_bytes(id);
            AssessmentAlertV1 {
                schema: "aos.assessment-alert/v1".into(),
                issue_key: key,
                issue: IssueObservation {
                    issue_key: key,
                    context_digest: Sha256Digest::of_bytes("component"),
                    family: IssueFamily::Coverage,
                    profile: Profile::Vulnerabilities,
                    lineage_ids: vec![id.into()],
                    source_keys: vec![],
                    material_digest: Sha256Digest::of_bytes("unknown coverage"),
                    selection_context: None,
                    uncertain: true,
                },
                state: AttentionState::Open,
                episode: 1,
                sequence: 1,
                assessment_digest: Sha256Digest::of_bytes("original assessment"),
                updated_at: Timestamp::from_unix_seconds(1000).unwrap(),
                acknowledgements: vec![],
                lineage_keys: vec![],
            }
        })
        .collect::<Vec<_>>();
    alerts.sort_by_key(|alert| alert.issue_key);
    Ok(AlertReadSnapshotV1 {
        schema: ALERT_READ_SNAPSHOT_V1.into(),
        resource_scope: "registry-incarnation".into(),
        limit: 1,
        as_of: Timestamp::from_unix_seconds(1000)?,
        expires_at: Timestamp::from_unix_seconds(1900)?,
        alerts,
        page_handles: vec![
            "0123456789abcdef0123456789abcdef".into(),
            "abcdef0123456789abcdef0123456789".into(),
        ],
    })
}

#[test]
fn retained_attention_pages_bind_original_revisions_selector_and_custody_clock() -> Result<()> {
    let snapshot = capture()?;
    assert_eq!(
        AlertReadSnapshotV1::from_slice(&snapshot.to_bytes()?)?,
        snapshot
    );
    let first = snapshot.page(&snapshot.resource_scope, 1, None, &snapshot.as_of)?;
    let token = first.next_issue.as_deref().unwrap();
    let (digest, handle) = parse_alert_cursor(token)?;
    assert_eq!(digest, snapshot.digest()?);
    let next = snapshot.page(
        &snapshot.resource_scope,
        1,
        Some(handle),
        &Timestamp::from_unix_seconds(1800)?,
    )?;
    assert_eq!(next.alerts, snapshot.alerts[1..2]);
    assert_eq!(next.as_of, first.as_of);
    assert_eq!(AlertPageV1::from_slice(&next.to_bytes()?)?, next);
    let query = serde_json::json!({"schema":"aos.assessment-alert-query/v1", "limit":1,
        "resourceScope":snapshot.resource_scope, "afterIssue": token});
    AlertQueryV1::from_slice(&serde_json::to_vec(&query)?)?;
    for (scope, limit, now, expected) in [
        (
            "foreign",
            1,
            snapshot.as_of.clone(),
            ScanPageError::SelectorChanged,
        ),
        (
            "registry-incarnation",
            2,
            snapshot.as_of.clone(),
            ScanPageError::SelectorChanged,
        ),
        (
            "registry-incarnation",
            1,
            snapshot.expires_at.clone(),
            ScanPageError::CursorExpired,
        ),
        (
            "registry-incarnation",
            1,
            Timestamp::from_unix_seconds(999)?,
            ScanPageError::CursorExpired,
        ),
    ] {
        assert_eq!(
            snapshot
                .page(scope, limit, Some(handle), &now)
                .unwrap_err()
                .downcast_ref::<ScanPageError>(),
            Some(&expected)
        );
    }
    for cursor in [
        snapshot.alerts[0].issue_key.to_string(),
        token.replacen("a1:", "s1:", 1),
        token.to_uppercase(),
    ] {
        assert!(parse_alert_cursor(&cursor).is_err());
    }
    assert!(
        snapshot
            .page(
                &snapshot.resource_scope,
                1,
                Some("00000000000000000000000000000000"),
                &snapshot.as_of
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn attention_capture_refuses_reordered_future_ambiguous_or_excessive_content() -> Result<()> {
    let snapshot = capture()?;
    let mut changed = snapshot.clone();
    changed.alerts.swap(0, 1);
    assert!(changed.to_bytes().is_err());
    let mut changed = snapshot.clone();
    changed.alerts[0].updated_at = Timestamp::from_unix_seconds(1001)?;
    assert!(changed.to_bytes().is_err());
    let mut changed = snapshot.clone();
    changed.page_handles[1] = changed.page_handles[0].clone();
    assert!(changed.to_bytes().is_err());
    let mut changed = snapshot.clone();
    changed.expires_at = Timestamp::from_unix_seconds(1901)?;
    assert!(changed.to_bytes().is_err());
    let mut changed = serde_json::to_value(&snapshot)?;
    changed["privateAuthority"] = serde_json::json!("caller cannot add a grant");
    assert!(AlertReadSnapshotV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    let mut changed = serde_json::to_value(&snapshot)?;
    changed["pageHandles"] = serde_json::Value::Null;
    assert!(AlertReadSnapshotV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    let mut excessive = snapshot;
    excessive.alerts = vec![excessive.alerts[0].clone(); MAX_CAPTURE_ALERTS + 1];
    assert!(excessive.to_bytes().is_err());
    assert!(AlertReadSnapshotV1::from_slice(b"{\"schema\":\"x\",\"schema\":\"y\"}").is_err());
    Ok(())
}
