//! Frozen status times, exact selectors and closed capture custody.

use anyhow::Result;
use aos_assessment::{input::Profile, time::Timestamp};
use aos_contract::Sha256Digest;

use super::*;
use crate::application::{ProfileStatus, SubjectStatus};

fn fixture() -> Result<(StatusQueryV2, StatusReadSnapshotV1)> {
    let now = Timestamp::from_unix_seconds(1_800_000_000)?;
    let selection = StatusQueryV2 {
        schema: "aos.assessment-status-query/v2".into(),
        profiles: vec![Profile::Updates],
        limit: 1,
        resource_scope: Some("registry-incarnation".into()),
        inventory_digest: None,
        policy_digest: None,
        cursor: None,
    };
    let deadline = Timestamp::from_unix_seconds(now.unix_seconds() + 5)?;
    let pages = ["first", "second"]
        .into_iter()
        .map(|name| AssessmentStatusV1 {
            schema: "aos.assessment-status/v1".into(),
            resource_scope: "registry-incarnation".into(),
            inventory_digest: Sha256Digest::of_bytes("inventory"),
            inventory_revision: 1,
            policy_digest: Sha256Digest::of_bytes("policy"),
            as_of: now.clone(),
            source_status: vec![],
            subjects: vec![SubjectStatus {
                subject_ref: name.into(),
                package_coordinate: format!("fixture/{name}"),
                version: "1.0.0".into(),
                platform: "x86_64-linux".into(),
                output: "out".into(),
                profiles: vec![ProfileStatus {
                    profile: Profile::Updates,
                    desired_generation: 2,
                    committed_generation: 1,
                    assessment_digest: Some(Sha256Digest::of_bytes(name)),
                    input_digest: Some(Sha256Digest::of_bytes("input")),
                    validated_until: Some(deadline.clone()),
                    fresh: true,
                    pending: true,
                }],
            }],
            next_subject: None,
        })
        .collect();
    let snapshot = StatusReadSnapshotV1 {
        schema: STATUS_READ_SNAPSHOT_V1.into(),
        selection: selection.clone(),
        expires_at: Timestamp::from_unix_seconds(now.unix_seconds() + 900)?,
        pages,
        page_handles: vec!["0123456789abcdef0123456789abcdef".into()],
    };
    Ok((selection, snapshot))
}

#[test]
fn continuation_preserves_original_freshness_pending_heads_and_time() -> Result<()> {
    let (mut query, snapshot) = fixture()?;
    let first = snapshot.page(&query, &snapshot.pages[0].as_of)?;
    query.cursor = first.next_cursor;
    let later = Timestamp::from_unix_seconds(snapshot.pages[0].as_of.unix_seconds() + 10)?;

    let retained = StatusReadSnapshotV1::from_slice(&snapshot.to_bytes()?)?;
    let page = retained.page(&query, &later)?;

    assert_eq!(page.page, snapshot.pages[1]);
    assert!(page.page.subjects[0].profiles[0].fresh);
    assert!(page.page.subjects[0].profiles[0].pending);
    assert!(page.next_cursor.is_none());
    assert_eq!(StatusPageV2::from_slice(&page.to_bytes()?)?, page);
    assert!(retained.page(&query, &snapshot.expires_at).is_err());
    Ok(())
}

#[test]
fn cursor_refuses_changed_scope_profiles_constraints_limit_and_handles() -> Result<()> {
    let (mut query, snapshot) = fixture()?;
    let now = &snapshot.pages[0].as_of;
    query.cursor = snapshot.page(&query, now)?.next_cursor;
    for changed in [
        StatusQueryV2 {
            limit: 2,
            ..query.clone()
        },
        StatusQueryV2 {
            resource_scope: Some("different-incarnation".into()),
            ..query.clone()
        },
        StatusQueryV2 {
            profiles: vec![Profile::Vulnerabilities],
            ..query.clone()
        },
        StatusQueryV2 {
            inventory_digest: Some(Sha256Digest::of_bytes("different")),
            ..query.clone()
        },
        StatusQueryV2 {
            policy_digest: Some(Sha256Digest::of_bytes("different")),
            ..query.clone()
        },
    ] {
        assert!(snapshot.page(&changed, now).is_err());
    }
    let mut unbound = query.clone();
    unbound.resource_scope = None;
    assert!(unbound.validate().is_err());
    query.cursor = Some(format!(
        "t1:{}:{}",
        snapshot.digest()?.hex(),
        "0".repeat(32)
    ));
    assert!(snapshot.page(&query, now).is_err());
    assert!(
        parse_status_cursor(&format!(
            "c1:{}:{}",
            snapshot.digest()?.hex(),
            "0".repeat(32)
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn capture_refuses_mixed_context_reordered_subjects_and_legacy_positions() -> Result<()> {
    let (query, snapshot) = fixture()?;
    let mut changed = snapshot.clone();
    changed.pages[1].inventory_revision = 2;
    assert!(changed.to_bytes().is_err());
    let mut changed = snapshot.clone();
    changed.pages[1].as_of =
        Timestamp::from_unix_seconds(changed.pages[0].as_of.unix_seconds() + 1)?;
    assert!(changed.to_bytes().is_err());
    let mut changed = snapshot.clone();
    changed.pages[1].subjects[0].subject_ref = "first".into();
    assert!(changed.to_bytes().is_err());
    let mut changed = snapshot.clone();
    changed.pages[1].next_subject = Some("second".into());
    assert!(changed.to_bytes().is_err());
    let mut value = serde_json::to_value(query)?;
    value["afterSubject"] = "first".into();
    assert!(StatusQueryV2::from_slice(&serde_json::to_vec(&value)?).is_err());
    value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture object"))?
        .remove("afterSubject");
    value["cursor"] = serde_json::Value::Null;
    assert!(StatusQueryV2::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn valid_large_status_capture_reports_typed_encoding_exhaustion() -> Result<()> {
    let (_, mut snapshot) = fixture()?;
    let original = snapshot.pages[0].clone();
    snapshot.pages = (0..5000)
        .map(|index| {
            let mut page = original.clone();
            page.subjects[0].subject_ref = format!("subject-{index:04}");
            page.subjects[0].package_coordinate = "x".repeat(1024);
            page.subjects[0].version = "1".repeat(256);
            page
        })
        .collect();
    snapshot.page_handles = (1..snapshot.pages.len())
        .map(|index| format!("{index:032x}"))
        .collect();

    let error = snapshot.to_bytes().unwrap_err();

    assert_eq!(
        error.downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );
    Ok(())
}

#[test]
fn valid_wide_status_page_reports_typed_response_exhaustion() -> Result<()> {
    let (_, snapshot) = fixture()?;
    let mut inner = snapshot.pages[0].clone();
    let subject = inner.subjects[0].clone();
    inner.subjects = (0..100)
        .map(|index| {
            let mut subject = subject.clone();
            subject.subject_ref = format!("subject-{index:03}");
            subject.package_coordinate = "x".repeat(1024);
            subject.version = "1".repeat(256);
            subject.platform = "p".repeat(128);
            subject.output = "o".repeat(128);
            let state = subject.profiles[0].clone();
            subject.profiles = [
                Profile::LicenseSignals,
                Profile::Updates,
                Profile::Vulnerabilities,
            ]
            .map(|profile| ProfileStatus {
                profile,
                ..state.clone()
            })
            .to_vec();
            subject
        })
        .collect();
    inner.validate()?;
    let page = StatusPageV2 {
        schema: "aos.assessment-status-page/v2".into(),
        page: inner,
        expires_at: snapshot.expires_at,
        next_cursor: None,
    };

    let error = page.to_bytes().unwrap_err();

    assert_eq!(
        error.downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );
    Ok(())
}
