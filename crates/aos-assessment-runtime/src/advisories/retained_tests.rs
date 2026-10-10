//! Original advisory context, finite retention and opaque cursor qualification.

use super::*;
use crate::advisories::AdvisoryRevisionV1;
use aos_assessment::advisory::{ADVISORY_RECORD_V1, AdvisoryRecordV1};

fn fixture() -> Result<AdvisoryReadSnapshotV1> {
    let selection = AdvisoryQueryV2 {
        schema: "aos.assessment-advisory-query/v2".into(),
        advisory_id: "CVE-2026-12345".into(),
        resource_scope: Some("registry-incarnation".into()),
        assessment_digest: None,
        subject_ref: None,
        cursor: None,
        limit: 1,
    };
    let mut revisions = Vec::new();
    for index in 0..3 {
        let record = AdvisoryRecordV1 {
            schema: ADVISORY_RECORD_V1.into(),
            provider: "osv".into(),
            id: format!("OSV-2026-{index}"),
            modified: "2026-10-08T12:00:00Z".into(),
            withdrawn: Some("2026-10-09T12:00:00Z".into()),
            aliases: vec![selection.advisory_id.clone()],
            related: vec![],
            upstream: vec![],
            summary: "Retained original withdrawn revision".into(),
            affected: vec![],
            configuration: None,
            severity: vec![],
            references: vec![],
            source_digest: Sha256Digest::of_bytes(format!("original evidence {index}")),
        };
        revisions.push(AdvisoryRevisionV1 {
            record_digest: record.digest()?,
            record,
            finding_links: vec![],
        });
    }
    revisions.sort_by_key(|revision| revision.record_digest);
    let as_of = Timestamp::parse("2026-10-10T00:00:00Z")?;
    Ok(AdvisoryReadSnapshotV1 {
        schema: ADVISORY_READ_SNAPSHOT_V1.into(),
        selection: selection.clone(),
        expires_at: Timestamp::from_unix_seconds(as_of.unix_seconds() + 900)?,
        pages: revisions
            .into_iter()
            .map(|revision| AdvisoryPageV1 {
                schema: "aos.assessment-advisory-page/v1".into(),
                resource_scope: "registry-incarnation".into(),
                advisory_id: selection.advisory_id.clone(),
                as_of: as_of.clone(),
                assessment_context: None,
                revisions: vec![revision],
                next_record: None,
            })
            .collect(),
        page_handles: vec![
            "11111111111111111111111111111111".into(),
            "22222222222222222222222222222222".into(),
        ],
    })
}

#[test]
fn original_advisory_pages_reproduce_under_closed_opaque_cursors() -> Result<()> {
    let snapshot = fixture()?;
    let now = &snapshot.pages[0].as_of;
    let bytes = snapshot.to_bytes()?;
    let retained = AdvisoryReadSnapshotV1::from_slice(&bytes)?;
    assert_eq!(retained, snapshot);
    let mut query = snapshot.selection.clone();
    query.resource_scope = None;
    let first = retained.page(&query, now)?;
    assert_eq!(first.page, snapshot.pages[0]);
    assert!(first.page.next_record.is_none());
    assert_eq!(AdvisoryPageV2::from_slice(&first.to_bytes()?)?, first);
    query.resource_scope = snapshot.selection.resource_scope.clone();
    query.cursor = first.next_cursor.clone();
    let second = retained.page(&query, now)?;
    assert_eq!(second.page, snapshot.pages[1]);
    assert_eq!(second.page.as_of, first.page.as_of);
    query.cursor = second.next_cursor;
    let third = retained.page(&query, now)?;
    assert_eq!(third.page, snapshot.pages[2]);
    assert!(third.next_cursor.is_none());
    assert!(third.page.revisions[0].record.withdrawn.is_some());
    assert_eq!(
        AdvisoryQueryV2::from_slice(&serde_json::to_vec(&query)?)?,
        query
    );
    Ok(())
}

#[test]
fn changed_selection_forged_handles_wrong_kinds_and_expiry_are_refused() -> Result<()> {
    let snapshot = fixture()?;
    let now = &snapshot.pages[0].as_of;
    let first = snapshot.page(&snapshot.selection, now)?;
    let mut query = snapshot.selection.clone();
    query.cursor = first.next_cursor;
    for field in ["scope", "advisory", "limit", "assessment"] {
        let mut changed = query.clone();
        match field {
            "scope" => changed.resource_scope = Some("other-incarnation".into()),
            "advisory" => changed.advisory_id = "CVE-2026-99999".into(),
            "limit" => changed.limit = 2,
            "assessment" => {
                changed.assessment_digest = Some(Sha256Digest::of_bytes("other assessment"))
            }
            _ => unreachable!(),
        }
        assert!(snapshot.page(&changed, now).is_err());
    }
    let mut forged = query.clone();
    forged.cursor = Some(format!(
        "c1:{}:33333333333333333333333333333333",
        snapshot.digest()?.hex()
    ));
    assert!(snapshot.page(&forged, now).is_err());
    let mut foreign = query.clone();
    foreign.cursor = Some(format!(
        "s1:{}:11111111111111111111111111111111",
        snapshot.digest()?.hex()
    ));
    assert!(foreign.validate().is_err());
    let mut changed_digest = query.clone();
    changed_digest.cursor = Some(format!(
        "c1:{}:11111111111111111111111111111111",
        Sha256Digest::of_bytes("foreign capture").hex()
    ));
    assert!(snapshot.page(&changed_digest, now).is_err());
    assert!(snapshot.page(&query, &snapshot.expires_at).is_err());
    assert!(
        snapshot
            .page(
                &query,
                &Timestamp::from_unix_seconds(now.unix_seconds() - 1)?
            )
            .is_err()
    );
    query.resource_scope = None;
    assert!(query.validate().is_err());
    Ok(())
}

#[test]
fn captures_reject_corruption_and_preserve_explicit_empty_history() -> Result<()> {
    let snapshot = fixture()?;
    let mut corrupt = snapshot.clone();
    corrupt.page_handles[1] = corrupt.page_handles[0].clone();
    assert!(corrupt.to_bytes().is_err());
    let mut corrupt = snapshot.clone();
    corrupt.pages[1].revisions[0].record.summary = "Uncommitted revision".into();
    assert!(corrupt.to_bytes().is_err());
    let mut corrupt = snapshot.clone();
    corrupt.pages[1].as_of =
        Timestamp::from_unix_seconds(snapshot.pages[0].as_of.unix_seconds() + 1)?;
    assert!(corrupt.to_bytes().is_err());
    let mut corrupt = snapshot.clone();
    corrupt.expires_at =
        Timestamp::from_unix_seconds(snapshot.pages[0].as_of.unix_seconds() + 901)?;
    assert!(corrupt.to_bytes().is_err());
    let mut corrupt = serde_json::to_value(&snapshot)?;
    corrupt["unexpected"] = true.into();
    assert!(AdvisoryReadSnapshotV1::from_slice(&serde_json::to_vec(&corrupt)?).is_err());

    let mut empty = snapshot;
    empty.pages.truncate(1);
    empty.pages[0].revisions.clear();
    empty.page_handles.clear();
    let page = empty.page(&empty.selection, &empty.pages[0].as_of)?;
    assert!(page.page.revisions.is_empty());
    assert!(page.next_cursor.is_none());
    Ok(())
}
