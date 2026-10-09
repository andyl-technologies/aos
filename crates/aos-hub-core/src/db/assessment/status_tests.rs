//! Unassessed inventory visibility and independently pending profile projections.

use anyhow::Result;
use aos_assessment::input::Profile;

use super::scans_tests::setup;

#[tokio::test]
async fn status_includes_unassessed_subjects_and_tracks_each_profile_independently() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let profiles = [Profile::Updates, Profile::Vulnerabilities];
    let initial = db
        .assessment_status_page(registry_id, &profiles, "", 10)
        .await?;
    assert_eq!(initial.subjects.len(), 1);
    assert_eq!(initial.subjects[0].profiles.len(), 2);
    for state in &initial.subjects[0].profiles {
        assert_eq!(state.committed_generation, 0);
        assert!(!state.fresh && !state.pending);
        assert!(state.assessment_digest.is_none());
    }
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let pending = db
        .assessment_status_page(registry_id, &profiles, "", 10)
        .await?;
    assert!(pending.subjects[0].profiles[0].pending);
    assert_eq!(
        pending.subjects[0].profiles[0].desired_generation,
        scan.generation
    );
    assert!(!pending.subjects[0].profiles[0].fresh);
    assert!(!pending.subjects[0].profiles[1].pending);
    assert_eq!(pending.subjects[0].profiles[1].desired_generation, 0);
    assert!(
        db.assessment_status_page(registry_id, &profiles, "subject", 10)
            .await?
            .subjects
            .is_empty()
    );
    assert!(
        db.assessment_status_page(
            registry_id,
            &[Profile::Vulnerabilities, Profile::Updates],
            "",
            10
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn scan_lists_exclude_partial_admissions_and_foreign_registry_rows() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let rows = db.assessment_scan_summaries(registry_id, "", 10).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].scan_id, scan.scan_id);
    assert_eq!(rows[0].request_digest, scan.request_digest);
    assert!(
        db.assessment_scan_summaries(registry_id, &scan.scan_id, 10)
            .await?
            .is_empty()
    );
    let foreign = db
        .register_registry("other-assessment-fixture", &[], false)
        .await?;
    assert!(
        db.assessment_scan_summaries(foreign, "", 10)
            .await?
            .is_empty()
    );
    db.backend
        .execute(
            "UPDATE assessment_scans SET admission_complete = 0 WHERE scan_id = ?1",
            &vals![@slice scan.scan_id],
        )
        .await?;
    assert!(
        db.assessment_scan_summaries(registry_id, "", 10)
            .await?
            .is_empty()
    );
    assert!(
        db.assessment_scan_summaries(registry_id, "", 101)
            .await
            .is_err()
    );
    Ok(())
}
