//! Selection completeness, inventory race and bounded pagination tests.

use crate::cli::{AssessmentFreshnessArg, AssessmentProfileArg};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::application::{ProfileStatus, SubjectStatus};

use super::*;

fn args(packages: &[&str]) -> HubAssessmentScanSelectionArgs {
    HubAssessmentScanSelectionArgs {
        profiles: vec![AssessmentProfileArg::All],
        packages: packages.iter().map(|package| (*package).into()).collect(),
        freshness: Some(AssessmentFreshnessArg::Offline),
        idempotency_key: Some("fixture-selection".into()),
    }
}

fn page(subject: &str, coordinate: &str, more: bool) -> Result<AssessmentStatusV1> {
    Ok(AssessmentStatusV1 {
        schema: "aos.assessment-status/v1".into(),
        resource_scope: "registry-unique-incarnation".into(),
        inventory_digest: Sha256Digest::of_bytes("inventory"),
        inventory_revision: 7,
        policy_digest: Sha256Digest::of_bytes("policy"),
        as_of: Timestamp::from_unix_seconds(1_800_000_000)?,
        subjects: vec![SubjectStatus {
            subject_ref: subject.into(),
            package_coordinate: coordinate.into(),
            version: "1.2.0".into(),
            platform: "x86_64-linux".into(),
            output: "out".into(),
            profiles: assessment_profiles(&[AssessmentProfileArg::All])
                .into_iter()
                .map(|profile| ProfileStatus {
                    profile,
                    desired_generation: 0,
                    committed_generation: 0,
                    assessment_digest: None,
                    input_digest: None,
                    validated_until: None,
                    fresh: false,
                    pending: false,
                })
                .collect(),
        }],
        next_subject: more.then(|| subject.into()),
    })
}

#[test]
fn complete_pages_pin_all_versions_of_exact_coordinates_and_explicit_profiles() -> Result<()> {
    let args = args(&["fixture/package", "fixture/package"]);
    let mut selection = Selection::new(assessment_profiles(&args.profiles), &args.packages);
    selection.push(&page("a", "fixture/package", true)?)?;
    selection.push(&page("b", "fixture/unselected", true)?)?;
    selection.push(&page("c", "fixture/package", false)?)?;
    let request = selection.finish(&args)?;
    assert_eq!(request.subjects, ["a", "c"]);
    assert_eq!(request.inventory_revision, 7);
    assert_eq!(
        request.profiles,
        [
            Profile::LicenseSignals,
            Profile::Updates,
            Profile::Vulnerabilities
        ]
    );
    assert_eq!(request.freshness, FreshnessMode::Offline);
    assert_eq!(request.idempotency_key, "fixture-selection");
    Ok(())
}

#[test]
fn unknown_coordinates_and_unfinished_inventory_never_produce_submissions() -> Result<()> {
    let args = args(&["fixture/package", "fixture/absent"]);
    let mut selection = Selection::new(assessment_profiles(&args.profiles), &args.packages);
    selection.push(&page("a", "fixture/package", false)?)?;
    assert!(selection.finish(&args).is_err());
    let mut partial = Selection::new(assessment_profiles(&args.profiles), &[]);
    partial.push(&page("a", "fixture/package", true)?)?;
    assert!(partial.finish(&args).is_err());
    Ok(())
}

#[test]
fn every_inventory_policy_revision_and_resource_change_requires_restart() -> Result<()> {
    for change in 0..4 {
        let args = args(&[]);
        let mut selection = Selection::new(assessment_profiles(&args.profiles), &[]);
        selection.push(&page("a", "fixture/package", true)?)?;
        let mut next = page("b", "fixture/package", false)?;
        match change {
            0 => next.resource_scope = "replacement-registry-incarnation".into(),
            1 => next.inventory_revision += 1,
            2 => next.inventory_digest = Sha256Digest::of_bytes("replacement inventory"),
            _ => next.policy_digest = Sha256Digest::of_bytes("replacement policy"),
        }
        assert!(selection.push(&next).is_err());
        assert_eq!(selection.enumerated, 1);
    }
    Ok(())
}

#[test]
fn repeated_positions_and_changed_profile_sets_are_rejected() -> Result<()> {
    let args = args(&[]);
    let mut selection = Selection::new(assessment_profiles(&args.profiles), &[]);
    selection.push(&page("a", "fixture/package", true)?)?;
    assert!(
        selection
            .push(&page("a", "fixture/package", false)?)
            .is_err()
    );
    let mut next = page("b", "fixture/package", false)?;
    next.subjects[0].profiles.pop();
    assert!(selection.push(&next).is_err());
    assert_eq!(selection.subjects, ["a"]);
    Ok(())
}

#[test]
fn enumeration_is_bounded_and_an_empty_complete_inventory_is_unassessable() -> Result<()> {
    let args = args(&[]);
    let mut selection = Selection::new(assessment_profiles(&args.profiles), &[]);
    selection.enumerated = MAX_ENUMERATED_SUBJECTS;
    assert!(
        selection
            .push(&page("a", "fixture/package", false)?)
            .is_err()
    );
    let mut empty = page("a", "fixture/package", false)?;
    empty.subjects.clear();
    let mut selection = Selection::new(assessment_profiles(&args.profiles), &[]);
    selection.push(&empty)?;
    assert!(selection.finish(&args).is_err());
    Ok(())
}
