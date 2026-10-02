//! Case expansion and assessment tests over destination profiles.

use crate::artifact::{ArtifactKind, ArtifactRelation, ArtifactRelationship};
use crate::digest::Sha256Digest;
use crate::evidence::{EvidenceRecord, GateResult};
use crate::manifest::PackageResult;
use crate::plan::PlatformCell;
use crate::platform::{MatrixCell, Platform};
use crate::qualification::QualificationPhase;
use crate::qualification_evidence::{assess_observations, cases, validate_observations};
use crate::signing::SignerRole;
use crate::verify::tests::{
    EDGE, STABLE, artifact, digest, final_set, observations, package_id, planned,
    qualification_fixture, rebind, release_fixture, testing_fixture,
};

#[test]
fn shared_contract_has_exact_package_image_and_release_cases() -> anyhow::Result<()> {
    use crate::qualification::QualificationScope;
    let (plan, manifest) = qualification_fixture()?;
    let cases = cases(&plan, &manifest, Some(STABLE), QualificationPhase::Staging)?;
    let package_cases: Vec<_> = cases
        .iter()
        .filter(|case| case.requirement_id == "package-function")
        .collect();
    assert_eq!(package_cases.len(), 4);
    assert!(
        package_cases
            .iter()
            .all(|case| case.subjects.len() == 1 && case.platform.is_some())
    );
    assert!(
        cases
            .iter()
            .filter(|case| case.requirement_id.starts_with("image-"))
            .all(|case| case.platform.is_some_and(Platform::supports_images))
    );
    assert!(
        cases
            .iter()
            .find(|case| case.requirement_id == "staging-delivery")
            .unwrap()
            .platform
            .is_none()
    );
    // Native recovery remains a release obligation; operational recovery
    // exercises are admitted separately through the fitness requirements.
    let release_recovery: Vec<_> = cases
        .iter()
        .filter(|case| case.requirement_id.ends_with("-recovery") && case.target.is_none())
        .map(|case| case.requirement_id.as_str())
        .collect();
    assert_eq!(release_recovery, ["ability-native-recovery"]);
    let policy = &plan.qualification;
    assert!(
        policy
            .requirements
            .iter()
            .any(|gate| gate.scope == QualificationScope::Containers)
    );
    let records = observations(&plan, &manifest, Some(STABLE), QualificationPhase::Staging)?;
    validate_observations(
        &plan,
        &manifest,
        Some(STABLE),
        QualificationPhase::Staging,
        &records,
        "2026-09-01T00:00:02Z",
        None,
    )?;
    Ok(())
}

#[test]
fn package_cases_inherit_the_strongest_runtime_consumer_role() -> anyhow::Result<()> {
    use crate::qualification::{PackageRole, PackageRule};

    let (mut plan, mut manifest) = qualification_fixture()?;
    let dependency_name = "dependency";
    let dependency_id = |platform| format!("package/{dependency_name}/{platform}");

    let mut dependency_plan = plan.packages[0].clone();
    dependency_plan.name = dependency_name.to_owned();
    dependency_plan.platforms = Platform::ALL
        .into_iter()
        .map(|platform| PlatformCell {
            platform,
            decision: MatrixCell::Artifact {
                artifact: planned(&[dependency_id(platform)]),
            },
        })
        .collect();
    plan.packages.push(dependency_plan);
    plan.packages
        .sort_by(|left, right| left.name.cmp(&right.name));

    let dependency_result = PackageResult {
        name: dependency_name.to_owned(),
        platforms: Platform::ALL
            .into_iter()
            .map(|platform| PlatformCell {
                platform,
                decision: MatrixCell::Artifact {
                    artifact: final_set(&[dependency_id(platform)]),
                },
            })
            .collect(),
    };
    manifest.packages.push(dependency_result);
    manifest
        .packages
        .sort_by(|left, right| left.name.cmp(&right.name));

    for platform in Platform::ALL {
        let id = dependency_id(platform);
        let (artifact, _) = artifact(
            id.clone(),
            ArtifactKind::PackageNar,
            Some(platform),
            None,
            vec![
                ArtifactRelationship {
                    relation: ArtifactRelation::AuthenticatedBy,
                    target: "cache/example.narinfo".to_owned(),
                },
                ArtifactRelationship {
                    relation: ArtifactRelation::CorrespondingSource,
                    target: "source/example".to_owned(),
                },
                ArtifactRelationship {
                    relation: ArtifactRelation::LicensedBy,
                    target: "license/example".to_owned(),
                },
            ],
        )?;
        manifest.artifacts.push(artifact);
        manifest
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.id == package_id(platform))
            .unwrap()
            .relationships
            .push(ArtifactRelationship {
                relation: ArtifactRelation::Contains,
                target: id,
            });
    }

    let policy = &mut plan.qualification;
    policy.package_rules = vec![
        PackageRule {
            name: dependency_name.to_owned(),
            role: PackageRole::GeneralCatalog,
            inherit_dependency_obligations: true,
            execution: None,
        },
        PackageRule {
            name: "example".to_owned(),
            role: PackageRole::SystemIntegrity,
            inherit_dependency_obligations: true,
            execution: None,
        },
    ];
    rebind(&mut plan)?;

    let cases = cases(&plan, &manifest, Some(STABLE), QualificationPhase::Staging)?;
    let dependency_cases = cases
        .iter()
        .filter(|case| {
            case.id
                .starts_with(&format!("package-function/{dependency_name}/"))
        })
        .collect::<Vec<_>>();

    assert_eq!(dependency_cases.len(), Platform::ALL.len());
    assert!(
        dependency_cases
            .iter()
            .all(|case| case.package_role == Some(PackageRole::SystemIntegrity))
    );

    Ok(())
}

#[test]
fn recovery_package_case_binds_the_matching_image_and_predecessor() -> anyhow::Result<()> {
    use crate::qualification::PackageExecution;

    let (mut plan, mut manifest) = qualification_fixture()?;
    let platform = Platform::X86_64Linux;
    let package = manifest
        .packages
        .iter_mut()
        .find(|package| package.name == "example")
        .unwrap();
    package.platforms.retain(|cell| cell.platform == platform);
    for cell in &mut plan
        .packages
        .iter_mut()
        .find(|package| package.name == "example")
        .unwrap()
        .platforms
    {
        if cell.platform != platform {
            cell.decision = MatrixCell::NotApplicable {
                rule: "recovery-execution-fixture".into(),
                reason: "This fixture exercises recovery on x86_64 Linux only.".into(),
            };
        }
    }
    let package_subjects = match &package.platforms[0].decision {
        MatrixCell::Artifact { artifact } => artifact.artifact_ids.clone(),
        MatrixCell::Blocked { .. } | MatrixCell::NotApplicable { .. } => unreachable!(),
    };
    let image = manifest
        .images
        .iter()
        .find(|image| image.system_variant == "server")
        .unwrap();
    let image_subjects = match &image
        .platforms
        .iter()
        .find(|cell| cell.platform == platform)
        .unwrap()
        .decision
    {
        MatrixCell::Artifact { artifact } => artifact.artifact_ids.clone(),
        MatrixCell::Blocked { .. } | MatrixCell::NotApplicable { .. } => unreachable!(),
    };
    let policy = &mut plan.qualification;
    policy
        .package_rules
        .iter_mut()
        .find(|rule| rule.name == "example")
        .unwrap()
        .execution = Some(PackageExecution::RecoveryImage {
        system_variant: "server".into(),
    });
    rebind(&mut plan)?;

    let expanded = cases(&plan, &manifest, Some(STABLE), QualificationPhase::Staging)?;
    let case = expanded
        .iter()
        .find(|case| case.id == "package-function/example/x86_64-linux")
        .unwrap();
    let mut expected = package_subjects;
    expected.extend(image_subjects);
    expected.sort();
    expected.dedup();

    assert_eq!(case.subjects, expected);
    assert_eq!(case.predecessor, plan.qualification_predecessor);

    let mut missing_predecessor = plan.clone();
    missing_predecessor.qualification_predecessor = None;
    assert!(
        cases(
            &missing_predecessor,
            &manifest,
            Some(STABLE),
            QualificationPhase::Staging,
        )
        .is_err()
    );
    let mut missing_image = manifest.clone();
    missing_image
        .images
        .retain(|image| image.system_variant != "server");
    assert!(
        cases(
            &plan,
            &missing_image,
            Some(STABLE),
            QualificationPhase::Staging,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn qualification_classifies_eligible_and_blocked_packages() -> anyhow::Result<()> {
    let (mut plan, _) = qualification_fixture()?;
    let mut excluded = plan.packages[0].clone();
    excluded.name = "excluded-source-component".into();
    for cell in &mut excluded.platforms {
        cell.decision = MatrixCell::NotApplicable {
            rule: "source-only".into(),
            reason: "Retained as source, never published as a package.".into(),
        };
    }
    plan.packages.push(excluded);

    // Classification covers the full inventory, including source-only roots.
    assert!(
        plan.qualification
            .validate_plan(&plan)
            .unwrap_err()
            .to_string()
            .contains("complete package inventory")
    );
    let mut classification = plan.qualification.package_rules[0].clone();
    classification.name = "excluded-source-component".into();
    plan.qualification.package_rules.push(classification);
    rebind(&mut plan)?;
    plan.qualification.validate_plan(&plan)?;

    // A classified blocked target still fails this profile's completeness floor.
    let added = plan.packages.last_mut().unwrap();
    added.platforms[0].decision = MatrixCell::Blocked {
        required_work: "Complete target support.".into(),
        failure_evidence: crate::digest::Sha256Digest::of_bytes(b"blocked"),
    };
    assert!(
        plan.qualification
            .validate_plan(&plan)
            .unwrap_err()
            .to_string()
            .contains("complete package matrix")
    );

    plan.packages.pop();
    plan.qualification
        .package_rules
        .retain(|rule| rule.name != "excluded-source-component");
    rebind(&mut plan)?;
    let mut unclassified = plan.packages[0].clone();
    unclassified.name = "unclassified-published-package".into();
    plan.packages.push(unclassified);
    assert!(
        plan.qualification
            .validate_plan(&plan)
            .unwrap_err()
            .to_string()
            .contains("complete package inventory")
    );
    Ok(())
}

#[test]
fn qualification_binds_private_plan_without_requesting_it_as_a_public_object() -> anyhow::Result<()>
{
    let (plan, manifest) = qualification_fixture()?;
    let private_plan = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::ReleasePlan)
        .unwrap();
    let mut changed_plan = plan.clone();
    changed_plan.release_id = "different-release".into();
    for phase in [
        QualificationPhase::Build,
        QualificationPhase::Staging,
        QualificationPhase::Rollout,
        QualificationPhase::Complete,
    ] {
        let original = cases(&plan, &manifest, Some(STABLE), phase)?;
        let changed = cases(&changed_plan, &manifest, Some(STABLE), phase)?;
        assert!(!original.is_empty());
        for (before, after) in original.iter().zip(&changed) {
            assert!(!before.subjects.contains(&private_plan.id));
            assert_ne!(before.digest()?, after.digest()?);
        }
    }
    Ok(())
}

#[test]
fn missing_oci_artifact_and_removed_plan_gate_fail_closed() -> anyhow::Result<()> {
    let (mut plan, mut manifest) = qualification_fixture()?;
    plan.destinations
        .iter_mut()
        .find(|destination| destination.name == STABLE)
        .unwrap()
        .gates
        .pop();
    assert!(plan.validate().is_err());
    let (plan, _) = qualification_fixture()?;
    manifest
        .artifacts
        .retain(|artifact| artifact.kind != ArtifactKind::OciManifest);
    assert!(cases(&plan, &manifest, Some(STABLE), QualificationPhase::Staging).is_err());
    Ok(())
}

#[test]
fn qualification_rejects_missing_failed_replayed_and_stale_observations() -> anyhow::Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let records = observations(&plan, &manifest, Some(STABLE), QualificationPhase::Staging)?;
    let check = |records: &[EvidenceRecord], now| {
        validate_observations(
            &plan,
            &manifest,
            Some(STABLE),
            QualificationPhase::Staging,
            records,
            now,
            None,
        )
    };
    let now = "2026-09-01T00:00:02Z";
    assert!(check(&records[1..], now).is_err());
    let mut failed = records.clone();
    failed[0].result = GateResult::Failed;
    assert!(check(&failed, now).is_err());
    let mut replay = records.clone();
    replay[0].qualification.as_mut().unwrap().case_digest = digest("another-case");
    assert!(check(&replay, now).is_err());
    let mut missing = records.clone();
    missing[0].qualification.as_mut().unwrap().checks.clear();
    assert!(check(&missing, now).is_err());
    let mut future = records.clone();
    future[0].finished_at = "2026-09-02T00:00:00Z".into();
    assert!(check(&future, now).is_err());
    assert!(check(&records, "2026-10-02T00:00:02Z").is_err());
    let mut wrong_prior = records.clone();
    let update = wrong_prior
        .iter_mut()
        .find(|record| {
            record
                .qualification
                .as_ref()
                .is_some_and(|observation| observation.predecessor.is_some())
        })
        .unwrap();
    update.qualification.as_mut().unwrap().predecessor = None;
    assert!(check(&wrong_prior, now).is_err());
    assert!(
        validate_observations(
            &plan,
            &manifest,
            Some(STABLE),
            QualificationPhase::Complete,
            &records,
            now,
            None,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn completion_requires_measured_soak_and_nonzero_operation_denominators() -> anyhow::Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let mut records = observations(&plan, &manifest, Some(STABLE), QualificationPhase::Complete)?;
    let check = |records: &[EvidenceRecord]| {
        validate_observations(
            &plan,
            &manifest,
            Some(STABLE),
            QualificationPhase::Complete,
            records,
            "2026-09-15T00:00:01Z",
            None,
        )
    };
    assert!(check(&records).is_err());
    for record in &mut records {
        record.finished_at = "2026-09-15T00:00:00Z".into();
        record.qualification.as_mut().unwrap().observed_seconds = 1209600;
    }
    check(&records)?;
    records[0]
        .qualification
        .as_mut()
        .unwrap()
        .operations
        .clear();
    assert!(check(&records).is_err());
    Ok(())
}

#[test]
fn gates_follow_each_destination_profile() -> anyhow::Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let ids = |name: &str| -> Vec<String> {
        plan.destination(name)
            .unwrap()
            .gates
            .iter()
            .map(|gate| gate.policy_id.clone())
            .collect()
    };

    assert_eq!(ids("staging/stable"), ["build-integrity"]);
    let candidate = ids("production/candidate");
    assert!(candidate.contains(&"rollout-health".to_owned()));
    assert!(!candidate.contains(&"rollout-observation".to_owned()));
    assert!(candidate.iter().any(|id| id.ends_with("-functional")));
    assert!(!candidate.iter().any(|id| id.ends_with("-qualified")));
    let stable = ids(STABLE);
    assert!(stable.contains(&"rollout-observation".to_owned()));
    assert!(stable.iter().any(|id| id.ends_with("-qualified")));

    // A build-profile destination has nothing to observe after the build.
    assert!(
        cases(
            &plan,
            &manifest,
            Some("staging/stable"),
            QualificationPhase::Staging
        )?
        .is_empty()
    );
    assert_eq!(
        cases(
            &plan,
            &manifest,
            Some("staging/stable"),
            QualificationPhase::Build
        )?
        .len(),
        1
    );
    assert!(
        cases(
            &plan,
            &manifest,
            Some("production/candidate"),
            QualificationPhase::Complete
        )?
        .is_empty()
    );
    assert!(
        cases(
            &plan,
            &manifest,
            Some("production/edge"),
            QualificationPhase::Staging
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn smoke_drops_image_claims_when_the_release_is_not_image_affecting() -> anyhow::Result<()> {
    let (mut plan, manifest) = testing_fixture()?;
    let smoke = cases(&plan, &manifest, Some(EDGE), QualificationPhase::Staging)?;
    assert!(
        !smoke
            .iter()
            .any(|case| case.requirement_id.starts_with("claim-disk-"))
    );
    assert!(
        smoke
            .iter()
            .any(|case| case.requirement_id.starts_with("claim-container-"))
    );
    let packages: Vec<_> = smoke
        .iter()
        .filter(|case| case.requirement_id == "package-function")
        .map(|case| case.id.as_str())
        .collect();
    assert_eq!(packages, ["package-function/example/x86_64-linux"]);
    assert!(
        cases(
            &plan,
            &manifest,
            Some("staging/edge"),
            QualificationPhase::Staging
        )?
        .is_empty()
    );

    let records = observations(&plan, &manifest, Some(EDGE), QualificationPhase::Staging)?;
    validate_observations(
        &plan,
        &manifest,
        Some(EDGE),
        QualificationPhase::Staging,
        &records,
        "2026-09-01T00:00:02Z",
        None,
    )?;

    plan.change_scope.as_mut().unwrap().image_affecting = true;
    rebind(&mut plan)?;
    let affected = cases(&plan, &manifest, Some(EDGE), QualificationPhase::Staging)?;
    assert!(
        affected
            .iter()
            .any(|case| case.requirement_id.starts_with("claim-disk-"))
    );

    // Without a recorded scope a change-scoped destination cannot be planned.
    plan.change_scope = None;
    assert!(plan.validate().is_err());
    Ok(())
}

#[test]
fn soak_profile_requires_a_week_of_observation_for_qualified_claims() -> anyhow::Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let complete = cases(&plan, &manifest, Some(STABLE), QualificationPhase::Complete)?;
    assert!(
        complete
            .iter()
            .filter(|case| case.claim.is_some())
            .all(|case| case.minimum_observed_seconds == Some(604_800))
    );

    let mut records = observations(&plan, &manifest, Some(STABLE), QualificationPhase::Complete)?;
    let now = "2026-09-08T00:00:01Z";
    for record in &mut records {
        record.finished_at = "2026-09-08T00:00:00Z".into();
        record.qualification.as_mut().unwrap().observed_seconds = 604_800;
    }
    let check = |records: &[EvidenceRecord]| {
        validate_observations(
            &plan,
            &manifest,
            Some(STABLE),
            QualificationPhase::Complete,
            records,
            now,
            None,
        )
    };
    check(&records)?;
    for index in 0..records.len() {
        let mut short = records.clone();
        short[index]
            .qualification
            .as_mut()
            .unwrap()
            .observed_seconds = 604_799;
        assert!(
            check(&short).is_err(),
            "accepted a short window for {}",
            short[index].id
        );
    }
    Ok(())
}

#[test]
fn effective_profile_must_match_the_planned_destination() -> anyhow::Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let records = observations(&plan, &manifest, Some(STABLE), QualificationPhase::Staging)?;
    let planned = plan.destination(STABLE)?.effective();
    let now = "2026-09-01T00:00:02Z";
    assess_observations(
        &plan,
        &manifest,
        Some(STABLE),
        QualificationPhase::Staging,
        &records,
        now,
        Some(&planned),
    )?;
    let mut relaxed = planned;
    relaxed.soak_seconds = 86_400;
    assert!(
        assess_observations(
            &plan,
            &manifest,
            Some(STABLE),
            QualificationPhase::Staging,
            &records,
            now,
            Some(&relaxed),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn qualification_admission_is_fresh_and_bound_to_the_destination_ring() -> anyhow::Result<()> {
    use crate::qualification_admission::{
        QUALIFICATION_ADMISSION, QualificationAdmission, QualificationRolloutIntent,
    };

    let (plan, _) = qualification_fixture()?;
    let role = plan
        .signers
        .iter()
        .find(|role| role.role == SignerRole::Qualification)
        .unwrap();
    let mut admission = QualificationAdmission {
        schema_version: QUALIFICATION_ADMISSION.into(),
        phase: QualificationPhase::Complete,
        destination: STABLE.into(),
        rollout: None,
        registry: plan.registry.clone(),
        release_id: plan.release_id.clone(),
        plan_digest: Sha256Digest::of_bytes(crate::canonical::to_vec(&plan)?),
        manifest_digest: digest("manifest"),
        publication_receipt_digest: digest("publication"),
        journal_digest: digest("journal"),
        report_digest: digest("report"),
        policy_digest: plan.public_evidence_policy_digest,
        authority_id: role.key_ids[0].clone(),
        admitted_at: "2026-09-01T00:00:00Z".into(),
    };
    assert!(admission.validate(&plan, "2026-09-01T00:10:00Z").is_ok());
    assert!(admission.validate(&plan, "2026-09-01T00:10:01Z").is_err());
    assert!(admission.validate(&plan, "2026-08-31T23:59:59Z").is_err());

    let mut unplanned = admission.clone();
    unplanned.destination = "production/edge".into();
    assert!(unplanned.validate(&plan, "2026-09-01T00:00:00Z").is_err());
    let mut unknown = admission.clone();
    unknown.schema_version = "aos.release.qualification-admission/v0".into();
    assert!(unknown.validate(&plan, "2026-09-01T00:00:00Z").is_err());

    let destination = plan.destination(STABLE)?;
    admission.phase = QualificationPhase::Rollout;
    admission.rollout = Some(QualificationRolloutIntent::for_ring(destination, 2, 1)?);
    assert_eq!(
        admission
            .rollout
            .as_ref()
            .map(|intent| (intent.first_partition, intent.last_partition)),
        Some((4, 31))
    );
    assert!(admission.validate(&plan, "2026-09-01T00:00:00Z").is_ok());
    admission.rollout.as_mut().unwrap().last_partition = 255;
    assert!(admission.validate(&plan, "2026-09-01T00:00:00Z").is_err());
    assert!(QualificationRolloutIntent::for_ring(destination, 5, 1).is_err());
    assert!(QualificationRolloutIntent::for_ring(destination, 0, 1).is_err());

    admission.plan_digest = digest("another plan");
    assert!(admission.validate(&plan, "2026-09-01T00:00:00Z").is_err());
    Ok(())
}

#[test]
fn independent_review_follows_the_destination_review_threshold() -> anyhow::Result<()> {
    use crate::qualification_admission::{
        QUALIFICATION_REVIEW, QualificationReview, verify_reviews,
    };
    use crate::receipt::{RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT, SignedReceiptEnvelope};
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    let fixture = release_fixture()?;
    let (plan, _) = qualification_fixture()?;
    let report = b"exact reviewed observations";
    let review = QualificationReview {
        schema_version: QUALIFICATION_REVIEW.into(),
        plan_digest: Sha256Digest::of_bytes(crate::canonical::to_vec(&plan)?),
        report_digest: Sha256Digest::of_bytes(report),
        authority_id: fixture.key.key_id.clone(),
        accepted: true,
    };
    let signature = SigningKey::from_bytes(&[7_u8; 32]).sign(
        Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, crate::canonical::to_vec(&review)?)
            .as_bytes(),
    );
    let envelope = SignedReceiptEnvelope {
        schema_version: SIGNED_RECEIPT.into(),
        key_id: fixture.key.key_id.clone(),
        payload: serde_json::to_value(review)?,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    };
    let bytes = crate::canonical::to_vec(&envelope)?;
    let keys = [fixture.key];
    let reviewed = STABLE;

    assert!(verify_reviews(&plan, reviewed, report, &[bytes.clone()], &keys).is_ok());
    assert!(verify_reviews(&plan, reviewed, report, &[], &keys).is_err());
    assert!(
        verify_reviews(
            &plan,
            reviewed,
            report,
            &[bytes.clone(), bytes.clone()],
            &keys
        )
        .is_err()
    );
    assert!(verify_reviews(&plan, reviewed, b"changed report", &[bytes.clone()], &keys).is_err());
    // The build profile demands no review, but a supplied review must verify.
    assert!(verify_reviews(&plan, "staging/stable", report, &[], &keys).is_ok());
    assert!(verify_reviews(&plan, "staging/stable", b"other", &[bytes], &keys).is_err());
    assert!(verify_reviews(&plan, "production/edge", report, &[], &keys).is_err());
    Ok(())
}

#[test]
fn observations_cannot_be_replayed_for_changed_bytes_with_the_same_artifact_ids()
-> anyhow::Result<()> {
    let (plan, mut manifest) = qualification_fixture()?;
    let evidence = observations(&plan, &manifest, Some(STABLE), QualificationPhase::Staging)?;
    let check = |plan, manifest| {
        validate_observations(
            plan,
            manifest,
            Some(STABLE),
            QualificationPhase::Staging,
            &evidence,
            "2026-09-01T00:00:02Z",
            None,
        )
    };
    let artifact = manifest
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.kind == ArtifactKind::PackageNar)
        .unwrap();
    artifact.sha256 = digest("changed package bytes, unchanged logical artifact id");
    assert!(check(&plan, &manifest).is_err());

    let (mut another_plan, manifest) = qualification_fixture()?;
    another_plan.release_id = "another-release-with-the-same-artifacts".into();
    assert!(check(&another_plan, &manifest).is_err());
    Ok(())
}

#[test]
fn qualification_snapshot_uses_current_build_policy_but_cannot_be_published() -> anyhow::Result<()>
{
    let (mut snapshot, manifest) = qualification_fixture()?;
    let transition_requirements = [
        "image-update-recovery",
        super::NATIVE_ADAPTER_MATRIX_REQUIREMENT,
    ];
    let candidate_cases = cases(&snapshot, &manifest, None, QualificationPhase::Staging)?;
    let matrix_cases: Vec<_> = candidate_cases
        .iter()
        .filter(|case| case.requirement_id == super::NATIVE_ADAPTER_MATRIX_REQUIREMENT)
        .collect();
    assert!(!matrix_cases.is_empty());
    assert!(matrix_cases.iter().all(|case| case.predecessor.is_some()));

    let recovery_cases: Vec<_> = candidate_cases
        .iter()
        .filter(|case| {
            case.claim.as_ref().is_some_and(|claim| {
                claim.minimum_assurance >= crate::qualification::claims::AssuranceLevel::A2
                    && claim
                        .requirements
                        .iter()
                        .any(|id| id == "image-update-recovery")
            })
        })
        .collect();
    assert!(!recovery_cases.is_empty());
    assert!(recovery_cases.iter().all(|case| case.predecessor.is_some()));

    snapshot.qualification_predecessor = None;
    snapshot.release_id = format!(
        "{}{}",
        crate::plan::QUALIFICATION_SNAPSHOT_RELEASE_PREFIX,
        snapshot.version
    );
    snapshot.source.source_tag = format!(
        "{}{}",
        crate::plan::QUALIFICATION_SNAPSHOT_TAG_PREFIX,
        snapshot.version
    );
    let destinations = std::mem::take(&mut snapshot.destinations);

    snapshot.validate()?;
    assert!(snapshot.require_publishable_qualification().is_err());
    let staging_cases = cases(&snapshot, &manifest, None, QualificationPhase::Staging)?;
    assert!(!staging_cases.is_empty());
    assert!(staging_cases.iter().all(|case| {
        !transition_requirements.contains(&case.requirement_id.as_str())
            && case.predecessor.is_none()
            && case.claim.as_ref().is_none_or(|claim| {
                claim
                    .requirements
                    .iter()
                    .all(|id| !transition_requirements.contains(&id.as_str()))
            })
    }));
    assert!(
        cases(
            &snapshot,
            &manifest,
            Some(STABLE),
            QualificationPhase::Staging
        )
        .is_err()
    );

    let mut ordinary_name = snapshot.clone();
    ordinary_name.release_id = "ordinary-release".into();
    assert!(ordinary_name.validate().is_err());

    let mut ordinary_tag = snapshot.clone();
    ordinary_tag.source.source_tag = "release/ordinary".into();
    assert!(ordinary_tag.validate().is_err());

    let mut published = snapshot;
    published.destinations = destinations;
    assert!(published.validate().is_err());
    Ok(())
}
