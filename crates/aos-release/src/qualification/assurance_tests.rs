//! Adversarial admission tests for scoped operational assurance.

use anyhow::Result;

use crate::digest::Sha256Digest;
use crate::evidence::{EvidenceRecord, GateResult, QualificationReportV1};
use crate::qualification::QualificationPhase;
use crate::qualification::claims::{AssuranceLevel, ClaimDisposition};
use crate::qualification::environment::{Accelerator, Backend};
use crate::qualification_evidence::{assess_observations, validate_observations};
use crate::verify::tests::{observations, qualification_fixture};

const NOW: &str = "2026-09-01T00:00:02Z";

fn image_record(records: &mut [EvidenceRecord]) -> &mut EvidenceRecord {
    records
        .iter_mut()
        .find(|record| {
            record.platform == Some(crate::platform::Platform::X86_64Linux)
                && record
                    .qualification
                    .as_ref()
                    .unwrap()
                    .capabilities
                    .is_some()
        })
        .unwrap()
}

#[test]
fn actual_environment_must_match_every_required_dimension() -> Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let original = observations(&plan, &manifest, QualificationPhase::Staging)?;
    for dimension in [
        "accelerator",
        "host-platform",
        "security",
        "resources",
        "driver",
        "kernel",
        "digest",
    ] {
        let mut changed = original.clone();
        let observation = image_record(&mut changed).qualification.as_mut().unwrap();
        let environment = observation.environment.as_mut().unwrap();
        match dimension {
            "accelerator" => {
                if let Backend::Qemu { accelerator, .. } =
                    &mut environment.layers.last_mut().unwrap().backend
                {
                    *accelerator = match accelerator {
                        Accelerator::Tcg => Accelerator::Kvm,
                        Accelerator::Kvm => Accelerator::Tcg,
                    };
                }
            }
            "host-platform" => {
                environment.layers[0].platform = crate::platform::Platform::X86_64Darwin
            }
            "security" => environment.security.verity = false,
            "resources" => environment.resources.memory_mib = 1,
            "driver" => environment.devices[0].driver = "unbound".into(),
            "kernel" => environment.layers[0].kernel_release = None,
            "digest" => environment.firmware = Some("changed-firmware".into()),
            _ => unreachable!(),
        }
        // Even a correctly rehashed incompatible inventory must fail membership.
        if dimension != "digest" {
            observation.environment_digest = environment.digest()?;
        }
        assert!(
            validate_observations(&plan, &manifest, QualificationPhase::Staging, &changed, NOW)
                .is_err(),
            "accepted changed {dimension}"
        );
    }
    Ok(())
}

#[test]
fn cpu_family_scope_and_exact_sku_scope_have_distinct_membership() -> Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let case = crate::qualification_evidence::cases(&plan, &manifest, QualificationPhase::Staging)?
        .into_iter()
        .find(|case| {
            case.platform == Some(crate::platform::Platform::X86_64Linux) && case.target.is_some()
        })
        .unwrap();
    let mut scope = case.target.as_ref().unwrap().environment.clone().unwrap();
    let mut inventory = crate::qualification_fixture::environment(&case)?.unwrap();
    let required = &mut scope.layers.last_mut().unwrap().cpu;
    required.vendors = vec!["AMD".into()];
    required.features = vec!["sse2".into()];
    let actual = &mut inventory.layers.last_mut().unwrap().cpu;
    actual.vendor = "AMD".into();
    actual.features = vec!["sse2".into()];
    actual.sku = Some("tested-sku".into());
    scope.matches(&inventory)?;
    scope.layers.last_mut().unwrap().cpu.skus = vec!["tested-sku".into()];
    scope.matches(&inventory)?;
    inventory.layers.last_mut().unwrap().cpu.sku = Some("another-sku".into());
    assert!(scope.matches(&inventory).is_err());
    inventory.layers.last_mut().unwrap().cpu.sku = None;
    assert!(scope.matches(&inventory).is_err());
    scope.layers.last_mut().unwrap().cpu.skus.clear();
    scope.matches(&inventory)?;
    inventory.layers.last_mut().unwrap().cpu.features.clear();
    assert!(scope.matches(&inventory).is_err());
    Ok(())
}

#[test]
fn cloud_instance_and_region_are_recorded_scope_dimensions() -> Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let case = crate::qualification_evidence::cases(&plan, &manifest, QualificationPhase::Staging)?
        .into_iter()
        .find(|case| {
            case.target
                .as_ref()
                .is_some_and(|target| target.kind == crate::qualification::TargetKind::Image)
        })
        .unwrap();
    let mut scope = case.target.as_ref().unwrap().environment.clone().unwrap();
    let mut inventory = crate::qualification_fixture::environment(&case)?.unwrap();
    scope.layers.remove(0);
    inventory.layers.remove(0);
    let backend = Backend::Cloud {
        provider: "fixture-provider".into(),
        service: "compute".into(),
        sku: "exact-instance".into(),
        region: Some("region-a".into()),
    };
    scope.layers[0].backend = backend.clone();
    inventory.layers[0].backend = backend;
    scope.validate(case.platform.unwrap())?;
    scope.matches(&inventory)?;
    if let Backend::Cloud { sku, .. } = &mut inventory.layers[0].backend {
        *sku = "different-instance".into();
    }
    assert!(scope.matches(&inventory).is_err());
    inventory.layers[0].backend = scope.layers[0].backend.clone();
    if let Backend::Cloud { region, .. } = &mut inventory.layers[0].backend {
        *region = None;
    }
    assert!(scope.matches(&inventory).is_err());
    Ok(())
}

#[test]
fn cycle_measurements_cannot_be_replaced_by_affirmative_checks() -> Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let original = observations(&plan, &manifest, QualificationPhase::Staging)?;
    for count in [Some(9), None] {
        let mut changed = original.clone();
        let operations = &mut image_record(&mut changed)
            .qualification
            .as_mut()
            .unwrap()
            .operations;
        if let Some(count) = count {
            operations.insert("reboot_cycles".into(), count);
        } else {
            operations.remove("reboot_cycles");
        }
        assert!(
            validate_observations(&plan, &manifest, QualificationPhase::Staging, &changed, NOW)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn each_configuration_requires_its_own_complete_observation_window() -> Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let mut complete = observations(&plan, &manifest, QualificationPhase::Complete)?;
    for record in &mut complete {
        record.finished_at = "2026-09-15T00:00:00Z".into();
        record.qualification.as_mut().unwrap().observed_seconds = 1_209_600;
    }
    let now = "2026-09-15T00:00:01Z";
    validate_observations(
        &plan,
        &manifest,
        QualificationPhase::Complete,
        &complete,
        now,
    )?;
    for index in 0..complete.len() {
        let mut changed = complete.clone();
        changed[index]
            .qualification
            .as_mut()
            .unwrap()
            .observed_seconds = 1;
        assert!(
            validate_observations(
                &plan,
                &manifest,
                QualificationPhase::Complete,
                &changed,
                now
            )
            .is_err()
        );
    }
    let mut corrupt = complete;
    image_record(&mut corrupt)
        .qualification
        .as_mut()
        .unwrap()
        .operations
        .insert("data_integrity_failures".into(), 1);
    assert!(
        validate_observations(
            &plan,
            &manifest,
            QualificationPhase::Complete,
            &corrupt,
            now
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn capability_evidence_is_bound_to_exact_metadata_bytes_and_observed_image() -> Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let original = observations(&plan, &manifest, QualificationPhase::Staging)?;
    for change in ["metadata", "inventory", "absent", "artifact"] {
        let mut records = original.clone();
        let observation = image_record(&mut records).qualification.as_mut().unwrap();
        match change {
            "metadata" => {
                observation.capabilities.as_mut().unwrap().metadata["capabilities"]["kernel_options"]
                    ["CONFIG_EFI"] = "n".into()
            }
            "inventory" => {
                let environment = observation.environment.as_mut().unwrap();
                environment.image_capabilities_digest =
                    Some(Sha256Digest::of_bytes("different-image"));
                observation.environment_digest = environment.digest()?;
            }
            "absent" => observation.capabilities = None,
            "artifact" => {
                observation.capabilities.as_mut().unwrap().metadata_artifact = "unrelated".into()
            }
            _ => unreachable!(),
        }
        assert!(
            validate_observations(&plan, &manifest, QualificationPhase::Staging, &records, NOW)
                .is_err(),
            "accepted {change}"
        );
    }
    Ok(())
}

#[test]
fn optional_assessments_preserve_missing_and_failed_results_without_awarding_execution()
-> Result<()> {
    let (mut plan, manifest) = qualification_fixture()?;
    let contract = plan.qualification.as_mut().unwrap();
    let mut optional = contract
        .claims
        .iter()
        .find(|claim| {
            claim.id.starts_with("container-") && claim.phase == QualificationPhase::Staging
        })
        .unwrap()
        .clone();
    optional.id = "optional-reviewed-scope".into();
    optional.minimum_assurance = AssuranceLevel::A1;
    optional.blocks_release = false;
    contract.claims.push(optional);
    plan.gates = contract.gates(plan.release_class)?;
    plan.public_evidence_policy_digest = contract.digest()?;
    plan.validate()?;
    let records = observations(&plan, &manifest, QualificationPhase::Staging)?;
    let outcome = |records: &[EvidenceRecord]| -> Result<_> {
        validate_observations(&plan, &manifest, QualificationPhase::Staging, records, NOW)?;
        Ok(
            assess_observations(&plan, &manifest, QualificationPhase::Staging, records, NOW)?
                .into_iter()
                .find(|outcome| outcome.claim_id == "optional-reviewed-scope")
                .unwrap(),
        )
    };
    let assessed = outcome(&records)?;
    assert_eq!(assessed.achieved_assurance, AssuranceLevel::A1);
    assert_eq!(assessed.environment_digest, None);
    let mut missing = records.clone();
    missing.retain(|record| record.policy_id != "claim-optional-reviewed-scope");
    assert_eq!(outcome(&missing)?.disposition, ClaimDisposition::Missing);
    let mut failed = records.clone();
    failed
        .iter_mut()
        .find(|record| record.policy_id == "claim-optional-reviewed-scope")
        .unwrap()
        .result = GateResult::Failed;
    let failure = outcome(&failed)?;
    assert_eq!(failure.disposition, ClaimDisposition::Failed);
    assert_eq!(failure.achieved_assurance, AssuranceLevel::A0);
    let mut stale = records.clone();
    let record = stale
        .iter_mut()
        .find(|record| record.policy_id == "claim-optional-reviewed-scope")
        .unwrap();
    record.started_at = "2026-06-01T00:00:00Z".into();
    record.finished_at = "2026-06-01T00:00:00Z".into();
    assert_eq!(outcome(&stale)?.disposition, ClaimDisposition::Stale);
    let mut forged = records;
    forged
        .iter_mut()
        .find(|record| record.policy_id == "claim-optional-reviewed-scope")
        .unwrap()
        .qualification
        .as_mut()
        .unwrap()
        .assessment
        .as_mut()
        .unwrap()
        .scope_digest = Sha256Digest::of_bytes("another-scope");
    assert!(outcome(&forged).is_err());
    Ok(())
}

#[test]
fn report_assurance_is_recomputed_and_cannot_be_self_promoted_or_downgraded() -> Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let evidence = observations(&plan, &manifest, QualificationPhase::Staging)?;
    let claims = assess_observations(
        &plan,
        &manifest,
        QualificationPhase::Staging,
        &evidence,
        NOW,
    )?;
    let mut report = QualificationReportV1 {
        schema_version: "aos.release.qualification-report/v3".into(),
        phase: Some(QualificationPhase::Staging),
        admitted_at: Some(NOW.into()),
        staging_receipt_digest: Sha256Digest::of_bytes("staging"),
        manifest_digest: Sha256Digest::of_bytes("manifest"),
        claims: Some(claims),
        evidence,
    };
    report.validate_phase(&plan, &manifest, QualificationPhase::Staging, NOW)?;
    report.claims.as_mut().unwrap()[0].achieved_assurance = AssuranceLevel::A3;
    assert!(
        report
            .validate_phase(&plan, &manifest, QualificationPhase::Staging, NOW)
            .is_err()
    );
    report.schema_version = "aos.release.qualification-report/v2".into();
    report.claims = None;
    assert!(
        report
            .validate_phase(&plan, &manifest, QualificationPhase::Staging, NOW)
            .is_err()
    );
    Ok(())
}

#[test]
fn current_case_semantics_cannot_be_hashed_as_an_archived_case() -> Result<()> {
    let (plan, manifest) = qualification_fixture()?;
    let mut case =
        crate::qualification_evidence::cases(&plan, &manifest, QualificationPhase::Staging)?
            .into_iter()
            .find(|case| case.claim.is_some())
            .unwrap();
    case.schema_version = None;
    assert!(case.digest().is_err());
    case.schema_version = Some("unknown".into());
    assert!(case.digest().is_err());
    Ok(())
}
