//! Checks the limits and honest evidence of publication without qualification.

use anyhow::Result;

use crate::canonical;
use crate::digest::Sha256Digest;
use crate::manifest::ReleaseManifestV1;
use crate::plan::{ChannelIntent, ReleasePlanV1};
use crate::platform::MatrixCell;
use crate::qualification::QualificationPhase;

fn fixture() -> Result<(ReleasePlanV1, ReleaseManifestV1)> {
    let (mut plan, mut manifest) = crate::verify::tests::qualification_fixture()?;
    plan.staging_only = true;
    plan.registry = "andyl/testing".into();
    plan.intended_channels.clear();
    plan.qualification_predecessor = None;
    plan.gates = plan
        .qualification
        .as_ref()
        .unwrap()
        .gates(&plan.registry, plan.release_class)?;

    manifest.registry = plan.registry.clone();
    let plan_bytes = canonical::to_vec(&plan)?;
    manifest.plan_digest = Sha256Digest::of_bytes(&plan_bytes);
    for artifact in &mut manifest.artifacts {
        if artifact.kind == crate::artifact::ArtifactKind::ReleasePlan {
            artifact.sha256 = manifest.plan_digest;
            artifact.size_bytes = u64::try_from(plan_bytes.len())?;
        }
    }
    manifest.evidence.clear();
    Ok((plan, manifest))
}

#[test]
fn staging_publication_retains_current_inventory_without_qualification_claims() -> Result<()> {
    let (plan, manifest) = fixture()?;

    plan.require_staging_publication()?;
    manifest.validate(&plan)?;
    assert!(plan.require_publishable_qualification().is_err());
    assert!(
        crate::qualification_evidence::cases(&plan, &manifest, QualificationPhase::Staging,)
            .is_err()
    );
    Ok(())
}

#[test]
fn staging_publication_rejects_main_registry_and_channel_intent() -> Result<()> {
    let (plan, _) = fixture()?;
    let mut main = plan.clone();
    main.registry = "andyl/main".into();

    assert!(main.validate().is_err());

    let mut channel = plan;
    channel.intended_channels.push(ChannelIntent {
        channel: "stable".into(),
        first_partition: 0,
        last_partition: 255,
    });
    assert!(channel.validate().is_err());
    Ok(())
}

#[test]
fn staging_publication_rejects_a_blocked_inventory_cell() -> Result<()> {
    let (mut plan, _) = fixture()?;
    plan.packages[0].platforms[0].decision = MatrixCell::Blocked {
        required_work: "Complete the source build".into(),
        failure_evidence: Sha256Digest::of_bytes(b"source-build-pending"),
    };

    assert!(plan.validate().is_err());
    Ok(())
}

#[test]
fn staging_publication_rejects_missing_container_platforms() -> Result<()> {
    let (plan, mut manifest) = fixture()?;
    manifest.artifacts.retain(|artifact| {
        artifact.kind != crate::artifact::ArtifactKind::OciManifest
            || artifact.platform != Some(crate::platform::Platform::Aarch64Linux)
    });

    let error = manifest.validate(&plan).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("required OCI index/platform manifest")
    );
    Ok(())
}

#[test]
fn staging_publication_rejects_qualification_claims() -> Result<()> {
    let (_, qualified) = crate::verify::tests::qualification_fixture()?;
    let (plan, mut manifest) = fixture()?;
    manifest.evidence = qualified.evidence;

    assert!(!manifest.evidence.is_empty());
    assert!(manifest.validate(&plan).is_err());
    Ok(())
}

#[test]
fn unchecked_build_identity_cannot_be_reused_for_a_qualified_release() -> Result<()> {
    use crate::build::{BuildOutputEvidence, BuildReportV1, ReproducibilityResult};

    let (mut plan, _) = fixture()?;
    let MatrixCell::Artifact { artifact } = &mut plan.packages[0].platforms[0].decision else {
        panic!("fixture must contain a package artifact");
    };
    let output = &mut artifact.artifacts[0];
    output.derivation = Some("/nix/store/fixture.drv".into());
    output.output = Some("out".into());
    output.store_path = Some("/nix/store/fixture-output".into());
    let outputs = crate::build::planned_nix_outputs(&plan)?
        .into_iter()
        .map(|(id, planned)| BuildOutputEvidence {
            id: id.into(),
            package: planned.package.into(),
            version: planned.version.into(),
            license_expression: planned.license_expression.into(),
            source_store_paths: planned.source_store_paths.to_vec(),
            platform: planned.platform,
            derivation: planned.derivation.into(),
            output: planned.output.into(),
            store_path: planned.store_path.into(),
            nar_hash: "sha256:fixture".into(),
            nar_size: 1,
            closure_size: 1,
            references: Vec::new(),
            reproducibility: ReproducibilityResult::NotChecked,
        })
        .collect();
    let plan_digest = Sha256Digest::of_bytes(b"build-fixture");
    let report = BuildReportV1 {
        schema_version: crate::build::BUILD_REPORT_V1.into(),
        plan_digest,
        source_commit: plan.source.commit.clone(),
        outputs,
        sources: Vec::new(),
        completed_at: "2026-09-28T00:00:00Z".into(),
    };

    report.validate(&plan, plan_digest)?;

    plan.staging_only = false;
    let error = report.validate(&plan, plan_digest).unwrap_err();
    assert!(error.to_string().contains("repeat-build evidence"));
    Ok(())
}

#[test]
fn ordinary_plan_serialization_keeps_the_existing_identity() -> Result<()> {
    let (mut plan, _) = fixture()?;
    plan.staging_only = false;
    let value = serde_json::to_value(&plan)?;

    assert!(value.get("staging_only").is_none());
    let decoded: ReleasePlanV1 = serde_json::from_value(value)?;
    assert!(!decoded.staging_only);
    Ok(())
}
