//! Regression coverage for staged K3s native package, image, and OCI case bindings.

use anyhow::Result;

use super::*;
use crate::artifact::ArtifactKind;
use crate::manifest::ReleaseManifestV1;
use crate::plan::ReleasePlan;
use crate::platform::MatrixCell;
use crate::qualification::{K3sTopology, PackageExecution, PackageRole, PackageRule};

fn fixture(topology: K3sTopology) -> Result<(ReleasePlan, ReleaseManifestV1)> {
    let (mut plan, mut manifest) = crate::verify::tests::qualification_fixture()?;
    let template = manifest.packages[0].clone();
    let planned_template = plan.packages[0].clone();

    for name in topology.packages() {
        let mut planned = planned_template.clone();
        planned.name = name.into();
        for cell in &mut planned.platforms {
            if !cell.platform.supports_images() {
                cell.decision = MatrixCell::NotApplicable {
                    rule: "k3s-execution-fixture".into(),
                    reason: "This fixture exercises K3s only on Linux.".into(),
                };
            }
        }
        plan.packages.push(planned);
        let mut package = template.clone();
        package.name = name.into();
        package
            .platforms
            .retain(|cell| cell.platform.supports_images());
        for cell in &mut package.platforms {
            if let MatrixCell::Artifact { artifact } = &mut cell.decision {
                for id in &mut artifact.artifact_ids {
                    let mut record = manifest
                        .artifacts
                        .iter()
                        .find(|entry| entry.id == *id)
                        .unwrap()
                        .clone();
                    record.id = format!("k3s-fixture/{name}/{}", cell.platform);
                    *id = record.id.clone();
                    manifest.artifacts.push(record);
                }
            }
        }
        manifest.packages.push(package);
    }

    let policy = &mut plan.qualification;
    for name in topology.packages() {
        policy.package_rules.push(PackageRule {
            name: name.into(),
            role: PackageRole::QualifiedWorkload,
            inherit_dependency_obligations: true,
            execution: Some(PackageExecution::K3sFleet {
                system_variant: "server".into(),
                topology,
            }),
        });
    }
    crate::verify::tests::rebind(&mut plan)?;
    Ok((plan, manifest))
}

fn fleet_case(plan: &ReleasePlan, manifest: &ReleaseManifestV1) -> Result<QualificationCase> {
    cases(
        plan,
        manifest,
        Some(crate::verify::tests::STABLE),
        QualificationPhase::Staging,
    )?
    .into_iter()
    .find(|case| case.id == "package-function/k3s/x86_64-linux")
    .ok_or_else(|| anyhow::anyhow!("fixture did not expand its K3s case"))
}

#[test]
fn k3s_case_binds_native_packages_image_and_container() -> Result<()> {
    for topology in [K3sTopology::CombinedWorker, K3sTopology::ControlPlaneWorker] {
        let (plan, manifest) = fixture(topology)?;
        let case = fleet_case(&plan, &manifest)?;

        for name in topology.packages() {
            assert!(
                case.subjects
                    .contains(&format!("k3s-fixture/{name}/x86_64-linux"))
            );
            assert!(
                !case
                    .subjects
                    .contains(&format!("k3s-fixture/{name}/aarch64-linux"))
            );
        }
        assert!(case.subjects.contains(&"oci/index".into()));
        assert!(case.subjects.contains(&"oci/x86_64-linux".into()));
        assert!(!case.subjects.contains(&"oci/aarch64-linux".into()));
        assert!(case.predecessor.is_none());
        assert!(case.subjects.iter().any(|id| {
            manifest
                .artifacts
                .iter()
                .any(|record| record.id == *id && record.kind == ArtifactKind::Image)
        }));

        for id in [
            "k3s-fixture/k3s-worker/x86_64-linux",
            "oci/index",
            "oci/x86_64-linux",
        ] {
            let mut changed = manifest.clone();
            changed
                .artifacts
                .iter_mut()
                .find(|record| record.id == id)
                .unwrap()
                .sha256 = Sha256Digest::of_bytes(b"different staged bytes");
            assert_ne!(case.digest()?, fleet_case(&plan, &changed)?.digest()?);
        }
    }
    Ok(())
}

#[test]
fn k3s_missing_or_ambiguous_inputs_fail_closed() -> Result<()> {
    let (plan, manifest) = fixture(K3sTopology::CombinedWorker)?;

    let mut missing_companion = manifest.clone();
    missing_companion
        .packages
        .retain(|package| package.name != "k3s-worker");
    assert!(fleet_case(&plan, &missing_companion).is_err());

    let mut missing_payload = manifest.clone();
    missing_payload
        .artifacts
        .retain(|record| record.id != "k3s-fixture/k3s-worker/x86_64-linux");
    assert!(fleet_case(&plan, &missing_payload).is_err());

    let mut missing_image = manifest.clone();
    missing_image
        .images
        .retain(|image| image.system_variant != "server");
    assert!(fleet_case(&plan, &missing_image).is_err());

    for kind in [ArtifactKind::OciIndex, ArtifactKind::OciManifest] {
        let selected = manifest
            .artifacts
            .iter()
            .find(|record| {
                record.kind == kind
                    && (kind == ArtifactKind::OciIndex
                        || record.platform == Some(Platform::X86_64Linux))
            })
            .unwrap();
        let mut missing = manifest.clone();
        missing.artifacts.retain(|record| record.id != selected.id);
        assert!(fleet_case(&plan, &missing).is_err());

        let mut ambiguous = manifest.clone();
        let mut duplicate = selected.clone();
        duplicate.id.push_str("-duplicate");
        ambiguous.artifacts.push(duplicate);
        assert!(fleet_case(&plan, &ambiguous).is_err());
    }
    Ok(())
}

#[test]
fn k3s_policy_rejects_missing_role_and_unrelated_subject() -> Result<()> {
    let (plan, _) = fixture(K3sTopology::CombinedWorker)?;
    let policy = plan.qualification;
    policy.validate()?;

    let mut missing = policy.clone();
    missing
        .package_rules
        .retain(|rule| rule.name != "k3s-worker");
    assert!(
        missing
            .validate()
            .unwrap_err()
            .to_string()
            .contains("companion package rule")
    );

    let mut unrelated = policy;
    unrelated
        .package_rules
        .iter_mut()
        .find(|rule| rule.name == "k3s-combined")
        .unwrap()
        .execution = Some(PackageExecution::K3sFleet {
        system_variant: "server".into(),
        topology: K3sTopology::ControlPlaneWorker,
    });
    assert!(
        unrelated
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not exercise")
    );
    Ok(())
}
