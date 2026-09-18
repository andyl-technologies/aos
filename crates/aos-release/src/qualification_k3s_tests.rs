//! Regression coverage for staged K3s companion, image, and OCI case bindings.

use super::*;
use crate::qualification::{K3sTopology, PackageRole, PackageRule};

fn fixture(topology: K3sTopology) -> Result<(ReleasePlanV1, ReleaseManifestV1)> {
    let (mut plan, mut manifest) = crate::verify::tests::qualification_fixture()?;
    let template = manifest.packages[0].clone();
    let planned_template = plan.packages[0].clone();

    for name in topology.packages() {
        let mut planned = planned_template.clone();
        planned.name = name.into();
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
                if name != "k3s" {
                    let runtime = manifest
                        .artifacts
                        .iter()
                        .find(|record| record.id == artifact.artifact_ids[0])
                        .unwrap()
                        .clone();
                    let module_id = format!("k3s-fixture/{name}/{}/config", cell.platform);
                    let base_id =
                        format!("k3s-fixture/{name}/{}/configuration-base", cell.platform);
                    for (id, output) in [(&module_id, "config"), (&base_id, "out")] {
                        let mut record = runtime.clone();
                        record.id = id.clone();
                        record.output = Some(output.into());
                        record.store_path = Some(format!(
                            "/nix/store/00000000000000000000000000000000-{name}-{}-{output}",
                            cell.platform,
                        ));
                        artifact.artifact_ids.push(record.id.clone());
                        manifest.artifacts.push(record);
                    }
                    artifact.configuration = Some(crate::plan::PackageConfigurationBinding {
                        module_artifact: module_id,
                        evaluation_base_artifact: base_id,
                        dependency_outputs: Default::default(),
                    });
                }
            }
        }
        manifest.packages.push(package);
    }

    let policy = plan.qualification.as_mut().unwrap();
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
    plan.gates = policy.gates(&plan.registry, plan.release_class)?;
    plan.public_evidence_policy_digest = policy.digest()?;
    Ok((plan, manifest))
}

fn fleet_case(plan: &ReleasePlanV1, manifest: &ReleaseManifestV1) -> Result<QualificationCase> {
    cases(plan, manifest, QualificationPhase::Staging)?
        .into_iter()
        .find(|case| case.id == "package-function/k3s/x86_64-linux")
        .ok_or_else(|| anyhow::anyhow!("fixture did not expand its K3s case"))
}

#[test]
fn k3s_case_binds_native_companions_image_and_container() -> Result<()> {
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
                .any(|record| record.id == *id && record.kind == ArtifactKind::LogicalDisk)
        }));

        for id in [
            "k3s-fixture/k3s-worker/x86_64-linux",
            "k3s-fixture/k3s-worker/x86_64-linux/config",
            "k3s-fixture/k3s-worker/x86_64-linux/configuration-base",
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

    let mut missing_configuration = manifest.clone();
    let package = missing_configuration
        .packages
        .iter_mut()
        .find(|package| package.name == "k3s-worker")
        .unwrap();
    for cell in &mut package.platforms {
        if let MatrixCell::Artifact { artifact } = &mut cell.decision {
            artifact.configuration = None;
        }
    }
    assert!(fleet_case(&plan, &missing_configuration).is_err());

    let mut missing_module = manifest.clone();
    missing_module
        .artifacts
        .retain(|record| record.id != "k3s-fixture/k3s-worker/x86_64-linux/config");
    assert!(fleet_case(&plan, &missing_module).is_err());

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
    let policy = plan.qualification.unwrap();
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
