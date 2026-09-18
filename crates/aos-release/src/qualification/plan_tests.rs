//! Tests early binding of published package cells to their execution images.

use super::{K3sTopology, PackageExecution, PackageRole, PackageRule};
use crate::plan::ReleasePlanV1;
use crate::platform::{MatrixCell, Platform};

fn execution_plan(execution: PackageExecution) -> anyhow::Result<ReleasePlanV1> {
    let (mut plan, _) = crate::verify::tests::qualification_fixture()?;
    let package = &mut plan.packages[0];
    for cell in &mut package.platforms {
        if !cell.platform.supports_images() {
            cell.decision = MatrixCell::NotApplicable {
                rule: "linux-execution-fixture".into(),
                reason: "This fixture publishes the specialized package only on Linux.".into(),
            };
        }
    }

    let original_name = package.name.clone();
    let topology = match &execution {
        PackageExecution::K3sFleet { topology, .. } => Some(*topology),
        PackageExecution::RecoveryImage { .. } => None,
    };
    if topology.is_some() {
        package.name = "k3s".into();
    }
    let template = package.clone();
    let policy = plan.qualification.as_mut().unwrap();
    let rule = policy
        .package_rules
        .iter_mut()
        .find(|rule| rule.name == original_name)
        .unwrap();
    rule.name = template.name.clone();
    rule.execution = Some(execution);

    if let Some(topology) = topology {
        for name in topology.packages().iter().filter(|name| **name != "k3s") {
            let mut companion = template.clone();
            companion.name = (*name).into();
            plan.packages.push(companion);
            policy.package_rules.push(PackageRule {
                name: (*name).into(),
                role: PackageRole::QualifiedWorkload,
                inherit_dependency_obligations: true,
                execution: None,
            });
        }
    }
    plan.gates = policy.gates(&plan.registry, plan.release_class)?;
    plan.public_evidence_policy_digest = policy.digest()?;
    Ok(plan)
}

fn executions() -> [PackageExecution; 2] {
    [
        PackageExecution::RecoveryImage {
            system_variant: "server".into(),
        },
        PackageExecution::K3sFleet {
            system_variant: "server".into(),
            topology: K3sTopology::CombinedWorker,
        },
    ]
}

#[test]
fn published_execution_images_must_exist_before_building() -> anyhow::Result<()> {
    for execution in executions() {
        let mut plan = execution_plan(execution)?;
        plan.validate()?;

        plan.images[0].system_variant = "another-image".into();

        let error = plan.validate().unwrap_err().to_string();
        assert!(error.contains("requires execution image server"), "{error}");
    }
    Ok(())
}

#[test]
fn execution_image_requires_every_published_package_platform() -> anyhow::Result<()> {
    for execution in executions() {
        let mut plan = execution_plan(execution)?;
        plan.validate()?;
        plan.images[0]
            .platforms
            .retain(|cell| cell.platform != Platform::Aarch64Linux);

        let error = plan
            .qualification
            .as_ref()
            .unwrap()
            .validate_plan(&plan)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("requires execution image server for aarch64-linux"),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn blocked_package_cells_do_not_require_an_execution_image() -> anyhow::Result<()> {
    let mut plan = execution_plan(executions()[0].clone())?;
    for cell in &mut plan.packages[0].platforms {
        if cell.platform.supports_images() {
            cell.decision = MatrixCell::Blocked {
                required_work: "Complete the fixture's Linux package support.".into(),
                failure_evidence: crate::digest::Sha256Digest::of_bytes(b"fixture-blocked"),
            };
        }
    }
    plan.images[0].system_variant = "another-image".into();

    let policy = plan.qualification.as_ref().unwrap();
    policy.validate_package_execution_images(&plan)?;
    // The independent stable-release completeness requirement still applies.
    assert!(
        plan.validate()
            .unwrap_err()
            .to_string()
            .contains("requires a complete package matrix")
    );
    Ok(())
}
