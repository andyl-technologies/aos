//! Tests the deferred platform policy on both sides of the release contract.
//!
//! The contract keeps a deferred platform's targets but makes them optional
//! and claim-free; a plan may ship nothing on that platform; and case
//! expansion yields no case for it.

use crate::canonical;
use crate::digest::Sha256Digest;
use crate::manifest::ReleaseManifestV1;
use crate::plan::ReleasePlan;
use crate::platform::{MatrixCell, Platform};
use crate::qualification::{QualificationContract, QualificationPhase};
use crate::qualification_evidence::cases;
use crate::verify::tests::{
    EDGE, current_contract, qualification_fixture, rebind, testing_fixture,
};

const DEFERRED: Platform = Platform::Aarch64Linux;

/// Applies the Nix deferral of `aarch64-linux` to a complete contract.
///
/// `tests/qualification/policy.nix` asserts that the exported Nix contract is
/// exactly this transformation of the complete contract fixture.
fn defer(contract: &mut QualificationContract) {
    contract.deferred_platforms = vec![DEFERRED];
    let mut deferred_targets = Vec::new();
    for target in &mut contract.targets {
        if target.platform == DEFERRED {
            target.required = false;
            deferred_targets.push(target.id.clone());
        }
    }
    contract
        .claims
        .retain(|claim| !deferred_targets.contains(&claim.target));
}

fn blocked<T>() -> MatrixCell<T> {
    MatrixCell::Blocked {
        required_work: "Release aarch64-linux in a later edge release.".into(),
        failure_evidence: Sha256Digest::of_bytes(b"retained deferral note"),
    }
}

/// Returns the edge fixture with `aarch64-linux` deferred in plan and manifest.
fn deferred_fixture() -> anyhow::Result<(ReleasePlan, ReleaseManifestV1)> {
    let (mut plan, mut manifest) = testing_fixture()?;

    defer(&mut plan.qualification);
    let planned_cells = plan
        .packages
        .iter_mut()
        .flat_map(|package| &mut package.platforms)
        .chain(
            plan.images
                .iter_mut()
                .flat_map(|image| &mut image.platforms),
        );
    for cell in planned_cells.filter(|cell| cell.platform == DEFERRED) {
        cell.decision = blocked();
    }
    rebind(&mut plan)?;

    manifest
        .artifacts
        .retain(|artifact| artifact.platform != Some(DEFERRED));
    let final_cells = manifest
        .packages
        .iter_mut()
        .flat_map(|package| &mut package.platforms)
        .chain(
            manifest
                .images
                .iter_mut()
                .flat_map(|image| &mut image.platforms),
        );
    for cell in final_cells.filter(|cell| cell.platform == DEFERRED) {
        cell.decision = blocked();
    }
    Ok((plan, manifest))
}

fn rejection(contract: &QualificationContract) -> String {
    contract.validate().unwrap_err().to_string()
}

#[test]
fn deferred_contract_keeps_optional_claim_free_targets() -> anyhow::Result<()> {
    let mut contract = current_contract()?;
    defer(&mut contract);
    contract.validate()?;
    assert!(contract.is_deferred(DEFERRED));
    assert!(!contract.is_deferred(Platform::X86_64Linux));

    let mut required = contract.clone();
    for target in &mut required.targets {
        target.required = true;
    }
    assert!(rejection(&required).contains("cannot carry a required"));

    let mut claimed = contract.clone();
    let mut claim = claimed.claims[0].clone();
    claim.id = "disk-aarch64-linux-functional".into();
    claim.target = "disk-aarch64-linux".into();
    claimed.claims.push(claim);
    assert!(rejection(&claimed).contains("targets a deferred platform"));

    let mut everything = contract.clone();
    everything.deferred_platforms = vec![DEFERRED, Platform::X86_64Linux];
    assert!(rejection(&everything).contains("at least one Linux platform"));

    let mut darwin = contract.clone();
    darwin.deferred_platforms = vec![Platform::Aarch64Darwin, DEFERRED];
    assert!(rejection(&darwin).contains("only Linux platforms"));

    let mut duplicate = contract;
    duplicate.deferred_platforms = vec![DEFERRED, DEFERRED];
    assert!(rejection(&duplicate).contains("unique and sorted"));
    Ok(())
}

#[test]
fn released_platforms_still_require_their_targets() -> anyhow::Result<()> {
    let mut contract = current_contract()?;
    defer(&mut contract);
    for target in &mut contract.targets {
        if target.platform == Platform::X86_64Linux {
            target.required = false;
        }
    }
    assert!(rejection(&contract).contains("not deferred"));
    Ok(())
}

#[test]
fn an_empty_deferral_list_keeps_the_contract_encoding() -> anyhow::Result<()> {
    let contract = current_contract()?;
    assert!(contract.deferred_platforms.is_empty());

    let text = String::from_utf8(canonical::to_vec(&contract)?)?;
    assert!(!text.contains("deferred_platforms"));

    let mut deferred = contract.clone();
    defer(&mut deferred);
    let text = String::from_utf8(canonical::to_vec(&deferred)?)?;
    assert!(text.contains(r#""deferred_platforms":["aarch64-linux"]"#));
    assert_ne!(deferred.digest()?, contract.digest()?);
    Ok(())
}

#[test]
fn deferred_platforms_ship_only_blocked_or_inapplicable_cells() -> anyhow::Result<()> {
    let (plan, _) = deferred_fixture()?;
    plan.validate()?;

    let mut inapplicable = plan.clone();
    for cell in &mut inapplicable.images[0].platforms {
        if cell.platform == DEFERRED {
            cell.decision = MatrixCell::NotApplicable {
                rule: "platform-release-deferred".into(),
                reason: "aarch64-linux returns in a later edge release.".into(),
            };
        }
    }
    inapplicable.validate()?;

    let (complete, _) = testing_fixture()?;
    let artifact_cell = |platform: Platform| {
        complete.images[0]
            .platforms
            .iter()
            .find(|cell| cell.platform == platform)
            .map(|cell| cell.decision.clone())
    };

    let mut image = plan.clone();
    for cell in &mut image.images[0].platforms {
        if cell.platform == DEFERRED {
            cell.decision = artifact_cell(DEFERRED).unwrap();
        }
    }
    let error = image.validate().unwrap_err().to_string();
    assert!(error.contains("cannot ship system image"), "{error}");

    let mut package = plan.clone();
    let shipped = complete.packages[0]
        .platforms
        .iter()
        .find(|cell| cell.platform == DEFERRED)
        .map(|cell| cell.decision.clone())
        .unwrap();
    for cell in &mut package.packages[0].platforms {
        if cell.platform == DEFERRED {
            cell.decision = shipped.clone();
        }
    }
    let error = package.validate().unwrap_err().to_string();
    assert!(error.contains("cannot ship package example"), "{error}");

    let mut released = plan;
    for cell in &mut released.images[0].platforms {
        if cell.platform == Platform::X86_64Linux {
            cell.decision = blocked();
        }
    }
    let error = released.validate().unwrap_err().to_string();
    assert!(error.contains("required server image target"), "{error}");
    Ok(())
}

#[test]
fn complete_matrix_profiles_reject_a_deferral() -> anyhow::Result<()> {
    let (mut plan, _) = qualification_fixture()?;
    defer(&mut plan.qualification);
    let cells = plan
        .packages
        .iter_mut()
        .flat_map(|package| &mut package.platforms)
        .chain(
            plan.images
                .iter_mut()
                .flat_map(|image| &mut image.platforms),
        );
    for cell in cells.filter(|cell| cell.platform == DEFERRED) {
        cell.decision = MatrixCell::NotApplicable {
            rule: "platform-release-deferred".into(),
            reason: "aarch64-linux returns in a later release.".into(),
        };
    }
    rebind(&mut plan)?;

    let error = plan.validate().unwrap_err().to_string();
    assert!(error.contains("defers a platform"), "{error}");
    Ok(())
}

#[test]
fn deferred_platforms_yield_no_qualification_case() -> anyhow::Result<()> {
    let (plan, manifest) = deferred_fixture()?;
    let destinations = [None, Some("staging/edge"), Some(EDGE)];
    let phases = [
        QualificationPhase::Build,
        QualificationPhase::Staging,
        QualificationPhase::Rollout,
        QualificationPhase::Complete,
    ];

    let mut released_cases = 0;
    for destination in destinations {
        for phase in phases {
            for case in cases(&plan, &manifest, destination, phase)? {
                assert_ne!(case.platform, Some(DEFERRED), "{}", case.id);
                assert!(
                    case.target
                        .as_ref()
                        .is_none_or(|target| target.platform != DEFERRED),
                    "{}",
                    case.id
                );
                if case.platform == Some(Platform::X86_64Linux) {
                    released_cases += 1;
                }
            }
        }
    }
    // The released platform keeps its package, image and container cases.
    assert!(released_cases > 0);
    Ok(())
}

#[test]
fn a_deferred_artifact_in_the_manifest_is_rejected() -> anyhow::Result<()> {
    let (plan, mut manifest) = deferred_fixture()?;
    let (_, complete) = testing_fixture()?;
    let arm_container = complete
        .artifacts
        .iter()
        .find(|artifact| artifact.id == format!("oci/{DEFERRED}"))
        .cloned()
        .unwrap();
    manifest.artifacts.push(arm_container);

    let error = cases(&plan, &manifest, None, QualificationPhase::Staging)
        .unwrap_err()
        .to_string();
    assert!(error.contains("targets a deferred platform"), "{error}");
    Ok(())
}
