//! Plan-level destination, tier, and surface validation tests.

use super::*;
use crate::verify::tests::{hub_surfaces, qualification_fixture, testing_fixture};

#[test]
fn testing_tier_rejects_candidate_releases() -> anyhow::Result<()> {
    let (mut plan, _) = testing_fixture()?;
    assert_eq!(
        plan.destinations
            .iter()
            .map(|destination| destination.name.as_str())
            .collect::<Vec<_>>(),
        ["production/edge", "staging/edge"]
    );
    plan.version = "2026.9.0-rc.1".into();
    plan.release_class = ReleaseClass::Candidate;
    let error = plan.validate().unwrap_err().to_string();
    assert!(error.contains("no destination on the testing"), "{error}");

    let (mut plan, _) = testing_fixture()?;
    plan.destinations[1].channel = "candidate".into();
    plan.destinations[1].name = "staging/candidate".into();
    assert!(plan.validate().is_err());
    Ok(())
}

#[test]
fn production_tier_rejects_edge_releases_and_channels() -> anyhow::Result<()> {
    let (mut plan, _) = qualification_fixture()?;
    plan.version = "2026.9.0-dev.20260901.1".into();
    plan.release_class = ReleaseClass::Edge;
    assert!(plan.validate().is_err());

    let (mut plan, _) = qualification_fixture()?;
    let destination = plan
        .destinations
        .iter_mut()
        .find(|destination| destination.name == "staging/candidate")
        .unwrap();
    destination.channel = "edge".into();
    destination.name = "staging/edge".into();
    assert!(plan.validate().is_err());
    Ok(())
}

#[test]
fn final_versions_plan_candidate_and_stable_and_per_train_channels() -> anyhow::Result<()> {
    let (mut plan, _) = qualification_fixture()?;
    let names: Vec<_> = plan
        .destinations
        .iter()
        .map(|destination| destination.name.clone())
        .collect();
    assert_eq!(
        names,
        [
            "production/candidate",
            "production/stable",
            "staging/candidate",
            "staging/stable",
        ]
    );

    // Per-train channels are planned by kind.
    for destination in &mut plan.destinations {
        if destination.channel == "stable" {
            destination.channel = "stable-2026.9".into();
            destination.name = format!("{}/stable-2026.9", destination.surface);
        }
    }
    plan.validate()?;
    assert_eq!(
        parse_destination_name("production/stable-2026.9")?.1,
        "stable-2026.9"
    );
    assert!(parse_destination_name("production/nightly").is_err());
    assert!(parse_destination_name("edge").is_err());

    plan.destinations
        .retain(|destination| destination.channel != "candidate");
    assert!(
        plan.validate().is_err(),
        "final versions go to candidate too"
    );
    Ok(())
}

#[test]
fn surfaces_are_distinct_and_static_staging_cannot_feed_a_hub() -> anyhow::Result<()> {
    let (plan, _) = qualification_fixture()?;
    let static_surface = |role, identity: &str| PlannedSurface {
        role,
        kind: SurfaceKind::Static,
        origin: "s3://aos-registry/andyl-main".into(),
        readback_origin: Some("https://cdn.example.org/andyl-main".into()),
        identity: identity.into(),
    };
    let with_signer = |mut plan: ReleasePlan| {
        plan.signers.push(crate::verify::tests::signer(
            crate::signing::SignerRole::SurfaceReceipt,
        ));
        plan
    };

    let mut hub_then_static = with_signer(plan.clone());
    hub_then_static.surfaces[1] = static_surface(SurfaceRole::Production, "cdn-2026-09");
    hub_then_static.validate()?;
    let mut unsigned = plan.clone();
    unsigned.surfaces[1] = static_surface(SurfaceRole::Production, "cdn-2026-09");
    assert!(
        unsigned.validate().is_err(),
        "static surfaces need a receipt signer"
    );

    let mut both_static = hub_then_static.clone();
    both_static.surfaces[0] = static_surface(SurfaceRole::Staging, "cdn-staging");
    both_static.validate()?;

    let mut static_then_hub = with_signer(plan.clone());
    static_then_hub.surfaces[0] = static_surface(SurfaceRole::Staging, "cdn-staging");
    let error = static_then_hub.validate().unwrap_err().to_string();
    assert!(
        error.contains("cannot verify static staging receipts"),
        "{error}"
    );

    let mut same_identity = plan.clone();
    same_identity.surfaces[1].identity = same_identity.surfaces[0].identity.clone();
    assert!(same_identity.validate().is_err());
    let mut missing = plan.clone();
    missing.surfaces.pop();
    assert!(missing.validate().is_err());
    let mut s3_without_readback = with_signer(plan);
    s3_without_readback.surfaces = hub_surfaces();
    s3_without_readback.surfaces[1] = static_surface(SurfaceRole::Production, "cdn");
    s3_without_readback.surfaces[1].readback_origin = None;
    assert!(s3_without_readback.validate().is_err());
    Ok(())
}
