//! Fitness attestation freshness, binding, and signature tests.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::receipt::{RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT, SignedReceiptEnvelope};
use crate::verify::tests::{STABLE, qualification_fixture, release_fixture};

const PERFORMED: &str = "2026-09-01T00:00:00Z";

fn report(kind: &FitnessKind) -> FitnessReport {
    FitnessReport {
        schema_version: FITNESS_REPORT.into(),
        performed_at: PERFORMED.into(),
        checks: kind
            .checks
            .iter()
            .map(|check| {
                (
                    check.clone(),
                    CheckObservation {
                        passed: true,
                        detail: "exercised".into(),
                    },
                )
            })
            .collect(),
        operator: "oncall".into(),
    }
}

fn live(plan: &ReleasePlan) -> LiveBindings {
    LiveBindings {
        registry: plan.registry.clone(),
        surface: Some("hub-production-v1".into()),
        surface_kind: Some(SurfaceKind::Hub),
        hub_schema: Some("42".into()),
        signer_roster: Some(signer_roster_digest(plan).unwrap()),
        tooling: Some(Sha256Digest::of_bytes("tooling")),
        alert_config: Some(Sha256Digest::of_bytes("alert")),
    }
}

#[test]
fn attestation_age_follows_the_profile_demand() -> anyhow::Result<()> {
    let (plan, _) = qualification_fixture()?;
    let contract = &plan.qualification;
    let soak = contract.profile("soak")?;
    let live = live(&plan);

    // Weekly automated exercises may be 14 days old; operator ones 90 days.
    for (name, max_age_days) in [("alert-delivery", 14), ("hub-restore", 90)] {
        let kind = contract.fitness_kind(name)?;
        let attestation =
            report(kind).attest(kind, &live, Sha256Digest::of_bytes("report"), "key")?;
        let seconds = max_age_days * 86_400;
        let at = |offset: u64| {
            humantime::format_rfc3339_seconds(
                humantime::parse_rfc3339(PERFORMED).unwrap()
                    + std::time::Duration::from_secs(offset),
            )
            .to_string()
        };
        attestation.validate_for(soak, kind, &live, &at(seconds))?;
        assert!(
            attestation
                .validate_for(soak, kind, &live, &at(seconds + 1))
                .is_err()
        );
        assert!(
            attestation
                .validate_for(soak, kind, &live, "2026-08-31T23:59:59Z")
                .is_err()
        );
    }

    // key-rotation is demanded by soak but not by functional.
    let rotation = contract.fitness_kind("key-rotation")?;
    let attestation =
        report(rotation).attest(rotation, &live, Sha256Digest::of_bytes("r"), "key")?;
    attestation.validate_for(soak, rotation, &live, PERFORMED)?;
    let functional = contract.profile("functional")?;
    assert!(
        attestation
            .validate_for(functional, rotation, &live, PERFORMED)
            .is_err()
    );
    Ok(())
}

#[test]
fn bindings_must_match_live_identities() -> anyhow::Result<()> {
    let (plan, _) = qualification_fixture()?;
    let contract = &plan.qualification;
    let soak = contract.profile("soak")?;
    let live = live(&plan);
    let kind = contract.fitness_kind("key-rotation")?;
    let attestation = report(kind).attest(kind, &live, Sha256Digest::of_bytes("report"), "key")?;

    let mut moved = live.clone();
    moved.surface = Some("hub-production-v2".into());
    assert!(
        attestation
            .validate_for(soak, kind, &moved, PERFORMED)
            .is_err()
    );
    let mut rotated = live.clone();
    rotated.signer_roster = Some(Sha256Digest::of_bytes("another roster"));
    assert!(
        attestation
            .validate_for(soak, kind, &rotated, PERFORMED)
            .is_err()
    );
    let mut unknown = live.clone();
    unknown.surface = None;
    assert!(
        attestation
            .validate_for(soak, kind, &unknown, PERFORMED)
            .is_err()
    );
    let mut other_registry = live.clone();
    other_registry.registry = "andyl/testing".into();
    assert!(
        attestation
            .validate_for(soak, kind, &other_registry, PERFORMED)
            .is_err()
    );

    // Hub schema is vacuous (null) for static surfaces and required for Hubs.
    let hub = contract.fitness_kind("hub-restore")?;
    let mut static_live = live.clone();
    static_live.surface_kind = Some(SurfaceKind::Static);
    static_live.hub_schema = None;
    let static_attestation =
        report(hub).attest(hub, &static_live, Sha256Digest::of_bytes("report"), "key")?;
    assert_eq!(static_attestation.bindings["hub-schema"], None);
    static_attestation.validate_for(soak, hub, &static_live, PERFORMED)?;
    assert!(
        static_attestation
            .validate_for(soak, hub, &live, PERFORMED)
            .is_err()
    );

    let mut null_surface = static_attestation;
    null_surface.bindings.insert("surface".into(), None);
    assert!(null_surface.validate(hub).is_err());
    Ok(())
}

#[test]
fn attestations_require_exact_passing_checks_and_planned_signers() -> anyhow::Result<()> {
    let (plan, _) = qualification_fixture()?;
    let contract = &plan.qualification;
    let live = live(&plan);
    let kind = contract.fitness_kind("storage-restore")?;

    let mut failed = report(kind);
    failed.checks.values_mut().next().unwrap().passed = false;
    assert!(
        failed
            .attest(kind, &live, Sha256Digest::of_bytes("r"), "key")
            .is_err()
    );
    let mut missing = report(kind);
    missing.checks.pop_first();
    assert!(
        missing
            .attest(kind, &live, Sha256Digest::of_bytes("r"), "key")
            .is_err()
    );

    let fixture = release_fixture()?;
    let attestation = report(kind).attest(
        kind,
        &live,
        Sha256Digest::of_bytes("r"),
        &fixture.key.key_id,
    )?;
    let payload = crate::canonical::to_vec(&attestation)?;
    let signature = SigningKey::from_bytes(&[7_u8; 32])
        .sign(Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload).as_bytes());
    let envelope = crate::canonical::to_vec(&SignedReceiptEnvelope {
        schema_version: SIGNED_RECEIPT.into(),
        key_id: fixture.key.key_id.clone(),
        payload: serde_json::from_slice(&payload)?,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    })?;
    let keys = [fixture.key];
    let verified = FitnessAttestation::verify_signed(&envelope, &plan, &keys)?;
    assert_eq!(verified, attestation);

    let mut foreign = plan.clone();
    for role in &mut foreign.signers {
        if role.role == SignerRole::ReleaseEvidence {
            role.key_ids = vec!["another-evidence-key".into()];
        }
    }
    assert!(FitnessAttestation::verify_signed(&envelope, &foreign, &keys).is_err());
    Ok(())
}

#[test]
fn destinations_require_every_demanded_kind() -> anyhow::Result<()> {
    let (plan, _) = qualification_fixture()?;
    let contract = &plan.qualification;
    let live = live(&plan);
    let attestations: Vec<_> = contract
        .fitness
        .iter()
        .map(|kind| report(kind).attest(kind, &live, Sha256Digest::of_bytes("r"), "key"))
        .collect::<Result<_>>()?;

    require_destination_fitness(&plan, STABLE, &attestations, &live, PERFORMED)?;
    // Build-profile destinations demand no fitness.
    require_destination_fitness(&plan, "staging/stable", &[], &live, PERFORMED)?;

    let without_rotation: Vec<_> = attestations
        .iter()
        .filter(|attestation| attestation.kind != "key-rotation")
        .cloned()
        .collect();
    require_destination_fitness(
        &plan,
        "production/candidate",
        &without_rotation,
        &live,
        PERFORMED,
    )?;
    let error = require_destination_fitness(&plan, STABLE, &without_rotation, &live, PERFORMED)
        .unwrap_err()
        .to_string();
    assert!(error.contains("key-rotation"), "{error}");
    assert!(
        require_destination_fitness(&plan, STABLE, &attestations, &live, "2027-01-01T00:00:00Z")
            .is_err()
    );
    Ok(())
}
