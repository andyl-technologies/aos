//! Profile override policy, threshold, and plan-binding tests.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::plan::planned_destinations;
use crate::receipt::{RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT, SignedReceiptEnvelope};
use crate::verify::tests::{STABLE, qualification_fixture, requested};

fn emergency(plan: &ReleasePlan, authority_id: &str) -> ProfileOverride {
    ProfileOverride {
        schema_version: PROFILE_OVERRIDE.into(),
        registry: plan.registry.clone(),
        release_id: plan.release_id.clone(),
        destination: STABLE.into(),
        incident_reference: "INC-2026-0042".into(),
        soak_seconds: Some(86_400),
        rings: Some(vec![
            RolloutRing {
                partitions: 32,
                observe_seconds: 3_600,
            },
            RolloutRing {
                partitions: 256,
                observe_seconds: 0,
            },
        ]),
        authority_id: authority_id.into(),
        approved_at: "2026-09-02T00:00:00Z".into(),
    }
}

fn signed(approval: &ProfileOverride, seed: u8) -> Vec<u8> {
    let payload = crate::canonical::to_vec(approval).unwrap();
    let signature = SigningKey::from_bytes(&[seed; 32])
        .sign(Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload).as_bytes());
    crate::canonical::to_vec(&SignedReceiptEnvelope {
        schema_version: SIGNED_RECEIPT.into(),
        key_id: approval.authority_id.clone(),
        payload: serde_json::from_slice(&payload).unwrap(),
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    })
    .unwrap()
}

fn trusted(id: &str, seed: u8) -> TrustedEd25519Key {
    TrustedEd25519Key {
        key_id: id.into(),
        public_key: SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    }
}

#[test]
fn overrides_cannot_lower_soak_below_a_day_or_touch_fixed_fields() -> anyhow::Result<()> {
    let (plan, _) = qualification_fixture()?;
    let contract = &plan.qualification;
    let soak = contract.profile("soak")?;
    let approval = emergency(&plan, "key");
    let effective = approval.apply(soak)?;
    assert_eq!(effective.soak_seconds, 86_400);
    assert_eq!(effective.rings.len(), 2);

    let mut too_short = approval.clone();
    too_short.soak_seconds = Some(86_399);
    assert!(too_short.validate(soak).is_err());
    let mut partial = approval.clone();
    partial.rings.as_mut().unwrap().pop();
    assert!(partial.validate(soak).is_err());
    let mut nothing = approval.clone();
    nothing.soak_seconds = None;
    nothing.rings = None;
    assert!(nothing.validate(soak).is_err());
    let mut no_incident = approval.clone();
    no_incident.incident_reference = " ".into();
    assert!(no_incident.validate(soak).is_err());

    // Profiles without an override policy accept no relaxation at all.
    for name in ["build", "smoke", "functional"] {
        let fixed = contract.profile(name)?;
        let mut soak_only = approval.clone();
        soak_only.rings = None;
        assert!(soak_only.validate(fixed).is_err(), "{name} soak");
        let mut rings_only = approval.clone();
        rings_only.soak_seconds = None;
        assert!(rings_only.validate(fixed).is_err(), "{name} rings");
    }

    // The override identity ignores the individual signer.
    assert_eq!(approval.digest()?, emergency(&plan, "other").digest()?);
    Ok(())
}

#[test]
fn threshold_signed_overrides_bind_into_the_plan() -> anyhow::Result<()> {
    let (mut plan, _) = qualification_fixture()?;
    for role in &mut plan.signers {
        if role.role == SignerRole::ReleaseEvidence {
            role.key_ids = vec!["evidence-a".into(), "evidence-b".into()];
            role.threshold = 2;
        }
    }
    let contract = plan.qualification.clone();
    let keys = [trusted("evidence-a", 11), trusted("evidence-b", 12)];
    let first = signed(&emergency(&plan, "evidence-a"), 11);
    let second = signed(&emergency(&plan, "evidence-b"), 12);
    let verify = |envelopes: &[Vec<u8>]| {
        verify_overrides(
            &contract,
            &plan.registry,
            &plan.release_id,
            &plan.signers,
            envelopes,
            &keys,
        )
    };

    assert!(verify(&[first.clone()]).is_err(), "below threshold");
    assert!(
        verify(&[first.clone(), first.clone()]).is_err(),
        "repeated signer"
    );
    let mut disagreeing = emergency(&plan, "evidence-b");
    disagreeing.soak_seconds = Some(172_800);
    assert!(verify(&[first.clone(), signed(&disagreeing, 12)]).is_err());
    let mut forged = emergency(&plan, "evidence-b");
    forged.authority_id = "evidence-a".into();
    assert!(verify(&[first.clone(), signed(&forged, 12)]).is_err());

    let accepted = verify(&[first, second])?;
    assert_eq!(accepted.signers, ["evidence-a", "evidence-b"]);
    assert!(
        accepted.validate_for(&plan).is_err(),
        "plan does not bind it yet"
    );

    // Plan the override: the destination carries the relaxed values and the
    // plan references the override digest.
    let mut requests = requested(&plan)?;
    for request in &mut requests {
        if request.surface == crate::plan::SurfaceRole::Production && request.channel == "stable" {
            *request = accepted.requested_destination()?;
        }
    }
    plan.destinations = planned_destinations(&contract, &plan.registry, &requests, None)?;
    plan.profile_overrides = vec![accepted.reference.clone()];
    plan.validate()?;
    accepted.validate_for(&plan)?;
    assert_eq!(plan.destination(STABLE)?.soak_seconds, 86_400);
    assert_eq!(plan.destination(STABLE)?.ring_range(1)?, (0, 31));

    // Relaxed values without the bound override are rejected.
    let mut unbound = plan.clone();
    unbound.profile_overrides.clear();
    assert!(unbound.validate().is_err());
    // The override may not relax a fixed profile even when referenced.
    let mut candidate = plan.clone();
    candidate.profile_overrides = vec![ProfileOverrideRef {
        destination: "production/candidate".into(),
        override_digest: accepted.reference.override_digest,
    }];
    let destination = candidate
        .destinations
        .iter_mut()
        .find(|destination| destination.name == "production/candidate")
        .unwrap();
    destination.soak_seconds = 86_400;
    assert!(candidate.validate().is_err());
    Ok(())
}
