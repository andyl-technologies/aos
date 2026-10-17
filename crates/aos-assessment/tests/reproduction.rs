//! Reproduction receipts bind exact input agreement without an authority claim.

mod common;

use anyhow::Result;
use aos_assessment::bundle::{AssessmentBundleV1, BundleProfile, RawEvidenceMember};
use aos_assessment::input::Profile;
use aos_assessment::reproduction::{
    BundleReproductionV1, ReproductionAuthority, ReproductionClassification,
};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;

fn bundle(profile: BundleProfile) -> Result<AssessmentBundleV1> {
    let now = common::evaluated_at()?;
    let mut data = common::updates::data(now.clone())?;
    data.advisory_snapshot = None;
    data.advisories.clear();
    let input = data.freeze(vec![Profile::Updates], now)?;
    let raw = if profile == BundleProfile::SelfContained {
        vec![RawEvidenceMember::from_bytes(b"raw")?]
    } else {
        vec![]
    };
    AssessmentBundleV1::export(input, data, profile, raw)
}

#[test]
fn receipts_preserve_scope_replay_identity_and_explicit_external_custody() -> Result<()> {
    for profile in [BundleProfile::Reference, BundleProfile::SelfContained] {
        let bundle = bundle(profile)?;
        let now = common::evaluated_at()?;
        let receipt = BundleReproductionV1::reproduce(&bundle, "local-fixture", now.clone())?;
        assert_eq!(
            receipt.classification,
            ReproductionClassification::Reproduced
        );
        assert_eq!(receipt.authority, ReproductionAuthority::NotEstablished);
        assert_eq!(receipt.bundle_manifest_digest, bundle.verify()?);
        assert_eq!(
            receipt.external_raw_members as usize,
            bundle.manifest.external_references.len()
        );
        assert_eq!(
            BundleReproductionV1::from_slice(&receipt.to_bytes()?)?,
            receipt
        );
        assert_eq!(
            receipt.digest()?,
            Sha256Digest::of_canonical("aos.assessment-bundle-reproduction/v1", &receipt)?
        );
        receipt.verify_for(&bundle, "local-fixture", &now)?;
        assert!(receipt.verify_for(&bundle, "foreign-scope", &now).is_err());
        let output = String::from_utf8(receipt.to_bytes()?)?;
        for forbidden in [
            "https://",
            "argv",
            "credential",
            "ownerPath",
            "releaseEligible",
        ] {
            assert!(!output.contains(forbidden));
        }
    }
    Ok(())
}

#[test]
fn altered_content_or_clock_cannot_reuse_a_reproduction_receipt() -> Result<()> {
    let bundle = bundle(BundleProfile::Reference)?;
    let now = common::evaluated_at()?;
    let receipt = BundleReproductionV1::reproduce(&bundle, "local-fixture", now.clone())?;
    for changed in [
        "manifest",
        "inventory",
        "input",
        "assessment",
        "engine",
        "raw",
        "profile",
    ] {
        let mut altered = receipt.clone();
        let replacement = Sha256Digest::of_bytes("different content");
        match changed {
            "manifest" => altered.bundle_manifest_digest = replacement,
            "inventory" => altered.inventory_digest = replacement,
            "input" => altered.scan_input_digest = replacement,
            "assessment" => altered.assessment_digest = replacement,
            "engine" => altered.engine_digest = replacement,
            "raw" => altered.external_raw_members = 0,
            _ => {
                altered.profile = BundleProfile::SelfContained;
                altered.external_raw_members = 0;
            }
        }
        assert!(altered.verify_for(&bundle, "local-fixture", &now).is_err());
    }
    let earlier = Timestamp::from_unix_seconds(now.unix_seconds() - 1)?;
    assert!(
        receipt
            .verify_for(&bundle, "local-fixture", &earlier)
            .is_err()
    );
    assert!(BundleReproductionV1::reproduce(&bundle, "local-fixture", earlier).is_err());
    let mut altered_bundle = bundle.clone();
    altered_bundle.manifest.assessment_digest = Sha256Digest::of_bytes("forged result");
    assert!(BundleReproductionV1::reproduce(&altered_bundle, "local-fixture", now).is_err());
    Ok(())
}

#[test]
fn receipt_decoder_refuses_authority_escalation_and_ambiguous_json() -> Result<()> {
    let bundle = bundle(BundleProfile::Reference)?;
    let receipt =
        BundleReproductionV1::reproduce(&bundle, "local-fixture", common::evaluated_at()?)?;
    let value = serde_json::to_value(&receipt)?;
    for (field, forged) in [
        ("authority", "admitted"),
        ("classification", "trusted-attested"),
        ("schema", "other"),
        ("trusted", "true"),
    ] {
        let mut altered = value.clone();
        altered[field] = forged.into();
        assert!(BundleReproductionV1::from_slice(&serde_json::to_vec(&altered)?).is_err());
    }
    assert!(BundleReproductionV1::from_slice(b"{\"schema\":null}").is_err());
    assert!(BundleReproductionV1::from_slice(b"{\"schema\":\"a\",\"schema\":\"b\"}").is_err());
    assert!(BundleReproductionV1::from_slice(&vec![b' '; 65537]).is_err());
    Ok(())
}
