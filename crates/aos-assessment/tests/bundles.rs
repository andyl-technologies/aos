//! Offline export/import agreement, custody limits and malicious-member checks.

mod common;

use anyhow::Result;
use aos_assessment::bundle::{AssessmentBundleV1, BundleProfile, RawEvidenceMember};
use aos_assessment::input::Profile;
use aos_contract::Sha256Digest;

#[test]
fn self_contained_export_verifies_exact_raw_custody_and_offline_reproduction() -> Result<()> {
    let data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let raw = RawEvidenceMember::from_bytes(b"retained raw advisory")?;
    let bundle = AssessmentBundleV1::export(input, data, BundleProfile::SelfContained, vec![raw])?;
    assert!(bundle.manifest.external_references.is_empty());
    let identity = bundle.verify()?;
    let replay = AssessmentBundleV1::from_slice(&bundle.encoded()?)?;
    assert_eq!(replay.verify()?, identity);
    assert_eq!(replay.assessment.digest()?, bundle.assessment.digest()?);
    Ok(())
}

#[test]
fn reference_export_declares_missing_sources_and_cannot_claim_self_containment() -> Result<()> {
    let data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    assert!(
        AssessmentBundleV1::export(
            input.clone(),
            data.clone(),
            BundleProfile::SelfContained,
            vec![]
        )
        .is_err()
    );
    let bundle = AssessmentBundleV1::export(input, data, BundleProfile::Reference, vec![])?;
    assert_eq!(bundle.manifest.external_references.len(), 1);
    assert_eq!(bundle.manifest.external_references[0].byte_length, 21);
    bundle.verify()?;
    Ok(())
}

#[test]
fn changed_result_duplicate_objects_and_unlisted_content_are_rejected() -> Result<()> {
    let data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let bundle = AssessmentBundleV1::export(
        input,
        data,
        BundleProfile::SelfContained,
        vec![RawEvidenceMember::from_bytes(b"retained raw advisory")?],
    )?;
    let mut tampered = bundle.clone();
    tampered.assessment.subject_results[0].findings.clear();
    assert!(tampered.verify().is_err());
    tampered = bundle.clone();
    tampered.raw_members.push(tampered.raw_members[0].clone());
    assert!(tampered.verify().is_err());
    tampered = bundle;
    tampered.raw_members[0] = RawEvidenceMember::from_bytes(b"unlisted executable content")?;
    assert!(tampered.verify().is_err());
    Ok(())
}

#[test]
fn forged_sizes_digests_optional_nulls_and_extraction_paths_are_rejected() -> Result<()> {
    let raw = RawEvidenceMember::from_bytes(b"fixture")?;
    let mut forged = raw.clone();
    forged.byte_length = u64::MAX;
    assert!(forged.decode().is_err());
    forged = raw;
    forged.digest = Sha256Digest::of_bytes("wrong bytes");
    assert!(forged.decode().is_err());
    let data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let bundle = AssessmentBundleV1::export(input, data, BundleProfile::Reference, vec![])?;
    let mut value = serde_json::to_value(&bundle)?;
    value["data"]["advisorySnapshot"]["exploitCatalog"] = serde_json::Value::Null;
    assert!(AssessmentBundleV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value = serde_json::to_value(&bundle)?;
    value["rawMembers"] = serde_json::json!([{"path":"../../outside", "data":""}]);
    assert!(AssessmentBundleV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}
