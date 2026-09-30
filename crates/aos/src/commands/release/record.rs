//! `aos release record`: compose the public release record from admitted
//! qualification evidence.
//!
//! The record is derived, never authored: every field is copied from the
//! frozen plan, the final manifest, the signed staging-phase qualification of
//! one production destination, and the public report after each has been
//! verified here as `step publish` verifies them. The output is canonical JSON that `aos release tuf`
//! authorizes as a delegated target beside the manifest and `aos release
//! compose-surface` serves at `releases/<class>/<version>/release-record.json`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::evidence::QualificationReport;
use aos_release::manifest::ManifestEnvelopeV1;
use aos_release::plan::ReleasePlan;
use aos_release::receipt::{QualificationReceipt, verify_signed_receipt_with_key};
use aos_release::record::ReleaseRecordV1;

use super::{capture, verify};
use crate::cli::ReleaseRecordArgs;

/// Composes and writes the release record.
///
/// # Errors
/// Returns an error when any input fails verification, when the evidence
/// does not bind the bundle's exact manifest, or when the output already
/// exists or cannot be written.
pub(super) fn run(args: &ReleaseRecordArgs, printer: &Printer) -> Result<()> {
    let captured = capture::bundle(&args.bundle)?;
    let manifest_keys = verify::load_trusted_keys(&args.trusted_keys)?;
    let summary = aos_release::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        &manifest_keys,
    )?;
    let plan: ReleasePlan = canonical::from_slice(&captured.plan_bytes, "release plan")?;
    plan.require_publishable_qualification()?;
    let manifest: ManifestEnvelopeV1 =
        canonical::from_slice(&captured.manifest_bytes, "release manifest")?;
    let bundle_digest =
        aos_release::verify::bundle_digest(&captured.manifest_bytes, &captured.files)?;

    let destination = plan.destination(&args.to)?;
    if destination.surface != aos_release::plan::SurfaceRole::Production {
        bail!("release records describe production destinations");
    }

    // The staging receipt is checked only for the identities the signed
    // qualification binds by digest; the record does not restate it.
    let staging_bytes = capture::control_file(&args.staging_receipt, "signed staging receipt")?;
    let staging_digest = Sha256Digest::of_bytes(&staging_bytes);
    let staging: serde_json::Value = super::surface::receipt_payload(&staging_bytes)?;
    if staging.get("registry").and_then(serde_json::Value::as_str) != Some(plan.registry.as_str())
        || staging
            .get("release_id")
            .and_then(serde_json::Value::as_str)
            != Some(summary.release_id.as_str())
        || staging
            .get("manifest_digest")
            .and_then(serde_json::Value::as_str)
            != Some(summary.manifest_digest.to_string().as_str())
        || staging
            .get("bundle_digest")
            .and_then(serde_json::Value::as_str)
            != Some(bundle_digest.to_string().as_str())
    {
        bail!("staging receipt does not bind the exact release");
    }

    let qualification_bytes =
        capture::control_file(&args.signed_qualification, "signed qualification receipt")?;
    let qualification_keys = key_map(&args.qualification_keys)?;
    let (qualification_key_id, qualification): (String, QualificationReceipt) =
        verify_signed_receipt_with_key(&qualification_bytes, &qualification_keys)?;
    qualification.validate()?;
    let report_bytes = capture::control_file(&args.qualification_report, "qualification report")?;
    let report: QualificationReport = canonical::from_slice(&report_bytes, "qualification report")?;
    if canonical::to_vec(&report)? != report_bytes {
        bail!("qualification report is not canonical JSON");
    }
    if report.destination != destination.name {
        bail!("qualification report names a different destination");
    }
    report.validate(
        &plan,
        &manifest.payload,
        staging_digest,
        summary.manifest_digest,
    )?;
    if qualification_key_id != qualification.authority_id
        || qualification.staging_receipt_digest != staging_digest
        || qualification.manifest_digest != summary.manifest_digest
        || qualification.policy_digest != plan.public_evidence_policy_digest
        || qualification.report_digest != Sha256Digest::of_bytes(&report_bytes)
    {
        bail!("qualification evidence does not bind the exact release");
    }

    let record = ReleaseRecordV1::compose(
        &plan,
        &manifest.payload,
        summary.manifest_digest,
        &qualification,
        &qualification_bytes,
        &report,
    )?;
    record.validate()?;
    let bytes = canonical::to_vec(&record)?;
    write_new_file(&args.output, &bytes)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.record-result/v1",
        "release_id": record.release_id,
        "version": record.version,
        "train": record.train,
        "record_digest": Sha256Digest::of_bytes(&bytes),
        "claims": record.qualification.claims.len(),
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Composed release record for {} ({} claims) at {}",
        record.version,
        record.qualification.claims.len(),
        args.output.display()
    ));
    Ok(())
}

fn key_map(specifications: &[String]) -> Result<BTreeMap<String, [u8; 32]>> {
    Ok(verify::load_trusted_keys(specifications)?
        .into_iter()
        .map(|key| (key.key_id, key.public_key))
        .collect())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
