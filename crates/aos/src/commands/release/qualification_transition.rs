//! Authority signatures and fresh qualification at rollout hold points.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::evidence::QualificationReportV1;
use aos_release::manifest::ReleaseManifestV1;
use aos_release::plan::ReleasePlanV1;
use aos_release::qualification::QualificationPhase;
use aos_release::qualification_admission::QualificationAdmissionV1;
use aos_release::receipt::{
    RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT_V1, SignedReceiptEnvelopeV1,
    verify_signed_receipt_with_key,
};
use aos_release::signing::{
    SignatureAlgorithm, SignerRole, SigningContext, SigningOperation, SigningRequestV1,
    TrustedEd25519Key,
};
use aos_release::{Sha256Digest, canonical};

use super::{capture, qualification_run, signer::ExternalSigner, verify};
use crate::cli::ReleaseQualifyRunArgs;

pub(super) fn verify_reviews(
    plan: &ReleasePlanV1,
    report: &[u8],
    paths: &[PathBuf],
    keys: &[TrustedEd25519Key],
) -> Result<()> {
    let reviews = paths
        .iter()
        .map(|path| capture::control_file(path, "qualification review"))
        .collect::<Result<Vec<_>>>()?;
    aos_release::qualification_admission::verify_reviews(plan, report, &reviews, keys)
}

pub(super) async fn sign(
    args: &ReleaseQualifyRunArgs,
    plan: &ReleasePlanV1,
    manifest_digest: Sha256Digest,
    publication_receipt_digest: Sha256Digest,
    report: &[u8],
    reports: &BTreeMap<String, Vec<u8>>,
    publication: &[u8],
    phase: QualificationPhase,
    printer: &Printer,
) -> Result<()> {
    let journal = capture::control_file(
        args.journal
            .as_deref()
            .context("rollout/completion qualification requires --journal")?,
        "qualification input journal",
    )?;
    let entries = aos_release::state::parse_journal(&journal)?;
    let state = aos_release::verify::verify_journal(&entries)?;
    let latest = entries.last().context("empty qualification journal")?;
    let plan_digest = Sha256Digest::of_bytes(&canonical::to_vec(plan)?);
    if latest.plan_digest != plan_digest
        || latest.manifest_digest != Some(manifest_digest)
        || (phase == QualificationPhase::Rollout
            && !matches!(
                state,
                aos_release::state::ReleaseState::Promoted
                    | aos_release::state::ReleaseState::Rolling
            ))
        || (phase == QualificationPhase::Complete
            && state != aos_release::state::ReleaseState::Rolling)
    {
        bail!("qualification journal is not at the requested release hold point");
    }
    let (key_id, path) = args
        .authority_key
        .split_once('=')
        .context("authority key must be KEY_ID=PATH")?;
    let rollout = args
        .rollout_intent
        .as_ref()
        .map(|path| {
            canonical::from_slice(
                &capture::control_file(path, "qualification rollout intent")?,
                "qualification rollout intent",
            )
        })
        .transpose()?;
    let admission = QualificationAdmissionV1 {
        schema_version: "aos.release.qualification-admission/v1".into(),
        phase,
        rollout,
        registry: plan.registry.clone(),
        release_id: plan.release_id.clone(),
        plan_digest,
        manifest_digest,
        publication_receipt_digest,
        journal_digest: Sha256Digest::of_bytes(&journal),
        report_digest: Sha256Digest::of_bytes(report),
        policy_digest: plan.public_evidence_policy_digest,
        authority_id: key_id.to_owned(),
        admitted_at: args.qualified_at.clone(),
    };
    admission.validate(plan, &args.qualified_at)?;
    let payload = canonical::to_vec(&admission)?;
    let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload);
    let role = plan
        .signers
        .iter()
        .find(|role| role.role == SignerRole::Qualification)
        .context("missing qualification signer")?;
    let key = TrustedEd25519Key::from_encoded(
        key_id,
        &capture::control_file(Path::new(path), "qualification public key")?,
    )?;
    let request = SigningRequestV1 {
        schema_version: aos_release::signing::SIGNING_REQUEST_DOMAIN.into(),
        request_id: format!("qualification-admission/{}", plan.release_id),
        nonce: args.authority_nonce.clone(),
        registry: plan.registry.clone(),
        release_id: plan.release_id.clone(),
        plan_digest,
        manifest_digest: Some(manifest_digest),
        role: SignerRole::Qualification,
        key_id: key_id.to_owned(),
        provider_revision: role.provider_revision.clone(),
        algorithm: SignatureAlgorithm::Ed25519Payload,
        operation: SigningOperation::SignPayload,
        context: SigningContext::Payload {
            artifact_kind: "qualification-receipt-digest".into(),
        },
        payload_digest: Sha256Digest::of_bytes(digest.as_bytes()),
        approval_policy_digest: plan.restricted_operator_policy_digest,
    };
    let signer = ExternalSigner::new(
        args.authority_executable.clone(),
        Duration::from_secs(args.authority_timeout_seconds),
    )?;
    let response = signer
        .sign_ed25519_payload(
            &request,
            digest.as_bytes(),
            &key,
            &args.authority_verification_identity,
        )
        .await?;
    let envelope = SignedReceiptEnvelopeV1 {
        schema_version: SIGNED_RECEIPT_V1.into(),
        key_id: key_id.to_owned(),
        payload: serde_json::to_value(&admission)?,
        signature_base64: response.signature_base64.clone(),
    };
    let signed = canonical::to_vec(&envelope)?;
    let (_, verified): (String, QualificationAdmissionV1) = verify_signed_receipt_with_key(
        &signed,
        &BTreeMap::from([(key_id.to_owned(), key.public_key)]),
    )?;
    if verified != admission {
        bail!("qualification signer changed admission");
    }
    qualification_run::persist(
        &args.output,
        publication,
        report,
        reports,
        &payload,
        &signed,
        &canonical::to_vec(&response)?,
        &args.review_receipts,
    )?;
    printer.success(&format!(
        "Signed {:?} qualification for {}",
        phase, plan.release_id
    ));
    Ok(())
}

pub(super) fn verify_admission(
    plan: &ReleasePlanV1,
    manifest: &ReleaseManifestV1,
    directory: Option<&Path>,
    key_specs: &[String],
    manifest_keys: &[TrustedEd25519Key],
    phase: QualificationPhase,
    rollout: Option<&aos_release::qualification_admission::QualificationRolloutIntent>,
    journal: &[u8],
    production_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
) -> Result<Option<Sha256Digest>> {
    if plan.qualification.is_none() {
        return Ok(None);
    }
    let directory =
        directory.context("shared-contract channel operations require --qualification")?;
    let signed = capture::control_file(
        &directory.join("signed-qualification.json"),
        "signed hold-point qualification",
    )?;
    let keys: BTreeMap<_, _> = verify::load_trusted_keys(key_specs)?
        .into_iter()
        .map(|key| (key.key_id, key.public_key))
        .collect();
    let (key, admission): (String, QualificationAdmissionV1) =
        verify_signed_receipt_with_key(&signed, &keys)?;
    let now = humantime::format_rfc3339(std::time::SystemTime::now()).to_string();
    admission.validate(plan, &now)?;
    if admission.authority_id != key
        || admission.phase != phase
        || admission.rollout.as_ref() != rollout
        || admission.manifest_digest != manifest_digest
        || admission.publication_receipt_digest != production_digest
        || admission.journal_digest != Sha256Digest::of_bytes(journal)
    {
        bail!("qualification admission is for another release, receipt, phase, or journal");
    }
    let report = capture::control_file(
        &directory.join("qualification-report.json"),
        "hold-point observations",
    )?;
    canonical::require_canonical(&report, "hold-point observations")?;
    if Sha256Digest::of_bytes(&report) != admission.report_digest {
        bail!("qualification observation digest mismatch");
    }
    let parsed: QualificationReportV1 = canonical::from_slice(&report, "hold-point observations")?;
    if parsed.schema_version != "aos.release.qualification-report/v2"
        || parsed.phase != Some(phase)
        || parsed.manifest_digest != manifest_digest
        || parsed.staging_receipt_digest != production_digest
    {
        bail!("qualification report scope mismatch");
    }
    aos_release::qualification_evidence::validate_observations(
        plan,
        manifest,
        phase,
        &parsed.evidence,
        &now,
    )?;
    verify_report_files(directory, &parsed)?;
    verify_reviews(plan, &report, &review_paths(directory)?, manifest_keys)?;
    Ok(Some(Sha256Digest::of_bytes(&signed)))
}

/// Rechecks the retained report bodies and independent reviews at admission.
pub(super) fn verify_staging_report(
    plan: &ReleasePlanV1,
    manifest: &ReleaseManifestV1,
    report_path: &Path,
    report: &[u8],
    receipt: &aos_release::receipt::QualificationReceiptV1,
    keys: &[TrustedEd25519Key],
) -> Result<()> {
    if plan.qualification.is_none() {
        return Ok(());
    }
    let now = humantime::format_rfc3339(std::time::SystemTime::now()).to_string();
    let admitted = humantime::parse_rfc3339(&receipt.qualified_at)?;
    if admitted > humantime::parse_rfc3339(&now)? {
        bail!("qualification authority time is in the future");
    }
    let role = plan
        .signers
        .iter()
        .find(|role| role.role == SignerRole::Qualification)
        .context("missing planned qualification authority")?;
    if role.threshold != 1 || role.key_ids.as_slice() != [receipt.authority_id.as_str()] {
        bail!("qualification signer differs from the frozen plan");
    }
    let parsed: QualificationReportV1 = canonical::from_slice(report, "staging report")?;
    aos_release::qualification_evidence::validate_observations(
        plan,
        manifest,
        QualificationPhase::Staging,
        &parsed.evidence,
        &now,
    )?;
    let directory = report_path
        .parent()
        .context("qualification report lacks parent directory")?;
    verify_report_files(directory, &parsed)?;
    verify_reviews(plan, report, &review_paths(directory)?, keys)
}

fn review_paths(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                name.to_string_lossy().starts_with("review-")
                    && name.to_string_lossy().ends_with(".json")
            })
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn verify_report_files(directory: &Path, report: &QualificationReportV1) -> Result<()> {
    for record in &report.evidence {
        let bytes = capture::control_file(
            &directory
                .join("reports")
                .join(qualification_run::report_filename(&record.id)),
            "qualification executor report",
        )?;
        canonical::require_canonical(&bytes, "qualification executor report")?;
        if Sha256Digest::of_bytes(&bytes) != record.report_digest {
            bail!("retained report differs from the signed observation");
        }
    }
    Ok(())
}
