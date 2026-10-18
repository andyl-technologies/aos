//! Signed qualification decisions and their admission by later steps.
//!
//! A destination's qualification runs in up to three phases:
//!
//! - `staging`: observations over the staging surface's exact bytes, signed
//!   as a qualification receipt; `publish` admits it for a production
//!   destination (and a production Hub re-imports it);
//! - `rollout`: fresh health observations before one ring, signed as an
//!   admission that names the destination, ring, partition range, prior
//!   generation, and the exact input journal;
//! - `complete`: observations after the soak, signed as an admission over the
//!   rolling journal.
//!
//! Each signed decision is accompanied by its canonical report, the retained
//! executor reports under `reports/`, and independent reviews as
//! `review-*.json`, which admission re-verifies.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_release_coordinator::signer::ExternalSigner;

use anyhow::{Context as _, Result, bail};
use aos_cli_ui::output::Printer;
use aos_release_format::evidence::QualificationReport;
use aos_release_format::manifest::ReleaseManifestV1;
use aos_release_format::plan::{PlannedDestination, ReleasePlan};
use aos_release_format::qualification::QualificationPhase;
use aos_release_format::qualification_admission::{
    QUALIFICATION_ADMISSION, QualificationAdmission, QualificationRolloutIntent,
};
use aos_release_format::receipt::{
    QualificationReceipt, RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT, SignedReceiptEnvelope,
    verify_signed_receipt_with_key,
};
use aos_release_format::signing::{
    SignatureAlgorithm, SignerRole, SigningContext, SigningOperation, SigningRequest,
    TrustedEd25519Key,
};
use aos_release_format::state::ReleaseState;
use aos_release_format::{Sha256Digest, canonical};

use super::journal::Journal;
use super::{capture, qualification_run, surface};
use crate::cli::ReleaseQualifyRunArgs;

/// Policy id carried by every staging-phase qualification receipt.
pub(super) const STAGING_POLICY_ID: &str = "full-release-qualification";

/// A verified staging-phase qualification for one production destination.
pub(super) struct AdmittedQualification {
    /// Exact signed qualification envelope.
    pub(super) signed: Vec<u8>,
    /// SHA-256 of `signed`, recorded as journal evidence.
    pub(super) digest: Sha256Digest,
    /// Canonical qualification receipt payload.
    pub(super) payload: Vec<u8>,
}

/// Verifies independent reviews of an exact report for one destination.
pub(super) fn verify_reviews(
    plan: &ReleasePlan,
    destination: &str,
    report: &[u8],
    paths: &[PathBuf],
    keys: &[TrustedEd25519Key],
) -> Result<()> {
    let reviews = paths
        .iter()
        .map(|path| capture::control_file(path, "qualification review"))
        .collect::<Result<Vec<_>>>()?;
    aos_release_format::qualification_admission::verify_reviews(
        plan,
        destination,
        report,
        &reviews,
        keys,
    )
}

/// Returns whether the destination's profile selects any case at `phase`.
pub(super) fn phase_has_cases(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    destination: &str,
    phase: QualificationPhase,
) -> Result<bool> {
    Ok(!aos_release_format::qualification_evidence::cases(
        plan,
        manifest,
        Some(destination),
        phase,
    )?
    .is_empty())
}

/// Inputs of one rollout or completion admission signature.
pub(super) struct AdmissionSigning<'a> {
    /// Operator arguments naming the authority, nonce, ring, and output.
    pub(super) args: &'a ReleaseQualifyRunArgs,
    /// Frozen plan.
    pub(super) plan: &'a ReleasePlan,
    /// Destination whose phase is admitted.
    pub(super) destination: &'a PlannedDestination,
    /// Final manifest identity.
    pub(super) manifest_digest: Sha256Digest,
    /// Destination surface publication receipt.
    pub(super) publication: &'a surface::SignedReceipt,
    /// Canonical report bytes.
    pub(super) report: &'a [u8],
    /// Retained executor reports keyed by evidence id.
    pub(super) reports: &'a BTreeMap<String, Vec<u8>>,
    /// Hold point.
    pub(super) phase: QualificationPhase,
}

/// Signs a rollout or completion admission and persists the evidence tree.
pub(super) async fn sign(signing: AdmissionSigning<'_>, printer: &Printer) -> Result<()> {
    let AdmissionSigning {
        args,
        plan,
        destination,
        manifest_digest,
        publication,
        report,
        reports,
        phase,
    } = signing;
    let journal = Journal::read(
        args.journal
            .as_deref()
            .context("rollout/completion qualification requires --journal")?,
        "qualification input journal",
    )?;
    journal.require_release(plan, manifest_digest)?;
    match phase {
        QualificationPhase::Rollout => {
            journal.summary.require_rolling_allowed(&destination.name)?
        }
        QualificationPhase::Complete => {
            if journal.summary.state_of(&destination.name) != Some(ReleaseState::Rolling) {
                bail!(
                    "completion qualification requires {} to be rolling",
                    destination.name
                );
            }
        }
        _ => bail!("only rollout and completion admissions are signed here"),
    }
    if !journal.contains_evidence(publication.digest) {
        bail!("qualification journal does not record the destination's publication receipt");
    }

    let rollout = match phase {
        QualificationPhase::Rollout => Some(QualificationRolloutIntent::for_ring(
            destination,
            args.ring.context("rollout qualification requires --ring")?,
            args.prior_generation
                .context("rollout qualification requires --prior-generation")?,
        )?),
        _ => None,
    };
    let (key_id, path) = args
        .authority_key
        .split_once('=')
        .context("authority key must be KEY_ID=PATH")?;
    let plan_digest = Sha256Digest::of_bytes(&canonical::to_vec(plan)?);
    let admission = QualificationAdmission {
        schema_version: QUALIFICATION_ADMISSION.into(),
        phase,
        destination: destination.name.clone(),
        rollout,
        registry: plan.registry.clone(),
        release_id: plan.release_id.clone(),
        plan_digest,
        manifest_digest,
        publication_receipt_digest: publication.digest,
        journal_digest: Sha256Digest::of_bytes(&journal.bytes),
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
    let request = SigningRequest {
        schema_version: aos_release_format::signing::SIGNING_REQUEST_DOMAIN.into(),
        request_id: format!(
            "qualification-admission/{}/{}",
            plan.release_id,
            destination.name.replace('/', "-")
        ),
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
    let signer = ExternalSigner::resolve(
        args.authority_executable.as_deref(),
        args.authority_config.as_deref(),
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
    let envelope = SignedReceiptEnvelope {
        schema_version: SIGNED_RECEIPT.into(),
        key_id: key_id.to_owned(),
        payload: serde_json::to_value(&admission)?,
        signature_base64: response.signature_base64.clone(),
    };
    let signed = canonical::to_vec(&envelope)?;
    let (_, verified): (String, QualificationAdmission) = verify_signed_receipt_with_key(
        &signed,
        &BTreeMap::from([(key_id.to_owned(), key.public_key)]),
    )?;
    if verified != admission {
        bail!("qualification signer changed admission");
    }
    qualification_run::persist(
        &args.output,
        &publication.bytes,
        report,
        reports,
        &payload,
        &signed,
        &canonical::to_vec(&response)?,
        &args.review_receipts,
    )?;
    printer.success(&format!(
        "Signed {phase:?} qualification of {} for {}",
        destination.name, plan.release_id
    ));
    Ok(())
}

/// Inputs of one rollout or completion admission check.
pub(super) struct AdmissionCheck<'a> {
    /// Frozen plan.
    pub(super) plan: &'a ReleasePlan,
    /// Final manifest.
    pub(super) manifest: &'a ReleaseManifestV1,
    /// Destination whose channel operation is admitted.
    pub(super) destination: &'a PlannedDestination,
    /// Signed qualification directory, when supplied.
    pub(super) directory: Option<&'a Path>,
    /// Qualification authority keys as `KEY_ID=PATH`.
    pub(super) key_specs: &'a [String],
    /// Release-evidence keys for independent reviews.
    pub(super) review_keys: &'a [TrustedEd25519Key],
    /// Hold point.
    pub(super) phase: QualificationPhase,
    /// Exact channel operation the rollout admission must name.
    pub(super) rollout: Option<&'a QualificationRolloutIntent>,
    /// Exact input journal bytes.
    pub(super) journal: &'a [u8],
    /// Destination surface publication receipt digest.
    pub(super) publication_digest: Sha256Digest,
    /// Final manifest identity.
    pub(super) manifest_digest: Sha256Digest,
}

/// Verifies a signed rollout or completion admission when the phase has cases.
///
/// Returns the signed admission digest to record, or `None` when the
/// destination's profile selects no case at this phase (in which case no
/// directory may be supplied).
pub(super) fn verify_admission(check: AdmissionCheck<'_>) -> Result<Option<Sha256Digest>> {
    let name = check.destination.name.as_str();
    if !phase_has_cases(check.plan, check.manifest, name, check.phase)? {
        if check.directory.is_some() {
            bail!(
                "{name} has no {:?} qualification; omit --qualification",
                check.phase
            );
        }
        return Ok(None);
    }
    let directory = check
        .directory
        .with_context(|| format!("{name} requires a signed {:?} qualification", check.phase))?;
    let signed = capture::control_file(
        &directory.join("signed-qualification.json"),
        "signed hold-point qualification",
    )?;
    let keys = surface::key_map(check.key_specs)?;
    let (key, admission): (String, QualificationAdmission) =
        verify_signed_receipt_with_key(&signed, &keys)?;
    let now = super::journal::now_utc();
    admission.validate(check.plan, &now)?;
    if admission.authority_id != key
        || admission.phase != check.phase
        || admission.destination != name
        || admission.rollout.as_ref() != check.rollout
        || admission.manifest_digest != check.manifest_digest
        || admission.publication_receipt_digest != check.publication_digest
        || admission.journal_digest != Sha256Digest::of_bytes(check.journal)
    {
        bail!("qualification admission is for another destination, receipt, phase, or journal");
    }
    let report = capture::control_file(
        &directory.join("qualification-report.json"),
        "hold-point observations",
    )?;
    canonical::require_canonical(&report, "hold-point observations")?;
    if Sha256Digest::of_bytes(&report) != admission.report_digest {
        bail!("qualification observation digest mismatch");
    }
    let parsed: QualificationReport = canonical::from_slice(&report, "hold-point observations")?;
    if parsed.phase != check.phase
        || parsed.manifest_digest != check.manifest_digest
        || parsed.staging_receipt_digest != check.publication_digest
    {
        bail!("qualification report scope mismatch");
    }
    parsed.validate_phase(check.plan, check.manifest, name, check.phase, &now)?;
    verify_report_files(directory, &parsed)?;
    verify_reviews(
        check.plan,
        name,
        &report,
        &review_paths(directory)?,
        check.review_keys,
    )?;
    Ok(Some(Sha256Digest::of_bytes(&signed)))
}

/// Verifies one staging-phase evidence directory for a production destination.
///
/// The directory holds `qualification-report.json`, `signed-qualification.json`,
/// `reports/`, and `review-*.json`. The report must name the destination and
/// the exact staging receipt, remain fresh now, and carry the destination's
/// review threshold; the receipt must be signed by the plan's single
/// qualification authority.
pub(super) fn verify_staging_evidence(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    destination: &str,
    directory: &Path,
    staging_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    qualification_keys: &[String],
    review_keys: &[TrustedEd25519Key],
) -> Result<AdmittedQualification> {
    let report_bytes = capture::control_file(
        &directory.join("qualification-report.json"),
        "qualification report",
    )?;
    canonical::require_canonical(&report_bytes, "qualification report")?;
    let report: QualificationReport = canonical::from_slice(&report_bytes, "qualification report")?;
    if report.destination != destination {
        bail!("staging qualification report names a different destination");
    }
    report.validate(plan, manifest, staging_digest, manifest_digest)?;

    let signed = capture::control_file(
        &directory.join("signed-qualification.json"),
        "signed qualification receipt",
    )?;
    let keys = surface::key_map(qualification_keys)?;
    let (key_id, receipt): (String, QualificationReceipt) =
        verify_signed_receipt_with_key(&signed, &keys)?;
    receipt.validate()?;
    let role = plan
        .signers
        .iter()
        .find(|role| role.role == SignerRole::Qualification)
        .context("missing planned qualification authority")?;
    if key_id != receipt.authority_id
        || role.threshold != 1
        || role.key_ids.as_slice() != [receipt.authority_id.as_str()]
    {
        bail!("qualification signer differs from the frozen plan");
    }
    if receipt.staging_receipt_digest != staging_digest
        || receipt.manifest_digest != manifest_digest
        || receipt.policy_id != STAGING_POLICY_ID
        || receipt.policy_digest != plan.public_evidence_policy_digest
        || receipt.report_digest != Sha256Digest::of_bytes(&report_bytes)
    {
        bail!("qualification receipt does not bind the exact staged release");
    }
    let now = super::journal::now_utc();
    if humantime::parse_rfc3339(&receipt.qualified_at)? > humantime::parse_rfc3339(&now)? {
        bail!("qualification authority time is in the future");
    }
    report.validate_phase(
        plan,
        manifest,
        destination,
        QualificationPhase::Staging,
        &now,
    )?;
    verify_report_files(directory, &report)?;
    verify_reviews(
        plan,
        destination,
        &report_bytes,
        &review_paths(directory)?,
        review_keys,
    )?;
    Ok(AdmittedQualification {
        digest: Sha256Digest::of_bytes(&signed),
        payload: canonical::to_vec(&receipt)?,
        signed,
    })
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

fn verify_report_files(directory: &Path, report: &QualificationReport) -> Result<()> {
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
