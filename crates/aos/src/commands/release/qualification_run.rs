//! `aos maintain release step qualify-run`: one destination's qualification phase.
//!
//! The destination's profile and the plan's change scope select the cases of
//! the phase. Every case runs on its platform's native executor against the
//! exact anonymous objects of the surface under test: the staging surface for
//! the `staging` phase, the destination's own surface for `rollout` and
//! `complete`. The collected report is reviewed independently
//! (`--prepare-only`, then `--report-input` with review receipts) and signed
//! by the qualification authority: a qualification receipt for `staging`, a
//! destination-scoped admission for `rollout` (one ring) and `complete`.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::evidence::{
    GateResult, QUALIFICATION_EXECUTOR_REQUEST, QUALIFICATION_EXECUTOR_RESPONSE,
    QUALIFICATION_REPORT, QualificationExecutorRequest, QualificationExecutorResponse,
    QualificationReport,
};
use aos_release::plan::{PlannedDestination, ReleasePlan, SurfaceKind, SurfaceRole};
use aos_release::platform::Platform;
use aos_release::qualification::QualificationPhase;
use aos_release::qualification_evidence::{
    NATIVE_ADAPTER_MATRIX_REQUIREMENT, validate_matrix_for_case,
};
use aos_release::receipt::{
    QualificationReceipt, RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT, SignedReceiptEnvelope,
    verify_signed_receipt_with_key,
};
use aos_release::signing::{
    SignatureAlgorithm, SignerRole, SigningContext, SigningOperation, SigningRequest,
    TrustedEd25519Key,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use crate::cli::ReleaseQualifyRunArgs;

use super::access::{self, SignerNeed};
use super::capture;
use super::qualification_objects::{predecessor_bundle, public_objects, retained_predecessor};
use super::qualification_transition::{self, AdmissionSigning, STAGING_POLICY_ID};
use super::signer::ExternalSigner;
use super::surface::{self, SignedReceipt, project, readback};
use super::verify::{VerifiedBundle, verified_bundle};

const MAX_EXECUTOR_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXECUTOR_DIAGNOSTIC_BYTES: u64 = 64 * 1024;

/// Runs one qualification phase inside a retained attempt directory.
pub(super) async fn run(args: &ReleaseQualifyRunArgs, printer: &Printer) -> Result<()> {
    if args.output.exists() {
        bail!(
            "qualification output already exists: {}",
            args.output.display()
        );
    }
    let parent = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let attempt = tempfile::Builder::new()
        .prefix(".aos-qualification-attempt-")
        .tempdir_in(parent)?
        .keep();
    let result = run_attempt(args, printer, &attempt).await;
    match &result {
        Ok(()) => fs::write(attempt.join("result"), b"passed\n")?,
        Err(error) => fs::write(attempt.join("failure.txt"), format!("{error:#}\n"))?,
    }
    result.with_context(|| format!("qualification attempt retained at {}", attempt.display()))
}

async fn run_attempt(
    args: &ReleaseQualifyRunArgs,
    printer: &Printer,
    attempt: &Path,
) -> Result<()> {
    let phase = match args.phase.as_str() {
        "staging" => QualificationPhase::Staging,
        "rollout" => QualificationPhase::Rollout,
        "complete" => QualificationPhase::Complete,
        _ => bail!("unknown qualification hold point"),
    };
    let bundle = verified_bundle(&args.bundle, &args.trusted_keys)?;
    let plan = &bundle.plan;
    let destination = plan.destination(&args.to)?;
    let manifest_digest = bundle.summary.manifest_digest;

    // The staging phase observes the staging surface; later phases observe
    // the destination's own surface.
    let role = match phase {
        QualificationPhase::Staging => SurfaceRole::Staging,
        _ => destination.surface,
    };
    let publication = SignedReceipt::read(&args.staging_receipt, "publication receipt")?;
    let view_destination = receipt_destination(plan, destination, role)?;
    let receipt = surface::verify_publication_receipt(
        plan,
        view_destination,
        &publication,
        &surface::key_map(&args.hub_receipt_keys)?,
    )?;
    if receipt.bundle_digest != bundle.bundle_digest || receipt.manifest_digest != manifest_digest {
        bail!("publication receipt does not bind the qualification input");
    }
    let client = access::connect(plan, role, None, None, SignerNeed::None).await?;
    client.verify_identity().await?;

    validate_nonce(&args.executor_nonce, "executor nonce")?;
    validate_nonce(&args.authority_nonce, "authority nonce")?;
    let (evidence, mut reports) = if args.report_input.is_none() {
        collect_observations(
            args,
            &bundle,
            destination,
            phase,
            role,
            &publication,
            attempt,
        )
        .await?
    } else {
        (Vec::new(), BTreeMap::new())
    };

    let mut resolved_args = args.clone();
    if resolved_args.qualified_at == "now" {
        resolved_args.qualified_at = super::journal::now_utc();
    }
    let args = &resolved_args;
    let report = match &args.report_input {
        Some(path) => {
            let bytes = capture::control_file(path, "prepared qualification report")?;
            canonical::require_canonical(&bytes, "prepared qualification report")?;
            canonical::from_slice::<QualificationReport>(&bytes, "prepared qualification report")?
        }
        None => QualificationReport {
            claims: aos_release::qualification_evidence::assess_observations(
                plan,
                &bundle.manifest.payload,
                Some(&destination.name),
                phase,
                &evidence,
                &args.qualified_at,
                None,
            )?,
            destination: destination.name.clone(),
            phase,
            admitted_at: args.qualified_at.clone(),
            schema_version: QUALIFICATION_REPORT.to_owned(),
            staging_receipt_digest: publication.digest,
            manifest_digest,
            evidence,
        },
    };
    if report.phase != phase
        || report.destination != destination.name
        || report.staging_receipt_digest != publication.digest
        || report.manifest_digest != manifest_digest
    {
        bail!("prepared qualification report differs from this destination and hold point");
    }
    report.validate_phase(
        plan,
        &bundle.manifest.payload,
        &destination.name,
        phase,
        &args.qualified_at,
    )?;
    let report_bytes = canonical::to_vec(&report)?;
    if let Some(path) = &args.report_input {
        let parent = path
            .parent()
            .context("prepared report lacks parent directory")?;
        for record in &report.evidence {
            let bytes = capture::control_file(
                &parent.join("reports").join(report_filename(&record.id)),
                "prepared executor report",
            )?;
            if Sha256Digest::of_bytes(&bytes) != record.report_digest {
                bail!("prepared executor report digest differs from its observation");
            }
            reports.insert(record.id.clone(), bytes);
        }
    }

    if args.prepare_only {
        persist(
            &args.output,
            &publication.bytes,
            &report_bytes,
            &reports,
            b"",
            b"",
            b"",
            &[],
        )?;
        printer.success("Collected qualification observations for independent review; no authority signature was requested");
        return Ok(());
    }
    qualification_transition::verify_reviews(
        plan,
        &destination.name,
        &report_bytes,
        &args.review_receipts,
        &bundle.manifest_keys,
    )?;
    if phase != QualificationPhase::Staging {
        return qualification_transition::sign(
            AdmissionSigning {
                args,
                plan,
                destination,
                manifest_digest,
                publication: &publication,
                report: &report_bytes,
                reports: &reports,
                phase,
            },
            printer,
        )
        .await;
    }

    let receipt = QualificationReceipt {
        schema_version: aos_release::receipt::QUALIFICATION_RECEIPT.to_owned(),
        staging_receipt_digest: publication.digest,
        manifest_digest,
        policy_id: STAGING_POLICY_ID.to_owned(),
        policy_digest: plan.public_evidence_policy_digest,
        result: GateResult::Passed,
        report_digest: Sha256Digest::of_bytes(&report_bytes),
        authority_id: String::new(),
        nonce: args.authority_nonce.clone(),
        qualified_at: args.qualified_at.clone(),
    };
    let (receipt, signed_receipt, signing_response) =
        sign_receipt(args, plan, destination, receipt).await?;
    persist(
        &args.output,
        &publication.bytes,
        &report_bytes,
        &reports,
        &canonical::to_vec(&receipt)?,
        &signed_receipt,
        &signing_response,
        &args.review_receipts,
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.qualify-run-result/v1",
        "destination": destination.name,
        "release_id": plan.release_id,
        "evidence_count": report.evidence.len(),
        "claims": report.claims,
        "qualification_report_digest": receipt.report_digest,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Qualified {} case executions of {} for {}",
        report.evidence.len(),
        destination.name,
        plan.release_id
    ));
    Ok(())
}

/// Picks the planned destination through which a surface's receipt is viewed.
///
/// Hub receipts are not destination-bound; any planned destination on the
/// surface role names the view, preferring the destination under test.
fn receipt_destination<'a>(
    plan: &'a ReleasePlan,
    destination: &'a PlannedDestination,
    role: SurfaceRole,
) -> Result<&'a PlannedDestination> {
    if destination.surface == role {
        return Ok(destination);
    }
    plan.destinations
        .iter()
        .find(|candidate| candidate.surface == role)
        .with_context(|| format!("release plan has no {role} destination"))
}

/// Runs every case of the phase on its executor and returns sorted evidence.
async fn collect_observations(
    args: &ReleaseQualifyRunArgs,
    bundle: &VerifiedBundle,
    destination: &PlannedDestination,
    phase: QualificationPhase,
    role: SurfaceRole,
    publication: &SignedReceipt,
    attempt: &Path,
) -> Result<(
    Vec<aos_release::evidence::EvidenceRecord>,
    BTreeMap<String, Vec<u8>>,
)> {
    let plan = &bundle.plan;
    let executors = platform_paths(&args.executors)?;
    let identities = platform_values(&args.executor_identities, "executor identity")?;
    let timeout = bounded_timeout(args.executor_timeout_seconds, "executor")?;
    let cases = aos_release::qualification_evidence::cases(
        plan,
        &bundle.manifest.payload,
        Some(&destination.name),
        phase,
    )?;
    let needs_predecessor = cases.iter().any(|case| case.predecessor.is_some());
    let predecessor = match (needs_predecessor, &args.predecessor_bundle) {
        (true, Some(path)) => Some(retained_predecessor(
            path,
            plan.qualification_predecessor
                .as_ref()
                .context("update case lacks its planned predecessor")?,
            &bundle.manifest_keys,
        )?),
        (true, None) => bail!("image update qualification requires --predecessor-bundle"),
        (false, Some(_)) => bail!("qualification phase has no predecessor update case"),
        (false, None) => None,
    };

    let base = objects_base(plan, role)?;
    let projection = project::plan_projection(&args.bundle, &bundle.manifest.payload)?;
    let mut evidence = Vec::with_capacity(cases.len());
    let mut reports = BTreeMap::new();
    for case in cases {
        let platform = case.platform.unwrap_or(Platform::X86_64Linux);
        let request = QualificationExecutorRequest {
            schema_version: QUALIFICATION_EXECUTOR_REQUEST.to_owned(),
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            staging_receipt_digest: publication.digest,
            manifest_digest: bundle.summary.manifest_digest,
            policy_id: case.requirement_id.clone(),
            policy_digest: case.policy_digest,
            platform,
            subjects: case.subjects.clone(),
            objects: public_objects(
                &base,
                &projection,
                &bundle.manifest,
                &bundle.captured.manifest_bytes,
                &case.subjects,
            )?,
            retained_predecessor: predecessor_bundle(predecessor.as_ref(), &case)?,
            nonce: executor_nonce(&args.executor_nonce, &case.id, platform),
            qualification_case: case,
        };
        request.validate()?;
        let executable = executors
            .get(&request.platform)
            .context("missing applicable qualification executor")?;
        let identity = identities
            .get(&request.platform)
            .context("missing applicable executor identity")?;
        let case_name = Sha256Digest::of_bytes(canonical::to_vec(&request)?).hex();
        fs::write(
            attempt.join(format!("{case_name}-request.json")),
            canonical::to_vec(&request)?,
        )?;
        let response = invoke_executor(executable, timeout, &request).await?;
        fs::write(
            attempt.join(format!("{case_name}-response.json")),
            canonical::to_vec(&response)?,
        )?;
        verify_executor_response(&request, identity, &response)?;
        let report_bytes = canonical::canonical_json(&response.report)?;
        if reports
            .insert(response.evidence.id.clone(), report_bytes)
            .is_some()
        {
            bail!("qualification executor returned a duplicate evidence id");
        }
        evidence.push(response.evidence);
    }
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
    Ok((evidence, reports))
}

/// Returns the anonymous object base of the surface with `role`.
///
/// Hub objects are namespaced below `<hub>/<registry>/`; a static surface's
/// read-back origin is the registry root.
fn objects_base(plan: &ReleasePlan, role: SurfaceRole) -> Result<url::Url> {
    let surface = plan.surface(role)?;
    match surface.kind {
        SurfaceKind::Hub => readback::base_url(&format!("{}/{}", surface.origin, plan.registry)),
        SurfaceKind::Static => readback::base_url(surface.readback()),
    }
}

pub(super) fn verify_executor_response(
    request: &QualificationExecutorRequest,
    identity: &str,
    response: &QualificationExecutorResponse,
) -> Result<()> {
    if response.schema_version != QUALIFICATION_EXECUTOR_RESPONSE
        || response.request_digest != request.digest()?
    {
        bail!("qualification executor response does not bind its exact request");
    }
    response.evidence.validate()?;
    let case = &request.qualification_case;
    let expected_id = format!("qualification/{}", case.id);
    let case_digest = case.digest()?;
    if !response
        .evidence
        .qualification
        .as_ref()
        .is_some_and(|observation| observation.case_digest == case_digest)
    {
        bail!("qualification response lacks its exact case observation");
    }
    let matrix_passed = response
        .evidence
        .qualification
        .as_ref()
        .map(|observation| validate_matrix_for_case(case, observation))
        .transpose()?
        .flatten();
    let matrix_result_mismatch = matrix_passed
        .is_some_and(|passed| (response.evidence.result == GateResult::Passed) != passed);
    if response.evidence.id != expected_id
        || response.evidence.policy_id != request.policy_id
        || response.evidence.policy_digest != request.policy_digest
        || response.evidence.platform != case.platform
        || response.evidence.subjects != request.subjects
        || matrix_result_mismatch
        || (response.evidence.result != GateResult::Passed
            && case.requirement_id != NATIVE_ADAPTER_MATRIX_REQUIREMENT
            && case.claim.as_ref().is_none_or(|claim| claim.blocks_release))
        || response.evidence.authority_id != identity
        || response.evidence.nonce.as_deref() != Some(request.nonce.as_str())
        || response.evidence.report_digest
            != Sha256Digest::of_bytes(&canonical::canonical_json(&response.report)?)
    {
        bail!("qualification executor response differs from its closed request");
    }
    Ok(())
}

pub(super) async fn invoke_executor(
    executable: &Path,
    timeout: Duration,
    request: &QualificationExecutorRequest,
) -> Result<QualificationExecutorResponse> {
    invoke_scenario(executable, timeout, request, Path::new("/")).await
}

pub(super) async fn invoke_scenario(
    executable: &Path,
    timeout: Duration,
    request: &QualificationExecutorRequest,
    directory: &Path,
) -> Result<QualificationExecutorResponse> {
    super::signer::validate_signer_executable(executable)?;
    let input = canonical::to_vec(request)?;
    let mut child = Command::new(executable)
        .process_group(0)
        .env_clear()
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting qualification executor {}", executable.display()))?;
    // A scenario may own QEMU and remote-transport children. Closing only its
    // immediate process on timeout would leave those resources running.
    let group = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(rustix::process::Pid::from_raw)
        .context("qualification executor lacks a process group")?;
    let _group = ScenarioGroup(group);
    let mut stdin = child
        .stdin
        .take()
        .context("qualification executor lacks stdin")?;
    let stdout = child
        .stdout
        .take()
        .context("qualification executor lacks stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("qualification executor lacks stderr")?;
    let exchange = async {
        let write = async {
            stdin.write_all(&input).await?;
            stdin.shutdown().await?;
            // The executor reads one canonical JSON document through EOF. A
            // successful flush is not EOF while the pipe handle remains live.
            drop(stdin);
            Result::<()>::Ok(())
        };
        let read = read_limited(stdout, MAX_EXECUTOR_RESPONSE_BYTES);
        let diagnostics = read_limited(stderr, MAX_EXECUTOR_DIAGNOSTIC_BYTES);
        let (_, response, diagnostics) = tokio::try_join!(write, read, diagnostics)?;
        let status = child.wait().await?;
        Result::<_>::Ok((status, response, diagnostics))
    };
    let (status, response_bytes, diagnostics) = tokio::time::timeout(timeout, exchange)
        .await
        .context("qualification executor timed out")??;
    if directory != Path::new("/") {
        fs::write(directory.join("scenario-stdout"), &response_bytes)?;
        fs::write(directory.join("scenario-stderr"), &diagnostics)?;
    }
    if !status.success() {
        bail!(
            "qualification executor failed: {}",
            String::from_utf8_lossy(&diagnostics)
        );
    }
    if !diagnostics.is_empty() {
        bail!("qualification executor wrote diagnostics on a successful request");
    }
    canonical::require_canonical(&response_bytes, "qualification executor response")?;
    canonical::from_slice(&response_bytes, "qualification executor response")
}

struct ScenarioGroup(rustix::process::Pid);

impl Drop for ScenarioGroup {
    fn drop(&mut self) {
        let _ = rustix::process::kill_process_group(self.0, rustix::process::Signal::KILL);
    }
}

async fn read_limited(reader: impl AsyncRead + Unpin, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(maximum + 1).read_to_end(&mut bytes).await?;
    if u64::try_from(bytes.len())? > maximum {
        bail!("qualification executor stream exceeds its byte limit");
    }
    Ok(bytes)
}

async fn sign_receipt(
    args: &ReleaseQualifyRunArgs,
    plan: &ReleasePlan,
    destination: &PlannedDestination,
    mut receipt: QualificationReceipt,
) -> Result<(QualificationReceipt, Vec<u8>, Vec<u8>)> {
    let (key_id, key_path) = parse_pair(&args.authority_key, "qualification authority key")?;
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::Qualification)
        .context("release plan lacks a qualification signer")?;
    if requirement.threshold != 1 || requirement.key_ids.as_slice() != [key_id] {
        bail!("qualification receipt format requires the exact planned single-key authority");
    }
    receipt.authority_id = key_id.to_owned();
    receipt.validate()?;
    let payload = canonical::to_vec(&receipt)?;
    let receipt_digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload);
    let request = SigningRequest {
        schema_version: aos_release::signing::SIGNING_REQUEST_DOMAIN.to_owned(),
        request_id: format!(
            "qualification-receipt/{}/{}",
            plan.release_id,
            destination.name.replace('/', "-")
        ),
        nonce: args.authority_nonce.clone(),
        registry: plan.registry.clone(),
        release_id: plan.release_id.clone(),
        plan_digest: Sha256Digest::of_bytes(&canonical::to_vec(plan)?),
        manifest_digest: Some(receipt.manifest_digest),
        role: SignerRole::Qualification,
        key_id: key_id.to_owned(),
        provider_revision: requirement.provider_revision.clone(),
        algorithm: SignatureAlgorithm::Ed25519Payload,
        operation: SigningOperation::SignPayload,
        context: SigningContext::Payload {
            artifact_kind: "qualification-receipt-digest".to_owned(),
        },
        payload_digest: Sha256Digest::of_bytes(receipt_digest.as_bytes()),
        approval_policy_digest: plan.restricted_operator_policy_digest,
    };
    let key_bytes =
        capture::control_file(Path::new(key_path), "qualification authority public key")?;
    let trusted = TrustedEd25519Key::from_encoded(key_id, &key_bytes)?;
    let signer = ExternalSigner::new(
        args.authority_executable.clone(),
        bounded_timeout(args.authority_timeout_seconds, "qualification authority")?,
    )?;
    let response = signer
        .sign_ed25519_payload(
            &request,
            receipt_digest.as_bytes(),
            &trusted,
            &args.authority_verification_identity,
        )
        .await?;
    let signing_response = canonical::to_vec(&response)?;
    let envelope = SignedReceiptEnvelope {
        schema_version: SIGNED_RECEIPT.to_owned(),
        key_id: key_id.to_owned(),
        payload: serde_json::to_value(&receipt)?,
        signature_base64: response.signature_base64,
    };
    let bytes = canonical::to_vec(&envelope)?;
    let trusted_keys = BTreeMap::from([(key_id.to_owned(), trusted.public_key)]);
    let (_, verified): (String, QualificationReceipt) =
        verify_signed_receipt_with_key(&bytes, &trusted_keys)?;
    if verified != receipt {
        bail!("qualification authority envelope changed the receipt");
    }
    Ok((receipt, bytes, signing_response))
}

fn platform_paths(values: &[String]) -> Result<BTreeMap<Platform, PathBuf>> {
    platform_map(values, "executor", |value| {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            bail!("qualification executor path must be absolute");
        }
        super::signer::validate_signer_executable(&path)?;
        Ok(path)
    })
}

fn platform_values(values: &[String], label: &str) -> Result<BTreeMap<Platform, String>> {
    platform_map(values, label, |value| {
        if value.is_empty() {
            bail!("{label} cannot be empty");
        }
        Ok(value.to_owned())
    })
}

fn platform_map<T>(
    values: &[String],
    label: &str,
    parse: impl Fn(&str) -> Result<T>,
) -> Result<BTreeMap<Platform, T>> {
    let mut result = BTreeMap::new();
    for value in values {
        let (platform, value) = parse_pair(value, label)?;
        let platform = parse_platform(platform)?;
        if result.insert(platform, parse(value)?).is_some() {
            bail!("duplicate {label} for {platform}");
        }
    }
    Ok(result)
}

fn parse_platform(value: &str) -> Result<Platform> {
    Platform::ALL
        .into_iter()
        .find(|platform| platform.as_str() == value)
        .with_context(|| format!("unknown qualification platform {value}"))
}

fn parse_pair<'a>(value: &'a str, label: &str) -> Result<(&'a str, &'a str)> {
    let (left, right) = value
        .split_once('=')
        .with_context(|| format!("{label} must use NAME=VALUE"))?;
    if left.is_empty() || right.is_empty() {
        bail!("{label} must use nonempty NAME=VALUE");
    }
    Ok((left, right))
}

fn validate_nonce(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be 32 bytes of lowercase hexadecimal");
    }
    Ok(())
}

fn executor_nonce(seed: &str, policy: &str, platform: Platform) -> String {
    Sha256Digest::separated(
        "aos.release.qualification-executor-nonce/v1",
        format!("{seed}\0{policy}\0{platform}").as_bytes(),
    )
    .hex()
    .to_owned()
}

fn bounded_timeout(seconds: u64, label: &str) -> Result<Duration> {
    if seconds == 0 || seconds > 6 * 60 * 60 {
        bail!("{label} timeout must be within 1s..=6h");
    }
    Ok(Duration::from_secs(seconds))
}

pub(super) fn persist(
    output: &Path,
    staging: &[u8],
    report: &[u8],
    executor_reports: &BTreeMap<String, Vec<u8>>,
    receipt: &[u8],
    signed_receipt: &[u8],
    signing_response: &[u8],
    review_paths: &[PathBuf],
) -> Result<()> {
    if output.exists() {
        bail!(
            "qualification run output already exists: {}",
            output.display()
        );
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-qualification-run-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    let reports = root.join("reports");
    fs::create_dir(&reports)?;
    for (name, bytes) in [
        ("staging-receipt.json", staging),
        ("qualification-report.json", report),
        ("qualification-receipt.json", receipt),
        ("signed-qualification.json", signed_receipt),
        ("qualification-signing-response.json", signing_response),
    ] {
        if !bytes.is_empty() {
            write_file(&root.join(name), bytes)?;
        }
    }
    for (id, bytes) in executor_reports {
        write_file(&reports.join(report_filename(id)), bytes)?;
    }
    for (index, path) in review_paths.iter().enumerate() {
        write_file(
            &root.join(format!("review-{index}.json")),
            &capture::control_file(path, "qualification review")?,
        )?;
    }
    File::open(&reports)?.sync_all()?;
    File::open(&root)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &root,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Hashes the full id so slash replacement cannot alias two reports.
pub(super) fn report_filename(id: &str) -> String {
    format!(
        "{}.json",
        Sha256Digest::separated("aos.release.report-path/v1", id.as_bytes()).hex()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_configuration_is_closed() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        // Shared build caches may hard-link test binaries, while signer paths
        // must name a single-link file with private permissions.
        let signer_directory = tempfile::tempdir()?;
        let executable = signer_directory.path().join("executor");
        std::fs::copy(std::env::current_exe()?, &executable)?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;

        let all = Platform::ALL
            .into_iter()
            .map(|platform| format!("{platform}={}", executable.display()))
            .collect::<Vec<_>>();
        assert!(platform_paths(&all).is_ok());
        assert!(platform_paths(&all[..3]).is_ok());
        assert!(platform_paths(&[all[0].clone(), all[0].clone()]).is_err());
        Ok(())
    }

    #[test]
    fn executor_nonces_are_gate_and_platform_specific() {
        let seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_ne!(
            executor_nonce(seed, "install-v1", Platform::X86_64Linux),
            executor_nonce(seed, "install-v1", Platform::Aarch64Linux)
        );
        assert_ne!(
            executor_nonce(seed, "install-v1", Platform::X86_64Linux),
            executor_nonce(seed, "boot-v1", Platform::X86_64Linux)
        );
    }
}
