//! Native gate execution over exact anonymous staging objects.

use std::collections::{BTreeMap, BTreeSet};
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
    GateResult, QUALIFICATION_EXECUTOR_REQUEST_V1, QUALIFICATION_EXECUTOR_RESPONSE_V1,
    QUALIFICATION_REPORT_V1, QualificationExecutorRequestV1, QualificationExecutorResponseV1,
    QualificationObjectV1, QualificationReportV1,
};
use aos_release::manifest::ManifestEnvelopeV1;
use aos_release::platform::{MatrixCell, Platform};
use aos_release::receipt::{
    HubEnvironment, PublicationReceiptV1, QualificationReceiptV1, RECEIPT_SIGNATURE_DOMAIN,
    SIGNED_RECEIPT_V1, SignedReceiptEnvelopeV1, verify_signed_receipt_with_key,
};
use aos_release::signing::{
    SignatureAlgorithm, SignerRole, SigningContext, SigningOperation, SigningRequestV1,
    TrustedEd25519Key,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use crate::cli::ReleaseQualifyRunArgs;

use super::signer::ExternalSigner;
use super::{capture, hub_transition, verify};

const STAGING_HUB: &str = "https://aos.staging.andyl.org";
const MAX_EXECUTOR_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXECUTOR_DIAGNOSTIC_BYTES: u64 = 64 * 1024;

pub(super) async fn run(args: &ReleaseQualifyRunArgs, printer: &Printer) -> Result<()> {
    let captured = capture::bundle(&args.bundle)?;
    let manifest_keys = verify::load_trusted_keys(&args.trusted_keys)?;
    let summary = aos_release::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        &manifest_keys,
    )?;
    let plan: aos_release::plan::ReleasePlanV1 =
        canonical::from_slice(&captured.plan_bytes, "release plan")?;
    let manifest: ManifestEnvelopeV1 =
        canonical::from_slice(&captured.manifest_bytes, "release manifest")?;

    let staging_bytes = capture::control_file(&args.staging_receipt, "signed staging receipt")?;
    let staging_digest = Sha256Digest::of_bytes(&staging_bytes);
    let staging_keys = key_map(&args.hub_receipt_keys)?;
    let (_, staging): (String, PublicationReceiptV1) =
        verify_signed_receipt_with_key(&staging_bytes, &staging_keys)?;
    staging.validate()?;
    let bundle_digest =
        aos_release::verify::bundle_digest(&captured.manifest_bytes, &captured.files)?;
    if staging.environment != HubEnvironment::Staging
        || staging.deployment_id != plan.staging_deployment_id
        || staging.registry != plan.registry
        || staging.release_id != plan.release_id
        || staging.manifest_digest != summary.manifest_digest
        || staging.bundle_digest != bundle_digest
        || staging.staging_receipt_digest.is_some()
    {
        bail!("staging receipt does not bind the qualification input");
    }
    hub_transition::verify_deployment(
        &hub_transition::public_client()?,
        STAGING_HUB,
        &plan.staging_deployment_id,
    )
    .await?;

    validate_nonce(&args.executor_nonce, "executor nonce")?;
    validate_nonce(&args.authority_nonce, "authority nonce")?;
    let executors = platform_paths(&args.executors)?;
    let identities = platform_values(&args.executor_identities, "executor identity")?;
    let timeout = bounded_timeout(args.executor_timeout_seconds, "executor")?;
    let objects = public_objects(&plan.registry, &manifest, &captured.manifest_bytes)?;
    let platform_subjects = artifact_platform_subjects(&manifest);

    let mut evidence = Vec::new();
    let mut reports = BTreeMap::new();
    for gate in &plan.gates {
        for (platform, subjects) in &platform_subjects {
            let request = QualificationExecutorRequestV1 {
                schema_version: QUALIFICATION_EXECUTOR_REQUEST_V1.to_owned(),
                registry: plan.registry.clone(),
                release_id: plan.release_id.clone(),
                staging_receipt_digest: staging_digest,
                manifest_digest: summary.manifest_digest,
                policy_id: gate.policy_id.clone(),
                policy_digest: gate.policy_digest,
                platform: *platform,
                subjects: subjects.clone(),
                objects: objects.clone(),
                nonce: executor_nonce(&args.executor_nonce, &gate.policy_id, *platform),
            };
            request.validate()?;
            let executable = executors
                .get(platform)
                .context("missing qualification executor")?;
            let identity = identities
                .get(platform)
                .context("missing qualification executor identity")?;
            let response = invoke_executor(executable, timeout, &request).await?;
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
    }
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
    let report = QualificationReportV1 {
        schema_version: QUALIFICATION_REPORT_V1.to_owned(),
        staging_receipt_digest: staging_digest,
        manifest_digest: summary.manifest_digest,
        evidence,
    };
    report.validate(
        &plan,
        &manifest.payload,
        staging_digest,
        summary.manifest_digest,
    )?;
    let report_bytes = canonical::to_vec(&report)?;

    let receipt = QualificationReceiptV1 {
        schema_version: aos_release::receipt::QUALIFICATION_RECEIPT_V1.to_owned(),
        staging_receipt_digest: staging_digest,
        manifest_digest: summary.manifest_digest,
        policy_id: "full-release-qualification".to_owned(),
        policy_digest: plan.public_evidence_policy_digest,
        result: GateResult::Passed,
        report_digest: Sha256Digest::of_bytes(&report_bytes),
        authority_id: String::new(),
        nonce: args.authority_nonce.clone(),
        qualified_at: args.qualified_at.clone(),
    };
    let (receipt, signed_receipt, signing_response) = sign_receipt(args, &plan, receipt).await?;
    persist(
        &args.output,
        &staging_bytes,
        &report_bytes,
        &reports,
        &canonical::to_vec(&receipt)?,
        &signed_receipt,
        &signing_response,
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.qualify-run-result/v1",
        "release_id": plan.release_id,
        "evidence_count": report.evidence.len(),
        "qualification_report_digest": receipt.report_digest,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Qualified {} gate/platform executions for release {}",
        report.evidence.len(),
        plan.release_id
    ));
    Ok(())
}

fn artifact_platform_subjects(manifest: &ManifestEnvelopeV1) -> BTreeMap<Platform, Vec<String>> {
    let mut subjects = BTreeMap::<Platform, BTreeSet<String>>::new();
    for package in &manifest.payload.packages {
        for cell in &package.platforms {
            if let MatrixCell::Artifact { artifact } = &cell.decision {
                subjects
                    .entry(cell.platform)
                    .or_default()
                    .extend(artifact.artifact_ids.iter().cloned());
            }
        }
    }
    for image in &manifest.payload.images {
        for cell in &image.platforms {
            if let MatrixCell::Artifact { artifact } = &cell.decision {
                subjects
                    .entry(cell.platform)
                    .or_default()
                    .extend(artifact.artifact_ids.iter().cloned());
            }
        }
    }
    subjects
        .into_iter()
        .map(|(platform, values)| (platform, values.into_iter().collect()))
        .collect()
}

fn public_objects(
    registry: &str,
    manifest: &ManifestEnvelopeV1,
    manifest_bytes: &[u8],
) -> Result<Vec<QualificationObjectV1>> {
    let base = url::Url::parse(&format!("{STAGING_HUB}/{registry}/"))?;
    let mut objects = manifest
        .payload
        .artifacts
        .iter()
        .map(|artifact| {
            Ok(QualificationObjectV1 {
                artifact_id: artifact.id.clone(),
                url: base.join(artifact.path.as_str())?.to_string(),
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    objects.push(QualificationObjectV1 {
        artifact_id: "control/release-manifest-envelope".to_owned(),
        url: base.join("release-manifest.json")?.to_string(),
        size_bytes: u64::try_from(manifest_bytes.len())?,
        sha256: Sha256Digest::of_bytes(manifest_bytes),
    });
    objects.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(objects)
}

fn verify_executor_response(
    request: &QualificationExecutorRequestV1,
    identity: &str,
    response: &QualificationExecutorResponseV1,
) -> Result<()> {
    if response.schema_version != QUALIFICATION_EXECUTOR_RESPONSE_V1
        || response.request_digest != request.digest()?
    {
        bail!("qualification executor response does not bind its exact request");
    }
    response.evidence.validate()?;
    let expected_id = format!("qualification/{}/{}", request.policy_id, request.platform);
    if response.evidence.id != expected_id
        || response.evidence.policy_id != request.policy_id
        || response.evidence.policy_digest != request.policy_digest
        || response.evidence.platform != Some(request.platform)
        || response.evidence.subjects != request.subjects
        || response.evidence.result != GateResult::Passed
        || response.evidence.authority_id != identity
        || response.evidence.nonce.as_deref() != Some(request.nonce.as_str())
        || response.evidence.report_digest
            != Sha256Digest::of_bytes(&canonical::canonical_json(&response.report)?)
    {
        bail!("qualification executor response differs from its closed request");
    }
    Ok(())
}

async fn invoke_executor(
    executable: &Path,
    timeout: Duration,
    request: &QualificationExecutorRequestV1,
) -> Result<QualificationExecutorResponseV1> {
    super::signer::validate_signer_executable(executable)?;
    let input = canonical::to_vec(request)?;
    let mut child = Command::new(executable)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting qualification executor {}", executable.display()))?;
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
    plan: &aos_release::plan::ReleasePlanV1,
    mut receipt: QualificationReceiptV1,
) -> Result<(QualificationReceiptV1, Vec<u8>, Vec<u8>)> {
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
    let request = SigningRequestV1 {
        schema_version: aos_release::signing::SIGNING_REQUEST_DOMAIN.to_owned(),
        request_id: format!("qualification-receipt/{}", plan.release_id),
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
    let envelope = SignedReceiptEnvelopeV1 {
        schema_version: SIGNED_RECEIPT_V1.to_owned(),
        key_id: key_id.to_owned(),
        payload: serde_json::to_value(&receipt)?,
        signature_base64: response.signature_base64,
    };
    let bytes = canonical::to_vec(&envelope)?;
    let trusted_keys = BTreeMap::from([(key_id.to_owned(), trusted.public_key)]);
    let (_, verified): (String, QualificationReceiptV1) =
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
    if result.keys().copied().collect::<BTreeSet<_>>() != Platform::ALL.into_iter().collect() {
        bail!("{label} mappings must name all four canonical platforms exactly once");
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

fn key_map(specifications: &[String]) -> Result<BTreeMap<String, [u8; 32]>> {
    Ok(verify::load_trusted_keys(specifications)?
        .into_iter()
        .map(|key| (key.key_id, key.public_key))
        .collect())
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

fn persist(
    output: &Path,
    staging: &[u8],
    report: &[u8],
    executor_reports: &BTreeMap<String, Vec<u8>>,
    receipt: &[u8],
    signed_receipt: &[u8],
    signing_response: &[u8],
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
        write_file(&root.join(name), bytes)?;
    }
    for (id, bytes) in executor_reports {
        write_file(
            &reports.join(format!("{}.json", id.replace('/', "--"))),
            bytes,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_configuration_is_closed() -> Result<()> {
        let executable = std::env::current_exe()?;
        let all = Platform::ALL
            .into_iter()
            .map(|platform| format!("{platform}={}", executable.display()))
            .collect::<Vec<_>>();
        assert!(platform_paths(&all).is_ok());
        assert!(platform_paths(&all[..3]).is_err());
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
