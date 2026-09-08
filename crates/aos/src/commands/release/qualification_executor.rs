//! Native scenario selection, verified downloads, and retained execution attempts.
//!
//! The Nix-built registry selects executable closures; a remote request cannot
//! supply a command. Scenarios receive the original request on stdin and read
//! `objects.json` for verified local paths and `downloads.json` for transfer
//! evidence in their private working directory. Their stdout is a canonical
//! executor response. Every attempt is retained, including failures; the
//! coordinator still independently validates coverage.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::Sha256Digest;
use aos_release::canonical;
use aos_release::evidence::{
    EvidenceRecord, GateResult, QUALIFICATION_EXECUTOR_RESPONSE_V1, QualificationExecutorRequestV1,
    QualificationExecutorResponseV1,
};
use aos_release::manifest::{ManifestEnvelopeV1, ReleaseManifestV1};
use aos_release::plan::ReleasePlanV1;
use aos_release::platform::Platform;
use aos_release::qualification::QualificationPhase;
use aos_release::qualification::claims::CompatibilityAssessment;
use aos_release::qualification::environment::EnvironmentInventory;
use aos_release::qualification_evidence::{CheckObservation, QualificationObservation};
use reqwest::header::{CONTENT_RANGE, RANGE};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{capture, qualification_run};
use crate::cli::{
    ReleaseQualificationCommand, ReleaseQualificationExecuteArgs, ReleaseQualificationRespondArgs,
};

const SCENARIO_REPORT_V1: &str = "aos.release.qualification-scenario-report/v1";

/// Immutable executable selection, produced by `mkQualificationExecutor`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScenarioRegistry {
    schema_version: String,
    platform: Platform,
    scenarios: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    case_scenarios: BTreeMap<String, String>,
}

/// Common evidence fields embedded in every canonical native scenario report.
#[derive(Deserialize)]
struct ScenarioReport {
    schema_version: String,
    registry: String,
    release_id: String,
    staging_receipt_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    case_digest: Sha256Digest,
    started_at: String,
    finished_at: String,
    observed_seconds: u64,
    checks: BTreeMap<String, CheckObservation>,
    operations: BTreeMap<String, u64>,
    #[serde(default)]
    environment: Option<serde_json::Value>,
    #[serde(default)]
    assessment: Option<CompatibilityAssessment>,
    #[serde(default)]
    capabilities: Option<aos_release::qualification::capabilities::CapabilityEvidence>,
}

#[derive(Serialize)]
struct DownloadTrace {
    mode: &'static str,
    requests: Vec<DownloadRequestTrace>,
}

#[derive(Serialize)]
struct DownloadRequestTrace {
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_range: Option<String>,
}

pub(super) fn inspect(command: &ReleaseQualificationCommand, printer: &Printer) -> Result<()> {
    let ReleaseQualificationCommand::Cases(args) = command else {
        return match command {
            ReleaseQualificationCommand::Respond(args) => respond(args),
            ReleaseQualificationCommand::Execute(_) => {
                bail!("qualification execution requires the asynchronous dispatcher")
            }
            ReleaseQualificationCommand::Cases(_) => unreachable!(),
        };
    };
    let plan: ReleasePlanV1 = canonical::from_slice(
        &capture::control_file(&args.plan, "qualification plan")?,
        "qualification plan",
    )?;
    plan.validate()?;
    let bytes = capture::control_file(&args.manifest, "qualification manifest")?;
    let value: serde_json::Value = canonical::from_slice(&bytes, "qualification manifest")?;
    let manifest: ReleaseManifestV1 = if value.get("payload").is_some() {
        canonical::from_slice::<ManifestEnvelopeV1>(&bytes, "manifest envelope")?.payload
    } else {
        canonical::from_slice(&bytes, "manifest payload")?
    };
    let phase = match args.phase.as_str() {
        "build" => QualificationPhase::Build,
        "staging" => QualificationPhase::Staging,
        "rollout" => QualificationPhase::Rollout,
        "complete" => QualificationPhase::Complete,
        _ => bail!("unknown qualification phase"),
    };
    let cases = aos_release::qualification_evidence::cases(&plan, &manifest, phase)?;
    let case_digests = cases
        .iter()
        .map(|case| Ok((case.id.clone(), case.digest()?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let environment_profile_digests = cases
        .iter()
        .filter_map(|case| {
            case.target
                .as_ref()?
                .environment
                .as_ref()
                .map(|environment| (&case.id, environment))
        })
        .map(|(id, environment)| {
            Ok((
                id.clone(),
                Sha256Digest::of_canonical("aos.release.environment-profile/v1", environment)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let output = serde_json::json!({
        "status": "not-evaluated",
        "cases": cases,
        "case_digests": case_digests,
        "environment_profile_digests": environment_profile_digests,
    });
    if !printer.json_if_active(&output) {
        std::io::stdout().write_all(&canonical::canonical_json(&output)?)?;
        println!();
    }
    Ok(())
}

pub(super) async fn run(command: &ReleaseQualificationCommand, printer: &Printer) -> Result<()> {
    match command {
        ReleaseQualificationCommand::Cases(_) => inspect(command, printer),
        ReleaseQualificationCommand::Execute(args) => execute(args).await,
        ReleaseQualificationCommand::Respond(_) => inspect(command, printer),
    }
}

fn respond(args: &ReleaseQualificationRespondArgs) -> Result<()> {
    let request_bytes = capture::control_file(&args.request, "qualification request")?;
    canonical::require_canonical(&request_bytes, "qualification request")?;
    let request: QualificationExecutorRequestV1 =
        canonical::from_slice(&request_bytes, "qualification request")?;
    request.validate()?;

    let registry_bytes = capture::control_file(&args.scenarios, "scenario registry")?;
    canonical::require_canonical(&registry_bytes, "scenario registry")?;
    let registry: ScenarioRegistry = canonical::from_slice(&registry_bytes, "scenario registry")?;
    select(&registry, &request)?;

    let case = request
        .qualification_case
        .as_ref()
        .context("native scenario response requires a shared-contract case")?;
    let report_path = match (&args.report, &args.report_root) {
        (Some(path), None) => path.clone(),
        (None, Some(root)) => root.join(format!("{}.json", case.digest()?.hex())),
        _ => bail!("select exactly one scenario report or report root"),
    };
    let report_bytes = capture::control_file(&report_path, "scenario report")?;
    canonical::require_canonical(&report_bytes, "scenario report")?;
    let report: serde_json::Value = canonical::from_slice(&report_bytes, "scenario report")?;
    let fields: ScenarioReport = serde_json::from_value(report.clone())?;
    let response = build_response(
        &request,
        &registry_bytes,
        &report_bytes,
        report,
        fields,
        &args.identity,
    )?;
    std::io::stdout().write_all(&canonical::to_vec(&response)?)?;
    Ok(())
}

fn build_response(
    request: &QualificationExecutorRequestV1,
    registry_bytes: &[u8],
    report_bytes: &[u8],
    report: serde_json::Value,
    fields: ScenarioReport,
    identity: &str,
) -> Result<QualificationExecutorResponseV1> {
    let case = request
        .qualification_case
        .as_ref()
        .context("native scenario response requires a shared-contract case")?;
    validate_report_fields(request, case, &fields)?;

    let environment = match (&case.target, fields.environment.as_ref()) {
        (Some(_), Some(value)) => Some(serde_json::from_value::<EnvironmentInventory>(
            value.clone(),
        )?),
        _ => None,
    };
    let environment_digest = if let Some(environment) = &environment {
        environment.digest()?
    } else if let Some(assessment) = &fields.assessment {
        assessment.scope_digest
    } else {
        let value = fields
            .environment
            .as_ref()
            .context("scenario report lacks its execution environment inventory")?;
        Sha256Digest::of_bytes(&canonical::canonical_json(value)?)
    };
    let passed = fields.checks.values().all(|check| check.passed);
    let evidence = EvidenceRecord {
        qualification: Some(QualificationObservation {
            capabilities: fields.capabilities,
            environment,
            assessment: fields.assessment,
            case_digest: case.digest()?,
            executor_digest: Sha256Digest::of_bytes(&registry_bytes),
            environment_digest,
            checks: fields.checks,
            observed_seconds: fields.observed_seconds,
            operations: fields.operations,
            predecessor: case.predecessor.clone(),
        }),
        id: format!("qualification/{}", case.id),
        policy_id: request.policy_id.clone(),
        policy_digest: request.policy_digest,
        platform: case.platform,
        subjects: request.subjects.clone(),
        result: if passed {
            GateResult::Passed
        } else {
            GateResult::Failed
        },
        report_digest: Sha256Digest::of_bytes(&report_bytes),
        authority_id: identity.to_owned(),
        nonce: Some(request.nonce.clone()),
        started_at: fields.started_at,
        finished_at: fields.finished_at,
    };
    evidence.validate()?;
    let response = QualificationExecutorResponseV1 {
        schema_version: QUALIFICATION_EXECUTOR_RESPONSE_V1.to_owned(),
        request_digest: request.digest()?,
        evidence,
        report,
    };
    qualification_run::verify_executor_response(request, identity, &response)?;
    Ok(response)
}

fn validate_report_fields(
    request: &QualificationExecutorRequestV1,
    case: &aos_release::qualification_evidence::QualificationCase,
    report: &ScenarioReport,
) -> Result<()> {
    if report.schema_version != SCENARIO_REPORT_V1 {
        bail!("unsupported qualification scenario report schema");
    }
    if report.registry != request.registry
        || report.release_id != request.release_id
        || report.staging_receipt_digest != request.staging_receipt_digest
        || report.manifest_digest != request.manifest_digest
        || report.case_digest != case.digest()?
    {
        bail!("scenario report identity differs from the exact qualification request");
    }
    let required = case
        .checks
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    let actual = report
        .checks
        .keys()
        .collect::<std::collections::BTreeSet<_>>();
    if actual != required
        || report
            .checks
            .values()
            .any(|check| check.detail.trim().is_empty())
    {
        bail!("scenario report checks differ from the exact qualification case");
    }
    let start = humantime::parse_rfc3339(&report.started_at)?;
    let finish = humantime::parse_rfc3339(&report.finished_at)?;
    if !report.started_at.ends_with('Z')
        || !report.finished_at.ends_with('Z')
        || start > finish
        || report.observed_seconds > finish.duration_since(start)?.as_secs()
    {
        bail!("scenario report has inconsistent execution times");
    }
    match (&case.target, &report.environment, &report.assessment) {
        (Some(_), Some(_), Some(_)) => {}
        (Some(_), None, Some(_))
            if case.claim.as_ref().is_some_and(|claim| {
                claim.minimum_assurance == aos_release::qualification::claims::AssuranceLevel::A1
            }) => {}
        (Some(_), _, _) => {
            bail!("target scenario report lacks its environment or compatibility assessment")
        }
        (None, Some(_), None) => {}
        (None, _, _) => {
            bail!("release and package reports require an unscoped environment inventory")
        }
    }
    Ok(())
}

async fn execute(args: &ReleaseQualificationExecuteArgs) -> Result<()> {
    if !(1..=21_600).contains(&args.timeout_seconds) {
        bail!("scenario timeout must be between one second and six hours");
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut input)?;
    if input.len() > 16 * 1024 * 1024 {
        bail!("qualification request exceeds its byte limit");
    }
    canonical::require_canonical(&input, "qualification request")?;
    let request: QualificationExecutorRequestV1 =
        canonical::from_slice(&input, "qualification request")?;
    request.validate()?;
    let case = request
        .qualification_case
        .as_ref()
        .context("native scenario runner requires a shared-contract case")?;
    let registry_bytes = capture::control_file(&args.scenarios, "scenario registry")?;
    let registry: ScenarioRegistry = canonical::from_slice(&registry_bytes, "scenario registry")?;
    let executable = select(&registry, &request)?;
    super::signer::validate_signer_executable(Path::new(executable))?;

    fs::create_dir_all(&args.work_root)?;
    // Keep the directory before starting any effects so errors never erase an
    // attempt. tempfile creates it with mode 0700 on Unix.
    let directory = tempfile::Builder::new()
        .prefix("attempt-")
        .tempdir_in(&args.work_root)?
        .keep();
    fs::write(directory.join("request.json"), &input)?;
    fs::write(directory.join("scenario-registry.json"), &registry_bytes)?;
    let attempt = async {
        if let Some(retained) = &request.retained_predecessor {
            let captured = capture::bundle(Path::new(&retained.bundle_path))?;
            let trusted_keys = retained
                .trusted_keys
                .iter()
                .map(|key| {
                    aos_release::signing::TrustedEd25519Key::from_encoded(
                        &key.key_id,
                        &hex::decode(&key.public_key_hex)?,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let summary = aos_release::verify::verify_release(
                &captured.plan_bytes,
                &captured.manifest_bytes,
                &captured.files,
                &trusted_keys,
            )?;
            let expected = case
                .predecessor
                .as_ref()
                .context("retained predecessor lacks an update case")?;
            let manifest: aos_release::manifest::ManifestEnvelopeV1 =
                canonical::from_slice(&captured.manifest_bytes, "retained predecessor manifest")?;
            if manifest.payload.registry != expected.registry
                || summary.release_id != expected.release_id
                || summary.manifest_digest != expected.manifest_digest
            {
                bail!("retained predecessor verification differs from the execution case");
            }
            fs::write(
                directory.join("predecessor-verification.json"),
                canonical::to_vec(&summary)?,
            )?;
        }

        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(args.timeout_seconds))
            .build()?;
        let resumed_artifact = resumed_artifact(&request)?;
        let mut objects = BTreeMap::new();
        let mut downloads = BTreeMap::new();
        for object in &request.objects {
            let filename = Sha256Digest::of_bytes(object.artifact_id.as_bytes()).hex();
            let path = directory.join(filename);
            let trace = download_object(
                &client,
                object,
                &path,
                resumed_artifact.as_deref() == Some(object.artifact_id.as_str()),
            )
            .await?;
            objects.insert(object.artifact_id.clone(), path);
            downloads.insert(object.artifact_id.clone(), trace);
        }
        fs::write(directory.join("objects.json"), canonical::to_vec(&objects)?)?;
        fs::write(
            directory.join("downloads.json"),
            canonical::to_vec(&downloads)?,
        )?;

        let predecessor_directory = directory.join("predecessor");
        let mut predecessor_objects = BTreeMap::new();
        if request.retained_predecessor.is_some() {
            fs::create_dir(&predecessor_directory)?;
        }
        if let Some(retained) = &request.retained_predecessor {
            for object in &retained.objects {
                let filename = Sha256Digest::of_bytes(object.artifact_id.as_bytes()).hex();
                let path = predecessor_directory.join(&filename);
                let captured =
                    capture::copy_payload_file(Path::new(&object.source_path), &path, &filename)?;
                if captured.size_bytes != object.size_bytes || captured.sha256 != object.sha256 {
                    bail!(
                        "retained predecessor differs from the exact verified object {}",
                        object.artifact_id
                    );
                }
                predecessor_objects.insert(object.artifact_id.clone(), path);
            }
        }
        fs::write(
            directory.join("predecessor-objects.json"),
            canonical::to_vec(&predecessor_objects)?,
        )?;
        let response = qualification_run::invoke_scenario(
            Path::new(executable),
            Duration::from_secs(args.timeout_seconds),
            &request,
            &directory,
        )
        .await?;
        let bytes = canonical::to_vec(&response)?;
        fs::write(directory.join("response.json"), &bytes)?;
        qualification_run::verify_executor_response(&request, &args.identity, &response)?;
        let observation = response
            .evidence
            .qualification
            .as_ref()
            .context("scenario omitted observations")?;
        if observation.executor_digest != Sha256Digest::of_bytes(&registry_bytes)
            || observation.case_digest != case.digest()?
            || observation
                .checks
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                != case.checks.iter().cloned().collect()
            || observation
                .checks
                .values()
                .any(|check| check.detail.trim().is_empty())
            || observation.predecessor != case.predecessor
        {
            bail!("scenario observations differ from the configured executor or required case");
        }
        if let Some(assessment) = &observation.assessment {
            if response.report.get("assessment") != Some(&serde_json::to_value(assessment)?) {
                bail!("scenario assessment differs from its retained report");
            }
        }
        if observation.environment.is_some() || observation.assessment.is_none() {
            let environment = response
                .report
                .get("environment")
                .context("scenario report lacks actual environment inventory")?;
            if observation.environment_digest
                != Sha256Digest::of_bytes(&canonical::canonical_json(environment)?)
            {
                bail!("scenario environment digest differs from its recorded inventory");
            }
            if let Some(inventory) = &observation.environment {
                if &serde_json::to_value(inventory)? != environment {
                    bail!("structured execution inventory differs from the retained report");
                }
            }
        }
        Result::<Vec<u8>>::Ok(bytes)
    };
    let result = tokio::time::timeout(Duration::from_secs(args.timeout_seconds), attempt)
        .await
        .context("qualification attempt exceeded its total deadline")
        .and_then(|result| result);
    match result {
        Ok(bytes) => {
            fs::write(directory.join("result"), b"passed\n")?;
            std::io::stdout().write_all(&bytes)?;
            Ok(())
        }
        Err(error) => {
            fs::write(directory.join("failure.txt"), format!("{error:#}\n"))?;
            Err(error).with_context(|| {
                format!("qualification attempt retained at {}", directory.display())
            })
        }
    }
}

fn resumed_artifact(request: &QualificationExecutorRequestV1) -> Result<Option<String>> {
    let requires_resume = request.qualification_case.as_ref().is_some_and(|case| {
        case.checks
            .iter()
            .any(|check| check == "anonymous-download-and-resume")
    });
    if !requires_resume {
        return Ok(None);
    }

    request
        .objects
        .iter()
        .filter(|object| object.size_bytes > 1 && request.subjects.contains(&object.artifact_id))
        .max_by_key(|object| object.size_bytes)
        .map(|object| Some(object.artifact_id.clone()))
        .context("image resume qualification has no resumable subject object")
}

async fn download_object(
    client: &reqwest::Client,
    object: &aos_release::evidence::QualificationObjectV1,
    path: &Path,
    resume: bool,
) -> Result<DownloadTrace> {
    let mut file = File::options().create_new(true).write(true).open(path)?;
    let mut size = 0_u64;
    let mut hash = Sha256::new();
    let mut requests = Vec::new();

    if resume {
        let first_size = (object.size_bytes / 2).min(1024 * 1024).max(1);
        let ranges = [(0, first_size - 1), (first_size, object.size_bytes - 1)];
        for (start, end) in ranges {
            let range = format!("bytes={start}-{end}");
            let response = client.get(&object.url).header(RANGE, &range).send().await?;
            if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                bail!(
                    "resumed object download for {} did not return HTTP 206",
                    object.artifact_id
                );
            }
            let expected_content_range = format!("bytes {start}-{end}/{}", object.size_bytes);
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .context("resumed object download omitted Content-Range")?
                .to_str()
                .context("resumed object Content-Range is not ASCII")?
                .to_owned();
            if content_range != expected_content_range {
                bail!(
                    "resumed object download for {} returned an unexpected Content-Range",
                    object.artifact_id
                );
            }
            write_response(
                response,
                &mut file,
                &mut hash,
                &mut size,
                end - start + 1,
                object.size_bytes,
            )
            .await?;
            requests.push(DownloadRequestTrace {
                status: reqwest::StatusCode::PARTIAL_CONTENT.as_u16(),
                content_range: Some(content_range),
            });
        }
    } else {
        let response = client.get(&object.url).send().await?;
        if response.status() != reqwest::StatusCode::OK {
            bail!(
                "object download for {} did not return HTTP 200",
                object.artifact_id
            );
        }
        write_response(
            response,
            &mut file,
            &mut hash,
            &mut size,
            object.size_bytes,
            object.size_bytes,
        )
        .await?;
        requests.push(DownloadRequestTrace {
            status: reqwest::StatusCode::OK.as_u16(),
            content_range: None,
        });
    }

    if size != object.size_bytes
        || Sha256Digest::from_bytes(hash.finalize().into()) != object.sha256
    {
        bail!(
            "download differs from the exact signed object {}",
            object.artifact_id
        );
    }
    file.sync_all()?;

    Ok(DownloadTrace {
        mode: if resume { "range-resume" } else { "complete" },
        requests,
    })
}

async fn write_response(
    mut response: reqwest::Response,
    file: &mut File,
    hash: &mut Sha256,
    total_size: &mut u64,
    expected_size: u64,
    maximum_total_size: u64,
) -> Result<()> {
    let mut response_size = 0_u64;
    while let Some(chunk) = response.chunk().await? {
        let chunk_size = u64::try_from(chunk.len())?;
        response_size = response_size
            .checked_add(chunk_size)
            .context("object response size overflow")?;
        *total_size = total_size
            .checked_add(chunk_size)
            .context("object size overflow")?;
        if response_size > expected_size || *total_size > maximum_total_size {
            bail!("download exceeds planned object size");
        }
        hash.update(&chunk);
        file.write_all(&chunk)?;
    }
    if response_size != expected_size {
        bail!("download response differs from its requested byte range");
    }
    Ok(())
}

fn select<'a>(
    registry: &'a ScenarioRegistry,
    request: &QualificationExecutorRequestV1,
) -> Result<&'a str> {
    let v1 = registry.schema_version == "aos.release.qualification-scenarios/v1";
    let v2 = registry.schema_version == "aos.release.qualification-scenarios/v2";
    if (!v1 && !v2)
        || (v1 && !registry.case_scenarios.is_empty())
        || registry.platform != request.platform
    {
        bail!("scenario registry does not cover this request schema/platform");
    }
    let case_id = request
        .qualification_case
        .as_ref()
        .map(|case| case.id.as_str());
    let executable = case_id
        .and_then(|id| registry.case_scenarios.get(id))
        .or_else(|| registry.scenarios.get(&request.policy_id))
        .context("required scenario is not implemented in this executor")?;
    if !executable.starts_with("/nix/store/") || executable.contains("/../") {
        bail!("scenario executable must belong to an immutable Nix closure");
    }
    Ok(executable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package_case() -> aos_release::qualification_evidence::QualificationCase {
        aos_release::qualification_evidence::QualificationCase {
            schema_version: Some("aos.release.qualification-case/v2".into()),
            claim: None,
            measurements: BTreeMap::new(),
            minimum_observed_seconds: None,
            id: "package-function/example/x86_64-linux".into(),
            requirement_id: "package-function".into(),
            policy_digest: Sha256Digest::of_bytes(b"policy"),
            plan_digest: Sha256Digest::of_bytes(b"plan"),
            subjects_digest: Sha256Digest::of_bytes(b"subjects"),
            phase: QualificationPhase::Staging,
            platform: Some(Platform::X86_64Linux),
            package_role: Some(aos_release::qualification::PackageRole::GeneralCatalog),
            target: None,
            subjects: vec!["package/example/x86_64-linux".into()],
            checks: vec!["anonymous-download".into(), "functional-behavior".into()],
            method: aos_release::qualification::QualificationMethod::Automated,
            predecessor: None,
        }
    }

    fn package_request() -> Result<QualificationExecutorRequestV1> {
        let case = package_case();
        Ok(QualificationExecutorRequestV1 {
            schema_version: "aos.release.qualification-executor-request/v2".into(),
            qualification_case: Some(case.clone()),
            registry: "andyl/testing".into(),
            release_id: "release-2026.9.0".into(),
            staging_receipt_digest: Sha256Digest::of_bytes(b"receipt"),
            manifest_digest: Sha256Digest::of_bytes(b"manifest"),
            policy_id: case.requirement_id,
            policy_digest: case.policy_digest,
            platform: Platform::X86_64Linux,
            subjects: case.subjects,
            objects: vec![aos_release::evidence::QualificationObjectV1 {
                artifact_id: "package/example/x86_64-linux".into(),
                url: "https://aos.staging.andyl.org/andyl/testing/packages/example.nar.zst".into(),
                size_bytes: 42,
                sha256: Sha256Digest::of_bytes(b"nar"),
            }],
            retained_predecessor: None,
            nonce: "a".repeat(64),
        })
    }

    fn package_report() -> serde_json::Value {
        serde_json::json!({
            "schema_version": SCENARIO_REPORT_V1,
            "registry": "andyl/testing",
            "release_id": "release-2026.9.0",
            "staging_receipt_digest": Sha256Digest::of_bytes(b"receipt"),
            "manifest_digest": Sha256Digest::of_bytes(b"manifest"),
            "case_digest": package_case().digest().unwrap(),
            "started_at": "2026-09-06T18:00:00Z",
            "finished_at": "2026-09-06T18:01:00Z",
            "observed_seconds": 60,
            "checks": {
                "anonymous-download": {
                    "passed": true,
                    "detail": "Retained objects match the signed public inventory."
                },
                "functional-behavior": {
                    "passed": true,
                    "detail": "The package-specific primary and error operations passed."
                }
            },
            "operations": {"error_cases": 1, "primary_operations": 1},
            "environment": {
                "host": "qualification-host-01",
                "platform": "x86_64-linux"
            }
        })
    }

    #[test]
    fn scenario_registry_rejects_unknown_platform_and_mutable_executables() -> Result<()> {
        let registry = ScenarioRegistry {
            schema_version: "aos.release.qualification-scenarios/v1".into(),
            platform: Platform::X86_64Linux,
            scenarios: BTreeMap::from([(
                "gate".into(),
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-scenario/bin/run".into(),
            )]),
            case_scenarios: BTreeMap::new(),
        };
        let mut request = QualificationExecutorRequestV1 {
            schema_version: aos_release::evidence::QUALIFICATION_EXECUTOR_REQUEST_V1.into(),
            qualification_case: None,
            registry: "andyl/testing".into(),
            release_id: "fixture".into(),
            staging_receipt_digest: Sha256Digest::of_bytes(b"receipt"),
            manifest_digest: Sha256Digest::of_bytes(b"manifest"),
            policy_id: "gate".into(),
            policy_digest: Sha256Digest::of_bytes(b"policy"),
            platform: Platform::X86_64Linux,
            subjects: vec![],
            objects: vec![],
            retained_predecessor: None,
            nonce: "a".repeat(64),
        };
        assert!(select(&registry, &request).is_ok());
        request.platform = Platform::Aarch64Linux;
        assert!(select(&registry, &request).is_err());
        request.platform = Platform::X86_64Linux;
        request.policy_id = "request-chosen-command".into();
        assert!(select(&registry, &request).is_err());
        request.policy_id = "gate".into();
        let mutable = ScenarioRegistry {
            scenarios: BTreeMap::from([("gate".into(), "/tmp/scenario".into())]),
            ..registry
        };
        assert!(select(&mutable, &request).is_err());
        Ok(())
    }

    #[test]
    fn scenario_registry_v2_prefers_an_exact_case_override() -> Result<()> {
        let request = package_request()?;
        let case_id = request
            .qualification_case
            .as_ref()
            .context("fixture lacks a qualification case")?
            .id
            .clone();
        let generic = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-generic/bin/run";
        let recovery = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-recovery/bin/run";
        let registry = ScenarioRegistry {
            schema_version: "aos.release.qualification-scenarios/v2".into(),
            platform: Platform::X86_64Linux,
            scenarios: BTreeMap::from([("package-function".into(), generic.into())]),
            case_scenarios: BTreeMap::from([(case_id, recovery.into())]),
        };

        assert_eq!(select(&registry, &request)?, recovery);

        let fallback = ScenarioRegistry {
            case_scenarios: BTreeMap::new(),
            ..registry.clone()
        };
        assert_eq!(select(&fallback, &request)?, generic);

        let v1 = ScenarioRegistry {
            schema_version: "aos.release.qualification-scenarios/v1".into(),
            ..registry
        };
        assert!(select(&v1, &request).is_err());
        Ok(())
    }

    #[test]
    fn image_resume_selects_the_largest_subject_object() -> Result<()> {
        let mut request = package_request()?;
        let case = request
            .qualification_case
            .as_mut()
            .context("fixture lacks a qualification case")?;
        case.checks = vec!["anonymous-download-and-resume".into()];
        request.subjects = vec![
            "image/aos/x86_64-linux/metadata".into(),
            "image/aos/x86_64-linux/raw".into(),
        ];
        case.subjects.clone_from(&request.subjects);
        request.objects = vec![
            aos_release::evidence::QualificationObjectV1 {
                artifact_id: "control/release-manifest-envelope".into(),
                url: "https://aos.staging.andyl.org/andyl/testing/release-manifest.json".into(),
                size_bytes: 4096,
                sha256: Sha256Digest::of_bytes(b"manifest"),
            },
            aos_release::evidence::QualificationObjectV1 {
                artifact_id: "image/aos/x86_64-linux/metadata".into(),
                url: "https://aos.staging.andyl.org/andyl/testing/images/aos/x86_64-linux/metadata"
                    .into(),
                size_bytes: 8192,
                sha256: Sha256Digest::of_bytes(b"metadata"),
            },
            aos_release::evidence::QualificationObjectV1 {
                artifact_id: "image/aos/x86_64-linux/raw".into(),
                url: "https://aos.staging.andyl.org/andyl/testing/images/aos/x86_64-linux/raw"
                    .into(),
                size_bytes: 32768,
                sha256: Sha256Digest::of_bytes(b"raw"),
            },
        ];

        assert_eq!(
            resumed_artifact(&request)?,
            Some("image/aos/x86_64-linux/raw".into())
        );

        request.objects[2].size_bytes = 1;
        assert_eq!(
            resumed_artifact(&request)?,
            Some("image/aos/x86_64-linux/metadata".into())
        );
        Ok(())
    }

    #[test]
    fn scenario_report_is_bound_to_the_exact_request_and_executor() -> Result<()> {
        let request = package_request()?;
        request.validate()?;
        let report = package_report();
        let report_bytes = canonical::to_vec(&report)?;
        let fields: ScenarioReport = serde_json::from_value(report.clone())?;
        let registry_bytes = br#"{"schema_version":"aos.release.qualification-scenarios/v1"}"#;

        let response = build_response(
            &request,
            registry_bytes,
            &report_bytes,
            report,
            fields,
            "linux-x86-v1",
        )?;
        let observation = response
            .evidence
            .qualification
            .as_ref()
            .context("test response lacks its observation")?;

        assert_eq!(response.request_digest, request.digest()?);
        assert_eq!(
            observation.executor_digest,
            Sha256Digest::of_bytes(registry_bytes)
        );
        assert_eq!(
            response.evidence.report_digest,
            Sha256Digest::of_bytes(&report_bytes)
        );
        assert_eq!(response.evidence.authority_id, "linux-x86-v1");
        assert_eq!(
            response.evidence.nonce.as_deref(),
            Some(request.nonce.as_str())
        );
        Ok(())
    }

    #[test]
    fn update_request_requires_the_verified_predecessor_graph() -> Result<()> {
        let mut request = package_request()?;
        request.schema_version = aos_release::evidence::QUALIFICATION_EXECUTOR_REQUEST_V3.into();
        request
            .qualification_case
            .as_mut()
            .context("fixture lacks a qualification case")?
            .predecessor = Some(
            aos_release::qualification_evidence::QualificationPredecessor {
                registry: "andyl/testing".into(),
                release_id: "qualification-snapshot-2026.9.0".into(),
                manifest_digest: Sha256Digest::of_bytes(b"predecessor-manifest"),
            },
        );
        assert!(request.validate().is_err());

        request.retained_predecessor = Some(aos_release::evidence::QualificationRetainedBundleV1 {
            bundle_path: "/srv/aos/predecessor".into(),
            objects: vec![
                aos_release::evidence::QualificationRetainedObjectV1 {
                    artifact_id: "control/release-manifest-envelope".into(),
                    source_path: "/srv/aos/predecessor/release-manifest.json".into(),
                    size_bytes: 40,
                    sha256: Sha256Digest::of_bytes(b"manifest-envelope"),
                },
                aos_release::evidence::QualificationRetainedObjectV1 {
                    artifact_id: "package/example/x86_64-linux".into(),
                    source_path: "/srv/aos/predecessor/example.nar.zst".into(),
                    size_bytes: 42,
                    sha256: Sha256Digest::of_bytes(b"predecessor-nar"),
                },
            ],
            trusted_keys: vec![aos_release::evidence::QualificationTrustedKeyV1 {
                key_id: "release-2026".into(),
                public_key_hex: "11".repeat(32),
            }],
        });
        assert!(request.validate().is_ok());

        request
            .retained_predecessor
            .as_mut()
            .context("fixture lacks a retained predecessor")?
            .objects[1]
            .source_path = "relative/example.nar.zst".into();
        assert!(request.validate().is_err());
        Ok(())
    }

    #[test]
    fn scenario_report_rejects_check_time_and_environment_drift() -> Result<()> {
        let case = package_case();
        let report = package_report();
        let mut fields: ScenarioReport = serde_json::from_value(report.clone())?;
        fields.checks.remove("functional-behavior");
        let request = package_request()?;
        assert!(validate_report_fields(&request, &case, &fields).is_err());

        let mut report = package_report();
        report["finished_at"] = serde_json::json!("2026-09-06T17:59:00Z");
        let fields: ScenarioReport = serde_json::from_value(report)?;
        assert!(validate_report_fields(&request, &case, &fields).is_err());

        let mut report = package_report();
        report
            .as_object_mut()
            .context("test report is not an object")?
            .remove("environment");
        let fields: ScenarioReport = serde_json::from_value(report)?;
        assert!(validate_report_fields(&request, &case, &fields).is_err());

        let mut report = package_report();
        report["manifest_digest"] = serde_json::json!(Sha256Digest::of_bytes(b"other"));
        let fields: ScenarioReport = serde_json::from_value(report)?;
        assert!(validate_report_fields(&request, &case, &fields).is_err());
        Ok(())
    }
}
