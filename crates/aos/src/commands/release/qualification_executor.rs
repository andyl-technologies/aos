//! Native scenario selection, verified downloads, and retained execution attempts.
//!
//! The Nix-built registry selects executable closures; a remote request cannot
//! supply a command. Scenarios receive the original request on stdin and read
//! `objects.json` in their private working directory for verified local paths.
//! Their stdout is a canonical executor response. Every attempt is retained,
//! including failures; the coordinator still independently validates coverage.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::Sha256Digest;
use aos_release::canonical;
use aos_release::evidence::QualificationExecutorRequestV1;
use aos_release::manifest::{ManifestEnvelopeV1, ReleaseManifestV1};
use aos_release::plan::ReleasePlanV1;
use aos_release::platform::Platform;
use aos_release::qualification::QualificationPhase;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{capture, qualification_run};
use crate::cli::{ReleaseQualificationCommand, ReleaseQualificationExecuteArgs};

/// Immutable executable selection, produced by `mkQualificationExecutor`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScenarioRegistry {
    schema_version: String,
    platform: Platform,
    scenarios: BTreeMap<String, String>,
}

pub(super) fn inspect(command: &ReleaseQualificationCommand, printer: &Printer) -> Result<()> {
    let ReleaseQualificationCommand::Cases(args) = command else {
        bail!("qualification execution requires the asynchronous dispatcher");
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
    let output = serde_json::json!({"status": "not-evaluated", "cases": cases});
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
    }
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
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(args.timeout_seconds))
            .build()?;
        let mut objects = BTreeMap::new();
        for object in &request.objects {
            let filename = Sha256Digest::of_bytes(object.artifact_id.as_bytes()).hex();
            let path = directory.join(filename);
            let mut response = client.get(&object.url).send().await?.error_for_status()?;
            if response.status() != reqwest::StatusCode::OK {
                bail!("object download did not return HTTP 200");
            }
            let mut file = File::options().create_new(true).write(true).open(&path)?;
            let mut size = 0_u64;
            let mut hash = Sha256::new();
            while let Some(chunk) = response.chunk().await? {
                size = size
                    .checked_add(u64::try_from(chunk.len())?)
                    .context("object size overflow")?;
                if size > object.size_bytes {
                    bail!("download exceeds planned object size");
                }
                hash.update(&chunk);
                file.write_all(&chunk)?;
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
            objects.insert(object.artifact_id.clone(), path);
        }
        fs::write(directory.join("objects.json"), canonical::to_vec(&objects)?)?;
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

fn select<'a>(
    registry: &'a ScenarioRegistry,
    request: &QualificationExecutorRequestV1,
) -> Result<&'a str> {
    if registry.schema_version != "aos.release.qualification-scenarios/v1"
        || registry.platform != request.platform
    {
        bail!("scenario registry does not cover this request schema/platform");
    }
    let executable = registry
        .scenarios
        .get(&request.policy_id)
        .context("required scenario is not implemented in this executor")?;
    if !executable.starts_with("/nix/store/") || executable.contains("/../") {
        bail!("scenario executable must belong to an immutable Nix closure");
    }
    Ok(executable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_registry_rejects_unknown_platform_and_mutable_executables() -> Result<()> {
        let registry = ScenarioRegistry {
            schema_version: "aos.release.qualification-scenarios/v1".into(),
            platform: Platform::X86_64Linux,
            scenarios: BTreeMap::from([(
                "gate".into(),
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-scenario/bin/run".into(),
            )]),
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
}
