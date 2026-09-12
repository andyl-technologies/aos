//! Live foreground-supervisor driver for the application-container fleet test.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_ability_model::{
    ArtifactReference, EnvironmentId, ExecutionStage, InstanceId, LocalKey, ResourceId, RevisionId,
};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_contract::Sha256Digest;
use aos_package::config_eval::foreground_process_ability::{
    ForegroundProcessResourceSpec, ForegroundProcessSupervisor,
};

struct QualificationControl;

impl RuntimeControl for QualificationControl {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn elapsed_millis(&self) -> u64 {
        0
    }

    fn attempt_remaining_millis(&self) -> u64 {
        30_000
    }

    fn recovery_remaining_millis(&self) -> u64 {
        30_000
    }
}

pub(super) fn run(arguments: &[String]) -> Result<()> {
    if arguments.len() < 4 {
        bail!(
            "usage: aos-release-fleet-fixture foreground-process ACTION STATE_ROOT ARTIFACT ENTRY_POINT [ARG ...]"
        );
    }
    let action = arguments[0].as_str();
    let state_root = Path::new(&arguments[1]);
    let artifact = Path::new(&arguments[2]);
    let entry_point = &arguments[3];
    let spec = resource_spec(artifact, entry_point, &arguments[4..])?;
    let mut supervisor = ForegroundProcessSupervisor::new(state_root)
        .context("opening the foreground supervisor state root")?;

    let observation = match action {
        "start" => supervisor.start(&spec, &QualificationControl),
        "observe" => supervisor.observe(&spec),
        "stop" => supervisor.stop(&spec, &QualificationControl),
        _ => bail!("unsupported foreground fixture action: {action}"),
    }
    .context("executing the foreground supervisor action")?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "schema": "aos.ability.foreground-process-observation/v1",
            "running": observation.running,
            "process_identity": observation.process_identity,
        }))?
    );
    Ok(())
}

fn resource_spec(
    artifact: &Path,
    entry_point: &str,
    arguments: &[String],
) -> Result<ForegroundProcessResourceSpec> {
    let artifact = artifact
        .canonicalize()
        .context("canonicalizing the foreground artifact")?;
    let artifact_text = artifact.to_string_lossy().into_owned();
    Ok(ForegroundProcessResourceSpec {
        resource: ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("fleet")?,
                    key: LocalKey::new("reference-nginx")?,
                    stage: ExecutionStage::ApplicationContainer,
                },
                key: LocalKey::new("nginx")?,
            },
            key: LocalKey::new("service")?,
        },
        revision: RevisionId(Sha256Digest::separated(
            "aos.qualification.foreground-nginx-revision/v1",
            format!("{artifact_text}\0{entry_point}\0{}", arguments.join("\0")),
        )),
        artifact: ArtifactReference {
            content: Sha256Digest::separated(
                "aos.qualification.foreground-nginx-content/v1",
                &artifact_text,
            ),
            store_path: artifact_text.clone(),
            nar_hash: Sha256Digest::separated(
                "aos.qualification.foreground-nginx-nar/v1",
                &artifact_text,
            ),
            closure: Sha256Digest::separated(
                "aos.qualification.foreground-nginx-closure/v1",
                &artifact_text,
            ),
        },
        entry_point: entry_point.to_string(),
        arguments: arguments.to_vec(),
    })
}
