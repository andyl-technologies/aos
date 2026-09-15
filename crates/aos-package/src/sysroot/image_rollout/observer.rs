//! Independent qualification observations for the native image-rollout provider.
//!
//! The observer reads the provider-owned state for the exact checked rollout
//! request. It does not invoke the effect handler or inspect execution journals.

use std::fs;
use std::io::{self, Read, Write as _};
use std::path::{Component, Path};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{ABILITY_LIMITS_V1, LocalKey, Operation, ResourceId, ValueExpression};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::ability::AbilityRolloutState;
use super::{AbRolloutRequest, NativeAbRolloutBackend};

const ADAPTER: &str = "image-rollout";
const INTERFACE: &str = "aos.ab-image-rollout-effects";
const KIND: &str = "rollout";
const SCOPE: &str = "host-machine";
const IMAGE_PROFILE: &str = "/var/lib/profiles/image";
const BOOT_ROOT: &str = "/boot";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverArguments {
    request_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverRequest {
    adapter: LocalKey,
    scope: LocalKey,
    operation: Operation,
}

#[derive(Debug, Serialize)]
struct ObserverResult {
    provider: LocalKey,
    kind: LocalKey,
    scope: LocalKey,
    observation: String,
}

#[derive(Debug, Serialize)]
struct RolloutObservation {
    kind: LocalKey,
    resource: ResourceId,
    provider_state: Option<AbilityRolloutState>,
    image_state_digest: Option<Sha256Digest>,
    boot_selection_digest: Option<Sha256Digest>,
    kernel_command_line_digest: Option<Sha256Digest>,
    retention: Vec<FileObservation>,
}

#[derive(Debug, Serialize)]
struct FileObservation {
    path: String,
    digest: Sha256Digest,
}

/// Runs the package-owned read-only image-rollout qualification observer.
///
/// # Errors
///
/// Returns an error when the observer request is malformed, addresses another
/// implementation, contains unresolved inputs, or provider state cannot be
/// read within the canonical bounds.
pub fn run_from_process() -> Result<()> {
    let arguments: ObserverArguments = read_json(io::stdin())?;
    let request_path = Path::new(&arguments.request_path);
    ensure!(
        request_path.is_absolute()
            && !request_path
                .components()
                .any(|component| matches!(component, Component::ParentDir)),
        "qualification observer request path is not absolute and normalized"
    );

    let request: ObserverRequest = serde_json::from_slice(&read_bounded(request_path)?)?;
    validate_request(&request)?;
    let desired: AbRolloutRequest =
        serde_json::from_value(literal_value(&request.operation.inputs)?)
            .context("decoding checked image-rollout inputs")?;
    let observation = observe(&request.operation.target.resource, &desired)?;
    let observation = String::from_utf8(aos_contract::canonical::to_vec(&observation)?)
        .context("encoding qualification observation as UTF-8")?;
    let result = ObserverResult {
        provider: request.adapter,
        kind: local_key(KIND)?,
        scope: request.scope,
        observation,
    };

    io::stdout().write_all(&aos_contract::canonical::to_vec(&result)?)?;
    Ok(())
}

fn validate_request(request: &ObserverRequest) -> Result<()> {
    ensure!(
        request.adapter.as_str() == ADAPTER
            && request.scope.as_str() == SCOPE
            && request.operation.interface.name.as_str() == INTERFACE
            && request.operation.target.interface == request.operation.interface,
        "qualification observer request does not address this provider"
    );
    Ok(())
}

fn literal_value(expression: &ValueExpression) -> Result<serde_json::Value> {
    match expression {
        ValueExpression::Literal { value } => Ok(value.as_json().clone()),
        ValueExpression::List { items } => items
            .iter()
            .map(literal_value)
            .collect::<Result<Vec<_>>>()
            .map(serde_json::Value::Array),
        ValueExpression::Object { fields } => fields
            .iter()
            .map(|(name, value)| Ok((name.clone(), literal_value(value)?)))
            .collect::<Result<serde_json::Map<_, _>>>()
            .map(serde_json::Value::Object),
        _ => anyhow::bail!("image-rollout observer requires fully resolved checked inputs"),
    }
}

fn observe(resource: &ResourceId, request: &AbRolloutRequest) -> Result<RolloutObservation> {
    observe_at(
        resource,
        request,
        Path::new(IMAGE_PROFILE),
        Path::new(BOOT_ROOT),
        Path::new("/proc/cmdline"),
    )
}

fn observe_at(
    resource: &ResourceId,
    request: &AbRolloutRequest,
    image_profile: &Path,
    boot_root: &Path,
    kernel_command_line: &Path,
) -> Result<RolloutObservation> {
    let backend = NativeAbRolloutBackend::new(image_profile, boot_root);
    let execution_directory = backend.execution_directory(request)?;
    let provider_state: Option<AbilityRolloutState> =
        read_optional_json(&execution_directory.join("state.json"))?;
    if let Some(state) = provider_state.as_ref() {
        ensure!(
            state.request == *request,
            "durable rollout state differs from checked inputs"
        );
    }

    Ok(RolloutObservation {
        kind: local_key(KIND)?,
        resource: resource.clone(),
        provider_state,
        image_state_digest: read_optional_digest(&image_profile.join("state.json"))?,
        boot_selection_digest: read_optional_digest(&boot_root.join("loader/loader.conf"))?,
        kernel_command_line_digest: read_optional_digest(kernel_command_line)?,
        retention: observe_directory(&backend.retained_uki_directory(request)?)?,
    })
}

fn observe_directory(directory: &Path) -> Result<Vec<FileObservation>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut observed = Vec::new();
    for (index, entry) in entries
        .take(ABILITY_LIMITS_V1.max_collection_items as usize + 1)
        .enumerate()
    {
        ensure!(
            (index as u64) < ABILITY_LIMITS_V1.max_collection_items,
            "rollout retention inventory exceeds the canonical bound"
        );
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        observed.push(FileObservation {
            path: path
                .to_str()
                .context("rollout retention path is not UTF-8")?
                .to_owned(),
            digest: Sha256Digest::of_bytes(&read_bounded(&path)?),
        });
    }
    observed.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(observed)
}

fn read_json<T: serde::de::DeserializeOwned>(input: impl Read) -> Result<T> {
    let mut bytes = Vec::new();
    input
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "qualification observer input exceeds the canonical document bound"
    );
    serde_json::from_slice(&bytes).context("decoding qualification observer input")
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "observed path is not a regular file"
    );
    ensure!(
        metadata.len() <= ABILITY_LIMITS_V1.max_document_bytes,
        "observed file exceeds the canonical document bound"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "observed file grew beyond the canonical document bound"
    );
    Ok(bytes)
}

fn read_optional_digest(path: &Path) -> Result<Option<Sha256Digest>> {
    match read_bounded(path) {
        Ok(bytes) => Ok(Some(Sha256Digest::of_bytes(&bytes))),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|io| io.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn read_optional_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match read_bounded(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|io| io.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn local_key(value: &str) -> Result<LocalKey> {
    LocalKey::new(value).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AbRolloutRequest {
        serde_json::from_value(serde_json::json!({
            "strategy": "single-host-ab-v1",
            "concurrency": 1,
            "predecessor": {
                "toplevel": "/nix/store/00000000000000000000000000000000-predecessor",
                "uki": "/nix/store/11111111111111111111111111111111-predecessor.efi",
                "executor": "/nix/store/22222222222222222222222222222222-executor",
                "state-format": "fixture-state",
            },
            "candidate": {
                "toplevel": "/nix/store/33333333333333333333333333333333-candidate",
                "uki": "/nix/store/44444444444444444444444444444444-candidate.efi",
                "executor": "/nix/store/22222222222222222222222222222222-executor",
                "state-format": "fixture-state",
            },
            "retention-expires-at-millis": 42,
        }))
        .expect("rollout request fixture is valid")
    }

    fn resource() -> ResourceId {
        serde_json::from_value(serde_json::json!({
            "provider": {
                "environment": {
                    "authority": "test",
                    "key": "host",
                    "stage": "host",
                },
                "key": "rollout",
            },
            "key": "machine",
        }))
        .expect("resource fixture is valid")
    }

    #[test]
    fn observation_is_scoped_to_the_checked_rollout() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let image_profile = directory.path().join("image");
        let boot_root = directory.path().join("boot");
        let kernel_command_line = directory.path().join("cmdline");
        fs::create_dir_all(boot_root.join("loader")).expect("boot fixture is created");
        fs::create_dir_all(&image_profile).expect("profile fixture is created");
        fs::write(image_profile.join("state.json"), b"image-state")
            .expect("image state is written");
        fs::write(boot_root.join("loader/loader.conf"), b"default candidate\n")
            .expect("boot selection is written");
        fs::write(&kernel_command_line, b"aos.image=candidate\n")
            .expect("kernel command line is written");

        let observation = observe_at(
            &resource(),
            &request(),
            &image_profile,
            &boot_root,
            &kernel_command_line,
        )
        .expect("rollout substrate is observable");

        assert_eq!(observation.resource, resource());
        assert!(observation.provider_state.is_none());
        assert_eq!(
            observation.image_state_digest,
            Some(Sha256Digest::of_bytes(b"image-state"))
        );
        assert_eq!(
            observation.boot_selection_digest,
            Some(Sha256Digest::of_bytes(b"default candidate\n"))
        );
        assert_eq!(
            observation.kernel_command_line_digest,
            Some(Sha256Digest::of_bytes(b"aos.image=candidate\n"))
        );
        assert!(observation.retention.is_empty());
    }
}
