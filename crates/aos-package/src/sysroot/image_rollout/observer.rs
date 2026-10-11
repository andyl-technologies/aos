//! Read-only physical observations of one explicitly selected native image rollout.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::Path;

use anyhow::{Result, ensure};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::ability::AbilityRolloutState;
use super::{ImageRolloutRequest, NativeImageRolloutBackend};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    effect: String,
    rollout: ImageRolloutRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    schema: &'static str,
    effect: String,
    provider_state: Option<AbilityRolloutState>,
    image_state_digest: Option<Sha256Digest>,
}

/// Reports physical retained state without invoking handlers or selecting boot.
///
/// # Errors
/// Returns an error for malformed bounded input, mismatched retained identity,
/// nonregular state files, or an unreadable physical image index.
pub fn run_from_process() -> Result<()> {
    let mut bytes = Vec::new();
    io::stdin().take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "native rollout observation exceeds its bound"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    let image_profile = Path::new("/var/lib/profiles/image");
    let backend = NativeImageRolloutBackend::new(image_profile);
    let directory = backend.execution_directory(&request.rollout)?;
    let provider_state: Option<AbilityRolloutState> =
        read_optional_json(&directory.join("state.json"))?;
    if let Some(state) = &provider_state {
        ensure!(
            state.request == request.rollout,
            "physical rollout identity differs from requested observation"
        );
        backend.observe_operation(&request.rollout, "retain")?;
    }
    let observation = Observation {
        schema: "aos.native-image-rollout-observation/v1",
        effect: request.effect,
        provider_state,
        image_state_digest: read_optional_digest(&image_profile.join("state.json"))?,
    };
    io::stdout().write_all(&serde_json::to_vec(&observation)?)?;
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "observed path is not a regular file"
    );
    ensure!(
        metadata.len() <= 1024 * 1024,
        "observed file exceeds the canonical document bound"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() as u64 <= 1024 * 1024,
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
