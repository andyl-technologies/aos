//! Authenticated operator-source submission for expired image lease retirement.
//!
//! The checked profile output authenticates the exact prior request. Appended
//! package configuration invokes the native retirement handler; this module
//! never edits the image index or supplies physical retirement evidence.

use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, ensure};
use aos_core::output::Printer;
use serde_json::Value;

use super::{ImageRolloutRequest, RolloutImageIdentity};
use crate::config::ApmConfig;
use crate::profile::deployment::{committed_result, current_committed_generation};
use crate::sysroot::running_image_generation;

const RECEIPT: &str = "/var/lib/profiles/image/active-native-rollout.json";
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

fn read_receipt(path: &Path) -> Result<Option<Value>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "native image receipt is not an owned protected regular file"
    );
    ensure!(
        metadata.len() <= MAX_RECEIPT_BYTES,
        "native image receipt exceeds its bound"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECEIPT_BYTES,
        "native image receipt exceeds its bound"
    );
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn checked_request(
    receipt: &Value,
    committed: &Value,
    running: &RolloutImageIdentity,
    now: u64,
) -> Result<ImageRolloutRequest> {
    ensure!(
        receipt.get("schema").and_then(Value::as_str)
            == Some("aos.native-image-rollout-receipt/v1"),
        "unknown native image receipt schema"
    );
    let request: ImageRolloutRequest = serde_json::from_value(
        receipt
            .pointer("/input/rollout")
            .context("image receipt lacks exact rollout")?
            .clone(),
    )?;
    ensure!(
        committed.get("rollout") == Some(&serde_json::to_value(&request)?),
        "image receipt differs from its checked committed result"
    );
    let outcome = committed.get("outcome").and_then(Value::as_str);
    let selected = match outcome {
        Some("selected" | "candidate-healthy") => &request.candidate,
        Some("predecessor-fallback") => &request.predecessor,
        _ => anyhow::bail!("image lease lacks a committed terminal selection"),
    };
    ensure!(
        selected == running,
        "image retirement requires the exact actually running selected image"
    );
    ensure!(
        now >= request.retention_expires_at_millis,
        "inactive image lease has not expired"
    );
    Ok(request)
}

/// Commits explicit native retirement of the authenticated expired image lease.
///
/// Returns `false` when no native lease has been recorded. A successful `true`
/// result proves the retirement handler committed; staging must still perform
/// its independent slot-authority check under the shared stage lock.
///
/// # Errors
/// Returns an error for an unsafe receipt, missing committed proof, an unexpired
/// or unsettled lease, a changed running identity, or failed native retirement.
pub(crate) fn retire_expired_image_lease(config: &ApmConfig, printer: &Printer) -> Result<bool> {
    let Some(receipt) = read_receipt(Path::new(RECEIPT))? else {
        return Ok(false);
    };
    let (mut evaluation, profile) = super::submission::evaluation(config)?;
    let generation = current_committed_generation(&profile)?
        .context("image retirement requires a committed system profile")?;
    let prior_effect = receipt
        .get("effect")
        .and_then(Value::as_str)
        .context("native image receipt lacks its exact effect identity")?;
    let committed = committed_result(&profile, generation, prior_effect)?;
    let image = running_image_generation()?;
    let running = RolloutImageIdentity {
        toplevel: image.toplevel,
        boot_artifact_contract: image.boot_artifact_contract,
        executor: image.native_executor_ref,
        state_format: image.state_version,
    };
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let request = checked_request(&receipt, &committed, &running, now)?;
    let request_value = serde_json::to_value(&request)?;
    let source = tempfile::tempdir()?;
    let staging = tempfile::tempdir()?;
    let json = serde_json::to_string(&request_value)?;
    fs::write(
        source.path().join("image-retirement.nix"),
        format!(
            "{{ ... }}: {{ aos.imageRollout.retiredRequests = [ (builtins.fromJSON {}) ]; }}\n",
            crate::deployment::nix::nix_string(&json),
        ),
    )?;
    let snapshot = crate::runtime_modules::snapshot(source.path(), staging.path(), true)?;
    evaluation
        .configuration
        .extend(snapshot.entrypoints.iter().cloned());
    let effects = super::submission::project(&evaluation, "retirementEffects", staging.path())?;
    let digest = aos_contract::Sha256Digest::of_bytes(json.as_bytes()).hex();
    let effect = effects
        .get(&digest)
        .and_then(Value::as_str)
        .context("authored retirement request did not select its native effect")?;
    crate::install::native::append_runtime_snapshot(config, &snapshot, printer)?;
    let generation = current_committed_generation(&profile)?
        .context("retirement did not publish a committed generation")?;
    let result = committed_result(&profile, generation, effect)?;
    ensure!(
        result.get("rollout") == Some(&request_value)
            && result.get("outcome").and_then(Value::as_str) == Some("retired"),
        "native retirement did not commit the exact expired lease result"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn identity(name: &str) -> RolloutImageIdentity {
        RolloutImageIdentity {
            toplevel: name.into(),
            boot_artifact_contract: format!("{name}-contract"),
            executor: "executor".into(),
            state_format: "v1".into(),
        }
    }

    fn fixture() -> (Value, Value, RolloutImageIdentity) {
        let running = identity("second-image");
        let request = ImageRolloutRequest {
            predecessor: identity("first-image"),
            candidate: running.clone(),
            retention_expires_at_millis: 100,
        };
        (
            json!({"schema":"aos.native-image-rollout-receipt/v1","input":{"rollout":request}}),
            json!({"rollout":request,"outcome":"selected"}),
            running,
        )
    }

    #[test]
    fn expired_selected_lease_is_eligible_for_third_image() {
        let (receipt, result, running) = fixture();
        assert!(checked_request(&receipt, &result, &running, 100).is_ok());
    }

    #[test]
    fn unexpired_lease_cannot_authorize_overwrite() {
        let (receipt, result, running) = fixture();
        assert!(checked_request(&receipt, &result, &running, 99).is_err());
    }

    #[test]
    fn forged_receipt_or_changed_running_image_is_rejected() {
        let (mut receipt, result, running) = fixture();
        assert!(checked_request(&receipt, &result, &identity("third-image"), 100).is_err());
        receipt["input"]["rollout"]["retention-expires-at-millis"] = json!(0);
        assert!(checked_request(&receipt, &result, &running, 100).is_err());
    }

    #[test]
    fn uncertain_selection_is_not_retirement_authority() {
        let (receipt, mut result, running) = fixture();
        result["outcome"] = json!("pending");
        assert!(checked_request(&receipt, &result, &running, 100).is_err());
    }
}
