//! Production checked-plan provider state-transfer inspection for fleet tests.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_ability_model::Operation;
use aos_ability_runtime::bundle::{PLAN_BUNDLE_MAX_BYTES, ReloadablePlanBundle};
use aos_package::config_eval::ability_store::inspect_native_adapter_provider_state_transfer;
use aos_package::config_eval::supported_native_ability_features;

const OPERATION_MAX_BYTES: u64 = 1024 * 1024;

/// Replays a retained production bundle and writes its exact transfer contract.
pub(super) fn inspect(arguments: &[String]) -> Result<()> {
    let [bundle_path, operation_path, output_path] = arguments else {
        bail!(
            "usage: aos-release-fleet-fixture provider-state-transfer-contract PLAN_BUNDLE OPERATION OUTPUT"
        );
    };
    let bundle_path = Path::new(bundle_path);
    let operation_path = Path::new(operation_path);
    let output_path = Path::new(output_path);

    let metadata = fs::metadata(bundle_path)
        .with_context(|| format!("reading plan bundle metadata {}", bundle_path.display()))?;
    if metadata.len() > PLAN_BUNDLE_MAX_BYTES as u64 {
        bail!("provider state-transfer plan bundle exceeds its byte limit");
    }
    let bundle_bytes = fs::read(bundle_path)
        .with_context(|| format!("reading plan bundle {}", bundle_path.display()))?;
    let bundle = ReloadablePlanBundle::decode(&bundle_bytes)
        .context("decoding canonical provider state-transfer plan bundle")?;
    let plan = bundle
        .revalidate(supported_native_ability_features()?)
        .context("revalidating provider state-transfer plan bundle")?;

    let operation_metadata = fs::metadata(operation_path)
        .with_context(|| format!("reading operation metadata {}", operation_path.display()))?;
    if operation_metadata.len() > OPERATION_MAX_BYTES {
        bail!("provider state-transfer operation exceeds its byte limit");
    }
    let operation_bytes = fs::read(operation_path)
        .with_context(|| format!("reading exact operation {}", operation_path.display()))?;
    let operation: Operation = serde_json::from_slice(&operation_bytes)
        .context("decoding exact provider state-transfer operation")?;
    let contract = inspect_native_adapter_provider_state_transfer(&plan, &operation)
        .context("inspecting exact provider state-transfer route")?;

    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(output_path)
        .with_context(|| format!("creating transfer contract {}", output_path.display()))?;
    output
        .write_all(&contract.canonical_bytes()?)
        .with_context(|| format!("writing transfer contract {}", output_path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("syncing transfer contract {}", output_path.display()))?;
    let parent = output_path
        .parent()
        .context("transfer contract has no parent")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing transfer contract directory {}", parent.display()))?;

    println!("{}", contract.digest()?);
    Ok(())
}
