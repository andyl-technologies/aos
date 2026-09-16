//! Transactional activation of an evaluated host configuration.
//!
//! This module is the commit half of the on-host configuration pipeline.
//! Evaluation is side-effect free. Activation authenticates the checked
//! ability plan, retains its exact manifest as a content-addressed generation,
//! and lets the selected provider handlers converge the requested resources.

use std::fs::{File, OpenOptions};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::{error::Error, fmt};

use anyhow::{Context, Result, bail};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::materialize::ConfigManifest;
use crate::store::create_config_gc_roots;
use crate::sysroot::{
    commit_current_generation_pub, recover_generation_state_pub, save_generation_state_pub,
};
use crate::types::{ConfigGeneration, ImageGeneration, ProfileScope};

const ACTIVATION_RECORD: &str = "activation.json";
const DEFAULT_SWITCH_LOCK: &str = "/run/apm/switch.lock";

/// Resolves the global switch lock from an explicit path or AOS root filesystem.
fn resolve_switch_lock(root: Option<&str>, explicit: Option<&str>) -> PathBuf {
    if let Some(explicit) = explicit.filter(|path| Path::new(path).is_absolute()) {
        return PathBuf::from(explicit);
    }
    let Some(root) = root.filter(|root| !root.is_empty()) else {
        return PathBuf::from(DEFAULT_SWITCH_LOCK);
    };
    let root = Path::new(root);
    if !root.is_absolute() || root == Path::new("/") {
        return PathBuf::from(DEFAULT_SWITCH_LOCK);
    }
    root.join(DEFAULT_SWITCH_LOCK.trim_start_matches('/'))
}

/// Returns the global switch-lock path, honoring `$AOS_SWITCH_LOCK_PATH` and `$AOS_ROOT`.
pub(crate) fn default_switch_lock_path() -> PathBuf {
    resolve_switch_lock(
        std::env::var("AOS_ROOT").ok().as_deref(),
        std::env::var("AOS_SWITCH_LOCK_PATH").ok().as_deref(),
    )
}

/// Durable proof that a graph transaction reached the config pointer commit.
#[derive(Debug, Serialize)]
struct ActivationRecord<'a> {
    schema: &'static str,
    generation: u32,
    generation_id: &'a str,
    transaction_manifest: &'a str,
    dropped_packages: Vec<&'a str>,
    status: &'static str,
    activation_exit: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_ability_transaction: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_ability_prior_generation: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredActivationRecord {
    pub(crate) schema: String,
    pub(crate) generation: u32,
    pub(crate) generation_id: String,
    pub(super) transaction_manifest: String,
    #[serde(rename = "dropped_packages")]
    _dropped_packages: Vec<String>,
    pub(crate) status: String,
    pub(crate) activation_exit: i32,
    pub(crate) native_ability_transaction: Option<String>,
    pub(crate) native_ability_prior_generation: Option<NonZeroU32>,
}

/// Returns generations retained by the current native recovery record.
///
/// A failed post-publication transition may leave the declarative pointer on
/// the new generation while the old consumer still uses resources rooted by
/// its predecessor. Configuration GC must retain that predecessor until a
/// later successful activation detaches it.
///
/// # Errors
///
/// Returns an error when the current activation record is malformed, differs
/// from configuration state, or names an unavailable recovery generation.
pub(crate) fn required_native_recovery_generations(
    profile: &Path,
    state: &crate::types::ConfigGenerationState,
) -> Result<std::collections::BTreeSet<u32>> {
    let mut required = std::collections::BTreeSet::new();
    if state.current == 0 {
        return Ok(required);
    }
    let mut visited = std::collections::BTreeSet::new();
    let mut generation = state.current;
    loop {
        if !visited.insert(generation) {
            bail!("native recovery generation chain contains a cycle");
        }
        let generation_state = state
            .generations
            .iter()
            .find(|candidate| candidate.number == generation)
            .with_context(|| {
                format!("native recovery generation {generation} is absent from state")
            })?;
        let generation_directory = profile.join(format!("gen-{generation}"));
        if !generation_directory
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_dir())
        {
            bail!("native recovery generation {generation} has no protected directory");
        }
        let structured =
            manifest_has_structured_activation(&generation_directory.join("manifest.json"))?;
        let record = read_stored_activation_record(
            &generation_directory.join(ACTIVATION_RECORD),
            structured,
        )?;
        let Some(record) = record else {
            break;
        };
        if record.schema != "aos.config-activation/v1"
            || record.generation != generation
            || record.generation_id != generation_state.manifest_hash
        {
            bail!("activation record differs from configuration state");
        }
        let native_recovery = match record.status.as_str() {
            "complete" if record.activation_exit == 0 => false,
            "degraded" | "native-pending" | "native-failed" if record.activation_exit == 6 => true,
            "complete" | "degraded" | "native-pending" | "native-failed" => {
                bail!("activation record has an inconsistent status and exit code");
            }
            _ => bail!("activation record has an unknown status"),
        };
        if !structured || !native_recovery {
            break;
        }
        if record.transaction_manifest.is_empty()
            || record
                .native_ability_transaction
                .as_deref()
                .is_none_or(str::is_empty)
        {
            bail!("structured recovery record is incomplete");
        }
        let Some(prior) = record.native_ability_prior_generation.map(NonZeroU32::get) else {
            break;
        };
        if prior == generation {
            bail!("native recovery generation references itself");
        }
        required.insert(prior);
        generation = prior;
    }
    Ok(required)
}

pub(crate) fn read_stored_activation_record(
    path: &Path,
    required: bool,
) -> Result<Option<StoredActivationRecord>> {
    const MAX_ACTIVATION_RECORD_BYTES: u64 = 64 * 1024;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "structured recovery generation has no activation record at {}",
                path.display()
            );
        }
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_ACTIVATION_RECORD_BYTES {
        bail!(
            "activation record {} is not a bounded regular file",
            path.display()
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("parsing {}", path.display()))
}

fn manifest_has_structured_activation(path: &Path) -> Result<bool> {
    const MAX_CONFIG_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading current manifest metadata at {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CONFIG_MANIFEST_BYTES {
        bail!(
            "current manifest {} is not a bounded regular file",
            path.display()
        );
    }
    let document: Value = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    let inputs = document
        .get("inputs")
        .and_then(Value::as_object)
        .context("current manifest has no inputs object")?;
    Ok(inputs
        .get("ability_activation")
        .is_some_and(|activation| !activation.is_null()))
}

/// Inputs consumed by the activation commit.
#[derive(Debug, Clone)]
pub struct ActivateConfigParams {
    /// Evaluator-produced manifest; retained unchanged as the source intent.
    pub manifest: PathBuf,
    /// Root containing durable activation evidence.
    pub marker_root: PathBuf,
    /// System-generation profile root.
    pub profile: PathBuf,
    /// Running image ABI used to pin the config generation.
    pub module_abi: u32,
    /// Global system-switch lock shared with direct image activation.
    pub switch_lock: PathBuf,
    /// Test seam for the authoritative running image identity.
    /// Production resolves this from the image-generation index and measured
    /// image metadata, never from the selected config generation.
    pub running_image: Option<ImageGeneration>,
    /// Image-generation profile holding retained base-library roots.
    pub image_profile: PathBuf,
    /// Whether the caller already owns `switch_lock` across its state read.
    pub switch_lock_held: bool,
    /// Require TPM-backed generation evidence before publishing the pointer.
    pub require_attestation_quote: bool,
}

impl Default for ActivateConfigParams {
    fn default() -> Self {
        Self {
            manifest: PathBuf::from("/run/aos/manifest.json"),
            marker_root: PathBuf::from("/run/aos"),
            profile: ProfileScope::System.profile_path(),
            module_abi: 1,
            switch_lock: default_switch_lock_path(),
            running_image: None,
            image_profile: PathBuf::from("/var/lib/profiles/image"),
            switch_lock_held: false,
            require_attestation_quote: false,
        }
    }
}

/// A classified failure from checked ability activation.
#[derive(Debug)]
pub struct ActivationFailure {
    exit_code: i32,
    message: String,
}

impl ActivationFailure {
    /// Classifies a post-commit structured transition failure as degraded.
    pub(crate) fn degraded(message: impl Into<String>) -> Self {
        Self {
            exit_code: 6,
            message: message.into(),
        }
    }

    /// Returns the process exit code the service contract must observe.
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }
}

impl fmt::Display for ActivationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ActivationFailure {}

/// Activates the converged host manifest as a configuration generation.
///
/// A byte-identical manifest reuses its existing generation. A new manifest
/// creates `gen-N`, pins its runtime and source closures, and records the exact
/// checked manifest before the selected provider handlers run.
///
/// # Errors
///
/// Returns an error if inputs are malformed, running image identity cannot be
/// authenticated, generation preparation fails, activation fails before the
/// swap, or publishing the committed pointer fails. Exit code `6` is returned
/// as an error *after* committing because the switch stands but the system is
/// degraded.
pub fn activate_config(params: &ActivateConfigParams) -> Result<u32> {
    let manifest = load_config_manifest(&params.manifest)?;
    manifest
        .inputs
        .ability_activation
        .as_ref()
        .context("configuration activation requires a checked ability plan")?;
    super::native_activation::activate_config(params, manifest)
}

pub(crate) fn load_config_manifest(path: &Path) -> Result<ConfigManifest> {
    let manifest_text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: ConfigManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("parsing {}", path.display()))?;
    manifest
        .validate()
        .with_context(|| format!("validating {}", path.display()))?;
    Ok(manifest)
}

/// Replaces a committed activation's provisional status after native convergence.
///
/// # Errors
///
/// Returns an error when the committed record is missing, malformed, belongs
/// to another generation, or cannot be durably replaced.
pub(crate) fn publish_structured_activation_success(
    params: &ActivateConfigParams,
    generation: u32,
    expected_generation_id: &str,
    expected_transaction_manifest: &str,
    expected_native_transaction: &aos_ability_model::TransactionId,
) -> Result<()> {
    let generation_record = params
        .profile
        .join(format!("gen-{generation}"))
        .join(ACTIVATION_RECORD);
    let mut record: Value = serde_json::from_slice(
        &std::fs::read(&generation_record)
            .with_context(|| format!("reading {}", generation_record.display()))?,
    )
    .with_context(|| format!("parsing {}", generation_record.display()))?;
    if record.get("schema").and_then(Value::as_str) != Some("aos.config-activation/v1")
        || record.get("generation").and_then(Value::as_u64) != Some(u64::from(generation))
        || record.get("generation_id").and_then(Value::as_str) != Some(expected_generation_id)
        || record.get("transaction_manifest").and_then(Value::as_str)
            != Some(expected_transaction_manifest)
        || record.get("status").and_then(Value::as_str) != Some("native-pending")
        || record
            .get("native_ability_transaction")
            .and_then(Value::as_str)
            != Some(expected_native_transaction.0.as_str())
    {
        bail!("committed activation record differs from the pending native transaction");
    }
    record["status"] = Value::String("complete".to_string());
    record["activation_exit"] = Value::from(0);
    write_json_atomic(&generation_record, &record)?;
    write_json_atomic(&params.marker_root.join(ACTIVATION_RECORD), &record)
}

/// Records that a pending native transaction settled without installing its target.
///
/// # Errors
///
/// Returns an error unless the current proof names the exact pending manifest
/// and transaction, or when the replacement cannot be durably published.
pub(crate) fn publish_structured_activation_settled_failure(
    params: &ActivateConfigParams,
    generation: u32,
    expected_generation_id: &str,
    expected_transaction_manifest: &str,
    expected_native_transaction: &aos_ability_model::TransactionId,
) -> Result<()> {
    let generation_record = params
        .profile
        .join(format!("gen-{generation}"))
        .join(ACTIVATION_RECORD);
    let mut record: Value = serde_json::from_slice(
        &std::fs::read(&generation_record)
            .with_context(|| format!("reading {}", generation_record.display()))?,
    )
    .with_context(|| format!("parsing {}", generation_record.display()))?;
    if record.get("schema").and_then(Value::as_str) != Some("aos.config-activation/v1")
        || record.get("generation").and_then(Value::as_u64) != Some(u64::from(generation))
        || record.get("generation_id").and_then(Value::as_str) != Some(expected_generation_id)
        || record.get("transaction_manifest").and_then(Value::as_str)
            != Some(expected_transaction_manifest)
        || record.get("status").and_then(Value::as_str) != Some("native-pending")
        || record
            .get("native_ability_transaction")
            .and_then(Value::as_str)
            != Some(expected_native_transaction.0.as_str())
    {
        bail!("committed activation record differs from the settled native transaction");
    }
    record["status"] = Value::String("native-failed".to_string());
    record["activation_exit"] = Value::from(6);
    write_json_atomic(&generation_record, &record)?;
    write_json_atomic(&params.marker_root.join(ACTIVATION_RECORD), &record)
}

/// Commits a prevalidated structured candidate while its caller owns the switch lock.
///
/// # Errors
///
/// Returns an error under the same conditions as [`activate_config`].
pub(crate) fn commit_structured_config_while_locked(
    params: &ActivateConfigParams,
    manifest: &ConfigManifest,
    transaction: &aos_ability_model::TransactionId,
    prior_generation: Option<u32>,
) -> Result<u32> {
    require_native_transaction_context(manifest, true)?;

    let running_image = params
        .running_image
        .clone()
        .map(Ok)
        .unwrap_or_else(crate::sysroot::running_image_generation)?;
    if manifest.module_abi != params.module_abi || manifest.module_abi != running_image.module_abi {
        bail!(
            "manifest module_abi {} does not match running image ABI {}",
            manifest.module_abi,
            params.module_abi
        );
    }
    verify_manifest_store_paths_realized(manifest)?;

    let manifest_value =
        serde_json::to_value(manifest).context("serializing checked configuration manifest")?;
    let generation_id = crate::canonical_json_digest(&manifest_value)?;
    let drop_record = serde_json::json!({
        "projected": false,
        "source_manifest_hash": generation_id,
        "dropped": [],
    });

    std::fs::create_dir_all(&params.profile)
        .with_context(|| format!("creating {}", params.profile.display()))?;
    let mut state = recover_generation_state_pub(&params.profile)?;
    if manifest.inputs.runtime_modules.is_some() {
        let expected = manifest
            .inputs
            .expected_current_generation
            .context("runtime-module manifest has no expected current generation")?;
        if state.current != expected {
            bail!(
                "stale configuration candidate: evaluated from generation {expected}, but generation {} is current",
                state.current
            );
        }
    }

    let image_parent = running_image.number;
    let existing = state.generations.iter().find(|generation| {
        generation.manifest_hash == generation_id
            && generation.module_abi_pinned == params.module_abi
            && generation.image_gen_parent == image_parent
            && params
                .profile
                .join(format!("gen-{}", generation.number))
                .is_dir()
    });
    let number = match existing {
        Some(generation) => {
            validate_retained_manifest(
                &params.profile.join(format!("gen-{}", generation.number)),
                &generation_id,
            )?;
            generation.number
        }
        None => {
            let number = state.next;
            prepare_generation(
                params,
                &manifest_value,
                &drop_record,
                &generation_id,
                &running_image,
                number,
            )?;
            let record = config_generation_record(
                &running_image,
                number,
                params.module_abi,
                &generation_id,
                manifest,
            )?;
            state.next = number.saturating_add(1);
            state.generations.push(record);
            if params.image_profile.join("state.json").is_file() {
                let images =
                    crate::sysroot::load_image_generation_state_pub(&params.image_profile)?;
                crate::store::reconcile_image_gc_roots(&params.image_profile, &images, &state)?;
            }
            save_generation_state_pub(&params.profile, &state)?;
            number
        }
    };

    let transaction_manifest = crate::canonical_json_digest(&manifest_value)?;
    publish_activation_record(
        params,
        &generation_id,
        &transaction_manifest,
        number,
        transaction,
        prior_generation,
    )?;
    crate::attestation::persist_generation_attestation(
        &params.profile.join(format!("gen-{number}")),
        &generation_id,
        &generation_id,
        manifest,
        &running_image,
        params.require_attestation_quote,
        true,
    )?;
    commit_current_generation_pub(&params.profile, &mut state, number)?;
    publish_runtime_activation_marker(params, number)?;

    Err(ActivationFailure::degraded(format!(
        "configuration generation {number} is committed pending native ability convergence"
    ))
    .into())
}

/// Requires structured manifests to carry an authenticated native transaction context.
///
/// # Errors
///
/// Returns an error when a structured manifest reaches the internal generation
/// commit without the native transaction that authorized it.
pub(crate) fn require_native_transaction_context(
    manifest: &ConfigManifest,
    transaction_present: bool,
) -> Result<()> {
    if manifest.inputs.ability_activation.is_some() && !transaction_present {
        bail!(
            "checked ability activation reached generation commit without its native transaction"
        );
    }
    Ok(())
}

fn publish_activation_record(
    params: &ActivateConfigParams,
    generation_id: &str,
    transaction_manifest: &str,
    generation: u32,
    native_transaction: &aos_ability_model::TransactionId,
    native_prior_generation: Option<u32>,
) -> Result<()> {
    let record = ActivationRecord {
        schema: "aos.config-activation/v1",
        generation,
        generation_id,
        transaction_manifest,
        dropped_packages: Vec::new(),
        status: "native-pending",
        activation_exit: 6,
        native_ability_transaction: Some(native_transaction.0.as_str()),
        native_ability_prior_generation: native_prior_generation,
    };
    let value = serde_json::to_value(record).context("serializing activation record")?;
    let generation_path = params
        .profile
        .join(format!("gen-{generation}"))
        .join(ACTIVATION_RECORD);
    write_json_atomic(&generation_path, &value)?;
    Ok(())
}

fn publish_runtime_activation_marker(params: &ActivateConfigParams, generation: u32) -> Result<()> {
    let generation_path = params
        .profile
        .join(format!("gen-{generation}"))
        .join(ACTIVATION_RECORD);
    let value: Value = serde_json::from_slice(
        &std::fs::read(&generation_path)
            .with_context(|| format!("reading {}", generation_path.display()))?,
    )
    .with_context(|| format!("parsing {}", generation_path.display()))?;
    write_json_atomic(&params.marker_root.join(ACTIVATION_RECORD), &value)
}

fn verify_manifest_store_paths_realized(manifest: &ConfigManifest) -> Result<()> {
    let mut paths: std::collections::BTreeSet<&str> =
        manifest.store_paths.iter().map(String::as_str).collect();
    paths.extend(
        manifest
            .inputs
            .package_modules
            .modules
            .iter()
            .map(|module| module.store_path.as_str()),
    );
    paths.extend([
        manifest.inputs.base_lib.store_path.as_str(),
        manifest.inputs.evaluator.store_path.as_str(),
        manifest.inputs.host_nix.store_path.as_str(),
        manifest.inputs.instance_facts.store_path.as_str(),
    ]);
    for path in paths {
        super::materialize::validate_canonical_store_path(path)?;
        std::fs::metadata(path)
            .with_context(|| format!("required manifest store path {path:?} is not realized"))?;
    }
    Ok(())
}

pub(crate) struct SwitchLockGuard {
    file: File,
}

impl Drop for SwitchLockGuard {
    fn drop(&mut self) {
        // Release the process-wide exclusion independently of descriptor
        // closure. A duplicated descriptor may otherwise retain the flock
        // after this guard leaves scope and reject the next system switch.
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

fn acquire_switch_lock(path: &Path) -> Result<SwitchLockGuard> {
    let parent = path.parent().context("switch lock path has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating switch lock directory {}", parent.display()))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening switch lock {}", path.display()))?;
    flock(&file, FlockOperation::NonBlockingLockExclusive).with_context(|| {
        format!(
            "locking {}; another system switch is active",
            path.display()
        )
    })?;
    Ok(SwitchLockGuard { file })
}

/// Acquires the global system-switch lock for a non-manifest activation path.
///
/// # Errors
///
/// Returns an error when the lock cannot be created or another switch owns it.
pub(crate) fn acquire_switch_lock_pub(path: &Path) -> Result<SwitchLockGuard> {
    acquire_switch_lock(path)
}

fn prepare_generation(
    params: &ActivateConfigParams,
    manifest: &Value,
    drop_record: &Value,
    generation_id: &str,
    running_image: &ImageGeneration,
    number: u32,
) -> Result<()> {
    let dir = params.profile.join(format!("gen-{number}"));
    let staged = params
        .profile
        .join(format!(".gen-{number}.stage.{}", std::process::id()));
    if dir.exists() {
        let retained_id = std::fs::read_to_string(dir.join("generation-id"))
            .with_context(|| format!("reading orphaned generation identity {}", dir.display()))?;
        if retained_id.trim() == generation_id {
            validate_retained_manifest(&dir, generation_id)?;
            return Ok(());
        }
        bail!(
            "configuration generation number collision at {}",
            dir.display()
        );
    }
    if staged.exists() {
        std::fs::remove_dir_all(&staged)
            .with_context(|| format!("removing stale generation stage {}", staged.display()))?;
    }
    std::fs::create_dir_all(&staged).with_context(|| format!("creating {}", staged.display()))?;
    let toplevel = staged.join("toplevel");
    if !toplevel.exists() {
        #[cfg(unix)]
        std::os::unix::fs::symlink(&running_image.toplevel, &toplevel)
            .with_context(|| format!("creating {}", toplevel.display()))?;
    }
    write_json_atomic(&staged.join("manifest.json"), manifest)?;
    write_json_atomic(&staged.join("drop-set.json"), drop_record)?;
    write_bytes_durable(
        &staged.join("generation-id"),
        format!("{generation_id}\n").as_bytes(),
    )?;
    let outputs = manifest_string_array(manifest, "storePaths");
    let mut sources = manifest
        .pointer("/inputs/package_modules/modules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|module| module.get("store_path").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    for pointer in [
        "/inputs/base_lib/store_path",
        "/inputs/evaluator/store_path",
        "/inputs/host_nix/store_path",
        "/inputs/instance_facts/store_path",
        "/inputs/runtime_modules/store_path",
    ] {
        if let Some(source) = manifest
            .pointer(pointer)
            .and_then(Value::as_str)
            .filter(|path| path.starts_with("/nix/store/"))
        {
            sources.push(source.to_string());
        }
    }
    create_config_gc_roots(&staged, &outputs, &sources)?;
    sync_tree_directories(&staged)?;
    std::fs::rename(&staged, &dir)
        .with_context(|| format!("publishing durable generation {}", dir.display()))?;
    sync_directory(&params.profile)
}

fn validate_retained_manifest(generation_dir: &Path, expected_hash: &str) -> Result<()> {
    let path = generation_dir.join("manifest.json");
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading retained manifest {}", path.display()))?;
    let manifest: ConfigManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing retained manifest {}", path.display()))?;
    manifest
        .validate()
        .with_context(|| format!("validating retained manifest {}", path.display()))?;
    let value = serde_json::to_value(&manifest)?;
    let actual = crate::canonical_json_digest(&value)?;
    if actual != expected_hash {
        bail!(
            "retained manifest {} hash mismatch: recorded {expected_hash}, actual {actual}",
            path.display()
        );
    }
    Ok(())
}

fn config_generation_record(
    running_image: &ImageGeneration,
    number: u32,
    module_abi: u32,
    manifest_hash: &str,
    manifest: &ConfigManifest,
) -> Result<ConfigGeneration> {
    Ok(ConfigGeneration {
        number,
        created_at: crate::metadata::now_rfc3339(),
        image_gen_parent: running_image.number,
        module_abi_pinned: module_abi,
        manifest_hash: manifest_hash.to_string(),
        package_modules: manifest.inputs.package_modules.modules.clone(),
        host_nix_ref: manifest.inputs.host_nix.store_path.clone(),
        host_nix_commit: None,
        facts_hash: manifest.inputs.instance_facts.facts_hash.clone(),
        facts_ref: manifest.inputs.instance_facts.store_path.clone(),
        base_lib_ref: manifest.inputs.base_lib.store_path.clone(),
        evaluator_ref: manifest.inputs.evaluator.store_path.clone(),
    })
}

fn manifest_string_array(manifest: &Value, key: &str) -> Vec<String> {
    manifest
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn write_json_atomic(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("JSON output path has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let temp = parent.join(format!(".json.tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes_durable(&temp, &bytes)?;
    std::fs::rename(&temp, path).with_context(|| format!("publishing {}", path.display()))?;
    sync_directory(parent)
}

fn write_bytes_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("opening {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn sync_tree_directories(root: &Path) -> Result<()> {
    for child in ["cfg", "cfgsrc"] {
        let path = root.join(child);
        if path.is_dir() {
            sync_directory(&path)?;
        }
    }
    sync_directory(root)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::types::ConfigGenerationState;

    #[test]
    fn switch_lock_is_rooted_only_by_an_absolute_aos_root() {
        assert_eq!(
            resolve_switch_lock(None, None),
            Path::new(DEFAULT_SWITCH_LOCK)
        );
        assert_eq!(
            resolve_switch_lock(Some(""), None),
            Path::new(DEFAULT_SWITCH_LOCK)
        );
        assert_eq!(
            resolve_switch_lock(Some("/"), None),
            Path::new(DEFAULT_SWITCH_LOCK)
        );
        assert_eq!(
            resolve_switch_lock(Some("relative"), None),
            Path::new(DEFAULT_SWITCH_LOCK)
        );
        assert_eq!(
            resolve_switch_lock(Some("/tmp/aos-root"), None),
            Path::new("/tmp/aos-root/run/apm/switch.lock")
        );
        assert_eq!(
            resolve_switch_lock(Some("/tmp/aos-root"), Some("/tmp/switch.lock")),
            Path::new("/tmp/switch.lock")
        );
        assert_eq!(
            resolve_switch_lock(Some("/tmp/aos-root"), Some("relative.lock")),
            Path::new("/tmp/aos-root/run/apm/switch.lock")
        );
    }

    #[test]
    fn switch_lock_guard_unlocks_before_the_last_descriptor_closes() {
        let root = tempfile::tempdir().unwrap();
        let lock_path = root.path().join("switch.lock");
        let guard = acquire_switch_lock(&lock_path).unwrap();
        let duplicate = guard.file.try_clone().unwrap();

        drop(guard);

        let replacement = acquire_switch_lock(&lock_path).unwrap();
        drop(replacement);
        drop(duplicate);
    }

    #[test]
    fn stored_activation_record_rejects_unknown_fields_and_zero_predecessor() {
        let record = serde_json::json!({
            "schema": "aos.config-activation/v1",
            "generation": 2,
            "generation_id": "sha256:generation",
            "transaction_manifest": "sha256:transaction",
            "dropped_packages": [],
            "status": "native-pending",
            "activation_exit": 6,
            "native_ability_transaction": "sha256:ability-transaction",
            "native_ability_prior_generation": 1,
        });

        let mut extended = record.clone();
        extended
            .as_object_mut()
            .unwrap()
            .insert("compatibility_marker".to_string(), Value::Bool(true));
        serde_json::from_value::<StoredActivationRecord>(extended)
            .expect_err("activation records must reject unknown fields");

        let mut zero_predecessor = record;
        zero_predecessor["native_ability_prior_generation"] = serde_json::json!(0);
        serde_json::from_value::<StoredActivationRecord>(zero_predecessor)
            .expect_err("zero must not encode an absent predecessor");
    }

    fn setup() -> (TempDir, ActivateConfigParams, Value) {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("profile");
        let toplevel = root.path().join("toplevel");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&toplevel).unwrap();
        let current = ConfigGeneration {
            number: 1,
            created_at: "1970-01-01T00:00:00Z".to_string(),
            image_gen_parent: 1,
            module_abi_pinned: 7,
            manifest_hash: "sha256:legacy-fixture".to_string(),
            package_modules: vec![crate::types::PackageModule {
                package: "fixture".to_string(),
                document_digest: format!("sha256:{}", "a".repeat(64)),
                store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-config".to_string(),
                nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                entrypoint: "module.nix".to_string(),
                origin: crate::types::PackageModuleOrigin::Registry,
            }],
            host_nix_ref: "/nix/store/cccccccccccccccccccccccccccccccc-host.nix".to_string(),
            host_nix_commit: None,
            facts_hash: "sha256:fixture".to_string(),
            facts_ref: "/nix/store/ffffffffffffffffffffffffffffffff-facts.json".to_string(),
            base_lib_ref: "/nix/store/dddddddddddddddddddddddddddddddd-base-lib".to_string(),
            evaluator_ref: "/nix/store/gggggggggggggggggggggggggggggggg-evaluator".to_string(),
        };
        let state = ConfigGenerationState {
            current: 1,
            next: 2,
            generations: vec![current],
        };
        save_generation_state_pub(&profile, &state).unwrap();
        std::os::unix::fs::symlink("gen-1", profile.join("current")).unwrap();

        let manifest = json!({
            "schema": "aos.config-manifest/v1",
            "packages": ["firewall", "web"],
            "config": {"firewall": {}, "web": {}},
            "graph": {"edges": {"web": ["firewall"], "firewall": []}},
            "etc": {},
            "jobScripts": {},
            "users": [],
            "storePaths": [
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-runtime",
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-firewall",
                "/nix/store/cccccccccccccccccccccccccccccccc-web"
            ],
            "module_abi": 7,
            "inputs": {
                "base_lib": {
                    "store_path": "/nix/store/dddddddddddddddddddddddddddddddd-base-lib",
                    "abi_hash": format!("sha256:{}", "0".repeat(64)),
                    "module_abi": 7
                },
                "evaluator": {
                    "store_path": "/nix/store/gggggggggggggggggggggggggggggggg-evaluator",
                    "store_hash": format!("sha256:{}", "1".repeat(40))
                },
                "package_modules": {
                    "registry": "test",
                    "release_tag": "1.0.0",
                    "tag_signer_key": "deadbeef",
                    "realization": format!("sha256:{}", "5".repeat(64)),
                    "modules": [{
                        "package": "firewall",
                        "document_digest": format!("sha256:{}", "2".repeat(64)),
                        "store_path": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-config",
                        "nar_hash": format!("sha256:{}", "0".repeat(52)),
                        "entrypoint": "module.nix",
                        "origin": "registry"
                    }]
                },
                "host_nix": {
                    "store_path": "/nix/store/cccccccccccccccccccccccccccccccc-host.nix",
                    "content_hash": format!("sha256:{}", "3".repeat(64)),
                    "trust_mode": "platform",
                    "platform": "test",
                    "signer_key": null
                },
                "instance_facts": {
                    "facts_hash": format!("sha256:{}", "4".repeat(64)),
                    "platform": "test",
                    "store_path": "/nix/store/ffffffffffffffffffffffffffffffff-facts.json"
                }
            },
            "packageOutputs": {
                "firewall": {
                    "version": "1", "platform": "test", "registry": "test",
                    "store_path": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-firewall",
                    "nar_hash": format!("sha256:{}", "0".repeat(52)),
                    "nar_size": 1,
                    "closure": [{
                        "store_path_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "store_path": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-firewall",
                        "realisations": [{"nar_hash": format!("sha256:{}", "0".repeat(52)), "nar_size": 1}]
                    }]
                },
                "web": {
                    "version": "1", "platform": "test", "registry": "test",
                    "store_path": "/nix/store/cccccccccccccccccccccccccccccccc-web",
                    "nar_hash": format!("sha256:{}", "1".repeat(52)),
                    "nar_size": 1,
                    "closure": [{
                        "store_path_hash": "cccccccccccccccccccccccccccccccc",
                        "store_path": "/nix/store/cccccccccccccccccccccccccccccccc-web",
                        "realisations": [{"nar_hash": format!("sha256:{}", "1".repeat(52)), "nar_size": 1}]
                    }]
                }
            },
            "ownership": {
                "etc": {},
                "jobScripts": {},
                "users": {},
                "storePaths": {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-runtime": "@base",
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-firewall": "firewall",
                    "/nix/store/cccccccccccccccccccccccccccccccc-web": "web"
                }
            }
        });
        let manifest_path = root.path().join("manifest.json");
        write_json_atomic(&manifest_path, &manifest).unwrap();
        let params = ActivateConfigParams {
            manifest: manifest_path,
            marker_root: root.path().join("markers"),
            profile,
            module_abi: 7,
            switch_lock: root.path().join("switch.lock"),
            running_image: Some(ImageGeneration {
                number: 1,
                boot_artifact_contract: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-boot-contract"
                    .to_string(),
                boot_provider_state: crate::types::BootProviderState {
                    schema: "aos.test.boot-generation-state/v1".to_string(),
                    evidence: serde_json::json!({}),
                },
                toplevel: toplevel.to_string_lossy().into_owned(),
                package_name: "aos-system".to_string(),
                version: "1".to_string(),
                state_version: "1".into(),
                native_executor_ref: "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-executor".into(),
                registry: "system".to_string(),
                kernel_path: None,
                evaluator_ref: "/nix/store/dddddddddddddddddddddddddddddddd-base-lib".to_string(),
                module_abi: 7,
                base_lib_abi_hash: format!("sha256:{}", "0".repeat(64)),
                created_at: "1970-01-01T00:00:00Z".to_string(),
            }),
            image_profile: root.path().join("image-profile"),
            switch_lock_held: false,
            require_attestation_quote: false,
        };
        (root, params, manifest)
    }
    #[test]
    fn production_activation_requires_a_checked_plan_before_prepare() {
        let (_root, params, _manifest) = setup();
        let error = activate_config(&params).expect_err("fixture has no checked ability plan");
        assert!(
            error
                .to_string()
                .contains("requires a checked ability plan"),
            "{error}"
        );
        assert!(!params.profile.join("gen-2").exists());
    }
}
