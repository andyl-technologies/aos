//! Transactional activation of an evaluated host configuration.
//!
//! This module is the commit half of the on-host configuration pipeline.
//! Evaluation and package rendering are deliberately side-effect free; once the soft
//! fetch/render wing settles, [`activate_config`] re-projects the manifest onto
//! the packages that actually materialized, creates or reuses a
//! content-addressed configuration generation, invokes the image's atomic
//! `activate` script, and only then publishes the generation pointer.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{error::Error, fmt};

use anyhow::{Context, Result, bail};
use rustix::fs::{FlockOperation, flock};
use serde::Serialize;
use serde_json::Value;

use super::materialize::ConfigManifest;
use crate::graph_compile::ConfigGraph;
use crate::graph_compile::reproject::{
    manifest_packages, materialized_subset, merge_staged_projection, reproject_manifest,
};
use crate::store::create_config_gc_roots;
use crate::sysroot::{
    clear_activation_intent_pub, commit_current_generation_pub, recover_generation_state_pub,
    save_generation_state_pub, write_activation_intent_pub,
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
}

/// Inputs consumed by the activation commit.
#[derive(Debug, Clone)]
pub struct ActivateConfigParams {
    /// Evaluator-produced manifest; retained unchanged as the source intent.
    pub manifest: PathBuf,
    /// Evaluator-produced dependency graph. Absence means independent packages.
    pub graph: PathBuf,
    /// Root containing `fetch/` and `render/` completion markers.
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
            graph: PathBuf::from("/run/aos/graph.json"),
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

/// A classified failure from the atomic activation script.
#[derive(Debug)]
pub struct ActivationFailure {
    exit_code: i32,
    message: String,
}

impl ActivationFailure {
    /// Classifies an indeterminate post-swap failure as requiring rescue.
    pub(crate) fn rescue(message: impl Into<String>) -> Self {
        Self {
            exit_code: 4,
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
/// manifest and degraded drop set before invoking `<toplevel>/activate N`.
/// The profile pointer is committed only after activation returns an exit code
/// whose contract says the `/etc` swap stands (`0`, `5`, or `6`).
///
/// # Errors
///
/// Returns an error if inputs are malformed, running image identity cannot be
/// authenticated, generation preparation fails, activation fails before the
/// swap, or publishing the committed pointer fails. Exit code `6` is returned
/// as an error *after* committing because the switch stands but the system is
/// degraded.
pub fn activate_config(params: &ActivateConfigParams) -> Result<u32> {
    activate_config_with(
        params,
        true,
        true,
        true,
        run_activation_with_credential_barrier,
    )
}

const CREDENTIAL_STAGED_VIEW_READY: &str = "AOS_CREDENTIAL_STAGED_VIEW_READY ";
const CREDENTIAL_STAGED_VIEW_CONTINUE: &[u8] = b"AOS_CREDENTIAL_STAGED_VIEW_CONTINUE\n";
const CREDENTIAL_BARRIER_READY: &str = "AOS_CREDENTIAL_BARRIER_READY ";
const CREDENTIAL_BARRIER_CONTINUE: &[u8] = b"AOS_CREDENTIAL_BARRIER_CONTINUE\n";

/// A credential checkpoint emitted by the activation script.
pub(crate) enum CredentialBarrier<'a> {
    /// The fully composed candidate `/etc`, before any live unit is stopped.
    StagedView(&'a Path),
    /// The post-swap daemon plan, immediately before credential publication.
    Publish(&'a Path),
}

/// Runs an activation script and services its credential validation and
/// publication barriers.
///
/// # Errors
///
/// Returns an error if the script cannot be started, barrier communication or
/// credential publication fails, or a successful script omits the barrier.
pub(crate) fn run_activation_with_credential_barrier(
    activate: &Path,
    number: u32,
    nonce: &str,
    barrier: &mut dyn FnMut(CredentialBarrier<'_>) -> Result<()>,
) -> Result<Option<i32>> {
    let mut child = Command::new(activate)
        .arg(number.to_string())
        .env("AOS_SWITCH_LOCK_HELD", "1")
        .env("AOS_ACTIVATION_NONCE", nonce)
        .env("AOS_CREDENTIAL_BARRIER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("running {}", activate.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("activation stdout was not piped")?;
    let mut stdin = child
        .stdin
        .take()
        .context("activation stdin was not piped")?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut validated_staged_view = false;
    let mut crossed_barrier = false;
    loop {
        line.clear();
        let read = match reader.read_line(&mut line) {
            Ok(read) => read,
            Err(error) => {
                drop(stdin);
                drop(reader);
                let _ = child.wait();
                return Err(ActivationFailure {
                    exit_code: 4,
                    message: format!(
                        "activation barrier communication failed: {error}; /etc state is indeterminate and rescue mode is required"
                    ),
                }
                .into());
            }
        };
        if read == 0 {
            break;
        }
        if let Some(candidate) = line.trim_end().strip_prefix(CREDENTIAL_STAGED_VIEW_READY) {
            if validated_staged_view || crossed_barrier || candidate.is_empty() {
                drop(stdin);
                drop(reader);
                let _ = child.wait();
                return Err(ActivationFailure {
                    exit_code: 2,
                    message:
                        "activation emitted an invalid pre-swap credential staged-view barrier"
                            .to_string(),
                }
                .into());
            }
            if let Err(error) = barrier(CredentialBarrier::StagedView(Path::new(candidate))) {
                drop(stdin);
                drop(reader);
                let _ = child.wait();
                return Err(error)
                    .context("validating credentials in the staged configuration view");
            }
            if let Err(error) = stdin
                .write_all(CREDENTIAL_STAGED_VIEW_CONTINUE)
                .and_then(|()| stdin.flush())
            {
                drop(stdin);
                drop(reader);
                let _ = child.wait();
                return Err(error).context("acknowledging credential staged-view validation");
            }
            validated_staged_view = true;
        } else if let Some(plan) = line.trim_end().strip_prefix(CREDENTIAL_BARRIER_READY) {
            if !validated_staged_view || crossed_barrier || plan.is_empty() {
                drop(stdin);
                drop(reader);
                let _ = child.wait();
                return Err(ActivationFailure {
                    exit_code: 4,
                    message: "activation emitted an invalid post-swap credential barrier; rescue mode is required".to_string(),
                }
                .into());
            }
            if let Err(error) = barrier(CredentialBarrier::Publish(Path::new(plan))) {
                drop(stdin);
                drop(reader);
                let _ = child.wait();
                return Err(error).context(
                    "configuration activation swapped /etc but credential publication failed; rescue mode is required",
                );
            }
            if let Err(error) = stdin
                .write_all(CREDENTIAL_BARRIER_CONTINUE)
                .and_then(|()| stdin.flush())
            {
                drop(stdin);
                drop(reader);
                let _ = child.wait();
                return Err(ActivationFailure {
                    exit_code: 4,
                    message: format!(
                        "activation credential acknowledgement failed: {error}; rescue mode is required"
                    ),
                }
                .into());
            }
            crossed_barrier = true;
        } else {
            if let Err(error) = std::io::stdout().write_all(line.as_bytes()) {
                drop(stdin);
                drop(reader);
                let _ = child.wait();
                return Err(ActivationFailure {
                    exit_code: 4,
                    message: format!(
                        "forwarding activation output failed: {error}; /etc state is indeterminate and rescue mode is required"
                    ),
                }
                .into());
            }
        }
    }
    drop(stdin);
    let status = child.wait().map_err(|error| ActivationFailure {
        exit_code: 4,
        message: format!(
            "waiting for activation after barrier communication failed: {error}; rescue mode is required"
        ),
    })?;
    if matches!(status.code(), Some(0 | 5 | 6)) && (!validated_staged_view || !crossed_barrier) {
        return Err(ActivationFailure {
            exit_code: 4,
            message: "activation succeeded without crossing the credential publication barrier; rescue mode is required".to_string(),
        }
        .into());
    }
    Ok(status.code())
}

fn activate_config_with<F>(
    params: &ActivateConfigParams,
    verify_realized_paths: bool,
    resolve_credentials: bool,
    detect_tpm: bool,
    run_activate: F,
) -> Result<u32>
where
    F: FnOnce(
        &Path,
        u32,
        &str,
        &mut dyn FnMut(CredentialBarrier<'_>) -> Result<()>,
    ) -> Result<Option<i32>>,
{
    activate_config_with_reconciliation(
        params,
        verify_realized_paths,
        resolve_credentials,
        detect_tpm,
        run_activate,
        |reconciliation, plan| {
            reconciliation
                .publish_with(|units| {
                    if units.is_empty() {
                        Ok(())
                    } else {
                        crate::sysroot::augment_reconcile_plan_with_credential_units(plan, units)
                    }
                })
                .map(|_| ())
        },
    )
}

fn activate_config_with_reconciliation<F, G>(
    params: &ActivateConfigParams,
    verify_realized_paths: bool,
    resolve_credentials: bool,
    detect_tpm: bool,
    run_activate: F,
    apply_credentials: G,
) -> Result<u32>
where
    F: FnOnce(
        &Path,
        u32,
        &str,
        &mut dyn FnMut(CredentialBarrier<'_>) -> Result<()>,
    ) -> Result<Option<i32>>,
    G: FnOnce(crate::credential_artifact::CredentialReconciliation, &Path) -> Result<()>,
{
    let _switch_lock = if params.switch_lock_held {
        None
    } else {
        Some(HeldSwitchLock(acquire_switch_lock(&params.switch_lock)?))
    };
    let running_image = params
        .running_image
        .clone()
        .map(Ok)
        .unwrap_or_else(crate::sysroot::running_image_generation)?;
    let manifest_text = std::fs::read_to_string(&params.manifest)
        .with_context(|| format!("reading {}", params.manifest.display()))?;
    let manifest: ConfigManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("parsing {}", params.manifest.display()))?;
    manifest
        .validate()
        .with_context(|| format!("validating {}", params.manifest.display()))?;
    if manifest.module_abi != params.module_abi || manifest.module_abi != running_image.module_abi {
        bail!(
            "manifest module_abi {} does not match running image ABI {}",
            manifest.module_abi,
            params.module_abi
        );
    }
    let graph = if params.graph.exists() {
        read_graph(&params.graph)?
    } else {
        ConfigGraph {
            edges: manifest.graph.edges.clone(),
        }
    };
    if graph.edges != manifest.graph.edges {
        bail!(
            "{} disagrees with the dependency graph embedded in {}",
            params.graph.display(),
            params.manifest.display()
        );
    }
    let full = serde_json::to_value(&manifest).context("serializing validated config manifest")?;
    let packages = manifest_packages(&full);
    let (fetched, rendered) = materialized_subset(&packages, &params.marker_root);
    let mut projection = reproject_manifest(&full, &graph, &fetched, &rendered)?;
    merge_staged_projection(
        &manifest,
        &params.marker_root.join("staging"),
        &mut projection,
    )?;
    if verify_realized_paths {
        // A soft-failed package is deliberately absent from the local store.
        // Requiring every path from the source intent here would turn the
        // package wing's bounded fetch failure into a hard activation failure
        // and make degraded re-projection impossible. The source manifest was
        // structurally validated above; realization is required only for the
        // dependency-closed manifest that will actually be committed.
        let projected: ConfigManifest = serde_json::from_value(projection.manifest.clone())
            .context("parsing projected manifest for realized-path verification")?;
        verify_manifest_store_paths_realized(&projected)?;
    }
    let credential_reconciliation = if resolve_credentials {
        let projected: ConfigManifest = serde_json::from_value(projection.manifest.clone())
            .context("parsing staged credential projection")?;
        let config = crate::config::ApmConfig::load(ProfileScope::System)
            .context("loading system credential encryption settings")?;
        crate::credential_artifact::reconcile_secret_refs(
            &config.settings,
            &crate::credential_artifact::aos_root_path(),
            &projected.credentials,
        )
        .context("resolving configuration credential references")?
    } else {
        crate::credential_artifact::CredentialReconciliation::default()
    };

    // Keep the evaluator output immutable. The exact projection consumed by
    // the activation script lives in gen-N/manifest.json, so an activation
    // failure cannot alter either the source intent or the active generation.
    if projection.projected {
        let source = params.marker_root.join("source-manifest.json");
        write_json_atomic(&source, &full)?;
    }

    std::fs::create_dir_all(&params.profile)
        .with_context(|| format!("creating {}", params.profile.display()))?;
    let mut state = recover_generation_state_pub(&params.profile)?;
    let image_parent = running_image.number;

    let existing = state.generations.iter().find(|generation| {
        generation.manifest_hash == projection.generation_id
            && generation.module_abi_pinned == params.module_abi
            && generation.image_gen_parent == image_parent
            && params
                .profile
                .join(format!("gen-{}", generation.number))
                .is_dir()
    });
    let (number, newly_prepared) = match existing {
        Some(generation) => {
            validate_retained_manifest(
                &params.profile.join(format!("gen-{}", generation.number)),
                &projection.generation_id,
            )?;
            (generation.number, false)
        }
        None => {
            let number = state.next;
            prepare_generation(
                params,
                &projection.manifest,
                &projection.drop_record(),
                &projection.generation_id,
                &running_image,
                number,
            )?;
            let record = config_generation_record(
                &running_image,
                number,
                params.module_abi,
                &projection.generation_id,
                &projection.manifest,
            )?;
            state.next = number.saturating_add(1);
            state.generations.push(record);
            if params.image_profile.join("state.json").is_file() {
                let images =
                    crate::sysroot::load_image_generation_state_pub(&params.image_profile)?;
                crate::store::reconcile_baselib_gc_roots(&params.image_profile, &images, &state)?;
            }
            // Make the prepared generation discoverable for crash recovery;
            // `current` remains unchanged until the swap succeeds.
            save_generation_state_pub(&params.profile, &state)?;
            (number, true)
        }
    };

    let activate = Path::new(&running_image.toplevel).join("activate");
    let nonce = write_activation_intent_pub(&params.profile, &state, number)?;
    let mut credential_reconciliation = Some(credential_reconciliation);
    let mut apply_credentials = Some(apply_credentials);
    let mut barrier = |event: CredentialBarrier<'_>| match event {
        CredentialBarrier::StagedView(candidate_etc) => credential_reconciliation
            .as_mut()
            .context("activation validated credentials after publication")?
            .validate_staged_view(candidate_etc),
        CredentialBarrier::Publish(plan) => {
            let reconciliation = credential_reconciliation
                .take()
                .context("activation crossed the credential publication barrier more than once")?;
            let apply = apply_credentials
                .take()
                .context("activation crossed the credential publication barrier more than once")?;
            apply(reconciliation, plan).map_err(|error| {
                ActivationFailure {
                    exit_code: 4,
                    message: format!(
                        "configuration activation swapped /etc but credential publication failed: {error:#}; rescue mode is required"
                    ),
                }
                .into()
            })
        }
    };
    let status = run_activate(&activate, number, &nonce, &mut barrier)?;

    match status {
        Some(activation_exit @ (0 | 5 | 6)) => {
            let generation_dir = params.profile.join(format!("gen-{number}"));
            crate::attestation::persist_generation_attestation(
                &generation_dir,
                &projection.generation_id,
                &projection.generation_id,
                &serde_json::from_value(projection.manifest.clone())
                    .context("parsing projected manifest for generation attestation")?,
                &running_image,
                params.require_attestation_quote,
                detect_tpm,
            )
            .map_err(|error| ActivationFailure {
                exit_code: 4,
                message: format!(
                    "configuration activation swapped /etc but generation attestation failed: {error:#}; rescue mode is required"
                ),
            })?;
            if credential_reconciliation.is_some() {
                return Err(ActivationFailure {
                    exit_code: 4,
                    message: "configuration activation crossed /etc swap without credential publication; rescue mode is required".to_string(),
                }
                .into());
            }
            commit_current_generation_pub(&params.profile, &mut state, number).map_err(|error| {
                ActivationFailure {
                    exit_code: 4,
                    message: format!(
                        "configuration activation swapped /etc but publishing the current generation failed: {error:#}; rescue mode is required"
                    ),
                }
            })?;
            let recorded_exit = if projection.projected {
                6
            } else {
                activation_exit
            };
            publish_activation_record(params, &projection, number, recorded_exit).map_err(
                |error| ActivationFailure {
                    exit_code: 4,
                    message: format!(
                        "configuration activation committed generation {number} but its activation record failed: {error:#}; rescue mode is required"
                    ),
                },
            )?;
            if recorded_exit == 6 {
                return Err(ActivationFailure {
                    exit_code: 6,
                    message: format!(
                        "configuration generation {number} was committed in degraded state"
                    ),
                }
                .into());
            }
            Ok(number)
        }
        Some(code @ 1..=3) => {
            clear_activation_intent_pub(&params.profile)?;
            if newly_prepared {
                // Preserve state for diagnosis, but never publish the pointer;
                // the activation contract guarantees the old `/etc` is live.
                eprintln!(
                    "config activation: prepared gen-{number} retained after pre-commit failure"
                );
            }
            Err(ActivationFailure {
                exit_code: code,
                message: format!(
                    "configuration activation failed before commit (exit {code}); the previous generation remains current"
                ),
            }
            .into())
        }
        Some(4) | None => Err(ActivationFailure {
            exit_code: 4,
            message: format!(
                "configuration activation stopped with an indeterminate /etc swap (exit {status:?}); rescue mode is required"
            ),
        }
        .into()),
        Some(code) => {
            bail!("configuration activation returned unsupported exit code {code}")
        }
    }
}

fn publish_activation_record(
    params: &ActivateConfigParams,
    projection: &crate::graph_compile::reproject::Reprojection,
    generation: u32,
    activation_exit: i32,
) -> Result<()> {
    let transaction = crate::graph_compile::read_transaction(&params.marker_root)?
        .context("graph transaction state disappeared before activation commit")?;
    let record = ActivationRecord {
        schema: "aos.config-activation/v1",
        generation,
        generation_id: &projection.generation_id,
        transaction_manifest: &transaction.manifest,
        dropped_packages: projection
            .dropped
            .iter()
            .map(|record| record.package.as_str())
            .collect(),
        status: if activation_exit == 6 || projection.projected {
            "degraded"
        } else {
            "complete"
        },
        activation_exit,
    };
    let value = serde_json::to_value(record).context("serializing activation record")?;
    let generation_path = params
        .profile
        .join(format!("gen-{generation}"))
        .join(ACTIVATION_RECORD);
    write_json_atomic(&generation_path, &value)?;
    write_json_atomic(&params.marker_root.join(ACTIVATION_RECORD), &value)
}

fn verify_manifest_store_paths_realized(manifest: &ConfigManifest) -> Result<()> {
    let mut paths: std::collections::BTreeSet<&str> =
        manifest.store_paths.iter().map(String::as_str).collect();
    paths.extend(
        manifest
            .inputs
            .config_modules
            .store_paths
            .iter()
            .map(String::as_str),
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

fn acquire_switch_lock(path: &Path) -> Result<File> {
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
    Ok(file)
}

/// Releases a switch lock explicitly before closing its descriptor.
///
/// An explicit unlock makes the activation boundary independent of descriptor
/// close timing, which is required when a long-lived process performs a later
/// activation against the same lock path.
struct HeldSwitchLock(File);

impl Drop for HeldSwitchLock {
    fn drop(&mut self) {
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}

/// Acquires the global system-switch lock for a non-manifest activation path.
///
/// # Errors
///
/// Returns an error when the lock cannot be created or another switch owns it.
pub(crate) fn acquire_switch_lock_pub(path: &Path) -> Result<File> {
    acquire_switch_lock(path)
}

fn read_graph(path: &Path) -> Result<ConfigGraph> {
    if !path.exists() {
        return Ok(ConfigGraph::default());
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    ConfigGraph::from_json(&text)
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
    if has_authoritative_host_network(manifest) {
        write_bytes_durable(&staged.join("host-network-authoritative"), b"\n")?;
    }

    let outputs = manifest_string_array(manifest, "storePaths");
    let mut sources = nested_string_array(manifest, &["inputs", "config_modules", "store_paths"]);
    for pointer in [
        "/inputs/base_lib/store_path",
        "/inputs/evaluator/store_path",
        "/inputs/host_nix/store_path",
        "/inputs/instance_facts/store_path",
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

fn has_authoritative_host_network(manifest: &Value) -> bool {
    manifest
        .pointer("/ownership/etc")
        .and_then(Value::as_object)
        .is_some_and(|owners| {
            owners.iter().any(|(path, owner)| {
                path.starts_with("systemd/network/")
                    && path.ends_with(".network")
                    && owner.as_str() == Some("@host")
            })
        })
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
    let actual = crate::graph_compile::reproject::hash_cjson(&value);
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
    manifest: &Value,
) -> Result<ConfigGeneration> {
    let host_nix_ref = manifest
        .pointer("/inputs/host_nix/store_path")
        .and_then(Value::as_str)
        .context("manifest has no host_nix store path")?
        .to_string();
    let facts_hash = manifest
        .pointer("/inputs/instance_facts/facts_hash")
        .and_then(Value::as_str)
        .context("manifest has no instance facts hash")?
        .to_string();
    let config_module_paths =
        nested_string_array(manifest, &["inputs", "config_modules", "store_paths"]);
    let config_module_packages =
        nested_string_array(manifest, &["inputs", "config_modules", "package_names"]);
    let config_module_closure = config_module_paths
        .first()
        .cloned()
        .or_else(|| {
            manifest
                .pointer("/inputs/config_modules/closure_hash")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .context("manifest has no config module source-closure identity")?;
    Ok(ConfigGeneration {
        number,
        created_at: crate::metadata::now_rfc3339(),
        image_gen_parent: running_image.number,
        module_abi_pinned: module_abi,
        manifest_hash: manifest_hash.to_string(),
        config_module_closure,
        config_module_paths,
        config_module_packages,
        host_nix_ref,
        host_nix_commit: None,
        facts_hash,
        facts_ref: manifest
            .pointer("/inputs/instance_facts/store_path")
            .and_then(Value::as_str)
            .context("manifest has no instance facts store path")?
            .to_string(),
        base_lib_ref: manifest
            .pointer("/inputs/base_lib/store_path")
            .and_then(Value::as_str)
            .context("manifest has no base-lib store path")?
            .to_string(),
        evaluator_ref: manifest
            .pointer("/inputs/evaluator/store_path")
            .and_then(Value::as_str)
            .context("manifest has no evaluator store path")?
            .to_string(),
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

fn nested_string_array(manifest: &Value, keys: &[&str]) -> Vec<String> {
    let mut value = manifest;
    for key in keys {
        let Some(next) = value.get(*key) else {
            return Vec::new();
        };
        value = next;
    }
    value
        .as_array()
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
    use crate::graph_compile::reproject::hash_cjson;
    use crate::sysroot::load_generation_state_pub;
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

    fn setup() -> (TempDir, ActivateConfigParams, Value) {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("profile");
        let toplevel = root.path().join("toplevel");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&toplevel).unwrap();
        std::fs::write(toplevel.join("activate"), b"test").unwrap();
        let current = ConfigGeneration {
            number: 1,
            created_at: "1970-01-01T00:00:00Z".to_string(),
            image_gen_parent: 1,
            module_abi_pinned: 7,
            manifest_hash: "sha256:legacy-fixture".to_string(),
            config_module_closure: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-config".to_string(),
            config_module_paths: vec![
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-config".to_string(),
            ],
            config_module_packages: vec!["fixture".to_string()],
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
            "credentials": {"firewall": {}, "web": {}},
            "graph": {"edges": {"web": ["firewall"], "firewall": []}},
            "etc": {},
            "jobScripts": {},
            "units": {},
            "users": [],
            "presets": [],
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
                "config_modules": {
                    "registry": "test",
                    "release_tag": "1.0.0",
                    "tag_signer_key": "deadbeef",
                    "realization": format!("sha256:{}", "5".repeat(64)),
                    "closure_hash": "sha256:9ab0c293d36b82b855c56917504b69670de56367c26d3bb7529a82b227bd1135",
                    "count": 1,
                    "store_paths": ["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-config"],
                    "nar_hashes": [format!("sha256:{}", "0".repeat(52))],
                    "package_names": ["firewall"],
                    "module_abi_compat": [{"min": 1, "max": 10}],
                    "authorizations": [{"owns": [], "contributes": {}}]
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
                    "closure": [{
                        "store_path_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "store_path": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-firewall",
                        "realisations": [{"nar_hash": "sha256:firewall", "nar_size": 1}]
                    }]
                },
                "web": {
                    "version": "1", "platform": "test", "registry": "test",
                    "store_path": "/nix/store/cccccccccccccccccccccccccccccccc-web",
                    "closure": [{
                        "store_path_hash": "cccccccccccccccccccccccccccccccc",
                        "store_path": "/nix/store/cccccccccccccccccccccccccccccccc-web",
                        "realisations": [{"nar_hash": "sha256:web", "nar_size": 1}]
                    }]
                }
            },
            "ownership": {
                "etc": {},
                "units": {},
                "jobScripts": {},
                "users": {},
                "presets": {},
                "storePaths": {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-runtime": "@base",
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-firewall": "firewall",
                    "/nix/store/cccccccccccccccccccccccccccccccc-web": "web"
                }
            }
        });
        let manifest_path = root.path().join("manifest.json");
        write_json_atomic(&manifest_path, &manifest).unwrap();
        write_json_atomic(
            &root.path().join("graph.json"),
            &json!({"edges": {"web": ["firewall"], "firewall": []}}),
        )
        .unwrap();
        let params = ActivateConfigParams {
            manifest: manifest_path,
            graph: root.path().join("graph.json"),
            marker_root: root.path().join("markers"),
            profile,
            module_abi: 7,
            switch_lock: root.path().join("switch.lock"),
            running_image: Some(ImageGeneration {
                number: 1,
                slot: crate::types::ImageSlot::A,
                uki_path: "EFI/Linux/aos-test+3.efi".to_string(),
                uki_source_path: None,
                toplevel: toplevel.to_string_lossy().into_owned(),
                package_name: "aos-system".to_string(),
                version: "1".to_string(),
                registry: "system".to_string(),
                kernel_path: None,
                evaluator_ref: "/nix/store/dddddddddddddddddddddddddddddddd-base-lib".to_string(),
                module_abi: 7,
                baselib_digest: format!("sha256:{}", "0".repeat(64)),
                root_verity_roothash: None,
                expected_pcr11: None,
                initrd_pcr11: None,
                recovery: None,
                created_at: "1970-01-01T00:00:00Z".to_string(),
            }),
            image_profile: root.path().join("image-profile"),
            switch_lock_held: false,
            require_attestation_quote: false,
        };
        (root, params, manifest)
    }

    fn mark(params: &ActivateConfigParams, package: &str) {
        let manifest: ConfigManifest =
            serde_json::from_slice(&std::fs::read(&params.manifest).unwrap()).unwrap();
        let mut transaction = crate::graph_compile::graph_transaction(&manifest).unwrap();
        transaction.completed = true;
        std::fs::create_dir_all(&params.marker_root).unwrap();
        std::fs::write(
            crate::graph_compile::transaction_state_path(&params.marker_root),
            serde_json::to_vec(&transaction).unwrap(),
        )
        .unwrap();
        let pin = transaction.packages.get(package).unwrap();
        let marker = format!("{} {pin}\n", transaction.manifest);
        for wing in ["fetch", "render"] {
            let dir = params.marker_root.join(wing);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{package}.ok")), &marker).unwrap();
        }
        let stage_dir = crate::graph_compile::subverbs::staging_package_dir(
            &params.marker_root.join("staging"),
            &manifest,
            package,
        )
        .unwrap();
        let stage = json!({
            "schema": "aos.render-stage/v1",
            "manifest": transaction.manifest,
            "package_pin": pin,
            "package": package,
            "artifacts": [],
            "units": {},
            "credentials": manifest
                .credentials
                .get(package)
                .cloned()
                .unwrap_or(Value::Null),
        });
        crate::config_eval::materialize::write_bytes_beneath(
            &stage_dir,
            "stage.json",
            &serde_json::to_vec(&stage).unwrap(),
            "0600",
        )
        .unwrap();
    }

    #[test]
    fn only_authoritative_host_network_ownership_retires_metadata_seed() {
        let host = json!({
            "ownership": {
                "etc": {"systemd/network/20-host.network": "@host"}
            }
        });
        assert!(has_authoritative_host_network(&host));

        for owner in ["@base", "firewall", "@host-forged"] {
            let manifest = json!({
                "ownership": {
                    "etc": {"systemd/network/20-package.network": owner}
                }
            });
            assert!(
                !has_authoritative_host_network(&manifest),
                "owner {owner:?} must not retire the metadata network seed"
            );
        }
    }

    #[test]
    fn host_ownership_outside_networkd_does_not_retire_metadata_seed() {
        for path in [
            "network/20-host.network",
            "systemd/network/20-host.netdev",
            "systemd/networking/20-host.network",
        ] {
            let mut manifest = json!({"ownership": {"etc": {}}});
            manifest
                .pointer_mut("/ownership/etc")
                .and_then(Value::as_object_mut)
                .unwrap()
                .insert(path.to_string(), json!("@host"));
            assert!(
                !has_authoritative_host_network(&manifest),
                "path {path:?} is not an authoritative networkd network file"
            );
        }
    }

    #[test]
    fn production_activation_rejects_unrealized_pinned_paths_before_prepare() {
        let (_root, params, _manifest) = setup();
        let error = activate_config(&params).expect_err("fixture store paths are not realized");
        assert!(
            error.to_string().contains("required manifest store path"),
            "{error}"
        );
        assert!(!params.profile.join("gen-2").exists());
    }

    #[test]
    fn successful_activation_commits_exact_generation() {
        let (_root, params, manifest) = setup();
        mark(&params, "firewall");
        mark(&params, "web");

        let number = activate_config_with(
            &params,
            false,
            false,
            false,
            |activate, number, _nonce, barrier| {
                assert!(activate.ends_with("activate"));
                assert_eq!(number, 2);
                barrier(CredentialBarrier::StagedView(Path::new("/unused")))?;
                barrier(CredentialBarrier::Publish(Path::new("/unused")))?;
                Ok(Some(0))
            },
        )
        .unwrap();

        assert_eq!(number, 2);
        let state = load_generation_state_pub(&params.profile).unwrap();
        assert_eq!(state.current, 2);
        let expected_hash = hash_cjson(&manifest);
        assert_eq!(state.generations[1].manifest_hash, expected_hash);
        assert_eq!(
            state.generations[1].config_module_paths,
            vec!["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-config".to_string()]
        );
        assert_eq!(
            state.generations[1].facts_ref,
            "/nix/store/ffffffffffffffffffffffffffffffff-facts.json"
        );
        assert_eq!(
            std::fs::read_link(params.profile.join("current")).unwrap(),
            PathBuf::from("gen-2")
        );
        assert_eq!(
            serde_json::from_str::<Value>(
                &std::fs::read_to_string(params.profile.join("gen-2/manifest.json")).unwrap()
            )
            .unwrap(),
            manifest
        );
        let activation: Value = serde_json::from_slice(
            &std::fs::read(params.profile.join("gen-2/activation.json")).unwrap(),
        )
        .unwrap();
        let runtime_activation: Value = serde_json::from_slice(
            &std::fs::read(params.marker_root.join("activation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(activation, runtime_activation);
        assert_eq!(activation["schema"], "aos.config-activation/v1");
        assert_eq!(activation["generation"], 2);
        let attestation: Value = serde_json::from_slice(
            &std::fs::read(params.profile.join("gen-2/gen-attestation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(attestation["schema"], "aos.gen-attestation/v1");
        assert_eq!(attestation["generation_id"], expected_hash);
        assert_eq!(attestation["manifest_hash"], expected_hash);
        assert_eq!(attestation["quote_status"], "unquoted-tpm-unavailable");
        for field in ["registry", "release_tag", "tag_signer_key", "realization"] {
            assert_eq!(
                attestation["inputs"]["config_modules"][field],
                manifest["inputs"]["config_modules"][field],
                "config-module release field {field} must survive manifest-to-attestation projection"
            );
        }
        assert_eq!(
            attestation["inputs"]["host_nix"]["content_hash"],
            manifest["inputs"]["host_nix"]["content_hash"]
        );
        assert_eq!(
            attestation["inputs"]["instance_facts"]["facts_hash"],
            manifest["inputs"]["instance_facts"]["facts_hash"]
        );
        assert_eq!(activation["generation_id"], expected_hash);
        assert_eq!(activation["status"], "complete");
        assert_eq!(activation["activation_exit"], 0);
        assert_eq!(activation["dropped_packages"], json!([]));
        let rooted = std::fs::read_dir(params.profile.join("gen-2/cfgsrc"))
            .unwrap()
            .map(|entry| std::fs::read_link(entry.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        for input in [
            "/nix/store/dddddddddddddddddddddddddddddddd-base-lib",
            "/nix/store/gggggggggggggggggggggggggggggggg-evaluator",
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-config",
            "/nix/store/cccccccccccccccccccccccccccccccc-host.nix",
            "/nix/store/ffffffffffffffffffffffffffffffff-facts.json",
        ] {
            assert!(
                rooted.contains(&PathBuf::from(input)),
                "missing GC root for {input}"
            );
        }
    }

    #[test]
    fn credential_reconciliation_failure_refuses_pointer_and_proof() {
        let (_root, params, _manifest) = setup();
        mark(&params, "firewall");
        mark(&params, "web");

        let error = activate_config_with_reconciliation(
            &params,
            false,
            false,
            false,
            |_activate, number, _nonce, barrier| {
                assert_eq!(number, 2);
                barrier(CredentialBarrier::StagedView(Path::new("/unused")))?;
                barrier(CredentialBarrier::Publish(Path::new("/unused")))?;
                Ok(Some(0))
            },
            |_reconciliation, _plan| bail!("injected credential publication failure"),
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("credential publication failed"),
            "{error:#}"
        );
        assert_eq!(
            error
                .downcast_ref::<ActivationFailure>()
                .expect("credential failure is classified post-swap")
                .exit_code(),
            4
        );
        assert_eq!(
            load_generation_state_pub(&params.profile).unwrap().current,
            1
        );
        assert!(!params.marker_root.join(ACTIVATION_RECORD).exists());
    }

    #[test]
    fn required_quote_fails_closed_before_pointer_publication_without_tpm() {
        let (_root, mut params, _manifest) = setup();
        params.require_attestation_quote = true;
        mark(&params, "firewall");
        mark(&params, "web");

        let error = activate_config_with(
            &params,
            false,
            false,
            false,
            |_activate, _number, _nonce, barrier| {
                barrier(CredentialBarrier::StagedView(Path::new("/unused")))?;
                barrier(CredentialBarrier::Publish(Path::new("/unused")))?;
                Ok(Some(0))
            },
        )
        .expect_err("measured activation must require TPM evidence");
        let failure = error
            .downcast_ref::<ActivationFailure>()
            .expect("classified activation failure");
        assert_eq!(failure.exit_code(), 4);
        assert_eq!(
            load_generation_state_pub(&params.profile).unwrap().current,
            1
        );
        assert!(!params.profile.join("gen-2/gen-attestation.json").exists());
    }

    #[test]
    fn identical_manifest_is_not_reused_across_image_parents() {
        let (_root, mut params, _manifest) = setup();
        mark(&params, "firewall");
        mark(&params, "web");
        assert_eq!(
            activate_config_with(
                &params,
                false,
                false,
                false,
                |_activate, _number, _nonce, barrier| {
                    barrier(CredentialBarrier::StagedView(Path::new("/unused")))?;
                    barrier(CredentialBarrier::Publish(Path::new("/unused")))?;
                    Ok(Some(0))
                }
            )
            .unwrap(),
            2
        );

        let mut state = load_generation_state_pub(&params.profile).unwrap();
        let mut next_image = state.generations[1].clone();
        next_image.number = 3;
        next_image.image_gen_parent = 3;
        next_image.manifest_hash = "sha256:not-the-current-manifest".to_string();
        std::fs::create_dir_all(params.profile.join("gen-3")).unwrap();
        state.next = 4;
        state.generations.push(next_image);
        save_generation_state_pub(&params.profile, &state).unwrap();
        commit_current_generation_pub(&params.profile, &mut state, 3).unwrap();
        params
            .running_image
            .as_mut()
            .expect("test running image")
            .number = 3;

        assert_eq!(
            activate_config_with(
                &params,
                false,
                false,
                false,
                |_activate, number, _nonce, barrier| {
                    assert_eq!(number, 4);
                    barrier(CredentialBarrier::StagedView(Path::new("/unused")))?;
                    barrier(CredentialBarrier::Publish(Path::new("/unused")))?;
                    Ok(Some(0))
                }
            )
            .unwrap(),
            4
        );
        let state = load_generation_state_pub(&params.profile).unwrap();
        assert_eq!(state.current, 4);
        assert_eq!(state.generations[3].image_gen_parent, 3);
    }

    #[test]
    fn identical_manifest_refuses_tampered_retained_generation() {
        let (_root, params, _manifest) = setup();
        mark(&params, "firewall");
        mark(&params, "web");
        assert_eq!(
            activate_config_with(
                &params,
                false,
                false,
                false,
                |_activate, _number, _nonce, barrier| {
                    barrier(CredentialBarrier::StagedView(Path::new("/unused")))?;
                    barrier(CredentialBarrier::Publish(Path::new("/unused")))?;
                    Ok(Some(0))
                }
            )
            .unwrap(),
            2
        );

        let retained = params.profile.join("gen-2/manifest.json");
        let mut tampered: Value =
            serde_json::from_slice(&std::fs::read(&retained).unwrap()).unwrap();
        tampered["config"]["web"]["tampered"] = json!(true);
        write_json_atomic(&retained, &tampered).unwrap();

        let error = activate_config_with(
            &params,
            false,
            false,
            false,
            |_activate, _number, _nonce, _barrier| {
                panic!("tampered generation must be rejected before activation")
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("hash mismatch"));
    }

    #[test]
    fn preswap_failure_never_changes_current_or_source_manifest() {
        let (_root, params, manifest) = setup();
        mark(&params, "firewall");
        mark(&params, "web");

        let error = activate_config_with(
            &params,
            false,
            false,
            false,
            |_activate, _number, _nonce, _barrier| Ok(Some(2)),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("previous generation remains current")
        );
        let state = load_generation_state_pub(&params.profile).unwrap();
        assert_eq!(state.current, 1);
        assert_eq!(
            std::fs::read_link(params.profile.join("current")).unwrap(),
            PathBuf::from("gen-1")
        );
        assert_eq!(
            serde_json::from_str::<Value>(&std::fs::read_to_string(&params.manifest).unwrap())
                .unwrap(),
            manifest
        );
    }

    #[test]
    fn orphaned_durable_generation_is_reused_after_prepublication_crash() {
        let (_root, params, _manifest) = setup();
        mark(&params, "firewall");
        mark(&params, "web");
        activate_config_with(
            &params,
            false,
            false,
            false,
            |_activate, _number, _nonce, _barrier| Ok(Some(2)),
        )
        .unwrap_err();

        let mut state = load_generation_state_pub(&params.profile).unwrap();
        state
            .generations
            .retain(|generation| generation.number != 2);
        state.next = 2;
        save_generation_state_pub(&params.profile, &state).unwrap();

        assert_eq!(
            activate_config_with(
                &params,
                false,
                false,
                false,
                |_activate, number, _nonce, barrier| {
                    assert_eq!(number, 2);
                    barrier(CredentialBarrier::StagedView(Path::new("/unused")))?;
                    barrier(CredentialBarrier::Publish(Path::new("/unused")))?;
                    Ok(Some(0))
                }
            )
            .unwrap(),
            2
        );
        let recovered = load_generation_state_pub(&params.profile).unwrap();
        assert_eq!(recovered.current, 2);
        assert_eq!(
            recovered
                .generations
                .iter()
                .filter(|generation| generation.number == 2)
                .count(),
            1
        );
    }

    #[test]
    fn degraded_activation_commits_dependency_closed_projection() {
        let (_root, params, manifest) = setup();
        mark(&params, "web");

        let number = activate_config_with(
            &params,
            false,
            false,
            false,
            // The /etc reconcile itself is healthy. The missing package
            // markers alone must classify the committed projection as
            // degraded and surface exit 6.
            |_activate, _number, _nonce, barrier| {
                barrier(CredentialBarrier::StagedView(Path::new("/unused")))?;
                barrier(CredentialBarrier::Publish(Path::new("/unused")))?;
                Ok(Some(0))
            },
        )
        .unwrap_err();
        assert!(number.to_string().contains("was committed"));
        let state = load_generation_state_pub(&params.profile).unwrap();
        assert_eq!(state.current, 2);
        let projected: Value = serde_json::from_str(
            &std::fs::read_to_string(params.profile.join("gen-2/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(projected["packages"], json!([]));
        assert_eq!(
            serde_json::from_str::<Value>(&std::fs::read_to_string(&params.manifest).unwrap())
                .unwrap(),
            manifest
        );
        let drops: Value = serde_json::from_str(
            &std::fs::read_to_string(params.profile.join("gen-2/drop-set.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(drops["projected"], true);
        assert_eq!(drops["dropped"].as_array().unwrap().len(), 2);
        let activation: Value = serde_json::from_slice(
            &std::fs::read(params.marker_root.join("activation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(activation["status"], "degraded");
        assert_eq!(activation["activation_exit"], 6);
        assert_eq!(activation["dropped_packages"], json!(["firewall", "web"]));
    }
}
