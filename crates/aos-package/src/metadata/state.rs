//! Durable provisioning evidence and last-known-good host input.
//!
//! The initrd stash is intentionally volatile. After `/var` is mounted,
//! stage 2 copies the validated storage plan and authorization evidence into:
//!
//! ```text
//! /var/lib/aos-provisioning/
//! ├── audit.json
//! ├── initial-plan.json
//! ├── desired/
//! │   ├── provisioning-plan.json
//! │   ├── repart-targets
//! │   └── repart.d/
//! └── current/
//!     ├── host.nix
//!     ├── host.nix.sig
//!     ├── facts.json
//!     ├── .metadata-result.json
//!     └── .provisioning-result.json
//! ```
//!
//! `audit.json` and `initial-plan.json` are write-once evidence for the GPT
//! commit. `desired/` follows the latest authenticated, validated storage
//! projection and is the stable definition directory for an explicit
//! post-provision `systemd-repart` invocation. `current/` is updated only after
//! full stage-2 evaluation emitted a manifest, so metadata outages can reuse a
//! previously accepted input without replacing the active generation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::fetcher::Facts;
use super::provisioning::{PROVISIONING_RESULT_FILE, ProvisioningResult, ProvisioningSource};
use super::repart::{REPART_DIR, REPART_TARGETS_FILE, STORAGE_PLAN_FILE};
use super::stash::{MetadataResult, sha256_hex};

/// Default durable state directory.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/aos-provisioning";
/// Write-once provisioning audit record.
pub const AUDIT_FILE: &str = "audit.json";
/// Write-once copy of the plan that created the GPT marker.
pub const INITIAL_PLAN_FILE: &str = "initial-plan.json";

/// Parameters recorded alongside the durable provisioning commit.
pub struct PersistProvisioningOptions {
    /// Volatile initrd/stage-2 metadata stash.
    pub stash_dir: PathBuf,
    /// Durable state directory on `/var`.
    pub state_dir: PathBuf,
    /// ABI of the base module library that evaluated the plan.
    pub module_abi: u32,
    /// Image version whose initrd committed the plan.
    pub image_version: String,
}

/// Durable, non-functional evidence for the one-time storage commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningAudit {
    /// Must equal `aos.provisioning-audit/v1`.
    pub schema: String,
    /// Best-effort UTC timestamp recorded after `/var` became available.
    pub committed_at: String,
    /// Operator or fallback provenance arm.
    pub source: ProvisioningSource,
    /// SHA-256 of the normalized plan committed to storage.
    pub plan_sha256: String,
    /// SHA-256 of exact accepted `host.nix`, when operator-driven.
    pub host_nix_sha256: Option<String>,
    /// Applied trust mode, when operator-driven.
    pub trust_mode: Option<String>,
    /// Detected platform.
    pub platform_id: Option<String>,
    /// Trusted signing-key fingerprint in signed mode.
    pub signer: Option<String>,
    /// Base module ABI used for the restricted evaluation.
    pub module_abi: u32,
    /// Image version whose initrd committed storage.
    pub image_version: String,
    /// Platform instance identifier, when available.
    pub instance_id: Option<String>,
    /// SHA-256 of normalized `facts.json`, when available.
    pub facts_sha256: Option<String>,
}

/// Persists the latest validated definitions and write-once commit evidence.
///
/// Returns `Ok(false)` when this boot did not produce a validated plan. This is
/// normal on a provisioned boot whose metadata source is unavailable.
///
/// # Errors
///
/// Returns an error when source records are malformed, required plan files are
/// incomplete, or durable outputs cannot be atomically replaced.
pub fn persist_provisioning_state(opts: &PersistProvisioningOptions) -> Result<bool> {
    let plan_path = opts.stash_dir.join(STORAGE_PLAN_FILE);
    if !plan_path.is_file() {
        return Ok(false);
    }
    let source = read_source(&opts.stash_dir)?;
    let plan =
        std::fs::read(&plan_path).with_context(|| format!("reading {}", plan_path.display()))?;
    let targets = opts.stash_dir.join(REPART_TARGETS_FILE);
    let definitions = opts.stash_dir.join(REPART_DIR);
    if !targets.is_file() || !definitions.is_dir() {
        bail!("validated provisioning plan has no complete rendered definition set");
    }

    std::fs::create_dir_all(&opts.state_dir)
        .with_context(|| format!("creating {}", opts.state_dir.display()))?;
    replace_desired(&opts.state_dir, &plan_path, &targets, &definitions)?;

    let initial_plan = opts.state_dir.join(INITIAL_PLAN_FILE);
    if !initial_plan.exists() {
        atomic_write(&initial_plan, &plan)?;
    }
    let audit_path = opts.state_dir.join(AUDIT_FILE);
    if !audit_path.exists() {
        let audit = build_audit(opts, source, &plan)?;
        let encoded =
            serde_json::to_vec_pretty(&audit).context("serializing provisioning audit")?;
        atomic_write(&audit_path, &encoded)?;
    }
    Ok(true)
}

/// Caches exact authorized runtime inputs after full evaluation succeeded.
///
/// Returns `Ok(false)` when no fresh authorized `host.nix` exists.
///
/// # Errors
///
/// Returns an error when the accepted-byte binding is invalid or the durable
/// cache cannot be atomically replaced.
pub fn cache_runtime_input(stash_dir: &Path, state_dir: &Path) -> Result<bool> {
    let host = stash_dir.join("host.nix");
    if !host.is_file() {
        return Ok(false);
    }
    super::provisioning::verify_host_binding(stash_dir)?;
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    let temp = state_dir.join(format!("current.new.{}", std::process::id()));
    if temp.exists() {
        std::fs::remove_dir_all(&temp)
            .with_context(|| format!("removing stale {}", temp.display()))?;
    }
    std::fs::create_dir_all(&temp).with_context(|| format!("creating {}", temp.display()))?;
    copy_required(&host, &temp.join("host.nix"))?;
    copy_required(
        &stash_dir.join(PROVISIONING_RESULT_FILE),
        &temp.join(PROVISIONING_RESULT_FILE),
    )?;
    for file in ["facts.json", ".metadata-result.json"] {
        copy_optional(&stash_dir.join(file), &temp.join(file))?;
    }
    copy_optional(&stash_dir.join("user-data.sig"), &temp.join("host.nix.sig"))?;
    replace_directory(state_dir, "current", &temp)?;
    Ok(true)
}

/// Restores the last fully evaluated host input when fresh metadata is absent.
///
/// Restored bytes are checked against their recorded SHA-256 before becoming
/// visible to stage-2 evaluation.
///
/// # Errors
///
/// Returns an error when cached state is incomplete, its binding is invalid,
/// or files cannot be copied into the volatile stash.
pub fn restore_runtime_input(stash_dir: &Path, state_dir: &Path) -> Result<bool> {
    if stash_dir.join("host.nix").is_file() {
        return Ok(false);
    }
    let current = if state_dir.join("current").is_dir() {
        state_dir.join("current")
    } else if state_dir.join("current.old").is_dir() {
        state_dir.join("current.old")
    } else {
        return Ok(false);
    };
    std::fs::create_dir_all(stash_dir)
        .with_context(|| format!("creating {}", stash_dir.display()))?;
    for file in [
        "host.nix",
        PROVISIONING_RESULT_FILE,
        "facts.json",
        ".metadata-result.json",
        "user-data.sig",
    ] {
        let path = stash_dir.join(file);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("clearing stale {}", path.display()))?;
        }
    }
    copy_required(&current.join("host.nix"), &stash_dir.join("host.nix"))?;
    copy_required(
        &current.join(PROVISIONING_RESULT_FILE),
        &stash_dir.join(PROVISIONING_RESULT_FILE),
    )?;
    for file in ["facts.json", ".metadata-result.json"] {
        copy_optional(&current.join(file), &stash_dir.join(file))?;
    }
    copy_optional(
        &current.join("host.nix.sig"),
        &stash_dir.join("user-data.sig"),
    )?;
    if let Err(error) = super::provisioning::verify_host_binding(stash_dir) {
        for file in ["host.nix", PROVISIONING_RESULT_FILE] {
            let path = stash_dir.join(file);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing invalid {}", path.display()))?;
            }
        }
        return Err(error).context("validating cached host input");
    }
    Ok(true)
}

fn build_audit(
    opts: &PersistProvisioningOptions,
    source: ProvisioningSource,
    plan: &[u8],
) -> Result<ProvisioningAudit> {
    let authorization =
        read_optional_json::<ProvisioningResult>(&opts.stash_dir.join(PROVISIONING_RESULT_FILE))?;
    let metadata =
        read_optional_json::<MetadataResult>(&opts.stash_dir.join(".metadata-result.json"))?;
    let facts = read_optional_json::<Facts>(&opts.stash_dir.join("facts.json"))?;
    let platform_id = authorization
        .as_ref()
        .map(|record| record.platform_id.clone())
        .or_else(|| metadata.as_ref().map(|record| record.platform_id.clone()));
    Ok(ProvisioningAudit {
        schema: "aos.provisioning-audit/v1".to_string(),
        committed_at: super::now_rfc3339(),
        source,
        plan_sha256: sha256_hex(plan),
        host_nix_sha256: authorization
            .as_ref()
            .map(|record| record.host_nix_sha256.clone()),
        trust_mode: authorization
            .as_ref()
            .map(|record| record.trust_mode.as_str().to_string()),
        platform_id,
        signer: authorization.and_then(|record| record.signer),
        module_abi: opts.module_abi,
        image_version: opts.image_version.clone(),
        instance_id: facts.as_ref().and_then(|record| record.instance_id.clone()),
        facts_sha256: metadata.map(|record| record.facts_hash),
    })
}

fn read_source(stash_dir: &Path) -> Result<ProvisioningSource> {
    let value = std::fs::read_to_string(stash_dir.join("provisioning-source"))
        .context("reading provisioning source")?;
    value.trim().parse()
}

fn read_optional_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {}", path.display()))
        .map(Some)
}

fn replace_desired(
    state_dir: &Path,
    plan: &Path,
    targets: &Path,
    definitions: &Path,
) -> Result<()> {
    let temp = state_dir.join(format!("desired.new.{}", std::process::id()));
    if temp.exists() {
        std::fs::remove_dir_all(&temp)
            .with_context(|| format!("removing stale {}", temp.display()))?;
    }
    std::fs::create_dir_all(&temp).with_context(|| format!("creating {}", temp.display()))?;
    copy_required(plan, &temp.join(STORAGE_PLAN_FILE))?;
    copy_required(targets, &temp.join(REPART_TARGETS_FILE))?;
    copy_tree(definitions, &temp.join(REPART_DIR))?;
    replace_directory(state_dir, "desired", &temp)
}

fn replace_directory(state_dir: &Path, name: &str, temp: &Path) -> Result<()> {
    let destination = state_dir.join(name);
    let backup = state_dir.join(format!("{name}.old"));
    if backup.exists() {
        std::fs::remove_dir_all(&backup)
            .with_context(|| format!("removing {}", backup.display()))?;
    }
    if destination.exists() {
        std::fs::rename(&destination, &backup)
            .with_context(|| format!("moving {} to {}", destination.display(), backup.display()))?;
    }
    if let Err(error) = std::fs::rename(temp, &destination) {
        if backup.exists() && !destination.exists() {
            std::fs::rename(&backup, &destination).with_context(|| {
                format!(
                    "restoring {} after failed replacement",
                    destination.display()
                )
            })?;
        }
        return Err(error)
            .with_context(|| format!("installing durable directory {}", destination.display()));
    }
    if backup.exists() {
        std::fs::remove_dir_all(&backup)
            .with_context(|| format!("removing {}", backup.display()))?;
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)
        .with_context(|| format!("creating {}", destination.display()))?;
    for entry in
        std::fs::read_dir(source).with_context(|| format!("reading {}", source.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", source.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading type of {}", entry.path().display()))?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            copy_required(&entry.path(), &target)?;
        } else {
            bail!("refusing non-file entry {}", entry.path().display());
        }
    }
    Ok(())
}

fn copy_required(source: &Path, destination: &Path) -> Result<()> {
    std::fs::copy(source, destination)
        .with_context(|| format!("copying {} to {}", source.display(), destination.display()))?;
    Ok(())
}

fn copy_optional(source: &Path, destination: &Path) -> Result<()> {
    if source.is_file() {
        copy_required(source, destination)?;
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&temp, bytes).with_context(|| format!("writing {}", temp.display()))?;
    std::fs::rename(&temp, path).with_context(|| format!("installing {}", path.display()))
}
