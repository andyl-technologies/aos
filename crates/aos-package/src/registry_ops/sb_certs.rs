//! Committed Secure Boot certificate enrollment, retirement, and SBAT floors.

use crate::SbCertsCommand;
use crate::config::ApmConfig;
use crate::registry::sb_certs;
use crate::registry::sb_certs::{RevokedSbCert, SbCert, SbCertsToml};
use crate::registry_ops::config::resolve_registry_name;
use crate::registry_ops::git::{commit_registry, refresh_registry_object_store};
use crate::registry_ops::publish::ensure_writable_registry_clone;
use crate::registry_ops::signing::ResolvedSigningKey;
use crate::registry_ops::trust::{load_committed_roster, resolve_roster_commit_key};
use crate::types::SbatEntry;
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use std::path::{Path, PathBuf};

/// `apr sb-certs ...` — manage the committed Secure Boot validation catalog.
///
/// Mutates the `sb-certs.toml` roster in an authoring clone (RFC-0006 phase
/// 4): the active db-cert set, its revocations, and the per-component SBAT
/// revocation floor. Each mutation loads-or-creates the catalog, applies the
/// change, and writes it back via
/// [`crate::registry::sb_certs::write_sb_certs_toml`]. Unless `--no-commit`
/// is given the change is committed (optionally signed by an active
/// `keys.toml` maintainer key) the same way `keys.toml` changes are, so the
/// catalog stays covered by the registry's release signature and reaches
/// consumers on their next `apm update`.
///
/// # Errors
///
/// Returns an error when the registry name cannot be resolved, the clone is
/// not writable, the catalog fails validation, the commit-signing key cannot
/// be resolved, or the write/commit fails.
pub fn run_sb_certs(config: &ApmConfig, command: &SbCertsCommand, printer: &Printer) -> Result<()> {
    match command {
        SbCertsCommand::List { registry } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let catalog = load_committed_sb_certs(&dir)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "registry": registry_name,
                    "active": catalog.active.iter().map(|c| serde_json::json!({
                        "id": c.id,
                        "cert_sha256": c.cert_sha256,
                    })).collect::<Vec<_>>(),
                    "revoked": catalog.revoked.iter().map(|r| serde_json::json!({
                        "id": r.id,
                        "reason": r.reason,
                    })).collect::<Vec<_>>(),
                    "sbat_floor": catalog.sbat_floor.iter().map(|f| serde_json::json!({
                        "component": f.component,
                        "generation": f.generation,
                    })).collect::<Vec<_>>(),
                }));
                return Ok(());
            }
            if catalog.active.is_empty()
                && catalog.revoked.is_empty()
                && catalog.sbat_floor.is_empty()
            {
                printer.info(&format!(
                    "Registry '{registry_name}' has no Secure Boot catalog (sb-certs.toml)."
                ));
                return Ok(());
            }
            printer.header(&format!("sb-certs.toml for registry '{registry_name}'"));
            if catalog.active.is_empty() {
                printer.plain("active: none");
            } else {
                printer.plain("active:");
                for cert in &catalog.active {
                    printer.plain(&format!("  {}: {}", cert.id, cert.cert_sha256));
                }
            }
            if catalog.revoked.is_empty() {
                printer.plain("revoked: none");
            } else {
                printer.plain("revoked:");
                for rev in &catalog.revoked {
                    match &rev.reason {
                        Some(reason) => printer.plain(&format!("  {}: {}", rev.id, reason)),
                        None => printer.plain(&format!("  {}", rev.id)),
                    }
                }
            }
            if catalog.sbat_floor.is_empty() {
                printer.plain("sbat_floor: none");
            } else {
                printer.plain("sbat_floor:");
                for entry in &catalog.sbat_floor {
                    printer.plain(&format!("  {}: {}", entry.component, entry.generation));
                }
            }
            Ok(())
        }
        SbCertsCommand::Add {
            id,
            cert_sha256,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let (registry_name, dir) = resolve_sb_certs_target(config, registry.as_deref())?;
            let mut catalog = load_committed_sb_certs(&dir)?;
            let commit_key = sb_certs_commit_key(
                config,
                &dir,
                &registry_name,
                *no_commit,
                signing_key.as_deref(),
                signing_key_id.as_deref(),
            )?;
            add_sb_cert(&mut catalog, id, cert_sha256)?;
            persist_committed_sb_certs(
                &dir,
                &catalog,
                *no_commit,
                &format!("registry: add Secure Boot db cert {id}"),
                commit_key.as_ref().map(|k| k.path()),
            )?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "sb_certs_add",
                    "status": "added",
                    "registry": registry_name,
                    "id": id,
                    "cert_sha256": cert_sha256,
                    "committed": !*no_commit,
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Added active Secure Boot db cert '{id}' to registry '{registry_name}'."
            ));
            Ok(())
        }
        SbCertsCommand::Retire {
            id,
            reason,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let (registry_name, dir) = resolve_sb_certs_target(config, registry.as_deref())?;
            let mut catalog = load_committed_sb_certs(&dir)?;
            let commit_key = sb_certs_commit_key(
                config,
                &dir,
                &registry_name,
                *no_commit,
                signing_key.as_deref(),
                signing_key_id.as_deref(),
            )?;
            retire_sb_cert(&mut catalog, id, reason.as_deref())?;
            persist_committed_sb_certs(
                &dir,
                &catalog,
                *no_commit,
                &format!("registry: retire Secure Boot db cert {id}"),
                commit_key.as_ref().map(|k| k.path()),
            )?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "sb_certs_retire",
                    "status": "retired",
                    "registry": registry_name,
                    "id": id,
                    "reason": reason.as_deref(),
                    "committed": !*no_commit,
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Retired Secure Boot db cert '{id}' from registry '{registry_name}'."
            ));
            Ok(())
        }
        SbCertsCommand::SetFloor {
            component,
            generation,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let (registry_name, dir) = resolve_sb_certs_target(config, registry.as_deref())?;
            let mut catalog = load_committed_sb_certs(&dir)?;
            let commit_key = sb_certs_commit_key(
                config,
                &dir,
                &registry_name,
                *no_commit,
                signing_key.as_deref(),
                signing_key_id.as_deref(),
            )?;
            set_sbat_floor(&mut catalog, component, *generation)?;
            persist_committed_sb_certs(
                &dir,
                &catalog,
                *no_commit,
                &format!("registry: set SBAT floor {component}={generation}"),
                commit_key.as_ref().map(|k| k.path()),
            )?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "sb_certs_set_floor",
                    "status": "set",
                    "registry": registry_name,
                    "component": component,
                    "generation": generation,
                    "committed": !*no_commit,
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Set SBAT revocation floor '{component}' = {generation} for registry '{registry_name}'."
            ));
            Ok(())
        }
    }
}

/// Resolve the registry name and require a writable authoring clone for an
/// `apr sb-certs` mutation.
fn resolve_sb_certs_target(
    config: &ApmConfig,
    registry: Option<&str>,
) -> Result<(String, PathBuf)> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    ensure_writable_registry_clone(&registry_name, &dir)?;
    Ok((registry_name, dir))
}

/// Load the committed `sb-certs.toml` catalog, defaulting to an empty
/// catalog when the file does not exist yet.
///
/// # Errors
///
/// Returns an error when the registry directory is missing or the catalog
/// fails to load/validate.
fn load_committed_sb_certs(dir: &Path) -> Result<SbCertsToml> {
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }
    Ok(sb_certs::load_sb_certs_toml(dir)?.unwrap_or_default())
}

/// Write `sb-certs.toml` and, unless `no_commit`, commit and refresh the
/// dumb-HTTP object store — the same persistence path `keys.toml` uses.
///
/// # Errors
///
/// Returns an error when the catalog fails validation, the write fails, or
/// the commit/object-store refresh fails.
fn persist_committed_sb_certs(
    dir: &Path,
    catalog: &SbCertsToml,
    no_commit: bool,
    message: &str,
    signing_key: Option<&str>,
) -> Result<()> {
    sb_certs::write_sb_certs_toml(dir, catalog)?;
    if !no_commit {
        commit_registry(dir, message, signing_key)?;
        refresh_registry_object_store(dir)
            .context("refreshing dumb-HTTP object store after sb-certs.toml update")?;
    }
    Ok(())
}

/// Resolve the maintainer key that signs an `sb-certs.toml` commit.
///
/// The catalog is part of the signed tree, so its commits must be signed by
/// an active `keys.toml` maintainer key exactly like a roster change. This
/// reuses [`resolve_roster_commit_key`] against the committed `keys.toml`:
/// the only unsigned case is a registry whose key roster is still empty
/// (bootstrap). Returns `None` when `no_commit` is set.
///
/// # Errors
///
/// Returns an error when the key roster is non-empty but no signing key was
/// provided, or the requested key cannot be resolved.
fn sb_certs_commit_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    no_commit: bool,
    signing_key: Option<&str>,
    signing_key_id: Option<&str>,
) -> Result<Option<ResolvedSigningKey>> {
    if no_commit {
        return Ok(None);
    }
    let roster = load_committed_roster(dir)?;
    resolve_roster_commit_key(
        config,
        dir,
        registry_name,
        &roster,
        signing_key,
        signing_key_id,
    )
}

/// Append an active db cert after validating the id is non-empty and unused
/// and the digest is a 64-char lowercase hex SHA-256.
///
/// # Errors
///
/// Returns an error when the id is empty or already present, the digest is
/// malformed, or the same digest is already enrolled under another id.
fn add_sb_cert(catalog: &mut SbCertsToml, id: &str, cert_sha256: &str) -> Result<()> {
    if id.is_empty() {
        bail!("Secure Boot db cert id is empty");
    }
    let digest = cert_sha256.to_ascii_lowercase();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("--cert-sha256 must be a 64-character hex SHA-256 digest, got '{cert_sha256}'");
    }
    if catalog.active.iter().any(|c| c.id == id) {
        bail!("active db cert id '{id}' already exists in sb-certs.toml");
    }
    if catalog
        .active
        .iter()
        .any(|c| c.cert_sha256.eq_ignore_ascii_case(&digest))
    {
        bail!("db cert digest already enrolled in sb-certs.toml under another id");
    }
    catalog.active.push(SbCert {
        id: id.to_string(),
        cert_sha256: digest,
    });
    Ok(())
}

/// Move db cert `id` into the revoked set.
///
/// The id must name an active db cert; an already-revoked id is rejected.
/// The cert stays under `[[active]]` (as `validate_catalog` requires every
/// revocation to reference an active entry) and gains a `[[revoked]]` row.
///
/// # Errors
///
/// Returns an error when `id` is empty, is not active, or is already
/// revoked.
fn retire_sb_cert(catalog: &mut SbCertsToml, id: &str, reason: Option<&str>) -> Result<()> {
    if id.is_empty() {
        bail!("Secure Boot db cert id is empty");
    }
    if !catalog.active.iter().any(|c| c.id == id) {
        bail!("db cert id '{id}' is not active in sb-certs.toml");
    }
    if catalog.revoked.iter().any(|r| r.id == id) {
        bail!("db cert id '{id}' is already revoked in sb-certs.toml");
    }
    catalog.revoked.push(RevokedSbCert {
        id: id.to_string(),
        reason: reason.map(str::to_string),
    });
    Ok(())
}

/// Set or raise the SBAT revocation floor for `component`.
///
/// A floor may only be raised, never lowered: lowering would re-admit a
/// component the fleet already revoked. An absent component is inserted.
///
/// # Errors
///
/// Returns an error when `component` is empty or the requested generation is
/// below the existing floor.
fn set_sbat_floor(catalog: &mut SbCertsToml, component: &str, generation: u32) -> Result<()> {
    if component.is_empty() {
        bail!("SBAT floor component is empty");
    }
    if let Some(entry) = catalog
        .sbat_floor
        .iter_mut()
        .find(|entry| entry.component == component)
    {
        if generation < entry.generation {
            bail!(
                "refusing to lower the SBAT floor for '{component}' from {} to {generation}: \
                 a floor may only be raised",
                entry.generation,
            );
        }
        entry.generation = generation;
    } else {
        catalog.sbat_floor.push(SbatEntry {
            component: component.to_string(),
            generation,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
