//! Realisation graph maintenance and store signing-key selection.

use crate::StoreCommand;
use crate::config::ApmConfig;
use crate::registry::store;
use crate::registry::store::StoreMap;
use crate::registry_ops::config::{registry_content_addressed, resolve_registry_name};
use crate::registry_ops::git::{commit_registry_paths, refresh_registry_object_store};
use crate::registry_ops::publish::{RegistryPublishLock, ensure_writable_registry_clone};
use crate::registry_ops::signing::{
    ResolvedSigningKey, registry_config_by_name, resolve_producer_signing_key,
};
use crate::registry_ops::store_paths::{
    StoreWriteReport, collect_package_store_paths, extract_hash, introspect_closure_nars,
    write_store_files,
};
use crate::registry_ops::trust::load_committed_roster;
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use std::collections::HashSet;
use std::path::Path;

/// `apr cache` subcommands for the static Nix binary cache.
///
/// `generate` renders the registry's published store paths into a static
/// cache directory (narinfos plus compressed NARs, signed with `--key`
/// when given), optionally uploads it to each `--upload-url` (falling back
/// to the `upload_urls` persisted by `apr origin config` when no flag is
/// given), and with `--cache-url` upserts the committed `[caches]` stack in
/// `registry.toml`, committing the pointer change unless `--no-commit` is
/// set.
///
/// # Errors
///
/// Fails when cache generation, an upload, the pointer commit, or the
/// object-store refresh fails.
/// `apr store` - maintains the registry's `store/` realisation graph
/// (RFC-0005).
///
/// The graph is append-mostly: `bless` adds a realisation computed from the
/// local Nix store, `revoke` removes one (a security event with the same
/// review weight as a key retirement), `verify` checks graph health and
/// coverage, and `backfill` records every published closure in one pass so an
/// existing registry becomes fully covered.
///
/// # Errors
///
/// Fails when the registry cannot be resolved, the referenced store paths
/// are not valid in the local Nix store, a record cannot be read or written,
/// a blessing conflicts without `--bless`, verification finds errors, or the
/// commit fails.
pub async fn run_store(
    config: &ApmConfig,
    command: &StoreCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        StoreCommand::Bless {
            store_path,
            no_commit,
            message,
            key,
            key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            ensure_writable_registry_clone(&registry_name, &dir)?;
            let signing_key =
                resolve_optional_signing_key(config, &dir, &registry_name, key, key_id)?;
            let content_addressed = registry_content_addressed(&dir);
            let _publish_lock = RegistryPublishLock::acquire(&dir)?;

            // Bless the whole closure of the path (records every member).
            let report = write_store_files(&dir, store_path, content_addressed, true, printer)
                .with_context(|| format!("writing store/ records for {store_path}"))?;

            printer.kv("Store graph", &report.summary());
            let changed = report.created + report.blessed > 0;
            let mut committed = false;
            if changed && !*no_commit {
                let default_msg = format!("store: bless {store_path}");
                let msg = message.as_deref().unwrap_or(&default_msg);
                commit_registry_paths(
                    &dir,
                    msg,
                    &[dir.join(store::STORE_DIR)],
                    signing_key.as_ref().map(|k| k.path()),
                )?;
                refresh_registry_object_store(&dir)
                    .context("refreshing dumb-HTTP object store after store bless")?;
                committed = true;
                printer.success(&format!("Committed: {msg}"));
            } else if !changed {
                printer.info("Graph already covers this content; nothing to commit.");
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "store_bless",
                    "registry": registry_name,
                    "store_path": store_path,
                    "created": report.created,
                    "blessed": report.blessed,
                    "unchanged": report.unchanged,
                    "content_addressed": report.content_addressed,
                    "committed": committed,
                }));
            }
            Ok(())
        }

        StoreCommand::Revoke {
            store_path,
            realisation,
            no_commit,
            message,
            key,
            key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            ensure_writable_registry_clone(&registry_name, &dir)?;
            let signing_key =
                resolve_optional_signing_key(config, &dir, &registry_name, key, key_id)?;
            let _publish_lock = RegistryPublishLock::acquire(&dir)?;

            let ia_hash = extract_hash(store_path);
            if !store::remove_realisations(&dir, ia_hash, realisation.as_deref())? {
                bail!("no matching store/ realisation for {ia_hash}; nothing to revoke");
            }

            printer.success(&format!(
                "Revoked {} for {ia_hash}.",
                realisation.as_deref().unwrap_or("all realisations"),
            ));
            let mut committed = false;
            if !*no_commit {
                let default_msg = format!("store: revoke {ia_hash}");
                let msg = message.as_deref().unwrap_or(&default_msg);
                commit_registry_paths(
                    &dir,
                    msg,
                    &[dir.join(store::STORE_DIR)],
                    signing_key.as_ref().map(|k| k.path()),
                )?;
                refresh_registry_object_store(&dir)
                    .context("refreshing dumb-HTTP object store after store revoke")?;
                committed = true;
                printer.success(&format!("Committed: {msg}"));
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "store_revoke",
                    "registry": registry_name,
                    "ia_hash": ia_hash,
                    "realisation": realisation,
                    "committed": committed,
                }));
            }
            Ok(())
        }

        StoreCommand::Verify { deep, registry } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            store_verify(&dir, &registry_name, *deep, printer)
        }

        StoreCommand::Backfill {
            bless,
            no_commit,
            message,
            key,
            key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            ensure_writable_registry_clone(&registry_name, &dir)?;
            let signing_key =
                resolve_optional_signing_key(config, &dir, &registry_name, key, key_id)?;
            let content_addressed = registry_content_addressed(&dir);
            let _publish_lock = RegistryPublishLock::acquire(&dir)?;

            let roots = collect_package_store_paths(&dir)?;
            if roots.is_empty() {
                bail!("registry has no published store paths to backfill");
            }

            let mut report = StoreWriteReport::default();
            for root in &roots {
                printer.info(&format!("Recording closure of {root}"));
                report.merge(
                    write_store_files(&dir, root, content_addressed, *bless, printer)
                        .with_context(|| format!("writing store/ records for {root}"))?,
                );
            }
            printer.kv("Roots", &roots.len().to_string());
            printer.kv("Store graph", &report.summary());

            let changed = report.created + report.blessed > 0;
            let mut committed = false;
            if changed && !*no_commit {
                let default_msg = format!(
                    "store: backfill realisation graph ({} closures)",
                    roots.len(),
                );
                let msg = message.as_deref().unwrap_or(&default_msg);
                commit_registry_paths(
                    &dir,
                    msg,
                    &[dir.join(store::STORE_DIR)],
                    signing_key.as_ref().map(|k| k.path()),
                )?;
                refresh_registry_object_store(&dir)
                    .context("refreshing dumb-HTTP object store after store backfill")?;
                committed = true;
                printer.success(&format!("Committed: {msg}"));
            } else if !changed {
                printer.info("Graph already covers every published closure.");
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "store_backfill",
                    "registry": registry_name,
                    "roots": roots.len(),
                    "created": report.created,
                    "blessed": report.blessed,
                    "unchanged": report.unchanged,
                    "content_addressed": report.content_addressed,
                    "committed": committed,
                }));
            }
            Ok(())
        }
    }
}

/// Resolve a producer signing key only when `--key`/`--key-id` was given
/// (the `apr publish` convention).
fn resolve_optional_signing_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    key: &Option<String>,
    key_id: &Option<String>,
) -> Result<Option<ResolvedSigningKey>> {
    if key.is_some() || key_id.is_some() {
        Ok(Some(resolve_producer_signing_key(
            config,
            dir,
            registry_name,
            key.as_deref(),
            key_id.as_deref(),
        )?))
    } else {
        Ok(None)
    }
}

/// Resolves the signing key for a committed cache-pointer update.
///
/// A registry without a trust roster may retain the unsigned local-development
/// behavior. Once active roster keys exist, however, publishing an unsigned
/// head would make the registry unusable to verifying consumers. Explicit
/// options win; otherwise a sole locally configured active key is selected.
pub(in crate::registry_ops) fn resolve_cache_pointer_signing_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    key: Option<&str>,
    key_id: Option<&str>,
) -> Result<Option<ResolvedSigningKey>> {
    if key.is_some() || key_id.is_some() {
        return resolve_producer_signing_key(config, dir, registry_name, key, key_id).map(Some);
    }

    let roster = load_committed_roster(dir)?;
    if roster.active.is_empty() {
        return Ok(None);
    }
    let registry_config = registry_config_by_name(config, registry_name).ok_or_else(|| {
        anyhow::anyhow!(
            "registry '{registry_name}' has an active trust roster but no producer configuration"
        )
    })?;
    let candidates = roster
        .active
        .iter()
        .filter(|entry| registry_config.signing_keys.contains_key(&entry.id))
        .map(|entry| entry.id.as_str())
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [key_id] => {
            resolve_producer_signing_key(config, dir, registry_name, None, Some(key_id)).map(Some)
        }
        [] => bail!(
            "registry '{registry_name}' has active trust keys but none has local private key material; pass --registry-key or configure one under [registry.signing_keys]"
        ),
        _ => bail!(
            "registry '{registry_name}' has multiple locally configured active keys; select one with --registry-key-id"
        ),
    }
}

/// `apr store verify` - checks graph health: record parseability, coverage of
/// every published closure member (reachable via dependency edges), and (with
/// `deep`) agreement with the local Nix store's actual NAR hashes.
fn store_verify(dir: &Path, registry_name: &str, deep: bool, printer: &Printer) -> Result<()> {
    let graph = StoreMap::load(dir).context("loading store/ graph")?;
    if !graph.is_present() {
        bail!(
            "registry '{registry_name}' publishes no store/ realisation graph; \
             run `apr store backfill` to create one"
        );
    }

    let mut errors = 0u32;
    let mut members_checked = 0u32;

    // Coverage: every member reachable from every published package root has a
    // record with a blessed NAR.
    for root in collect_package_store_paths(dir)? {
        let mut seen = HashSet::new();
        let mut stack = vec![extract_hash(&root).to_string()];
        while let Some(hash) = stack.pop() {
            if !seen.insert(hash.clone()) {
                continue;
            }
            members_checked += 1;
            match graph.get(&hash) {
                None => {
                    printer.warning(&format!("closure member {hash} has no store/ record"));
                    errors += 1;
                }
                Some(record) if record.blessed_nars().is_empty() => {
                    printer.warning(&format!("store/ record {hash} has no blessed NAR"));
                    errors += 1;
                }
                Some(_) => stack.extend(graph.direct_deps(&hash)),
            }
        }
    }

    // Deep: recompute every locally-available closure member's NAR hash and
    // require it to match a blessed NAR in the record.
    let mut deep_checked = 0u32;
    if deep {
        for root in collect_package_store_paths(dir)? {
            let members = match introspect_closure_nars(&root) {
                Ok(members) => members,
                Err(err) => {
                    printer.warning(&format!(
                        "skipping deep check for {root} (not introspectable locally): {err:#}"
                    ));
                    continue;
                }
            };
            for member in members {
                deep_checked += 1;
                let ia_hash = extract_hash(&member.path);
                let blessed = graph.blessed_nars(ia_hash);
                if blessed.is_empty() {
                    printer.warning(&format!("{}: no store/ record for {ia_hash}", member.path));
                    errors += 1;
                    continue;
                }
                if !blessed
                    .iter()
                    .any(|nar| nar.matches(&member.nar_hash, member.nar_size))
                {
                    printer.error(&format!(
                        "{}: local store content is NOT blessed (local {} / {} bytes)",
                        member.path, member.nar_hash, member.nar_size,
                    ));
                    errors += 1;
                }
            }
        }
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "store_verify",
            "registry": registry_name,
            "records": graph.len(),
            "members_checked": members_checked,
            "deep_checked": deep_checked,
            "errors": errors,
        }));
    }

    if errors > 0 {
        bail!("store/ graph verification failed with {errors} error(s)");
    }
    printer.success(&format!(
        "Graph OK: {} record(s), {members_checked} closure member(s) covered{}.",
        graph.len(),
        if deep {
            format!(", {deep_checked} deep-checked")
        } else {
            String::new()
        },
    ));
    Ok(())
}

#[cfg(test)]
mod tests;
