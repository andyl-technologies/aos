//! Static cache, web, and origin publication with upload configuration.

use crate::config::ApmConfig;
use crate::registry::membership::{CacheMembership, HeadMembership};
use crate::registry::webgen::WebConfig;
use crate::registry::{nixcache, objectstore, state, static_upload, webgen};
use crate::registry_ops::config::{
    format_size, registry_cache_max_age_days, registry_upload_auth_config, resolve_registry_name,
    resolve_upload_urls, warn_on_cache_gc,
};
use crate::registry_ops::git::{commit_registry, refresh_registry_object_store};
use crate::registry_ops::publish::RegistryPublishLock;
use crate::registry_ops::signing::ResolvedSigningKey;
use crate::registry_ops::store_commands::resolve_cache_pointer_signing_key;
use crate::types::{RegistryFile, RegistryUploadAuthConfig};
use crate::{CacheCommand, OriginCommand, UploadConfigField, WebCommand};
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use clap::ValueEnum as _;
use std::path::Path;

pub async fn run_cache(
    config: &ApmConfig,
    command: &CacheCommand,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    match command {
        CacheCommand::Generate {
            output,
            key,
            registry_key,
            registry_key_id,
            cache_url,
            upload_urls,
            auth,
            priority,
            no_commit,
            registry,
            jobs,
            no_skip,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let upload_urls = resolve_upload_urls(config, &registry_name, upload_urls);
            let output = output
                .clone()
                .unwrap_or_else(|| config.registry_cache_path(&registry_name));
            if dry_run {
                if printer.mode() == OutputMode::Json {
                    printer.json(&serde_json::json!({
                        "action": "cache_generate",
                        "dry_run": true,
                        "registry": registry_name,
                        "output_dir": output.to_string_lossy().to_string(),
                        "cache_url": cache_url.as_deref(),
                        "priority": priority,
                        "upload_urls": upload_urls,
                        "uploaded": false,
                        "cache_pointer_updated": false,
                        "committed": false,
                    }));
                } else {
                    printer.info(&format!(
                        "Would generate the static cache for {registry_name} in {}",
                        output.display(),
                    ));
                }
                return Ok(());
            }
            let upload_auth =
                auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
            let membership = if upload_urls.is_empty() || *no_skip {
                None
            } else {
                Some(
                    HeadMembership::from_urls(&upload_urls, &upload_auth)
                        .await
                        .context("creating remote cache membership checker")?,
                )
            };
            let membership = membership
                .as_ref()
                .map(|membership| membership as &dyn CacheMembership);
            let report = nixcache::generate_static_cache(
                &dir,
                &output,
                key.as_deref(),
                *priority,
                *jobs,
                membership,
                *no_skip,
                printer,
            )
            .await?;

            printer.success(&format!(
                "Generated static cache: {} narinfos, {} NARs ({} reused) in {}",
                report.narinfos,
                report.nars,
                report.local_reused,
                report.output_dir.display(),
            ));

            if !upload_urls.is_empty() {
                nixcache::upload_static_cache_to_all(
                    &output,
                    &upload_urls,
                    &upload_auth,
                    &report.root_hashes,
                    *no_skip,
                    printer,
                )
                .await?;
            }

            let mut cache_pointer_updated = false;
            let mut committed = false;
            if let Some(cache_url) = cache_url {
                if nixcache::upsert_registry_cache(&dir, cache_url, *priority)? {
                    cache_pointer_updated = true;
                    printer.info(&format!("Updated registry.toml [caches] -> {cache_url}"));
                    if !*no_commit {
                        let signing_key = resolve_cache_pointer_signing_key(
                            config,
                            &dir,
                            &registry_name,
                            registry_key.as_deref(),
                            registry_key_id.as_deref(),
                        )?;
                        commit_registry(
                            &dir,
                            "registry: update static cache pointer",
                            signing_key.as_ref().map(ResolvedSigningKey::path),
                        )?;
                        refresh_registry_object_store(&dir)
                            .context("refreshing dumb-HTTP object store after cache update")?;
                        committed = true;
                    }
                }
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "cache_generate",
                    "registry": registry_name,
                    "output_dir": report.output_dir.to_string_lossy().to_string(),
                    "paths": report.paths,
                    "narinfos": report.narinfos,
                    "nars": report.nars,
                    "local_reused": report.local_reused,
                    "remote_skipped": report.remote_skipped,
                    "root_hashes": report.root_hashes,
                    "cache_url": cache_url.as_deref(),
                    "priority": priority,
                    "upload_urls": upload_urls,
                    "uploaded": !upload_urls.is_empty(),
                    "cache_pointer_updated": cache_pointer_updated,
                    "committed": committed,
                }));
            }

            warn_on_cache_gc(
                &output,
                registry_cache_max_age_days(config, &registry_name),
                printer,
            );

            Ok(())
        }
        CacheCommand::Gc {
            registry,
            max_age,
            dry_run,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let output = config.registry_cache_path(&registry_name);
            let max_age_days =
                max_age.unwrap_or_else(|| registry_cache_max_age_days(config, &registry_name));
            let report = nixcache::gc_static_cache(&output, max_age_days, *dry_run)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "cache_gc",
                    "registry": registry_name,
                    "cache_dir": output.to_string_lossy().to_string(),
                    "max_age_days": max_age_days,
                    "dry_run": dry_run,
                    "candidates": report.candidates,
                    "deleted_files": report.deleted_files,
                    "deleted_bytes": report.deleted_bytes,
                    "deleted_bytes_human": format_size(report.deleted_bytes),
                    "hashes": report.hashes,
                }));
            } else if *dry_run {
                printer.info(&format!(
                    "Would delete {} staged cache pair(s) older than {max_age_days} day(s) from {}.",
                    report.candidates,
                    output.display(),
                ));
            } else {
                printer.success(&format!(
                    "Deleted {} staged cache file(s) ({}) from {}.",
                    report.deleted_files,
                    format_size(report.deleted_bytes),
                    output.display(),
                ));
            }
            Ok(())
        }
    }
}

/// `apr web` subcommands for the static on-CDN web surface.
///
/// `generate` renders the committed registry tree into the no-JS web
/// surface — `index.html`, `web/config.json`, `web/index.json`, per-package
/// `web/packages/<name>.json` snapshots, and `browse/<name>.html` static
/// pages — into `--output` (defaulting to a `web` directory beside the
/// registry clone), then optionally uploads it to each `--upload-url`
/// (falling back to the `upload_urls` persisted by `apr origin config` when
/// no flag is given), reusing the same static-upload path as
/// `apr cache generate` / `apr origin upload`.
///
/// The SPA dist (the WASM app) is out of scope here: this command emits the
/// content-bearing no-JS floor that the SPA progressively enhances when it
/// is dropped in alongside.
///
/// # Errors
///
/// Fails when web-surface generation or an upload fails.
pub async fn run_web(config: &ApmConfig, command: &WebCommand, printer: &Printer) -> Result<()> {
    match command {
        WebCommand::Generate {
            output,
            name,
            hub_url,
            accent,
            spa_dist,
            upload_urls,
            auth,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let output_dir = output.clone().unwrap_or_else(|| dir.join("web"));
            let upload_urls = resolve_upload_urls(config, &registry_name, upload_urls);

            let web_config = WebConfig {
                name: name.clone().unwrap_or_default(),
                accent: accent.clone(),
                hub_url: hub_url.clone(),
                spa_dist: spa_dist.clone(),
            };
            let written = webgen::generate_web_surface(&dir, &output_dir, web_config)?;

            printer.success(&format!(
                "Generated web surface: {} file(s) in {}",
                written.len(),
                output_dir.display(),
            ));

            if !upload_urls.is_empty() {
                let auth = auth
                    .auth_options_with_config(registry_upload_auth_config(config, &registry_name));
                webgen::upload_web_surface_to_all(&output_dir, &upload_urls, &auth, printer)
                    .await?;
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "web_generate",
                    "registry": registry_name,
                    "output_dir": output_dir.to_string_lossy().to_string(),
                    "files": written.len(),
                    "upload_urls": upload_urls,
                    "uploaded": !upload_urls.is_empty(),
                }));
            }

            Ok(())
        }
    }
}

/// `apr origin` subcommands for the static dumb-HTTP git origin.
///
/// `prepare-index-bundles` backfills the bounded index transport in an already
/// materialized surface. `upload` refreshes the static object store indexes and uploads the
/// registry's git origin files (objects, packs, refs, channel payloads)
/// to each destination — the `--upload-url` flags, or the persisted
/// `upload_urls` defaults when no flag is given — so consumers can sync
/// from a plain file server. `config` shows or persists those producer
/// upload defaults (destinations and backend auth) in the registry's
/// `[registry.upload_auth]` section.
///
/// # Errors
///
/// Fails when a bundle surface is incomplete, when `upload` has no destination (neither `--upload-url` flags
/// nor persisted defaults), when the object-store refresh or any upload
/// fails, when `config` both sets and unsets the same field, or when
/// `config` cannot read, parse, or rewrite the registry config file.
pub async fn run_origin(
    config: &ApmConfig,
    command: &OriginCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        OriginCommand::PrepareIndexBundles { surface_dir } => {
            objectstore::write_index_bundles_for_surface(surface_dir)?;
            printer.success(&format!(
                "Prepared 256 bounded index bundles in {}.",
                surface_dir.display()
            ));
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "origin_prepare_index_bundles",
                    "surface_dir": surface_dir.to_string_lossy(),
                    "bundles": 256,
                }));
            }
            Ok(())
        }
        OriginCommand::Upload {
            upload_urls,
            cache_dir,
            auth,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let upload_urls = resolve_upload_urls(config, &registry_name, upload_urls);
            if upload_urls.is_empty() {
                bail!(
                    "no upload destination: pass --upload-url <url> or persist defaults with \
                     `{} origin config --upload-url <url>`",
                    aos_core::invocation::package_registry_command(),
                );
            }
            let dir = config.scope.registries_path().join(&registry_name);
            // Ref metadata and loose-object canonicalization form one
            // publication snapshot. Keep registry writers out until every
            // destination has consumed that snapshot.
            let _publish_lock = RegistryPublishLock::acquire(&dir)?;
            refresh_registry_object_store(&dir)
                .context("refreshing static git origin before upload")?;
            let auth =
                auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
            // When a cache dir is given, upload its bytes before the git origin
            // (NARs/narinfos before the refs that point at them), reusing the
            // ordering `upload_static_cache_to_all` already owns. This command
            // derives no roots, so every narinfo is a member (root-last
            // collapses to narinfos-after-NARs, still producer-safe). `files`
            // and `bytes` below report the git-origin surface; the cache upload
            // prints its own per-destination success line.
            if let Some(cache_dir) = cache_dir.as_deref() {
                nixcache::upload_static_cache_to_all(
                    cache_dir,
                    &upload_urls,
                    &auth,
                    &[],
                    false,
                    printer,
                )
                .await?;
            }
            let report = static_upload::upload_static_origin_to_all(
                &dir,
                &upload_urls,
                &auth,
                false,
                printer,
            )
            .await?;

            printer.success(&format!(
                "Uploaded {} static origin file(s) ({}).",
                report.files,
                format_size(report.bytes),
            ));
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "origin_upload",
                    "registry": registry_name,
                    "upload_urls": upload_urls,
                    "cache_dir": cache_dir.as_ref().map(|path| path.to_string_lossy().to_string()),
                    "files": report.files,
                    "bytes": report.bytes,
                    "bytes_human": format_size(report.bytes),
                }));
            }
            Ok(())
        }
        OriginCommand::Config {
            upload_urls,
            token,
            view,
            http_user,
            http_password,
            header,
            s3_region,
            s3_profile,
            s3_endpoint,
            ssh_key,
            ssh_password,
            ssh_ask_pass,
            unset,
            registry,
        } => {
            let updates = UploadConfigUpdates {
                upload_urls,
                token: token.as_deref(),
                view: view.as_deref(),
                http_user: http_user.as_deref(),
                http_password: http_password.as_deref(),
                headers: header,
                s3_region: s3_region.as_deref(),
                s3_profile: s3_profile.as_deref(),
                s3_endpoint: s3_endpoint.as_deref(),
                ssh_key: ssh_key.as_deref(),
                ssh_password: ssh_password.as_deref(),
                ssh_ask_pass: *ssh_ask_pass,
            };
            origin_config(config, &updates, unset, registry.as_deref(), printer)
        }
    }
}

/// The `apr origin config` setter flags, grouped so [`origin_config`] can
/// treat "no flag given" uniformly across scalar, list, and boolean fields.
struct UploadConfigUpdates<'a> {
    /// Replacement default destinations; empty means "not given".
    upload_urls: &'a [String],
    token: Option<&'a str>,
    view: Option<&'a str>,
    http_user: Option<&'a str>,
    http_password: Option<&'a str>,
    /// Replacement extra HTTP headers; empty means "not given".
    headers: &'a [String],
    s3_region: Option<&'a str>,
    s3_profile: Option<&'a str>,
    s3_endpoint: Option<&'a str>,
    ssh_key: Option<&'a str>,
    ssh_password: Option<&'a str>,
    /// `--ssh-ask-pass` was passed; `false` means "leave unchanged".
    ssh_ask_pass: bool,
}

impl UploadConfigUpdates<'_> {
    /// Whether any setter flag was given at all.
    fn is_empty(&self) -> bool {
        self.upload_urls.is_empty()
            && self.token.is_none()
            && self.view.is_none()
            && self.http_user.is_none()
            && self.http_password.is_none()
            && self.headers.is_empty()
            && self.s3_region.is_none()
            && self.s3_profile.is_none()
            && self.s3_endpoint.is_none()
            && self.ssh_key.is_none()
            && self.ssh_password.is_none()
            && !self.ssh_ask_pass
    }

    /// Whether the setter for `field` was given (used to refuse a
    /// simultaneous `--unset` of the same field).
    fn sets(&self, field: UploadConfigField) -> bool {
        match field {
            UploadConfigField::UploadUrls => !self.upload_urls.is_empty(),
            UploadConfigField::Token => self.token.is_some(),
            UploadConfigField::View => self.view.is_some(),
            UploadConfigField::HttpUser => self.http_user.is_some(),
            UploadConfigField::HttpPassword => self.http_password.is_some(),
            UploadConfigField::Headers => !self.headers.is_empty(),
            UploadConfigField::S3Region => self.s3_region.is_some(),
            UploadConfigField::S3Profile => self.s3_profile.is_some(),
            UploadConfigField::S3Endpoint => self.s3_endpoint.is_some(),
            UploadConfigField::SshKey => self.ssh_key.is_some(),
            UploadConfigField::SshPassword => self.ssh_password.is_some(),
            UploadConfigField::SshAskPass => self.ssh_ask_pass,
        }
    }

    /// Apply every given setter onto `upload`.
    fn apply(&self, upload: &mut RegistryUploadAuthConfig) {
        if !self.upload_urls.is_empty() {
            upload.upload_urls = self.upload_urls.to_vec();
        }
        if let Some(token) = self.token {
            upload.token = Some(token.to_string());
        }
        if let Some(view) = self.view {
            upload.view = Some(view.to_string());
        }
        if let Some(http_user) = self.http_user {
            upload.http_user = Some(http_user.to_string());
        }
        if let Some(http_password) = self.http_password {
            upload.http_password = Some(http_password.to_string());
        }
        if !self.headers.is_empty() {
            upload.headers = self.headers.to_vec();
        }
        if let Some(s3_region) = self.s3_region {
            upload.s3_region = Some(s3_region.to_string());
        }
        if let Some(s3_profile) = self.s3_profile {
            upload.s3_profile = Some(s3_profile.to_string());
        }
        if let Some(s3_endpoint) = self.s3_endpoint {
            upload.s3_endpoint = Some(s3_endpoint.to_string());
        }
        if let Some(ssh_key) = self.ssh_key {
            upload.ssh_key = Some(ssh_key.to_string());
        }
        if let Some(ssh_password) = self.ssh_password {
            upload.ssh_password = Some(ssh_password.to_string());
        }
        if self.ssh_ask_pass {
            upload.ssh_ask_pass = true;
        }
    }
}

/// Clear `field` on `upload` (the `--unset` half of `apr origin config`).
fn unset_upload_config_field(upload: &mut RegistryUploadAuthConfig, field: UploadConfigField) {
    match field {
        UploadConfigField::UploadUrls => upload.upload_urls.clear(),
        UploadConfigField::Token => upload.token = None,
        UploadConfigField::View => upload.view = None,
        UploadConfigField::HttpUser => upload.http_user = None,
        UploadConfigField::HttpPassword => upload.http_password = None,
        UploadConfigField::Headers => upload.headers.clear(),
        UploadConfigField::S3Region => upload.s3_region = None,
        UploadConfigField::S3Profile => upload.s3_profile = None,
        UploadConfigField::S3Endpoint => upload.s3_endpoint = None,
        UploadConfigField::SshKey => upload.ssh_key = None,
        UploadConfigField::SshPassword => upload.ssh_password = None,
        UploadConfigField::SshAskPass => upload.ssh_ask_pass = false,
    }
}

/// `apr origin config` — shows or persists the producer upload defaults in
/// the registry's `[registry.upload_auth]` section.
///
/// With no setter or `--unset` flag, prints the currently persisted
/// defaults. Otherwise each given setter replaces the stored value (lists
/// — `--upload-url`, `--header` — are replaced wholesale, not appended),
/// each `--unset FIELD` clears the stored value, and the section is
/// rewritten in place, preserving every other field of the config file.
/// Unsetting the last stored field removes the whole section.
///
/// Unlike the flags on `origin upload`/`cache generate`/`release`, the
/// setters here read nothing from the environment: only values given
/// explicitly on the command line are persisted.
///
/// # Errors
///
/// Fails when the same field is both set and `--unset` in one invocation;
/// when the registry has no `registries.d` config to record into (created
/// by `apr add`); or when the config file cannot be read, parsed, or
/// rewritten.
fn origin_config(
    config: &ApmConfig,
    updates: &UploadConfigUpdates<'_>,
    unset: &[UploadConfigField],
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let config_path = config.registry_config_path_for_update(&registry_name);
    if !config_path.exists() {
        bail!(
            "registry '{registry_name}' has no config at {}; register the registry first with \
             `{} add <url>`, then re-run this command",
            config_path.display(),
            aos_core::invocation::package_registry_command(),
        );
    }

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let rf: RegistryFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", config_path.display()))?;
    let mut upload = rf.registry.upload_auth.unwrap_or_default();

    if updates.is_empty() && unset.is_empty() {
        print_upload_config(&registry_name, &config_path, &upload, printer);
        return Ok(());
    }

    for field in unset {
        if updates.sets(*field) {
            bail!(
                "cannot both set and --unset '{}' in the same invocation",
                field.to_possible_value().map_or_else(
                    || format!("{field:?}"),
                    |value| value.get_name().to_string(),
                ),
            );
        }
        unset_upload_config_field(&mut upload, *field);
    }
    updates.apply(&mut upload);

    state::save_upload_auth(&config_path, &upload)?;
    printer.success(&format!(
        "Updated upload defaults for registry '{registry_name}'.",
    ));
    print_upload_config(&registry_name, &config_path, &upload, printer);
    Ok(())
}

/// Print the persisted upload defaults, as key/value lines or JSON.
fn print_upload_config(
    registry_name: &str,
    config_path: &Path,
    upload: &RegistryUploadAuthConfig,
    printer: &Printer,
) {
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "origin_config",
            "registry": registry_name,
            "config": config_path.display().to_string(),
            "upload_auth": upload,
        }));
        return;
    }

    printer.kv("Config", &config_path.display().to_string());
    if *upload == RegistryUploadAuthConfig::default() {
        printer.info("No upload defaults configured.");
        return;
    }
    if !upload.upload_urls.is_empty() {
        printer.kv("Upload URLs", &upload.upload_urls.join(", "));
    }
    let scalar_fields = [
        ("Token", &upload.token),
        ("View", &upload.view),
        ("HTTP user", &upload.http_user),
        ("HTTP password", &upload.http_password),
    ];
    for (label, value) in scalar_fields {
        if let Some(value) = value {
            printer.kv(label, value);
        }
    }
    if !upload.headers.is_empty() {
        printer.kv("Headers", &upload.headers.join(", "));
    }
    let scalar_fields = [
        ("S3 region", &upload.s3_region),
        ("S3 profile", &upload.s3_profile),
        ("S3 endpoint", &upload.s3_endpoint),
        ("SSH key", &upload.ssh_key),
        ("SSH password", &upload.ssh_password),
    ];
    for (label, value) in scalar_fields {
        if let Some(value) = value {
            printer.kv(label, value);
        }
    }
    if upload.ssh_ask_pass {
        printer.kv("SSH ask pass", "true");
    }
}
