//! Native AOS registry authoring, signing, release staging, and publication.
//!
//! Consumer acquisition and verification live in `aos-registry-client`; this
//! crate owns mutations and the APR command vocabulary without package runtime policy.

mod commands;
mod error;
use error::RegistryAuthoringError;
pub use commands::*;
pub mod registry;
pub mod registry_ops;
use aos_registry_client::{config, dry_run, hub_auth, provenance, security, sshkey, types};
#[cfg(test)] mod gitcmd;
#[cfg(test)] mod testutil;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result, bail};
use aos_cli_ui::output::{OutputMode, Printer};
use aos_registry_client::registry::{Registry, RegistrySet};
use aos_registry_format::consumer::*;
use aos_registry_client::types::ProfileScope;
use aos_registry_client::registry::{channel, git, keys, state};

/// Reports whether a registry subcommand honors the global `--dry-run` flag.
///
/// `--dry-run` is a promise that nothing is written, so a command that accepts
/// the flag and mutates anyway breaks it in the most damaging direction. The
/// dispatcher refuses the flag for anything absent from this list rather than
/// silently ignoring it, and [`crate::dry_run`] enforces the promise beneath
/// the handlers.
///
/// Read-only subcommands are absent on purpose. `--dry-run` means nothing for
/// them, and accepting it would suggest the flag had been considered where it
/// had not; refusing says plainly that the command never writes anyway.
///
/// `release` is accepted only when its explicit preview option is set.
/// Clap propagates that option into the global flag as well, so rejecting
/// the global value would also reject valid release previews.
fn implements_global_dry_run(command: &RegistryCommand) -> bool {
    matches!(
        command,
        RegistryCommand::Add { .. }
            | RegistryCommand::Branch { .. }
            | RegistryCommand::Cache { .. }
            | RegistryCommand::Change { .. }
            | RegistryCommand::Channel { .. }
            | RegistryCommand::Commit { .. }
            | RegistryCommand::Create { .. }
            | RegistryCommand::Disable { .. }
            | RegistryCommand::Enable { .. }
            | RegistryCommand::Keys { .. }
            | RegistryCommand::Merge { .. }
            | RegistryCommand::Origin { .. }
            | RegistryCommand::Publish { .. }
            | RegistryCommand::Pull { .. }
            | RegistryCommand::Push { .. }
            | RegistryCommand::Remove { .. }
            | RegistryCommand::Release { dry_run: true, .. }
            | RegistryCommand::Sign { .. }
            | RegistryCommand::Store { .. }
            | RegistryCommand::Tag { .. }
            | RegistryCommand::Trust { .. }
            | RegistryCommand::Unpublish { .. }
            | RegistryCommand::Web { .. }
    )
}

/// Dispatch an `apr` subcommand to its handler.
///
/// The consumer-facing lifecycle commands (`list`, `add`, `remove`) are
/// implemented in this module; everything else delegates to [`registry_ops`].
pub async fn run(
    config: &config::ApmConfig,
    command: &RegistryCommand,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    if dry_run && !implements_global_dry_run(command) {
        bail!("--dry-run is not implemented for this apr subcommand");
    }

    match command {
        RegistryCommand::List => registry_list(config, printer).await,
        RegistryCommand::Add {
            url,
            name,
            priority,
            commit,
            branch,
            channel,
            tag,
            version,
            trust_key,
            no_verify,
            no_clone,
        } => {
            registry_add(
                config,
                url,
                name.as_deref(),
                *priority,
                commit.as_deref(),
                branch.as_deref(),
                channel.as_deref(),
                tag.as_deref(),
                version.as_deref(),
                trust_key,
                *no_verify,
                !no_clone,
                printer,
            )
            .await
        }
        RegistryCommand::Remove {
            name,
            keep_local,
            force,
        } => registry_remove(config, name, *keep_local, *force, printer).await,
        RegistryCommand::Enable { name } => registry_set_enabled(config, name, true, printer).await,
        RegistryCommand::Disable { name } => {
            registry_set_enabled(config, name, false, printer).await
        }
        RegistryCommand::Trust { command } => registry_ops::run_trust(config, command, printer),
        RegistryCommand::Keys { command } => registry_ops::run_keys(config, command, printer),
        RegistryCommand::Create {
            name,
            remote,
            trust_key,
            trust_key_id,
            roster_key,
            key,
            key_id,
        } => {
            let roster = registry_ops::InitialRoster {
                trust_key: trust_key.as_deref(),
                trust_key_id: trust_key_id.as_deref(),
                roster_keys: roster_key,
            };
            registry_ops::create(
                config,
                name,
                remote.as_deref(),
                &roster,
                key.as_deref(),
                key_id.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Publish {
            store_path,
            name,
            version,
            platform,
            description,
            homepage,
            license,
            maintainer,
            sysroot,
            previous,
            source_drv,
            image_payloads,
            image_disks,
            image_infos,
            image_formats,
            image_contract_schemas,
            bless,
            no_ca,
            no_commit,
            message,
            key,
            key_id,
            registry,
        } => {
            registry_ops::publish(
                config,
                store_path,
                name.as_deref(),
                version.as_deref(),
                platform.as_deref(),
                description.as_deref(),
                homepage.as_deref(),
                license.as_deref(),
                maintainer.as_deref(),
                *sysroot,
                previous.as_deref(),
                source_drv.as_deref(),
                image_payloads,
                image_disks,
                image_infos,
                image_formats,
                image_contract_schemas,
                *bless,
                *no_ca,
                *no_commit,
                message.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Unpublish {
            package,
            version,
            platform,
            no_commit,
            message,
            key,
            key_id,
            registry,
        } => {
            registry_ops::unpublish(
                config,
                package,
                version.as_deref(),
                platform.as_deref(),
                *no_commit,
                message.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Show {
            package,
            version,
            raw,
            registry,
        } => {
            registry_ops::show(
                config,
                package,
                version.as_deref(),
                *raw,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Packages {
            platform,
            outdated,
            registry,
        } => {
            registry_ops::packages(
                config,
                platform.as_deref(),
                *outdated,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Verify {
            package,
            fix,
            registry,
        } => {
            registry_ops::verify(
                config,
                package.as_deref(),
                *fix,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Diff {
            stat,
            remote,
            registry,
        } => registry_ops::diff(config, *stat, *remote, registry.as_deref(), printer).await,
        RegistryCommand::Validate {
            package,
            platform,
            fix,
            jobs,
            registry,
        } => {
            registry_ops::validate(
                config,
                package.as_deref(),
                platform.as_deref(),
                *fix,
                *jobs,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Status { registry } => {
            registry_ops::status(config, registry.as_deref(), printer).await
        }
        RegistryCommand::Commit {
            paths,
            message,
            key,
            key_id,
            registry,
        } => {
            registry_ops::commit_changes(
                config,
                paths,
                message,
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Log {
            package,
            n,
            registry,
        } => registry_ops::log(config, package.as_deref(), *n, registry.as_deref(), printer).await,
        RegistryCommand::Branch { command } => {
            registry_ops::run_branch(config, command, printer).await
        }
        RegistryCommand::Push {
            branch,
            set_upstream,
            force,
            registry,
        } => {
            registry_ops::push(
                config,
                branch.as_deref(),
                *set_upstream,
                *force,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Pull { rebase, registry } => {
            registry_ops::pull(config, *rebase, registry.as_deref(), printer).await
        }
        RegistryCommand::Merge {
            branch,
            no_ff,
            squash,
            registry,
        } => {
            registry_ops::merge(
                config,
                branch,
                *no_ff,
                *squash,
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Channel { command } => {
            registry_ops::run_channel(config, command, printer).await
        }
        RegistryCommand::Change { command } => {
            registry_ops::run_change(config, command, printer).await
        }
        RegistryCommand::Cache { command } => {
            registry_ops::run_cache(config, command, dry_run, printer).await
        }
        RegistryCommand::Store { command } => {
            registry_ops::run_store(config, command, printer).await
        }
        RegistryCommand::Origin { command } => {
            registry_ops::run_origin(config, command, printer).await
        }
        RegistryCommand::Web { command } => registry_ops::run_web(config, command, printer).await,
        RegistryCommand::Stage { command } => {
            registry_ops::run_stage(config, command, printer).await
        }
        RegistryCommand::Release {
            semver,
            stage,
            stage_revision,
            from_stage,
            container_release,
            container_signature_input,
            container_layout,
            container_repository,
            store_path,
            name,
            version,
            platform,
            description,
            homepage,
            license,
            maintainer,
            sysroot,
            previous,
            source_drv,
            image_payloads,
            image_disks,
            image_infos,
            image_formats,
            image_contract_schemas,
            bless,
            message,
            channel,
            init_channel,
            count,
            partitions,
            key,
            key_id,
            rotate_from,
            cache_key,
            cache_url,
            cache_priority,
            no_skip,
            upload_urls,
            auth,
            dry_run,
            resume,
            registry,
            jobs,
        } => {
            registry_ops::release(
                config,
                semver,
                container_release.as_deref(),
                container_signature_input.as_deref(),
                store_path.as_deref(),
                name.as_deref(),
                version.as_deref(),
                platform.as_deref(),
                description.as_deref(),
                homepage.as_deref(),
                license.as_deref(),
                maintainer.as_deref(),
                *sysroot,
                previous.as_deref(),
                source_drv.as_deref(),
                image_payloads,
                image_disks,
                image_infos,
                image_formats,
                image_contract_schemas,
                *bless,
                message.as_deref(),
                channel.as_deref(),
                *init_channel,
                *count,
                partitions.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                rotate_from.as_deref(),
                cache_key.as_deref(),
                cache_url.as_deref(),
                *cache_priority,
                *no_skip,
                upload_urls,
                auth,
                *dry_run,
                *resume,
                registry.as_deref(),
                *jobs,
                container_layout.as_deref(),
                container_repository.as_deref(),
                stage.as_deref(),
                *stage_revision,
                from_stage.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Tag {
            name,
            message,
            key,
            key_id,
            registry,
        } => {
            registry_ops::tag(
                config,
                name,
                message.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        RegistryCommand::Sign {
            tag,
            key,
            key_id,
            registry,
        } => {
            registry_ops::sign(
                config,
                tag.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
    }
}

/// `apr list` — print every configured registry (name, URL, priority,
/// transport, tracking mode, package count, sync state), plus any local
/// authoring clones that have no `registries.d/` entry.
pub async fn registry_list(config: &config::ApmConfig, printer: &Printer) -> Result<()> {
    let configured_names: Vec<&str> = config
        .registries
        .iter()
        .map(|(cfg, _)| cfg.name.as_str())
        .collect();
    let local = registry_ops::local_registries(&config.scope.registries_path(), &configured_names);

    if printer.mode() == OutputMode::Json {
        let cache_dir = config.cache_path();
        let registries = config
            .registries
            .iter()
            .map(|(reg_config, state)| {
                let tracking = reg_config
                    .tracking_mode()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|_| "invalid".to_string());
                let packages_dir = cache_dir.join(&reg_config.name).join("packages");
                let signing_required = reg_config.signing.as_ref().map(|signing| signing.required);
                serde_json::json!({
                    "name": &reg_config.name,
                    "url": &reg_config.url,
                    "priority": reg_config.priority,
                    "enabled": reg_config.enabled,
                    "status": if reg_config.enabled { "enabled" } else { "disabled" },
                    "transport": format!("{:?}", reg_config.transport()),
                    "tracking": tracking,
                    "packages": count_packages_in_dir(&packages_dir),
                    "last_update": state.as_ref().and_then(|state| state.last_update.as_ref()),
                    "last_commit": state.as_ref().and_then(|state| state.last_commit.as_ref()),
                    "signing_required": signing_required,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!(registries));
        return Ok(());
    }

    if config.registries.is_empty() {
        printer.info(&format!(
            "No registries configured. Add one with `{} add <url>`.",
            aos_cli_ui::invocation::package_registry_command()
        ));
        print_local_registries(&local, printer);
        return Ok(());
    }

    printer.header("Configured registries:");
    printer.plain("");

    for (reg_config, state) in &config.registries {
        let status = if reg_config.enabled {
            "enabled"
        } else {
            "disabled"
        };

        let tracking = reg_config
            .tracking_mode()
            .map(|m| m.to_string())
            .unwrap_or_else(|_| "invalid".to_string());

        printer.header(&format!(
            "  {} (priority {})",
            reg_config.name, reg_config.priority
        ));
        printer.kv("URL", &reg_config.url);
        printer.kv("Status", status);
        printer.kv("Transport", &format!("{:?}", reg_config.transport()));
        printer.kv("Tracking", &tracking);

        let cache_dir = config.cache_path();
        let packages_dir = cache_dir.join(&reg_config.name).join("packages");
        let pkg_count = count_packages_in_dir(&packages_dir);
        printer.kv("Packages", &format!("{pkg_count}"));

        if let Some(s) = state {
            if let Some(ref ts) = s.last_update {
                printer.kv("Last update", ts);
            }
            if let Some(ref commit) = s.last_commit {
                let short = &commit[..commit.len().min(12)];
                printer.kv("Last commit", short);
            }
        } else {
            printer.kv(
                "Last update",
                &format!(
                    "never (run `{} update`)",
                    aos_cli_ui::invocation::package_manager_command()
                ),
            );
        }

        if let Some(ref signing) = reg_config.signing {
            printer.kv("Signing", &format!("required={}", signing.required));
        }

        printer.plain("");
    }

    print_local_registries(&local, printer);

    Ok(())
}

/// Print the `apr list` section for local clones that have no
/// `registries.d/` entry — typically registries authored with `apr create`,
/// which are otherwise invisible to consumer-side commands.
fn print_local_registries(local: &[registry_ops::LocalRegistry], printer: &Printer) {
    if local.is_empty() {
        return;
    }

    printer.header("Local registries (not configured):");
    printer.plain("");

    for reg in local {
        printer.header(&format!("  {}", reg.name));
        printer.kv("Path", &reg.path.display().to_string());
        if let Some(ref origin) = reg.origin {
            printer.kv("Remote", origin);
        }
        printer.kv("Packages", &reg.packages.to_string());
        printer.plain("");
    }

    printer.info(&format!(
        "Local registries are not used for installs until configured with `{} add <url>`.",
        aos_cli_ui::invocation::package_registry_command()
    ));
}

/// `apr add` — register a registry by writing `registries.d/<name>.toml`
/// (with at most one tracking field and optional `[registry.signing]`),
/// pinning the `--trust-key` if given, then syncing the initial clone unless
/// `--no-clone` was passed. A failed initial sync is non-fatal.
struct RegistryAddConfigToml<'a> {
    name: &'a str,
    url: &'a str,
    priority: u32,
    commit: Option<&'a str>,
    branch: Option<&'a str>,
    channel: Option<&'a str>,
    tag: Option<&'a str>,
    version: Option<&'a str>,
    trusted_key: Option<&'a security::TrustedKey>,
    no_verify: bool,
}

fn registry_add_config_toml(config: RegistryAddConfigToml<'_>) -> Result<String> {
    let mut registry = toml::map::Map::new();
    registry.insert("name".into(), toml::Value::String(config.name.to_string()));
    registry.insert("url".into(), toml::Value::String(config.url.to_string()));
    registry.insert(
        "priority".into(),
        toml::Value::Integer(config.priority.into()),
    );
    registry.insert("enabled".into(), toml::Value::Boolean(true));

    if let Some(commit) = config.commit {
        registry.insert("commit".into(), toml::Value::String(commit.to_string()));
    } else if let Some(branch) = config.branch {
        registry.insert("branch".into(), toml::Value::String(branch.to_string()));
    } else if let Some(channel) = config.channel {
        registry.insert("channel".into(), toml::Value::String(channel.to_string()));
    } else if let Some(tag) = config.tag {
        registry.insert("tag".into(), toml::Value::String(tag.to_string()));
    } else if let Some(version) = config.version {
        registry.insert("version".into(), toml::Value::String(version.to_string()));
    }

    if let Some(key) = config.trusted_key {
        let mut signing = toml::map::Map::new();
        signing.insert("required".into(), toml::Value::Boolean(true));
        signing.insert(
            "public_key".into(),
            toml::Value::String(format!(
                "{}:{}:{}",
                key.registry, key.algorithm, key.public_key
            )),
        );
        registry.insert("signing".into(), toml::Value::Table(signing));
    } else if config.no_verify {
        let mut signing = toml::map::Map::new();
        signing.insert("required".into(), toml::Value::Boolean(false));
        registry.insert("signing".into(), toml::Value::Table(signing));
    }

    let mut root = toml::map::Map::new();
    root.insert("registry".into(), toml::Value::Table(registry));
    Ok(toml::to_string_pretty(&toml::Value::Table(root))?)
}

#[allow(clippy::too_many_arguments)]
pub async fn registry_add(
    config: &config::ApmConfig,
    url: &str,
    name_override: Option<&str>,
    priority: u32,
    commit: Option<&str>,
    branch: Option<&str>,
    channel: Option<&str>,
    tag: Option<&str>,
    version: Option<&str>,
    trust_keys: &[String],
    no_verify: bool,
    clone: bool,
    printer: &Printer,
) -> Result<()> {
    let name = name_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| derive_registry_name(url));
    validate_registry_name(&name)?;

    if config.find_registry(&name).is_some() {
        bail!(
            "registry '{}' already exists. Remove it first with `{} remove {}`.",
            name,
            aos_cli_ui::invocation::package_registry_command(),
            name
        );
    }

    if let Some(c) = commit {
        validate_commit_hash(c)?;
    }
    // Validate version constraint if provided.
    if let Some(v) = version {
        semver::VersionReq::parse(v)
            .map_err(|e| anyhow::anyhow!("invalid version constraint '{}': {}", v, e))?;
    }
    if let Some(b) = branch {
        validate_branch_name(b)?;
    }
    if let Some(c) = channel {
        validate_channel_name(c)?;
    }
    if let Some(t) = tag {
        validate_git_ref_name(t)?;
    }
    let trusted_keys = trust_keys
        .iter()
        .map(|key| {
            let (registry, algorithm, public_key) = security::parse_signing_key(key)?;
            if registry != name {
                bail!(
                    "--trust-key belongs to registry '{}', expected '{}'",
                    registry,
                    name,
                );
            }
            Ok(security::TrustedKey {
                registry,
                algorithm,
                fingerprint: security::key_fingerprint(&public_key),
                public_key,
                source: security::KeySource::Tofu,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    printer.header(&format!("Adding registry '{name}'..."));
    printer.kv("URL", url);
    printer.kv("Priority", &priority.to_string());

    // A brand-new registry is a self-sufficient definition, written to the
    // writable config layer (`/var/lib/apm/config` for --system), never the
    // read-only `/etc/apm` seed.
    let registries_dir = config.scope.writable_config_dir().join("registries.d");
    fs::create_dir_all(&registries_dir)
        .with_context(|| format!("creating {}", registries_dir.display()))?;

    let toml_path = registries_dir.join(format!("{name}.toml"));

    let tracking = if let Some(c) = commit {
        format!("commit:{}", c.chars().take(12).collect::<String>())
    } else if let Some(b) = branch {
        format!("branch:{b}")
    } else if let Some(c) = channel {
        format!("channel:{c}")
    } else if let Some(t) = tag {
        format!("tag:{t}")
    } else if let Some(v) = version {
        format!("version:{v}")
    } else {
        "default".to_string()
    };

    if tracking != "default" {
        printer.kv("Tracking", &tracking);
    }
    if no_verify && trusted_keys.is_empty() {
        // Verification is fail-closed by default; the explicit opt-out is
        // recorded in the config so the choice is visible and auditable.
        printer.kv("Signing", "verification disabled (--no-verify)");
    }

    let toml_content = registry_add_config_toml(RegistryAddConfigToml {
        name: &name,
        url,
        priority,
        commit,
        branch,
        channel,
        tag,
        version,
        trusted_key: trusted_keys.first(),
        no_verify,
    })?;
    fs::write(&toml_path, &toml_content)
        .with_context(|| format!("writing {}", toml_path.display()))?;
    for key in &trusted_keys {
        security::KeyStore::new(config.scope.trusted_keys_dirs()).store(key)?;
    }
    if !trusted_keys.is_empty() {
        printer.kv(
            "Signing",
            &format!("{} trusted key(s) pinned", trusted_keys.len()),
        );
    }

    let pkg_cmd = aos_cli_ui::invocation::package_manager_command();

    if !clone {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "action": "registry_add",
                "status": "added",
                "registry": &name,
                "name": &name,
                "url": url,
                "priority": priority,
                "enabled": true,
                "tracking": &tracking,
                "clone": false,
                "synced": false,
                "config": toml_path.to_string_lossy(),
                "signing_required": !no_verify,
                "verification_disabled": no_verify,
                "trusted_key_pinned": !trusted_keys.is_empty(),
                "trusted_keys_pinned": trusted_keys.len(),
            }));
            return Ok(());
        }
        printer.success(&format!(
            "Registry '{name}' added. Run `{pkg_cmd} update --registry {name}` to sync package metadata."
        ));
        return Ok(());
    }

    printer.success(&format!("Registry '{name}' added."));

    if aos_cli_ui::invocation::binary_name() == "apr" {
        materialize_authoring_clone(config, &name, url, branch, tag, commit, printer)?;
    }

    // Materialise the local clone under the scope's registry-storage directory
    // by syncing now. The config was just written to disk, so reload the scope
    // to pick it up and reuse the regular update path (clone/fetch + state
    // save-back). A sync failure is non-fatal: the registry is registered and
    // can be retried with `<pkg> update`.
    let synced = config::ApmConfig::load(config.scope)?;
    let sync_printer = if printer.mode() == OutputMode::Json {
        Printer::new(0, true, false)
    } else {
        printer.clone()
    };
    let sync_result = update::run(&synced, Some(&name), &sync_printer).await;
    if let Err(e) = sync_result {
        if printer.mode() == OutputMode::Json {
            let packages_dir = config.cache_path().join(&name).join("packages");
            printer.json(&serde_json::json!({
                "action": "registry_add",
                "status": "added",
                "registry": &name,
                "name": &name,
                "url": url,
                "priority": priority,
                "enabled": true,
                "tracking": &tracking,
                "clone": true,
                "synced": false,
                "sync_error": e.to_string(),
                "packages": count_packages_in_dir(&packages_dir),
                "config": toml_path.to_string_lossy(),
                "signing_required": !no_verify,
                "verification_disabled": no_verify,
                "trusted_key_pinned": !trusted_keys.is_empty(),
                "trusted_keys_pinned": trusted_keys.len(),
            }));
            return Ok(());
        }
        printer.warning(&format!(
            "Registry '{name}' was added, but the initial sync failed: {e}\n\
             Retry with `{pkg_cmd} update --registry {name}`."
        ));
    }
    if printer.mode() == OutputMode::Json {
        let reloaded = config::ApmConfig::load(config.scope)?;
        let state = reloaded
            .registries
            .iter()
            .find(|(cfg, _)| cfg.name == name)
            .and_then(|(_, state)| state.as_ref());
        let packages_dir = config.cache_path().join(&name).join("packages");
        printer.json(&serde_json::json!({
            "action": "registry_add",
            "status": "added",
            "registry": &name,
            "name": &name,
            "url": url,
            "priority": priority,
            "enabled": true,
            "tracking": &tracking,
            "clone": true,
            "synced": true,
            "sync_error": null,
            "packages": count_packages_in_dir(&packages_dir),
            "last_commit": state.and_then(|state| state.last_commit.as_ref()),
            "config": toml_path.to_string_lossy(),
            "signing_required": !no_verify,
            "verification_disabled": no_verify,
            "trusted_key_pinned": !trusted_keys.is_empty(),
            "trusted_keys_pinned": trusted_keys.len(),
        }));
    }

    Ok(())
}

/// Materializes the writable producer clone used by `apr add`.
fn materialize_authoring_clone(
    config: &config::ApmConfig,
    name: &str,
    url: &str,
    branch: Option<&str>,
    tag: Option<&str>,
    commit: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let clone_dir = config.scope.registries_path().join(name);
    if clone_dir.join(".git").is_dir() {
        return Ok(());
    }
    if clone_dir.exists() {
        fs::remove_dir_all(&clone_dir).with_context(|| {
            format!(
                "removing consumer metadata tree before cloning {}",
                clone_dir.display()
            )
        })?;
    }
    if let Some(parent) = clone_dir.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    let normalized = url.strip_prefix("git+").unwrap_or(url);
    clone_authoring_registry(&clone_dir, normalized, branch, tag, commit)
        .with_context(|| format!("cloning registry '{name}' from {url}"))?;

    printer.info(&format!("Authoring clone ready at {}", clone_dir.display()));
    Ok(())
}

/// Clone `url` into `clone_dir` for authoring, then check out the requested
/// ref, using libgit2 for smart transports (local, `git://`, `ssh://`) and the
/// pure-Rust dumb-HTTP reader for static `http(s)://` origins.
fn clone_authoring_registry(
    clone_dir: &std::path::Path,
    url: &str,
    branch: Option<&str>,
    tag: Option<&str>,
    commit: Option<&str>,
) -> Result<()> {
    if url.starts_with("http://") || url.starts_with("https://") {
        // libgit2 cannot read the static dumb-HTTP object tree; init locally
        // and fetch through the pure-Rust reader.
        let repo = init_sha256_authoring_repository(clone_dir)?;
        repo.remote("origin", url).context("adding origin remote")?;
        let refspecs = vec![
            "+refs/heads/*:refs/remotes/origin/*".to_string(),
            "+refs/tags/*:refs/tags/*".to_string(),
            // Capture the origin's default branch so a bare clone can check it
            // out, mirroring `RepoBuilder`/`git clone` on smart transports.
            "+HEAD:refs/remotes/origin/HEAD".to_string(),
        ];
        let dir = clone_dir.to_path_buf();
        let fetch_url = url.to_string();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(aos_registry_client::registry::repo::fetch(&dir, &fetch_url, &refspecs))
        })
        .context("fetching registry objects")?;

        // With no explicit ref, dumb-HTTP has no worktree checked out yet;
        // resolve and check out the origin's default branch.
        let default_branch;
        let effective_branch = if branch.is_none() && tag.is_none() && commit.is_none() {
            default_branch = default_remote_branch(&repo);
            default_branch.as_deref()
        } else {
            branch
        };
        return checkout_authoring_ref(&repo, effective_branch, tag, commit);
    }

    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(aos_registry_client::registry::repo::credentials);
    let mut fetch_options = git2::FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);
    let mut builder = git2::build::RepoBuilder::new();
    builder.fetch_options(fetch_options);
    // RepoBuilder checks out the remote HEAD; only an explicit ref needs more.
    let repo = builder
        .clone(url, clone_dir)
        .with_context(|| format!("cloning {url}"))?;
    checkout_authoring_ref(&repo, branch, tag, commit)
}

/// Initializes the non-bare SHA-256 repository used by a producer clone.
fn init_sha256_authoring_repository(clone_dir: &Path) -> Result<git2::Repository> {
    let mut options = git2::RepositoryInitOptions::new();
    options.object_format(git2::ObjectFormat::Sha256);
    git2::Repository::init_opts(clone_dir, &options)
        .with_context(|| format!("initializing {}", clone_dir.display()))
}

/// Resolve the origin's default branch (the branch its `HEAD` points at) from
/// the fetched `refs/remotes/origin/*`, by matching the captured
/// `refs/remotes/origin/HEAD` object id. Returns `None` for an empty origin.
fn default_remote_branch(repo: &git2::Repository) -> Option<String> {
    let head_oid = repo.refname_to_id("refs/remotes/origin/HEAD").ok()?;
    let references = repo.references_glob("refs/remotes/origin/*").ok()?;
    for reference in references {
        let Ok(reference) = reference else { continue };
        let Ok(name) = reference.name() else { continue };
        if name.ends_with("/HEAD") {
            continue;
        }
        if reference.target() == Some(head_oid) {
            return name
                .strip_prefix("refs/remotes/origin/")
                .map(ToString::to_string);
        }
    }
    None
}

/// Check out the branch, tag, commit, or remote HEAD an authoring clone wants.
fn checkout_authoring_ref(
    repo: &git2::Repository,
    branch: Option<&str>,
    tag: Option<&str>,
    commit: Option<&str>,
) -> Result<()> {
    if let Some(branch) = branch {
        let remote_ref = format!("refs/remotes/origin/{branch}");
        let object = repo
            .revparse_single(&remote_ref)
            .with_context(|| format!("resolving origin/{branch}"))?;
        let target = object
            .peel_to_commit()
            .context("remote branch is not a commit")?;
        repo.branch(branch, &target, true)
            .with_context(|| format!("creating local branch '{branch}'"))?;
        repo.checkout_tree(&object, None)
            .with_context(|| format!("checking out '{branch}'"))?;
        repo.set_head(&format!("refs/heads/{branch}"))
            .with_context(|| format!("switching to '{branch}'"))?;
    } else if let Some(spec) = tag.or(commit) {
        let object = repo
            .revparse_single(spec)
            .with_context(|| format!("resolving '{spec}'"))?;
        let target = object.peel_to_commit().context("target is not a commit")?;
        repo.checkout_tree(&object, None)
            .with_context(|| format!("checking out '{spec}'"))?;
        repo.set_head_detached(target.id())
            .with_context(|| format!("detaching HEAD at '{spec}'"))?;
    }
    // No branch resolved (e.g. an empty origin): nothing to check out. For
    // smart transports `RepoBuilder` has already checked out the remote HEAD.
    Ok(())
}

/// Version-control summary of the git repository at or above `dir`: the short
/// `HEAD` commit, the branch name, and whether the working tree has
/// uncommitted tracked changes.
///
/// Reads through libgit2, so it works without the `git` CLI on `PATH`. Every
/// field degrades to `None`/`false` when it cannot be determined; this drives
/// the best-effort `aos describe` output.
pub fn local_git_info(dir: &Path) -> (Option<String>, Option<String>, bool) {
    let Ok(repo) = git2::Repository::discover(dir) else {
        return (None, None, false);
    };
    let head = repo.head().ok();
    let branch = head
        .as_ref()
        .and_then(|h| h.shorthand().ok())
        .map(ToString::to_string);
    let commit = head
        .as_ref()
        .and_then(|h| h.peel_to_commit().ok())
        .and_then(|c| {
            let short = c.as_object().short_id().ok()?;
            short.as_str().ok().map(ToString::to_string)
        });
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(false);
    let dirty = repo
        .statuses(Some(&mut opts))
        .map(|statuses| !statuses.is_empty())
        .unwrap_or(false);
    (commit, branch, dirty)
}

/// `apr remove` — delete a registry's config file, metadata cache, local
/// clone (unless `--keep-local`), and pinned trusted keys.
///
/// Refuses to delete an authoring clone with uncommitted or unpushed work
/// unless `--force` is passed. Installed packages are deliberately left
/// untouched; they become orphans visible via `apm orphans`.
pub async fn registry_remove(
    config: &config::ApmConfig,
    name: &str,
    keep_local: bool,
    force: bool,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(name)?;
    let clone_dir = config.scope.registries_path().join(name);

    // A registry can exist as a local authoring clone (`apr create`) without
    // a registries.d entry; accept those too so everything `apr list` shows
    // can be removed.
    if config.find_registry(name).is_none() && !clone_dir.is_dir() {
        return Err(RegistryAuthoringError::RegistryError {
            message: format!("registry '{name}' not found"),
        }
        .into());
    }

    if !keep_local
        && !force
        && let Some(reason) = registry_ops::authoring_clone_precious(&clone_dir)?
    {
        return Err(RegistryAuthoringError::RegistryError {
            message: format!(
                "registry '{name}' has a local authoring clone at {} with {reason}.\n\
                 Push it first, keep it with --keep-local, or delete it anyway with --force.",
                clone_dir.display(),
            ),
        }
        .into());
    }

    // Removing a registry is a config operation over user-owned paths
    // (`registries.d/`, the local clone, the metadata cache, trusted keys). It
    // deliberately does NOT touch the package profile under
    // `/var/lib/profiles`: that is `apm`'s domain, requires privileges an
    // unprivileged `apr` invocation may not have, and gating a config delete on
    // installed-package state conflates the two tools. Any packages still
    // installed from this registry become orphans; `apm orphans` surfaces them.
    let toml_path = registry_config_path_for_removal(config, name)?;
    let toml_existed = toml_path.exists();

    if toml_path.exists() {
        fs::remove_file(&toml_path).with_context(|| format!("removing {}", toml_path.display()))?;
    }

    let mut cache_removed = false;
    let mut local_removed = false;
    if !keep_local {
        let cache_dir = config.cache_path().join(name);
        if cache_dir.exists() {
            let _ = fs::remove_dir_all(&cache_dir);
            cache_removed = !cache_dir.exists();
        }

        if clone_dir.exists() {
            let _ = fs::remove_dir_all(&clone_dir);
            local_removed = !clone_dir.exists();
        }
    }

    // Remove the runtime pin from the writable trusted-keys store and mask any
    // colocated read-only seed anchor.
    let trusted_keys_removed =
        security::KeyStore::new(config.scope.trusted_keys_dirs()).remove(name)?;

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "registry_remove",
            "status": "removed",
            "registry": name,
            "name": name,
            "keep_local": keep_local,
            "force": force,
            "config": toml_path.to_string_lossy(),
            "config_removed": toml_existed && !toml_path.exists(),
            "local": clone_dir.to_string_lossy(),
            "local_removed": local_removed,
            "cache_removed": cache_removed,
            "trusted_keys_removed": trusted_keys_removed,
            "orphan_command": format!("{} orphans", aos_cli_ui::invocation::package_manager_command()),
        }));
        return Ok(());
    }

    printer.success(&format!("Registry '{name}' removed."));
    printer.info(&format!(
        "Any packages installed from '{name}' are now orphaned; review them with `{} orphans`.",
        aos_cli_ui::invocation::package_manager_command()
    ));

    Ok(())
}

/// `apm registry enable|disable` — toggle whether a registry participates in
/// resolution and updates, while keeping its config, local clone, cache, and
/// trusted keys intact.
pub async fn registry_set_enabled(
    config: &config::ApmConfig,
    name: &str,
    enabled: bool,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(name)?;
    let (reg_config, _) = config
        .find_registry(name)
        .ok_or_else(|| RegistryAuthoringError::RegistryError {
            message: format!("registry '{name}' not found"),
        })?;

    let toml_path = config.registry_overlay_path(name);
    let previous_enabled = reg_config.enabled;
    write_registry_enabled(&toml_path, enabled)?;

    let action = if enabled {
        "registry_enable"
    } else {
        "registry_disable"
    };
    let status = if previous_enabled == enabled {
        "unchanged"
    } else if enabled {
        "enabled"
    } else {
        "disabled"
    };

    if printer.mode() == OutputMode::Json {
        let packages_dir = config.cache_path().join(name).join("packages");
        printer.json(&serde_json::json!({
            "action": action,
            "status": status,
            "registry": name,
            "name": name,
            "enabled": enabled,
            "previous_enabled": previous_enabled,
            "changed": previous_enabled != enabled,
            "config": toml_path.to_string_lossy(),
            "packages": count_packages_in_dir(&packages_dir),
        }));
        return Ok(());
    }

    match (enabled, previous_enabled == enabled) {
        (true, true) => printer.info(&format!("Registry '{name}' is already enabled.")),
        (true, false) => printer.success(&format!("Registry '{name}' enabled.")),
        (false, true) => printer.info(&format!("Registry '{name}' is already disabled.")),
        (false, false) => printer.success(&format!("Registry '{name}' disabled.")),
    }

    Ok(())
}

/// Persist a registry's `enabled` flag to the writable config layer.
///
/// When the writable-layer file already exists (an operator-added definition
/// or a prior overlay), its `enabled` field is updated in place, preserving
/// every other field. When it does not exist (a *seeded* registry), a minimal
/// `[registry]` overlay carrying only `enabled` is written, so the registry's
/// url/signing keep inheriting from the `/etc` seed rather than being shadowed
/// by a full copy.
///
/// # Errors
///
/// Returns an error when an existing file cannot be read or parsed, when the
/// parent directory cannot be created, or when the file cannot be written.
fn write_registry_enabled(path: &std::path::Path, enabled: bool) -> Result<()> {
    let mut root: toml::Value = if path.exists() {
        let content =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        toml::Value::Table(toml::map::Map::new())
    };

    let table = root
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{}: top level is not a TOML table", path.display()))?;
    let registry = table
        .entry("registry".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{}: [registry] is not a TOML table", path.display()))?;
    registry.insert("enabled".to_string(), toml::Value::Boolean(enabled));

    let rendered = toml::to_string_pretty(&root)?;
    fs::write(path, rendered).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive a registry name from its URL: the last path segment with any
/// trailing `/` or `.git` stripped, filtered to `[A-Za-z0-9_-]`.
fn derive_registry_name(url: &str) -> String {
    let cleaned = url.trim_end_matches('/').trim_end_matches(".git");
    let name = cleaned.rsplit('/').next().unwrap_or("unknown");
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
}

/// Count package TOML files in a registry's sharded `packages/` directory
/// (`packages/<first-letter>/<name>.toml`). Unreadable directories count as
/// zero rather than erroring — this only feeds informational output.
fn count_packages_in_dir(dir: &std::path::Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };

    let mut count = 0;
    for letter_entry in entries.flatten() {
        let letter_path = letter_entry.path();
        if !letter_path.is_dir() {
            continue;
        }
        let Ok(sub) = fs::read_dir(&letter_path) else {
            continue;
        };
        for entry in sub.flatten() {
            if entry
                .path()
                .extension()
                .map(|e| e == "toml")
                .unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    count
}

/// Return the writable-layer config file that `registry remove` should delete.
///
/// Removal only ever deletes from the writable layer
/// (`/var/lib/apm/config` for system scope). A registry that is (also) defined
/// by a read-only seed below it — typically `/etc/apm`, baked into the image —
/// cannot be removed this way: deleting the writable file would leave it
/// visible from the seed, and apm never writes `/etc`. Such a removal is
/// refused with guidance to blank the seed through signed host configuration.
fn registry_config_path_for_removal(config: &config::ApmConfig, name: &str) -> Result<PathBuf> {
    if registry_defined_by_seed(config, name) {
        return Err(RegistryAuthoringError::RegistryError {
            message: format!(
                "registry '{name}' is defined by a read-only seed (e.g. /etc/apm) that apm \
                 cannot modify. To remove a seeded registry, blank its seed file \
                 (replace the contents of registries.d/{name}.toml) through signed host.nix."
            ),
        }
        .into());
    }

    Ok(config
        .scope
        .writable_config_dir()
        .join("registries.d")
        .join(format!("{name}.toml")))
}

/// Whether a layer strictly below the writable one defines registry `name`.
///
/// A "definition" is a non-blank `registries.d/{name}.toml` that contributes a
/// `url`. Seeds always carry a `url`; a writable-layer overlay that only
/// adjusts state or `enabled` does not. Used to refuse removing a seeded
/// registry (which apm cannot delete) — see [`registry_config_path_for_removal`].
fn registry_defined_by_seed(config: &config::ApmConfig, name: &str) -> bool {
    let layers = config.scope.config_layers();
    // The last entry is the writable layer; everything below it is a seed.
    let seed_layers = &layers[..layers.len().saturating_sub(1)];
    seed_layers.iter().any(|layer| {
        config::registry_file_has_url(&layer.join("registries.d").join(format!("{name}.toml")))
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_client::config::ApmConfig;
    use aos_registry_client::types::*;
    use tempfile::TempDir;


    #[test]
    fn authoring_repository_uses_sha256_object_format() {
        let clone_dir = TempDir::new().unwrap();
        let repo = init_sha256_authoring_repository(clone_dir.path()).unwrap();

        assert!(!repo.is_bare());
        assert_eq!(repo.object_format(), git2::ObjectFormat::Sha256);
        assert_eq!(repo.path(), clone_dir.path().join(".git"));
    }



    fn make_config(
        tmp: &TempDir,
        registries: Vec<(RegistryConfig, Option<types::RegistryState>)>,
    ) -> ApmConfig {
        let config_dir = tmp.path().join("config");
        let registries_dir = config_dir.join("registries.d");
        fs::create_dir_all(&registries_dir).unwrap();

        for (reg_config, _) in &registries {
            let content = format!(
                "[registry]\nname = \"{}\"\nurl = \"{}\"\npriority = {}\n",
                reg_config.name, reg_config.url, reg_config.priority,
            );
            fs::write(
                registries_dir.join(format!("{}.toml", reg_config.name)),
                &content,
            )
            .unwrap();
        }

        let profile_dir = tmp.path().join("profile");
        fs::create_dir_all(profile_dir.join("meta")).unwrap();
        fs::write(
            profile_dir.join("state.json"),
            r#"{"current_generation": 0, "next_generation": 1}"#,
        )
        .unwrap();

        ApmConfig {
            settings: ApmSettings::default(),
            registries,
            scope: ProfileScope::User,
        }
    }



    fn reg_config(name: &str, priority: u32) -> RegistryConfig {
        RegistryConfig {
            name: name.into(),
            url: format!("https://registry.example.com/{name}"),
            priority,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        }
    }



    #[test]
    fn derive_name_from_https_url() {
        assert_eq!(
            derive_registry_name("https://registry.aos.dev/core"),
            "core"
        );
    }



    #[test]
    fn derive_name_from_git_url() {
        assert_eq!(
            derive_registry_name("git+https://github.com/andyl/registry.git"),
            "registry"
        );
    }



    #[test]
    fn derive_name_trailing_slash() {
        assert_eq!(
            derive_registry_name("https://registry.aos.dev/extra/"),
            "extra"
        );
    }



    #[tokio::test]
    async fn registry_list_shows_registries() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(
            &tmp,
            vec![
                (reg_config("aos-core", 500), None),
                (
                    reg_config("aos-extra", 400),
                    Some(types::RegistryState {
                        last_commit: Some("deadbeef1234".into()),
                        last_update: Some("2026-02-16T12:00:00Z".into()),
                        ..types::RegistryState::default()
                    }),
                ),
            ],
        );

        let printer = Printer::new(0, true, false);
        let result = registry_list(&config, &printer).await;
        assert!(result.is_ok());
    }



    #[tokio::test]
    async fn registry_list_empty() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);

        let printer = Printer::new(0, true, false);
        let result = registry_list(&config, &printer).await;
        assert!(result.is_ok());
    }



    #[tokio::test]
    async fn registry_add_creates_config_file() {
        let tmp = TempDir::new().unwrap();

        let config_dir = tmp.path().join("config-add");
        fs::create_dir_all(config_dir.join("registries.d")).unwrap();

        let name = derive_registry_name("https://registry.aos.dev/core");
        assert_eq!(name, "core");

        let toml_content = format!(
            "[registry]\nname = \"{name}\"\nurl = \"https://registry.aos.dev/core\"\npriority = 500\nenabled = true\n",
        );
        let toml_path = config_dir.join("registries.d").join(format!("{name}.toml"));
        fs::write(&toml_path, &toml_content).unwrap();

        assert!(toml_path.exists());
        let content = fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("name = \"core\""));
        assert!(content.contains("https://registry.aos.dev/core"));
        assert!(content.contains("priority = 500"));
    }



    #[test]
    fn registry_add_config_toml_escapes_url_and_tracking_fields() {
        let content = registry_add_config_toml(RegistryAddConfigToml {
            name: "quoted-url",
            url: "file:///tmp/registry with \"quotes\"\nand newline",
            priority: 750,
            commit: None,
            branch: Some("feature/quoted-url"),
            channel: None,
            tag: None,
            version: None,
            trusted_key: None,
            no_verify: true,
        })
        .unwrap();

        let parsed: types::RegistryFile = toml::from_str(&content).unwrap();
        assert_eq!(parsed.registry.name.as_deref(), Some("quoted-url"));
        assert_eq!(
            parsed.registry.url.as_deref(),
            Some("file:///tmp/registry with \"quotes\"\nand newline")
        );
        assert_eq!(parsed.registry.priority, 750);
        assert!(parsed.registry.enabled);
        assert_eq!(
            parsed.registry.branch.as_deref(),
            Some("feature/quoted-url")
        );
        assert_eq!(parsed.registry.signing.unwrap().required, false);
    }



    #[tokio::test]
    async fn registry_add_rejects_duplicate() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![(reg_config("core", 500), None)]);

        let printer = Printer::new(0, true, false);
        let result = registry_add(
            &config,
            "https://registry.aos.dev/core",
            None,
            500,
            None,
            None,
            None,
            None,
            None,
            &[],
            false,
            false,
            &printer,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already exists"), "got: {err}");
    }



    #[tokio::test]
    async fn registry_remove_not_found() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);

        let printer = Printer::new(0, true, false);
        let result = registry_remove(&config, "nonexistent", false, false, &printer).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"), "got: {err}");
    }



    #[test]
    fn registry_config_path_for_removal_targets_writable_layer() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);
        // A registry that no read-only seed defines resolves to the writable
        // layer, never the `/etc` seed. (The unique name is absent from any
        // real seed dir, so the seed check is deterministically false.)
        let path = registry_config_path_for_removal(&config, "operator-added-xyz").unwrap();
        assert!(path.starts_with(config.scope.writable_config_dir()));
        assert!(path.ends_with("registries.d/operator-added-xyz.toml"));
    }



    #[test]
    fn cache_upload_auth_args_map_to_backend_options() {
        let args = CacheUploadAuthArgs {
            token: Some("token".into()),
            view: Some("ops".into()),
            http_user: Some("user".into()),
            http_password: Some("pass".into()),
            header: vec!["X-Test: yes".into()],
            s3_region: Some("us-west-2".into()),
            s3_profile: Some("prod".into()),
            s3_endpoint: Some("https://minio.example".into()),
            ssh_key: Some("/tmp/key".into()),
            ssh_password: Some("ssh-pass".into()),
            ssh_ask_pass: true,
        };

        let auth = args.auth_options();
        assert_eq!(auth.token.as_deref(), Some("token"));
        assert_eq!(auth.view, "ops");
        assert_eq!(auth.http_user.as_deref(), Some("user"));
        assert_eq!(auth.http_password.as_deref(), Some("pass"));
        assert_eq!(auth.headers, vec!["X-Test: yes"]);
        assert_eq!(auth.s3_region.as_deref(), Some("us-west-2"));
        assert_eq!(auth.s3_profile.as_deref(), Some("prod"));
        assert_eq!(auth.s3_endpoint.as_deref(), Some("https://minio.example"));
        assert_eq!(auth.ssh_key.as_deref(), Some("/tmp/key"));
        assert_eq!(auth.ssh_password.as_deref(), Some("ssh-pass"));
        assert!(auth.ssh_ask_pass);
    }



    #[test]
    fn cache_upload_auth_args_merge_config_defaults_and_overrides() {
        let config = RegistryUploadAuthConfig {
            upload_urls: Vec::new(),
            token: Some("config-token".into()),
            view: Some("prod".into()),
            http_user: Some("config-user".into()),
            http_password: Some("config-pass".into()),
            headers: vec!["X-Config: yes".into()],
            s3_region: Some("us-east-1".into()),
            s3_profile: Some("default".into()),
            s3_endpoint: Some("https://config-minio.example".into()),
            ssh_key: Some("/etc/apm/config-key".into()),
            ssh_password: Some("config-ssh-pass".into()),
            ssh_ask_pass: true,
        };
        let args = CacheUploadAuthArgs {
            token: Some("cli-token".into()),
            view: None,
            http_user: None,
            http_password: Some("cli-pass".into()),
            header: vec!["X-Cli: yes".into()],
            s3_region: None,
            s3_profile: Some("cli-profile".into()),
            s3_endpoint: None,
            ssh_key: Some("/tmp/cli-key".into()),
            ssh_password: None,
            ssh_ask_pass: false,
        };

        let auth = args.auth_options_with_config(Some(&config));
        assert_eq!(auth.token.as_deref(), Some("cli-token"));
        assert_eq!(auth.view, "prod");
        assert_eq!(auth.http_user.as_deref(), Some("config-user"));
        assert_eq!(auth.http_password.as_deref(), Some("cli-pass"));
        assert_eq!(auth.headers, vec!["X-Cli: yes"]);
        assert_eq!(auth.s3_region.as_deref(), Some("us-east-1"));
        assert_eq!(auth.s3_profile.as_deref(), Some("cli-profile"));
        assert_eq!(
            auth.s3_endpoint.as_deref(),
            Some("https://config-minio.example")
        );
        assert_eq!(auth.ssh_key.as_deref(), Some("/tmp/cli-key"));
        assert_eq!(auth.ssh_password.as_deref(), Some("config-ssh-pass"));
        assert!(auth.ssh_ask_pass);
    }



    #[test]
    fn count_packages_empty_dir() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(count_packages_in_dir(tmp.path()), 0);
    }



    #[test]
    fn count_packages_with_toml_files() {
        let tmp = TempDir::new().unwrap();
        let c_dir = tmp.path().join("c");
        fs::create_dir_all(&c_dir).unwrap();
        fs::write(c_dir.join("curl.toml"), "test").unwrap();

        let z_dir = tmp.path().join("z");
        fs::create_dir_all(&z_dir).unwrap();
        fs::write(z_dir.join("zlib.toml"), "test").unwrap();
        fs::write(z_dir.join("zstd.toml"), "test").unwrap();

        assert_eq!(count_packages_in_dir(tmp.path()), 3);
    }
}
