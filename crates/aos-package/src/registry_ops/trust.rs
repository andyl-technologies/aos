//! Trust pins, committed signing-key rosters, and retirement re-signing.

use crate::config::ApmConfig;
use crate::registry::keys::{KeysToml, RevokedKey, RosterKey};
use crate::registry::verify::parse_tag_object;
use crate::registry::{channel, keys, objectstore, state};
use crate::registry_ops::channels::{
    read_channel_partition_map, semver_tag_object_map, update_channel_frontier,
    write_channel_partition_tag,
};
use crate::registry_ops::config::{configured_registry_names, resolve_registry_name};
use crate::registry_ops::git::{commit_registry, git, refresh_registry_object_store};

use crate::registry_ops::provenance::{
    PACKAGE_PROVENANCE_TRANSPARENCY_LOG, read_package_provenance_transparency_log_state,
};
use crate::registry_ops::signing::{
    ResolvedSigningKey, resolve_producer_signing_key, resolve_signing_key_source,
    trusted_key_from_line,
};
use crate::registry_ops::tags::release_tag_version;
use crate::security::{
    KeyStore, key_fingerprint, parse_signing_key, verify_payload_signature, verify_tag_signature,
};
use crate::types::{SigningKeySource, SigningKeySpec, validate_registry_name};
use crate::{KeysCommand, TrustCommand, sshkey};
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use std::path::Path;

/// `apr trust` subcommands for the consumer-side pinned trust store.
///
/// `pin` stores a `registry:Ed25519:<base64>` public key for a registry
/// (`--replace` drops existing pins first), `list` shows the pinned keys
/// per registry, and `remove` deletes a registry's pins.
///
/// # Errors
///
/// Fails when the registry name is not safe for trusted-key path use, the key
/// line does not parse or names a different registry, or the trust store
/// cannot be read or written.
pub fn run_trust(config: &ApmConfig, command: &TrustCommand, printer: &Printer) -> Result<()> {
    let store = KeyStore::new(config.scope.trusted_keys_dirs());
    match command {
        TrustCommand::Pin {
            registry,
            key,
            replace,
        } => {
            validate_registry_name(registry)?;
            let trusted = trusted_key_from_line(registry, key)?;

            if crate::dry_run::active() {
                let verb = if *replace {
                    "Would re-pin"
                } else {
                    "Would pin"
                };
                printer.info(&format!(
                    "{verb} trust key for registry '{registry}' ({})",
                    trusted.fingerprint
                ));
                if *replace {
                    printer.info("  --replace: any existing pinned key would be removed first.");
                }
                printer.info("Dry run: the trusted-key store is unchanged.");
                return Ok(());
            }

            if *replace {
                let _ = store.remove(registry)?;
            }
            store.store(&trusted)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "trust_pin",
                    "status": if *replace { "replaced" } else { "pinned" },
                    "registry": registry,
                    "replace": *replace,
                    "key": key,
                    "algorithm": trusted.algorithm,
                    "fingerprint": trusted.fingerprint,
                    "source": format!("{:?}", trusted.source),
                }));
                return Ok(());
            }
            let action = if *replace { "Re-pinned" } else { "Pinned" };
            printer.success(&format!(
                "{action} trust key for registry '{}' ({})",
                registry, trusted.fingerprint
            ));
            Ok(())
        }
        TrustCommand::List { registry } => {
            let registries = match registry {
                Some(name) => {
                    validate_registry_name(name)?;
                    vec![name.clone()]
                }
                None => configured_registry_names(config),
            };
            if printer.mode() == OutputMode::Json {
                let entries = registries
                    .iter()
                    .map(|name| {
                        let keys = store
                            .lookup_all(name)
                            .iter()
                            .map(|key| {
                                serde_json::json!({
                                    "algorithm": &key.algorithm,
                                    "fingerprint": &key.fingerprint,
                                    "source": format!("{:?}", key.source),
                                })
                            })
                            .collect::<Vec<_>>();
                        serde_json::json!({
                            "registry": name,
                            "keys": keys,
                        })
                    })
                    .collect::<Vec<_>>();
                printer.json(&serde_json::json!(entries));
                return Ok(());
            }
            if registries.is_empty() {
                printer.info("No configured registries to inspect.");
                return Ok(());
            }
            for name in registries {
                let keys = store.lookup_all(&name);
                if keys.is_empty() {
                    printer.plain(&format!("{name}: no pinned keys"));
                    continue;
                }
                for key in keys {
                    printer.plain(&format!(
                        "{}: {} {} ({:?})",
                        name, key.algorithm, key.fingerprint, key.source
                    ));
                }
            }
            Ok(())
        }
        TrustCommand::Remove { registry } => {
            validate_registry_name(registry)?;

            if crate::dry_run::active() {
                let pinned = !store.lookup_all(registry).is_empty();
                if pinned {
                    printer.info(&format!(
                        "Would remove pinned trust keys for registry '{registry}'"
                    ));
                } else {
                    printer.info(&format!(
                        "No pinned trust keys found for registry '{registry}'; nothing would change."
                    ));
                }
                printer.info("Dry run: the trusted-key store is unchanged.");
                return Ok(());
            }

            let removed = store.remove(registry)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "trust_remove",
                    "status": if removed { "removed" } else { "current" },
                    "registry": registry,
                    "removed": removed,
                }));
                return Ok(());
            }
            if removed {
                printer.success(&format!(
                    "Removed pinned trust keys for registry '{registry}'"
                ));
            } else {
                printer.info(&format!(
                    "No pinned trust keys found for registry '{registry}'"
                ));
            }
            Ok(())
        }
    }
}

/// `apr keys` subcommands for the committed `keys.toml` signing roster.
///
/// `list` prints active and revoked keys with fingerprints; `generate`
/// creates a new maintainer keypair; `register` adopts an externally-held
/// key without persisting key material; `add` appends a public key to the
/// active roster; `retire` moves a key to the revoked list and refreshes
/// affected channel partition signatures. Retirement fails before mutation
/// when a release would lose trust: released SemVer tag objects are immutable.
/// `--no-resign` explicitly revokes the key while preserving those objects and
/// reports the releases and partitions that no longer verify.
///
/// Roster-changing commits must be signed by an active maintainer key
/// whenever the roster was already non-empty, because clients verify
/// head-commit signatures against the keys they currently trust.
///
/// # Errors
///
/// Fails when a key id is invalid, duplicated, or revoked; when a
/// retirement would leave no active survivor key; when the commit signing
/// key cannot be resolved; when default retirement would invalidate an immutable
/// release; or when the roster write, commit, partition re-signing,
/// or object-store refresh fails.
pub fn run_keys(config: &ApmConfig, command: &KeysCommand, printer: &Printer) -> Result<()> {
    match command {
        KeysCommand::List { registry } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let roster = load_committed_roster(&dir)?;
            if printer.mode() == OutputMode::Json {
                let active = roster
                    .active
                    .iter()
                    .map(|entry| {
                        let (_registry, algorithm, public_key) = parse_signing_key(&entry.key)
                            .with_context(|| format!("invalid active key '{}'", entry.id))?;
                        Ok(serde_json::json!({
                            "id": &entry.id,
                            "algorithm": algorithm,
                            "fingerprint": key_fingerprint(&public_key),
                            "key": &entry.key,
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let revoked = roster
                    .revoked
                    .iter()
                    .map(|entry| {
                        serde_json::json!({
                            "id": &entry.id,
                            "reason": &entry.reason,
                        })
                    })
                    .collect::<Vec<_>>();
                printer.json(&serde_json::json!({
                    "registry": registry_name,
                    "active": active,
                    "revoked": revoked,
                }));
                return Ok(());
            }
            if roster.active.is_empty() && roster.revoked.is_empty() {
                printer.info(&format!(
                    "Registry '{registry_name}' has no keys in keys.toml."
                ));
                return Ok(());
            }

            printer.header(&format!("keys.toml for registry '{registry_name}'"));
            if roster.active.is_empty() {
                printer.plain("active: none");
            } else {
                printer.plain("active:");
                for entry in &roster.active {
                    let (_registry, algorithm, public_key) = parse_signing_key(&entry.key)
                        .with_context(|| format!("invalid active key '{}'", entry.id))?;
                    printer.plain(&format!(
                        "  {}: {} {}",
                        entry.id,
                        algorithm,
                        key_fingerprint(&public_key),
                    ));
                }
            }

            if roster.revoked.is_empty() {
                printer.plain("revoked: none");
            } else {
                printer.plain("revoked:");
                for entry in &roster.revoked {
                    if let Some(reason) = &entry.reason {
                        printer.plain(&format!("  {}: {}", entry.id, reason));
                    } else {
                        printer.plain(&format!("  {}", entry.id));
                    }
                }
            }
            Ok(())
        }
        KeysCommand::Generate {
            id,
            add,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => generate_roster_key(
            config,
            id,
            *add,
            *no_commit,
            signing_key.as_deref(),
            signing_key_id.as_deref(),
            registry.as_deref(),
            printer,
        ),
        KeysCommand::Register {
            id,
            key,
            key_command,
            registry,
        } => register_roster_key(
            config,
            id,
            key.as_deref(),
            key_command.as_deref(),
            registry.as_deref(),
            printer,
        ),
        KeysCommand::Add {
            id,
            key,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let mut roster = load_committed_roster(&dir)?;
            let commit_key = if *no_commit {
                None
            } else {
                resolve_roster_commit_key(
                    config,
                    &dir,
                    &registry_name,
                    &roster,
                    signing_key.as_deref(),
                    signing_key_id.as_deref(),
                )?
            };
            add_roster_key(&mut roster, &registry_name, id, key)?;

            if crate::dry_run::active() {
                printer.info(&format!(
                    "Would add signing key '{id}' to the roster of registry '{registry_name}'"
                ));
                printer.kv("Key", key);
                printer.kv("Active keys after", &roster.active.len().to_string());
                printer.info(if *no_commit {
                    "  --no-commit: keys.toml would be written without committing."
                } else {
                    "  A signed commit would record the roster change."
                });
                printer.info("Dry run: the roster is unchanged.");
                return Ok(());
            }

            persist_committed_roster(
                &dir,
                &roster,
                *no_commit,
                &format!("registry: add signing key {id}"),
                commit_key.as_ref().map(|k| k.path()),
            )?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "keys_add",
                    "status": "added",
                    "registry": registry_name,
                    "id": id,
                    "key": key,
                    "committed": !*no_commit,
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Added active signing key '{id}' to registry '{registry_name}'."
            ));
            Ok(())
        }
        KeysCommand::Retire {
            id,
            reason,
            vouched_by,
            no_commit,
            signing_key,
            signing_key_id,
            no_resign,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            retire_committed_key(
                config,
                &dir,
                &registry_name,
                RetirementOptions {
                    id,
                    reason: reason.as_deref(),
                    vouched_by,
                    no_commit: *no_commit,
                    signing_key: signing_key.as_deref(),
                    signing_key_id: signing_key_id.as_deref(),
                    no_resign: *no_resign,
                },
                printer,
            )
        }
    }
}

/// Inputs for a roster retirement and its signature refresh policy.
struct RetirementOptions<'a> {
    id: &'a str,
    reason: Option<&'a str>,
    vouched_by: &'a Option<String>,
    no_commit: bool,
    signing_key: Option<&'a str>,
    signing_key_id: Option<&'a str>,
    no_resign: bool,
}

/// Validate and persist a key retirement in the selected registry clone.
fn retire_committed_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    options: RetirementOptions<'_>,
    printer: &Printer,
) -> Result<()> {
    let RetirementOptions {
        id,
        reason,
        vouched_by,
        no_commit,
        signing_key,
        signing_key_id,
        no_resign,
    } = options;

    let mut roster = load_committed_roster(dir)?;
    let roster_before = roster.clone();
    let provenance_before_sequence = read_package_provenance_transparency_log_state(
        &dir.join(PACKAGE_PROVENANCE_TRANSPARENCY_LOG),
    )?
    .0;
    let vouching_id = retire_roster_key(
        &mut roster,
        id,
        reason,
        vouched_by,
        provenance_before_sequence,
    )?;

    // Check the post-retirement trust set before resolving private key
    // sources or writing the roster. Published identities cannot change
    // to compensate for revoked signatures.
    let survivors: Vec<String> = roster
        .active
        .iter()
        .map(|entry| entry.key.clone())
        .collect();
    let plan = plan_retirement_resign(dir, &survivors)?;
    if !no_resign {
        ensure_retirement_preserves_releases(&plan)?;
    }

    // The vouching survivor signs the retirement by default; the
    // key resolution runs against the pre-retire roster, where the
    // voucher is still active. Re-signing also needs this key, so
    // resolution failures abort before anything is modified.
    let signer = if no_commit && no_resign {
        None
    } else if signing_key.is_none() && signing_key_id.is_none() {
        Some(resolve_producer_signing_key(
            config,
            dir,
            registry_name,
            None,
            Some(&vouching_id),
        )?)
    } else {
        resolve_roster_commit_key(
            config,
            dir,
            registry_name,
            &roster_before,
            signing_key,
            signing_key_id,
        )?
    };

    if crate::dry_run::active() {
        printer.info(&format!(
            "Would retire signing key '{id}' from registry '{registry_name}' \
             (vouched by '{vouching_id}')"
        ));
        if let Some(reason) = reason {
            printer.kv("Reason", reason);
        }
        // Show the signatures that retirement invalidates, including
        // immutable releases when explicitly revoking without re-signing.
        print_resign_plan(&plan, printer);
        if no_resign {
            printer.info("  --no-resign: affected releases and partitions would lose trust.");
        }
        printer.info("Dry run: the roster and every signature are unchanged.");
        return Ok(());
    }

    persist_committed_roster(
        dir,
        &roster,
        no_commit,
        &format!("registry: retire signing key {id}"),
        if no_commit {
            None
        } else {
            signer.as_ref().map(|k| k.path())
        },
    )?;
    if no_resign {
        print_resign_plan(&plan, printer);
    } else if let Some(vouch_key) = signer.as_ref().map(|k| k.path()) {
        execute_retirement_resign(dir, &plan, vouch_key, printer)?;
    }
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "keys_retire",
            "status": "retired",
            "registry": registry_name,
            "id": id,
            "reason": reason,
            "vouched_by": vouching_id,
            "committed": !no_commit,
            "resigned": !no_resign,
            "resign_plan": resign_plan_json(&plan),
        }));
        return Ok(());
    }
    printer.success(&format!(
        "Retired signing key '{id}' from registry '{registry_name}' (vouched by '{vouching_id}')."
    ));
    Ok(())
}

/// Signatures that lose trust after a key retirement.
///
/// Release tags cannot be rewritten. Their presence blocks automatic
/// retirement, while affected channel partitions can be re-signed against
/// unchanged release objects when every release retains trust.
struct ResignPlan {
    affected_releases: Vec<String>,
    affected_partitions: Vec<(String, u8, semver::Version)>,
}

impl ResignPlan {
    fn is_empty(&self) -> bool {
        self.affected_releases.is_empty() && self.affected_partitions.is_empty()
    }
}

/// Enumerate the tags clients resolve and check which no longer verify
/// against the surviving active keys.
///
/// Covers every SemVer release tag, including releases without channels, and
/// every channel partition payload under `.git/channels/`. A partition is also
/// affected when its referenced release no longer verifies, even if its own
/// signature remains trusted.
fn plan_retirement_resign(dir: &Path, survivors: &[String]) -> Result<ResignPlan> {
    let release_tags = semver_tag_object_map(dir)?;
    let git_dir = objectstore::repo_git_dir(dir)?;
    let channels_dir = git_dir.join("channels");

    // (channel, bucket, version, payload signature fails against survivors)
    let mut partitions: Vec<(String, u8, semver::Version, bool)> = Vec::new();
    if channels_dir.exists() {
        let mut channel_names: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&channels_dir)
            .with_context(|| format!("reading {}", channels_dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                channel_names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        channel_names.sort();
        for channel_name in channel_names {
            let channel_dir = channels_dir.join(&channel_name);
            for bucket in 0..=u8::MAX {
                let path = channel_dir.join(channel::bucket_hex(bucket));
                if !path.exists() {
                    continue;
                }
                let payload =
                    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                let tag = parse_tag_object(&String::from_utf8_lossy(&payload))
                    .with_context(|| format!("parsing channel partition {}", path.display()))?;
                let version = release_tags.get(&tag.object).ok_or_else(|| {
                    anyhow::anyhow!(
                        "channel partition {} points at unknown release tag object {}",
                        path.display(),
                        tag.object,
                    )
                })?;
                // Inspect the served bytes directly: retirement preflight must
                // not write objects before deciding whether it can proceed.
                let verified = verify_partition_signature(&payload, survivors)?;
                partitions.push((channel_name.clone(), bucket, version.clone(), !verified));
            }
        }
    }

    let names = git(dir, &["tag", "--list"])?;
    let mut affected_releases = Vec::new();
    for name in names.lines() {
        if release_tag_version(name).is_some() && !verify_tag_signature(dir, name, survivors)? {
            // Preserve the actual ref spelling: resolving a normalized alias
            // would inspect a different signed object or a nonexistent ref.
            affected_releases.push(name.to_owned());
        }
    }
    affected_releases.sort();

    let affected_partitions = partitions
        .into_iter()
        .filter(|(_, _, version, failing)| {
            *failing
                || affected_releases
                    .iter()
                    .any(|name| release_tag_version(name).as_ref() == Some(version))
        })
        .map(|(channel, bucket, version, _)| (channel, bucket, version))
        .collect();

    Ok(ResignPlan {
        affected_releases,
        affected_partitions,
    })
}

/// Verify a partition payload without inserting it into the object database.
fn verify_partition_signature(payload: &[u8], survivors: &[String]) -> Result<bool> {
    let Ok(signed) = aos_registry_surface::tag::parse_signed_tag(payload) else {
        return Ok(false);
    };
    for key in survivors {
        if verify_payload_signature(&signed.signed_payload, &signed.signature, key, "git")? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Reject automatic retirement that would require rewriting release identity.
fn ensure_retirement_preserves_releases(plan: &ResignPlan) -> Result<()> {
    if !plan.affected_releases.is_empty() {
        let versions = plan
            .affected_releases
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "key retirement would invalidate immutable release tags ({versions}); \
             publish replacement releases with a surviving key, then use --no-resign \
             to explicitly revoke the key without rewriting released tag objects"
        );
    }
    Ok(())
}

/// Re-sign affected channel partitions with the vouching survivor's private key.
///
/// Release identities are checked before any mutation. Partitions continue to
/// reference the original release tag objects, and each touched channel's
/// branch head and object store are refreshed.
fn execute_retirement_resign(
    dir: &Path,
    plan: &ResignPlan,
    vouch_key: &str,
    printer: &Printer,
) -> Result<()> {
    ensure_retirement_preserves_releases(plan)?;
    if plan.is_empty() {
        return Ok(());
    }

    let mut touched_channels: Vec<&str> = Vec::new();
    for (channel_name, bucket, version) in &plan.affected_partitions {
        write_channel_partition_tag(dir, channel_name, *bucket, version, vouch_key)?;
        if !touched_channels.contains(&channel_name.as_str()) {
            touched_channels.push(channel_name);
        }
    }
    for channel_name in touched_channels {
        let map = read_channel_partition_map(dir, channel_name)?;
        update_channel_frontier(dir, channel_name, &map)?;
        printer.info(&format!("Re-signed channel '{channel_name}' partitions."));
    }

    refresh_registry_object_store(dir)
        .context("refreshing dumb-HTTP object store after key-retirement re-sign")?;
    Ok(())
}

/// Print the re-sign plan for manual handling (`--no-resign`).
fn print_resign_plan(plan: &ResignPlan, printer: &Printer) {
    if plan.is_empty() {
        printer.info("No release or channel partition signatures would lose trust.");
        return;
    }
    printer.warning("Affected signatures after retirement:");
    for version in &plan.affected_releases {
        printer.plain(&format!("  immutable release tag {version} loses trust"));
    }
    for (channel, bucket, version) in &plan.affected_partitions {
        printer.plain(&format!(
            "  channel {channel} partition {} -> {version}",
            channel::bucket_hex(*bucket),
        ));
    }
}

fn resign_plan_json(plan: &ResignPlan) -> serde_json::Value {
    let partitions = plan
        .affected_partitions
        .iter()
        .map(|(channel, bucket, version)| {
            serde_json::json!({
                "channel": channel,
                "bucket": *bucket,
                "bucket_hex": channel::bucket_hex(*bucket),
                "version": version.to_string(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "release_tags": plan
            .affected_releases
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "channel_partitions": partitions,
    })
}

/// Load the committed `keys.toml` roster, defaulting to an empty roster
/// when the file does not exist yet.
pub(in crate::registry_ops) fn load_committed_roster(dir: &Path) -> Result<KeysToml> {
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }
    Ok(keys::load_keys_toml(dir)?.unwrap_or_default())
}

/// `apr keys generate <id>`
///
/// Generates an OpenSSH Ed25519 maintainer keypair: the private key is
/// written under the per-scope config directory (mode `0600`, never
/// overwriting an existing file), its path is recorded in
/// `[registry.signing_keys]` so `--key-id <id>` resolves, and the public
/// half is printed in `registry:Ed25519:<base64>` form. With `--add` the
/// public key is also appended to the committed `keys.toml` roster via a
/// signed commit.
#[allow(clippy::too_many_arguments)]
fn generate_roster_key(
    config: &ApmConfig,
    id: &str,
    add: bool,
    no_commit: bool,
    signing_key: Option<&str>,
    signing_key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_roster_key_id(id)?;
    let registry_name = resolve_registry_name(config, registry)?;

    let keys_dir = config.scope.config_dir().join("keys");

    if crate::dry_run::active() {
        let key_path = keys_dir.join(format!("{registry_name}-{id}.key"));
        if key_path.exists() {
            bail!(
                "private key file {} already exists (refusing to overwrite an existing key)",
                key_path.display()
            );
        }
        printer.info(&format!(
            "Would mint an Ed25519 keypair '{id}' for registry '{registry_name}'"
        ));
        printer.kv("Would write private key", &key_path.display().to_string());
        if add {
            printer.info(if no_commit {
                "  --add --no-commit: the key would be appended to keys.toml, uncommitted."
            } else {
                "  --add: the key would be appended to keys.toml in a signed commit."
            });
        }
        // The public half is not printed: it does not exist yet, and a real run
        // mints different key material than any preview could show.
        printer.info("Dry run: no key was generated and nothing was written.");
        return Ok(());
    }

    {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(&keys_dir)
            .with_context(|| format!("creating key directory {}", keys_dir.display()))?;
    }

    let key_path = keys_dir.join(format!("{registry_name}-{id}.key"));
    let keypair = sshkey::Ed25519Keypair::generate();
    let pem = keypair.to_openssh_private_key(&format!("{registry_name}-{id}"));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&key_path).with_context(|| {
            format!(
                "creating private key file {} (refusing to overwrite an existing key)",
                key_path.display(),
            )
        })?;
        std::io::Write::write_all(&mut file, pem.as_bytes())
            .with_context(|| format!("writing {}", key_path.display()))?;
    }

    let trust_key = keypair.trust_key_line(&registry_name);
    let key_path_str = key_path.display().to_string();

    // Record the private key path so `--key-id <id>` resolves (§2.6).
    let config_path = config.registry_config_path_for_update(&registry_name);
    let configured = config_path.exists();
    if configured {
        state::upsert_signing_key(
            &config_path,
            id,
            &SigningKeySource::Path(key_path_str.clone()),
        )?;
        printer.kv("Config", &config_path.display().to_string());
    } else {
        printer.warning(&format!(
            "registry '{registry_name}' has no config at {}; to use --key-id {id}, add:\n\
             [registry.signing_keys]\n\"{id}\" = \"{key_path_str}\"",
            config_path.display(),
        ));
    }

    printer.kv("Key id", id);
    printer.kv("Private key", &key_path_str);
    printer.kv("Public key", &trust_key);
    printer.kv(
        "Fingerprint",
        &key_fingerprint(&keypair.public_key_base64()),
    );

    let mut committed = false;
    if add {
        let dir = config.scope.registries_path().join(&registry_name);
        let mut roster = load_committed_roster(&dir)?;
        if roster.active.is_empty() {
            bail!(
                "registry '{registry_name}' has an empty trust roster; seed the first key with \
                 `apr create {registry_name} --trust-key {trust_key} --key {key_path_str}` instead \
                 of --add"
            );
        }
        let commit_key = if no_commit {
            None
        } else {
            resolve_roster_commit_key(
                config,
                &dir,
                &registry_name,
                &roster,
                signing_key,
                signing_key_id,
            )?
        };
        add_roster_key(&mut roster, &registry_name, id, &trust_key)?;
        persist_committed_roster(
            &dir,
            &roster,
            no_commit,
            &format!("registry: add signing key {id}"),
            commit_key.as_ref().map(|k| k.path()),
        )?;
        committed = !no_commit;
        printer.success(&format!(
            "Added active signing key '{id}' to registry '{registry_name}'."
        ));
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "keys_generate",
            "status": "generated",
            "registry": registry_name,
            "id": id,
            "private_key": key_path_str,
            "public_key": trust_key,
            "fingerprint": key_fingerprint(&keypair.public_key_base64()),
            "configured": configured,
            "config": if configured {
                Some(config_path.to_string_lossy().to_string())
            } else {
                None
            },
            "added": add,
            "committed": committed,
        }));
    }

    Ok(())
}

/// `apr keys register <id>`
///
/// Adopt an externally-held maintainer key without generating or persisting
/// key material. The private key is obtained from a path (`--key`) or a
/// command (`--key-command`); its public half is derived with `ssh-keygen -y`
/// (the same tool git uses to sign); the source is recorded under
/// `[registry.signing_keys]` so `--key-id <id>` resolves it; and the
/// `registry:Ed25519:<base64>` trust line is printed for an existing
/// maintainer to add with `apr keys add`.
///
/// Unlike [`generate_roster_key`], nothing is generated and the private key
/// never lands in a tool-managed file: a command source is materialized only
/// transiently — long enough to derive the public key — and removed
/// immediately. Resolving the source here doubles as validation that the
/// configured path or command actually yields a usable key.
///
/// The registry must already have a `registries.d` config (created by
/// `apr registry add`): the recorded `[registry.signing_keys]` entry is the
/// whole point of this command, and the config file cannot be created here
/// because it requires the registry URL. A missing config is an error, and
/// it is checked up front so the key source (which may prompt, e.g. a
/// secrets-manager command) is never run for a registration that cannot be
/// recorded.
fn register_roster_key(
    config: &ApmConfig,
    id: &str,
    key: Option<&str>,
    key_command: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_roster_key_id(id)?;
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

    let source = match (key, key_command) {
        (Some(_), Some(_)) => bail!("use only one of --key or --key-command"),
        (Some(path), None) => SigningKeySource::Path(path.to_string()),
        (None, Some(command)) => SigningKeySource::Spec(SigningKeySpec {
            path: None,
            command: Some(command.to_string()),
        }),
        (None, None) => bail!("provide the key with --key <path> or --key-command <command>"),
    };

    let resolved = resolve_signing_key_source(id, &source)?;
    let trust_key = derive_trust_key(&registry_name, resolved.path())?;
    let (_registry, _algorithm, public_key) = parse_signing_key(&trust_key)?;

    if crate::dry_run::active() {
        // Registration only records where an already-held key lives, so the
        // preview can show the real derived identity a real run would record.
        printer.info(&format!(
            "Would register key '{id}' for registry '{registry_name}' in {}",
            config_path.display()
        ));
        printer.kv("Public key", &trust_key);
        printer.kv("Fingerprint", &key_fingerprint(&public_key));
        printer.info("Dry run: the configuration is unchanged.");
        return Ok(());
    }

    state::upsert_signing_key(&config_path, id, &source)?;
    printer.kv("Config", &config_path.display().to_string());

    printer.kv("Key id", id);
    match (source.path(), source.command()) {
        (Some(path), _) => printer.kv("Key path", path),
        (_, Some(command)) => printer.kv("Key command", command),
        _ => {}
    }
    printer.kv("Public key", &trust_key);
    printer.kv("Fingerprint", &key_fingerprint(&public_key));
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "keys_register",
            "status": "registered",
            "registry": registry_name,
            "id": id,
            "source": if source.path().is_some() { "path" } else { "command" },
            "configured": true,
            "config": config_path.to_string_lossy().to_string(),
            "public_key": trust_key,
            "fingerprint": key_fingerprint(&public_key),
        }));
        return Ok(());
    }
    printer.info(&format!(
        "Hand the public key to an active maintainer to add it:\n  {} keys add {id} {trust_key} --registry {registry_name}",
        aos_core::invocation::package_registry_command(),
    ));
    Ok(())
}

/// Derive the `registry:Ed25519:<base64>` trust line for the private key at
/// `key_path`.
///
/// The base64 field is the SSH wire-format public key the trust line carries,
/// read from the private key with the `ssh-key` crate (see
/// [`crate::security::public_ed25519_blob`]).
pub(in crate::registry_ops) fn derive_trust_key(
    registry_name: &str,
    key_path: &str,
) -> Result<String> {
    let blob = crate::security::public_ed25519_blob(Path::new(key_path))
        .context("deriving the public key from the signing key")?;
    Ok(format!("{registry_name}:Ed25519:{blob}"))
}

/// Write `keys.toml` back and, unless `no_commit`, commit it and refresh
/// the dumb-HTTP object store.
fn persist_committed_roster(
    dir: &Path,
    roster: &KeysToml,
    no_commit: bool,
    message: &str,
    signing_key: Option<&str>,
) -> Result<()> {
    keys::write_keys_toml(dir, roster)?;
    if !no_commit {
        commit_registry(dir, message, signing_key)?;
        refresh_registry_object_store(dir)
            .context("refreshing dumb-HTTP object store after keys.toml update")?;
    }
    Ok(())
}

/// Resolve the signing key for a roster-changing commit.
///
/// Roster commits must be signed whenever the pre-change roster is
/// non-empty: clients verify head-commit signatures against the keys they
/// already trust, so an unsigned roster change would be rejected on sync.
/// Only the bootstrap case (adding the first key to an empty roster, which
/// no client can verify yet) may proceed unsigned without an explicit key.
pub(in crate::registry_ops) fn resolve_roster_commit_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    roster_before: &KeysToml,
    key: Option<&str>,
    key_id: Option<&str>,
) -> Result<Option<ResolvedSigningKey>> {
    if key.is_some() || key_id.is_some() {
        return resolve_producer_signing_key(config, dir, registry_name, key, key_id).map(Some);
    }
    if roster_before.active.is_empty() {
        return Ok(None);
    }
    bail!(
        "registry '{registry_name}' has a non-empty trust roster, so roster changes must be \
         signed commits: pass --key <path> or --key-id <id> with an active maintainer key"
    )
}

/// Append an active key to the roster after validating that the id is
/// well-formed and unused, the key is not already present or revoked, and
/// the key's registry binding matches.
fn add_roster_key(roster: &mut KeysToml, registry_name: &str, id: &str, key: &str) -> Result<()> {
    validate_roster_key_id(id)?;
    if roster.active.iter().any(|entry| entry.id == id) {
        bail!("active signing key id '{id}' already exists in keys.toml");
    }
    if roster.revoked.iter().any(|entry| entry.id == id) {
        bail!("signing key id '{id}' is already revoked in keys.toml");
    }
    if roster.active.iter().any(|entry| entry.key == key) {
        bail!("signing key already exists in keys.toml under another id");
    }

    let (key_registry, _algorithm, _public_key) = parse_signing_key(key)?;
    if key_registry != registry_name {
        bail!(
            "signing key belongs to registry '{}', expected '{}'",
            key_registry,
            registry_name,
        );
    }

    roster.active.push(RosterKey {
        id: id.to_string(),
        key: key.to_string(),
    });
    Ok(())
}

/// Move key `id` from the active to the revoked roster, returning the id
/// of the vouching survivor key.
///
/// At least one active key must remain. `--vouched-by` is required when
/// more than one survivor exists and defaults to the sole survivor
/// otherwise; the voucher must itself be a surviving active key.
fn retire_roster_key(
    roster: &mut KeysToml,
    id: &str,
    reason: Option<&str>,
    vouched_by: &Option<String>,
    provenance_before_sequence: u64,
) -> Result<String> {
    validate_roster_key_id(id)?;
    let Some(position) = roster.active.iter().position(|entry| entry.id == id) else {
        if roster.revoked.iter().any(|entry| entry.id == id) {
            bail!("signing key id '{id}' is already revoked in keys.toml");
        }
        bail!("active signing key id '{id}' does not exist in keys.toml");
    };

    let survivors = roster
        .active
        .iter()
        .filter(|entry| entry.id != id)
        .map(|entry| entry.id.clone())
        .collect::<Vec<_>>();
    if survivors.is_empty() {
        bail!("cannot retire signing key '{id}': keys.toml must keep an active survivor key");
    }

    let vouching_id = match vouched_by.as_deref() {
        Some(vouching_id) => {
            validate_roster_key_id(vouching_id)?;
            if vouching_id == id {
                bail!("--vouched-by must name a different active key");
            }
            if !survivors.iter().any(|survivor| survivor == vouching_id) {
                bail!("--vouched-by '{vouching_id}' is not an active survivor key");
            }
            vouching_id.to_string()
        }
        None if survivors.len() == 1 => survivors[0].to_string(),
        None => bail!(
            "--vouched-by is required when more than one active survivor key remains ({})",
            survivors.join(", "),
        ),
    };

    let retired_key = roster.active.remove(position).key;
    upsert_revoked_key(roster, id, retired_key, provenance_before_sequence, reason);
    Ok(vouching_id)
}

/// Record `id` in the revoked list, updating the reason if it is already
/// there.
fn upsert_revoked_key(
    roster: &mut KeysToml,
    id: &str,
    key: String,
    provenance_before_sequence: u64,
    reason: Option<&str>,
) {
    let reason = reason.map(str::to_string);
    if let Some(entry) = roster.revoked.iter_mut().find(|entry| entry.id == id) {
        entry.key = Some(key);
        entry.provenance_before_sequence = Some(provenance_before_sequence);
        entry.reason = reason;
    } else {
        roster.revoked.push(RevokedKey {
            id: id.to_string(),
            key: Some(key),
            provenance_before_sequence: Some(provenance_before_sequence),
            reason,
        });
    }
}

pub(in crate::registry_ops) fn validate_roster_key_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("key id cannot be empty");
    }
    if id.trim() != id
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("key id '{id}' must contain only ASCII letters, digits, '.', '-', or '_'");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
