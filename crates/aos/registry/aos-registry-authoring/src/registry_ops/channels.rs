//! Signed rollout channel partitions and fix-forward channel advancement.

use crate::ChannelCommand;
use crate::registry::{channel, objectstore};
use crate::registry_ops::config::{registry_dir, resolve_registry_name};
use crate::registry_ops::git::{
    ensure_commit_identity, git, git2_identity, refresh_registry_object_store, semver_tag_versions,
};
use crate::registry_ops::signing::resolve_producer_signing_key;
use crate::registry_ops::tags::{assert_release_tag_exists, format_git_tz, release_commit};
use anyhow::{Context, Result};
use aos_cli_ui::output::{OutputMode, Printer};
use aos_registry_client::config::ApmConfig;
use aos_registry_client::registry::channel::PartitionMap;
#[cfg(test)]
use aos_registry_format::channel::parse_partition_list;
use aos_registry_format::channel::{PartitionTag, parse_partition_target};
pub(in crate::registry_ops) use aos_registry_format::channel::{
    ensure_channel_advance_fix_forward, select_partitions_for_advance,
};
use aos_registry_format::consumer::validate_channel_name;
use std::collections::BTreeMap;
use std::path::Path;

/// `apr channel` subcommands for staged rollouts.
///
/// `init` points all 256 partitions of a channel at one release;
/// `advance` moves a subset (`--count` for an ascending fill, or an
/// explicit `--partitions` list) to a newer release; `status` summarizes
/// per-version partition counts and the channel frontier. Partition
/// updates write signed tag payloads under `.git/channels/<channel>/` and
/// move the channel branch head to the frontier release.
///
/// # Errors
///
/// Fails when the semver argument does not parse, when the release tag
/// does not exist, when the signing key cannot be resolved, or when
/// partition payloads are missing or fail verification.
pub async fn run_channel(
    config: &ApmConfig,
    command: &ChannelCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        ChannelCommand::Init {
            channel,
            semver,
            key,
            key_id,
            registry,
        } => {
            let version = semver::Version::parse(semver)
                .with_context(|| format!("parsing release semver '{semver}'"))?;
            channel_init(
                config,
                channel,
                &version,
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        ChannelCommand::Advance {
            channel,
            semver,
            count,
            partitions,
            key,
            key_id,
            registry,
        } => {
            let version = semver::Version::parse(semver)
                .with_context(|| format!("parsing release semver '{semver}'"))?;
            channel_advance(
                config,
                channel,
                &version,
                *count,
                partitions.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        ChannelCommand::Status { channel, registry } => {
            channel_status(config, channel, registry.as_deref(), printer).await
        }
    }
}

/// The remote ref namespace a hub writes git-backed config change requests to.
///
/// A change request lives at `refs/hub/changes/<id>` — a ref, not a branch, so
/// consumers (who follow only signed tags and partitions) never see it. `apr
/// change` fetches these into a local `refs/hub/changes/*` mirror.
pub(in crate::registry_ops) const HUB_CHANGES_NS: &str = "refs/hub/changes/";

/// The `AOS-Change-Id` commit-message trailer a hub stamps on draft commits.
pub(in crate::registry_ops) const CHANGE_ID_TRAILER: &str = "AOS-Change-Id";

/// `apr channel init`: point all 256 partitions of a channel at one
/// release and set the channel branch to it.
async fn channel_init(
    config: &ApmConfig,
    channel_name: &str,
    version: &semver::Version,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    assert_release_tag_exists(&dir, version)?;

    if aos_registry_client::dry_run::active() {
        printer.info(&format!(
            "Would initialize channel '{channel_name}' of registry '{registry_name}' \
             with all 256 partitions on {version}"
        ));
        printer.kv("Signing key", signing_key.path());
        printer.info("  256 partition tags would be signed and the frontier set.");
        printer.info("Dry run: the channel is unchanged.");
        return Ok(());
    }

    let mut map = PartitionMap::new();
    for bucket in 0..=u8::MAX {
        write_channel_partition_tag(&dir, channel_name, bucket, version, signing_key.path())?;
        map.set(bucket as usize, version.clone())?;
    }
    update_channel_frontier(&dir, channel_name, &map)?;

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "channel_init",
            "registry": registry_name,
            "channel": channel_name,
            "version": version.to_string(),
            "partitions": 256,
            "frontier": version.to_string(),
        }));
        return Ok(());
    }

    printer.success(&format!(
        "Initialized channel '{channel_name}' with 256/256 partitions on {version}."
    ));
    Ok(())
}

/// `apr channel advance`: re-sign the selected partitions of an existing
/// channel against a newer release and recompute the frontier.
async fn channel_advance(
    config: &ApmConfig,
    channel_name: &str,
    version: &semver::Version,
    count: Option<usize>,
    partitions: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    assert_release_tag_exists(&dir, version)?;

    let mut map = read_channel_partition_map(&dir, channel_name)?;
    channel::assert_full_partition_set(&map)?;
    let selected = select_partitions_for_advance(count, partitions, &map, version)?;
    ensure_channel_advance_fix_forward(&map, &selected, version)?;
    if selected.is_empty() {
        if printer.mode() == OutputMode::Json {
            let frontier = channel::compute_frontier(&map);
            printer.json(&serde_json::json!({
                "action": "channel_advance",
                "registry": registry_name,
                "channel": channel_name,
                "version": version.to_string(),
                "partitions": [],
                "partition_count": 0,
                "frontier": frontier.as_ref().map(ToString::to_string),
                "status": "current",
            }));
            return Ok(());
        }
        printer.info("No partitions selected for advancement.");
        return Ok(());
    }

    if aos_registry_client::dry_run::active() {
        printer.info(&format!(
            "Would advance {} partition(s) of channel '{channel_name}' \
             in registry '{registry_name}' to {version}",
            selected.len()
        ));
        // The exact buckets are the reviewable part of a rollout: which slice
        // of the fleet this step would move.
        printer.kv(
            "Partitions",
            &selected
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        );
        printer.kv("Signing key", signing_key.path());
        printer.info("Dry run: the channel is unchanged.");
        return Ok(());
    }

    for bucket in &selected {
        write_channel_partition_tag(&dir, channel_name, *bucket, version, signing_key.path())?;
        map.set(*bucket as usize, version.clone())?;
    }
    update_channel_frontier(&dir, channel_name, &map)?;

    if printer.mode() == OutputMode::Json {
        let frontier = channel::compute_frontier(&map);
        let partition_count = selected.len();
        printer.json(&serde_json::json!({
            "action": "channel_advance",
            "registry": registry_name,
            "channel": channel_name,
            "version": version.to_string(),
            "partitions": &selected,
            "partition_count": partition_count,
            "frontier": frontier.as_ref().map(ToString::to_string),
            "status": "advanced",
        }));
        return Ok(());
    }

    printer.success(&format!(
        "Advanced channel '{channel_name}' {} partition(s) to {version}.",
        selected.len()
    ));
    Ok(())
}

/// `apr channel status`: summarize partition versions, missing partitions,
/// and the channel frontier.
async fn channel_status(
    config: &ApmConfig,
    channel_name: &str,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let dir = registry_dir(config, registry)?;
    let map = read_channel_partition_map(&dir, channel_name)?;
    let frontier = channel::compute_frontier(&map);
    let missing = map.iter().filter(|(_, target)| target.is_none()).count();
    let mut counts: BTreeMap<semver::Version, usize> = BTreeMap::new();
    for (_, target) in map.iter() {
        if let Some(version) = target {
            *counts.entry(version.clone()).or_default() += 1;
        }
    }

    if printer.mode() == OutputMode::Json {
        let versions = counts
            .iter()
            .rev()
            .map(|(version, count)| {
                serde_json::json!({
                    "version": version.to_string(),
                    "partitions": count,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!({
            "channel": channel_name,
            "frontier": frontier.as_ref().map(ToString::to_string),
            "missing_partitions": missing,
            "versions": versions,
        }));
        return Ok(());
    }

    printer.header(&format!("Channel: {channel_name}"));
    if let Some(frontier) = frontier {
        printer.kv("Frontier", &frontier.to_string());
    } else {
        printer.kv("Frontier", "none");
    }
    printer.kv("Missing partitions", &missing.to_string());
    for (version, count) in counts.iter().rev() {
        printer.kv(&version.to_string(), &format!("{count}/256"));
    }
    Ok(())
}

/// Point all 256 partitions of a channel at `version` and move the channel
/// branch to the new frontier. Returns the partition count (always 256).
pub(in crate::registry_ops) fn channel_init_dir(
    dir: &Path,
    channel_name: &str,
    version: &semver::Version,
    signing_key: &str,
    printer: &Printer,
) -> Result<usize> {
    validate_channel_name(channel_name)?;
    assert_release_tag_exists(dir, version)?;
    let mut map = PartitionMap::new();
    for bucket in 0..=u8::MAX {
        write_channel_partition_tag(dir, channel_name, bucket, version, signing_key)?;
        map.set(bucket as usize, version.clone())?;
    }
    update_channel_frontier(dir, channel_name, &map)?;
    printer.success(&format!(
        "Initialized channel '{channel_name}' with 256/256 partitions on {version}."
    ));
    Ok(256)
}

/// Advance the selected partitions of an existing channel to `version` and
/// update the frontier. Returns how many partitions were touched.
pub(in crate::registry_ops) fn channel_advance_dir(
    dir: &Path,
    channel_name: &str,
    version: &semver::Version,
    count: Option<usize>,
    partitions: Option<&str>,
    signing_key: &str,
    printer: &Printer,
) -> Result<usize> {
    validate_channel_name(channel_name)?;
    assert_release_tag_exists(dir, version)?;
    let mut map = read_channel_partition_map(dir, channel_name)?;
    channel::assert_full_partition_set(&map)?;
    let selected = select_partitions_for_advance(count, partitions, &map, version)?;
    ensure_channel_advance_fix_forward(&map, &selected, version)?;
    if selected.is_empty() {
        printer.info("No partitions selected for advancement.");
        return Ok(0);
    }
    for bucket in &selected {
        write_channel_partition_tag(dir, channel_name, *bucket, version, signing_key)?;
        map.set(*bucket as usize, version.clone())?;
    }
    update_channel_frontier(dir, channel_name, &map)?;
    printer.success(&format!(
        "Advanced channel '{channel_name}' {} partition(s) to {version}.",
        selected.len()
    ));
    Ok(selected.len())
}

/// Reconstruct a channel's partition map from the signed tag payloads
/// under `.git/channels/<name>/`, verifying each payload's channel-name
/// binding and resolving its target tag object to a release version.
pub(in crate::registry_ops) fn read_channel_partition_map(
    dir: &Path,
    channel_name: &str,
) -> Result<PartitionMap> {
    let release_tags = semver_tag_object_map(dir)?;
    let git_dir = objectstore::repo_git_dir(dir)?;
    let channel_dir = git_dir.join("channels").join(channel_name);
    let mut map = PartitionMap::new();

    for bucket in 0..=u8::MAX {
        let path = channel_dir.join(channel::bucket_hex(bucket));
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let tag = parse_partition_target(content.as_bytes(), channel_name, None)
            .with_context(|| format!("parsing channel partition {}", path.display()))?;
        let version = release_tags.get(&tag.object).ok_or_else(|| {
            anyhow::anyhow!(
                "channel partition {} points at unknown release tag object {}",
                path.display(),
                tag.object,
            )
        })?;
        map.set(bucket as usize, version.clone())?;
    }
    Ok(map)
}

/// Map each release tag's object id to its release version.
pub(in crate::registry_ops) fn semver_tag_object_map(
    dir: &Path,
) -> Result<BTreeMap<String, semver::Version>> {
    let mut map = BTreeMap::new();
    for version in semver_tag_versions(dir)? {
        let oid = assert_release_tag_exists(dir, &version)?;
        map.insert(oid, version);
    }
    Ok(map)
}

/// Sign and store the payload for one channel partition.
///
/// The shared partition renderer preserves Git's annotated-tag layout. The
/// signed payload is written directly into the object database and served as a
/// raw partition file, without creating or deleting a temporary tag reference.
pub(in crate::registry_ops) fn write_channel_partition_tag(
    dir: &Path,
    channel_name: &str,
    bucket: u8,
    version: &semver::Version,
    signing_key: &str,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let release_tag = assert_release_tag_exists(dir, version)?;
    ensure_commit_identity(dir)?;
    let repo = git2::Repository::open(dir)
        .with_context(|| format!("opening git repository at {}", dir.display()))?;
    let identity = git2_identity(&repo)?;
    let tagger = format!(
        "{} <{}> {} {}",
        identity.name().unwrap_or(""),
        identity.email().unwrap_or(""),
        identity.when().seconds(),
        format_git_tz(identity.when()),
    );
    let message = format!(
        "AOS channel {channel_name} partition {}",
        channel::bucket_hex(bucket)
    );
    let partition_tag = PartitionTag::new(channel_name, &release_tag, &tagger, &message)?;
    let payload = partition_tag.sign_with(|bytes| {
        aos_registry_client::security::sign_payload_signature(Path::new(signing_key), "git", bytes)
    })?;
    repo.odb()
        .context("opening object database")?
        .write(git2::ObjectType::Tag, &payload)
        .context("writing channel partition tag object")?;

    let git_dir = objectstore::repo_git_dir(dir)?;
    let channel_dir = git_dir.join("channels").join(channel_name);
    std::fs::create_dir_all(&channel_dir)
        .with_context(|| format!("creating {}", channel_dir.display()))?;
    let partition = channel_dir.join(channel::bucket_hex(bucket));
    std::fs::write(&partition, payload)
        .with_context(|| format!("writing {}", partition.display()))?;

    Ok(())
}

/// Recompute the channel frontier from the partition map, point
/// `refs/heads/<channel>` at the frontier release's commit, and refresh
/// the dumb-HTTP object store.
pub(in crate::registry_ops) fn update_channel_frontier(
    dir: &Path,
    channel_name: &str,
    map: &PartitionMap,
) -> Result<()> {
    channel::assert_full_partition_set(map)?;
    let frontier = channel::compute_frontier(map)
        .ok_or_else(|| anyhow::anyhow!("channel '{channel_name}' has no frontier"))?;
    let commit = release_commit(dir, &frontier)?;
    git(
        dir,
        &["update-ref", &format!("refs/heads/{channel_name}"), &commit],
    )?;
    refresh_registry_object_store(dir)
        .context("refreshing dumb-HTTP object store after channel update")?;
    Ok(())
}

#[cfg(test)]
mod tests;
