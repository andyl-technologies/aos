//! Signed rollout channel partitions and fix-forward channel advancement.

use crate::ChannelCommand;
use crate::config::ApmConfig;
use crate::registry::channel::PartitionMap;
use crate::registry::verify::{TagTarget, parse_tag_object, verify_name_binding};
use crate::registry::{channel, objectstore};
use crate::registry_ops::config::{registry_dir, resolve_registry_name};
use crate::registry_ops::git::{git, git_raw, refresh_registry_object_store, semver_tag_versions};
use crate::registry_ops::signing::resolve_producer_signing_key;
use crate::registry_ops::tags::{assert_release_tag_exists, release_commit, sign_tag};
use crate::types::validate_channel_name;
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
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

/// Resolve which partitions a channel advance should touch: `--count`
/// picks the lowest-numbered partitions not yet on the target version
/// (ascending fill), while `--partitions` names buckets explicitly.
/// Exactly one of the two must be given.
pub(in crate::registry_ops) fn select_partitions_for_advance(
    count: Option<usize>,
    partitions: Option<&str>,
    map: &PartitionMap,
    version: &semver::Version,
) -> Result<Vec<u8>> {
    match (count, partitions) {
        (Some(_), Some(_)) => bail!("use only one of --count or --partitions"),
        (None, None) => bail!("one of --count or --partitions is required"),
        (Some(count), None) => {
            if count > channel::PARTITION_COUNT {
                bail!("--count must be <= {}", channel::PARTITION_COUNT);
            }
            Ok(channel::ascending_fill(count, map, version))
        }
        (None, Some(spec)) => parse_partition_list(spec),
    }
}

/// Refuse producer-side channel rewrites that would lower any selected
/// partition's semver target.
fn ensure_channel_advance_fix_forward(
    map: &PartitionMap,
    selected: &[u8],
    version: &semver::Version,
) -> Result<()> {
    for bucket in selected {
        let Some(current) = map.get(*bucket) else {
            continue;
        };
        if version < current {
            bail!(
                "channel advance would decrement partition {} from {} to {}; publish a newer fix-forward release instead",
                channel::bucket_hex(*bucket),
                current,
                version,
            );
        }
    }
    Ok(())
}

fn parse_partition_list(spec: &str) -> Result<Vec<u8>> {
    let mut buckets = Vec::new();
    for raw in spec.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let bucket = parse_partition(raw)?;
        if !buckets.contains(&bucket) {
            buckets.push(bucket);
        }
    }
    if buckets.is_empty() {
        bail!("partition list is empty");
    }
    Ok(buckets)
}

/// Parse a single partition bucket: `0x`-prefixed or letter-containing
/// strings are hex, everything else is decimal.
fn parse_partition(raw: &str) -> Result<u8> {
    if let Some(hex) = raw.strip_prefix("0x") {
        return u8::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hex partition '{raw}'"));
    }
    if raw.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F')) {
        return u8::from_str_radix(raw, 16)
            .with_context(|| format!("invalid hex partition '{raw}'"));
    }
    raw.parse::<u8>()
        .with_context(|| format!("invalid decimal partition '{raw}'"))
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
        let tag = parse_tag_object(&content)
            .with_context(|| format!("parsing channel partition {}", path.display()))?;
        verify_name_binding(&tag, channel_name)?;
        if tag.target_type != TagTarget::Tag {
            bail!(
                "channel partition {} targets {:?}, expected tag",
                path.display(),
                tag.target_type,
            );
        }
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
/// Git can only sign tags through refs, so a temporary tag named after the
/// channel is force-created against the release tag object, its signed
/// payload is copied into `.git/channels/<channel>/<bucket>`, and the
/// temporary ref is deleted. The payload file is the durable artifact
/// consumers fetch and verify.
pub(in crate::registry_ops) fn write_channel_partition_tag(
    dir: &Path,
    channel_name: &str,
    bucket: u8,
    version: &semver::Version,
    signing_key: &str,
) -> Result<()> {
    let target = format!("{version}^{{tag}}");
    let message = format!(
        "AOS channel {channel_name} partition {}",
        channel::bucket_hex(bucket)
    );
    sign_tag(
        dir,
        channel_name,
        &target,
        Some(&message),
        signing_key,
        true,
    )?;
    let tag_ref = format!("refs/tags/{channel_name}^{{tag}}");
    let oid = git(dir, &["rev-parse", &tag_ref])?;
    let payload = git_raw(dir, &["cat-file", "-p", &oid])?;

    let git_dir = objectstore::repo_git_dir(dir)?;
    let channel_dir = git_dir.join("channels").join(channel_name);
    std::fs::create_dir_all(&channel_dir)
        .with_context(|| format!("creating {}", channel_dir.display()))?;
    let partition = channel_dir.join(channel::bucket_hex(bucket));
    std::fs::write(&partition, payload)
        .with_context(|| format!("writing {}", partition.display()))?;

    git(dir, &["tag", "-d", channel_name])
        .with_context(|| format!("deleting temporary channel tag '{channel_name}'"))?;
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
