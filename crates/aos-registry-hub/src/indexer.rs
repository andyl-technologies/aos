//! Fetch → verify → load → index orchestration.
//!
//! [`index_registry`] re-walks one registry surface exactly as an `apm`
//! client would and replaces its rebuildable index atomically:
//!
//! 1. Fetch `HEAD` + `info/refs` and pick the default branch's commit.
//!    If the `info/refs` bytes hash to the digest the current fresh index
//!    was built from, only the mutable channel partitions are re-verified
//!    (the incremental fast path); otherwise the full walk runs.
//! 2. Read the commit loose object; with `require_signatures`, verify its
//!    `gpgsig` SSH signature against the registry's pinned trust anchors
//!    (fail closed — an unverifiable surface is never displayed as fresh).
//! 3. Load the committed tree (`registry.toml`, `keys.toml`, packages,
//!    closures) and extend the trusted set with the verified roster's
//!    active keys, mirroring `apm`'s in-band rotation semantics.
//! 4. Verify every semver release tag (signature + name binding), capped
//!    at [`MAX_SEMVER_TAGS`], and probe each release's per-release
//!    `objects/info/packs` for pack presence.
//! 5. Resolve every channel (branch, capped at [`MAX_BRANCHES`]) by
//!    probing all 256 partition payloads, verifying each, and mapping its
//!    target tag object to a release.
//! 6. Enforce the anti-rollback floor: a channel whose frontier dropped
//!    below the highest frontier ever indexed is rejected.
//! 7. Write the snapshot in one transaction and raise the floors.
//!
//! Failures are classified by [`index_and_record`]: transport-level fetch
//! failures mark the index *stale* (surface unreachable, last good index
//! kept), anything else marks it *failed* (surface invalid).

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use aos_package::registry::verify::TagTarget;
use sha2::{Digest, Sha256};

use crate::db::{ChannelSummary, Database, IndexSnapshot, RegistryRecord, ReleaseRow};
use crate::fetch::SurfaceFetch;
use crate::surface::load::{load_registry_tree, ObjectReader};
use crate::surface::object::ObjectKind;
use crate::surface::refs::{parse_head, parse_info_refs, Refs};
use crate::surface::sshsig;
use crate::surface::tag::{parse_signed_tag, verify_signed_tag};

/// Maximum branches (channels) processed per index run.
///
/// A hostile or runaway surface advertising thousands of branches would
/// otherwise cost 256 partition fetches each; the first `MAX_BRANCHES`
/// in deterministic (lexicographic) order are processed and the rest are
/// skipped with a warning.
pub const MAX_BRANCHES: usize = 64;

/// Maximum semver release tags processed per index run.
///
/// The first `MAX_SEMVER_TAGS` in deterministic (lexicographic) order are
/// processed and the rest are skipped with a warning.
pub const MAX_SEMVER_TAGS: usize = 1024;

/// Outcome of one indexing run.
#[derive(Debug)]
pub struct IndexOutcome {
    /// The commit the index was built from.
    pub commit: String,
    /// Number of packages indexed.
    pub packages: usize,
    /// Number of verified releases.
    pub releases: usize,
    /// Number of channels resolved.
    pub channels: usize,
    /// Whether this run took the incremental channel-refresh fast path
    /// (unchanged `info/refs`; only channel partitions re-verified).
    pub incremental: bool,
}

/// Index one registered registry, recording failure state on error.
///
/// This is the entry point callers should use: it wraps [`index_registry`]
/// so that any failure is persisted as the registry's index state instead
/// of being lost with the returned error. Transport-level fetch failures
/// (classified via [`crate::fetch::is_fetch_error`]) mark the index
/// `stale`; everything else marks it `failed`.
///
/// # Errors
///
/// Returns the indexing error after recording it.
pub async fn index_and_record(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
) -> Result<IndexOutcome> {
    match index_registry(db, fetch, registry).await {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            let detail = format!("{err:#}");
            if crate::fetch::is_fetch_error(&err) {
                db.mark_index_stale(registry.id, &detail)?;
            } else {
                db.mark_index_failed(registry.id, &detail)?;
            }
            Err(err)
        }
    }
}

/// Index one registered registry surface into the database.
///
/// # Errors
///
/// Returns an error when the surface is unreachable, malformed, would
/// roll a channel back below its recorded floor, or — with
/// `require_signatures` — fails any signature or name-binding check.
pub async fn index_registry(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
) -> Result<IndexOutcome> {
    let refs_bytes = fetch
        .fetch("info/refs")
        .await?
        .with_context(|| format!("{}: info/refs not found", fetch.describe()))?;
    let refs = parse_info_refs(std::str::from_utf8(&refs_bytes).context("info/refs not UTF-8")?)?;
    let refs_digest = hex::encode(Sha256::digest(&refs_bytes));

    // Incremental fast path: an unchanged ref advertisement over a fresh
    // index means the immutable object graph is already verified — only
    // the mutable channel partitions need re-checking.
    let state_fresh = db
        .index_status(registry.id)?
        .is_some_and(|status| status.state == "fresh");
    if state_fresh && db.refs_digest(registry.id)?.as_deref() == Some(refs_digest.as_str()) {
        return index_incremental(db, fetch, registry, &refs).await;
    }

    let head = match fetch.fetch("HEAD").await? {
        Some(bytes) => parse_head(&String::from_utf8_lossy(&bytes)),
        None => None,
    };
    let (default_branch, commit_oid) =
        match head.and_then(|name| refs.branches.get(&name).copied().map(|oid| (name, oid))) {
            Some(found) => found,
            None => refs
                .branches
                .iter()
                .next()
                .map(|(name, oid)| (name.clone(), *oid))
                .context("surface advertises no branches")?,
        };
    tracing::debug!(branch = %default_branch, commit = %commit_oid, "indexing from");

    let reader = ObjectReader::new(fetch);
    let commit = reader.read_commit(commit_oid).await?;
    let mut trusted: Vec<String> = registry.trust_keys.clone();
    if registry.require_signatures {
        let signature = commit
            .signature
            .as_ref()
            .with_context(|| format!("commit {commit_oid} is unsigned"))?;
        sshsig::verify_armored(signature, &commit.signed_payload, &trusted)
            .with_context(|| format!("verifying commit {commit_oid}"))?;
    }

    let tree = load_registry_tree(fetch, commit_oid).await?;

    // In-band rotation: the roster committed by a verified commit extends
    // the trusted set for tag verification (apm pins these on sync).
    let mut roster_rows = Vec::new();
    if let Some(keys) = &tree.keys {
        for key in &keys.active {
            roster_rows.push((key.id.clone(), key.key.clone(), "active".to_string()));
            if !trusted.contains(&key.key) {
                trusted.push(key.key.clone());
            }
        }
        for revoked in &keys.revoked {
            roster_rows.push((revoked.id.clone(), String::new(), "revoked".to_string()));
        }
    }

    // Releases: every semver tag, verified (signature + name binding) and
    // resolved to its commit. BTreeMap iteration keeps the capped subset
    // deterministic.
    let mut semver_tags: Vec<_> = refs
        .tags
        .iter()
        .filter(|(name, _)| semver::Version::parse(name).is_ok())
        .collect();
    if semver_tags.len() > MAX_SEMVER_TAGS {
        tracing::warn!(
            total = semver_tags.len(),
            cap = MAX_SEMVER_TAGS,
            "capping semver release tags; processing the first {MAX_SEMVER_TAGS}"
        );
        semver_tags.truncate(MAX_SEMVER_TAGS);
    }
    let mut releases = Vec::new();
    for (tag_name, tag_oid) in semver_tags {
        let payload = reader.read_kind(*tag_oid, ObjectKind::Tag).await?;
        let (signed, signer) = if registry.require_signatures {
            let signed = verify_signed_tag(&payload, tag_name, &trusted)
                .with_context(|| format!("release tag '{tag_name}'"))?;
            let signer = parse_signed_tag(&payload)
                .ok()
                .map(|s| sshsig_signer(&s.signature));
            (signed, signer.flatten())
        } else {
            (lenient_tag(&payload, tag_name)?, None)
        };
        if signed.tag.target_type != TagTarget::Commit {
            bail!("release tag '{tag_name}' does not target a commit");
        }
        releases.push(ReleaseRow {
            semver: tag_name.clone(),
            tag_oid: tag_oid.to_hex(),
            commit_oid: signed.tag.object.clone(),
            signer,
            tagged_at: signed.tag.tagger_when,
            pack_present: probe_pack_presence(fetch, tag_name).await?,
        });
    }

    // Channels: branches are channel names; each resolves through 256
    // partition payloads pointing at release tag objects.
    let branch_names = capped_branch_names(&refs);
    let tag_to_semver: BTreeMap<String, String> = releases
        .iter()
        .map(|release| (release.tag_oid.clone(), release.semver.clone()))
        .collect();
    let channels =
        resolve_channels(fetch, registry, &branch_names, &trusted, &tag_to_semver).await?;
    enforce_floors(db, registry.id, &channels)?;

    let snapshot = IndexSnapshot {
        commit: commit_oid.to_hex(),
        name: tree.root.registry.name.clone(),
        description: tree.root.registry.description.clone(),
        caches: tree
            .root
            .caches
            .iter()
            .map(|c| (c.url.clone(), c.priority))
            .collect(),
        roster: roster_rows,
        packages: tree.packages,
        releases,
        channels,
        refs_digest: Some(refs_digest),
    };
    let outcome = IndexOutcome {
        commit: snapshot.commit.clone(),
        packages: snapshot.packages.len(),
        releases: snapshot.releases.len(),
        channels: snapshot.channels.len(),
        incremental: false,
    };
    db.apply_snapshot(registry.id, &snapshot)?;
    raise_floors(db, registry.id, &snapshot.channels)?;
    Ok(outcome)
}

/// The incremental fast path: `info/refs` is byte-identical to the fresh
/// index's digest, so the immutable object graph is unchanged — re-verify
/// only the mutable channel partitions and replace the channel tables.
async fn index_incremental(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
    refs: &Refs,
) -> Result<IndexOutcome> {
    tracing::debug!(source = %fetch.describe(), "refs unchanged; incremental channel refresh");

    // Rebuild the trusted set exactly as the full walk would have left
    // it: pinned anchors plus the verified roster's active keys.
    let mut trusted: Vec<String> = registry.trust_keys.clone();
    for (_key_id, public_key, status) in db.list_roster(registry.id)? {
        if status == "active" && !public_key.is_empty() && !trusted.contains(&public_key) {
            trusted.push(public_key);
        }
    }

    let releases = db.list_releases(registry.id)?;
    let tag_to_semver: BTreeMap<String, String> = releases
        .iter()
        .map(|release| (release.tag_oid.clone(), release.semver.clone()))
        .collect();

    let branch_names = capped_branch_names(refs);
    let channels =
        resolve_channels(fetch, registry, &branch_names, &trusted, &tag_to_semver).await?;
    enforce_floors(db, registry.id, &channels)?;
    db.update_channels(registry.id, &channels)?;
    raise_floors(db, registry.id, &channels)?;

    let commit = db
        .index_status(registry.id)?
        .and_then(|status| status.last_indexed_commit)
        .unwrap_or_default();
    Ok(IndexOutcome {
        commit,
        packages: db.list_packages(registry.id)?.len(),
        releases: releases.len(),
        channels: channels.len(),
        incremental: true,
    })
}

/// The advertised branch names in deterministic order, capped at
/// [`MAX_BRANCHES`] with a warning.
fn capped_branch_names(refs: &Refs) -> Vec<String> {
    let mut names: Vec<String> = refs.branches.keys().cloned().collect();
    if names.len() > MAX_BRANCHES {
        tracing::warn!(
            total = names.len(),
            cap = MAX_BRANCHES,
            "capping channels; processing the first {MAX_BRANCHES}"
        );
        names.truncate(MAX_BRANCHES);
    }
    names
}

/// Resolve channels by probing and verifying all 256 partitions each.
///
/// `tag_to_semver` maps release tag oids (hex) to their semver, so a
/// partition targeting an unknown tag object fails loudly.
async fn resolve_channels(
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
    branch_names: &[String],
    trusted: &[String],
    tag_to_semver: &BTreeMap<String, String>,
) -> Result<Vec<ChannelSummary>> {
    let mut channels = Vec::new();
    for channel_name in branch_names {
        let mut partitions: Vec<Option<String>> = vec![None; 256];
        let mut frontier: Option<semver::Version> = None;
        let mut present = false;
        for bucket in 0u16..=255 {
            let path = format!("channels/{channel_name}/{bucket:02x}");
            let Some(payload) = fetch.fetch(&path).await? else {
                continue;
            };
            present = true;
            let signed = if registry.require_signatures {
                verify_signed_tag(&payload, channel_name, trusted)
                    .with_context(|| format!("partition {path}"))?
            } else {
                lenient_tag(&payload, channel_name)?
            };
            if signed.tag.target_type != TagTarget::Tag {
                bail!("partition {path} does not target a tag object");
            }
            let semver_str = tag_to_semver.get(&signed.tag.object).with_context(|| {
                format!(
                    "partition {path} targets unknown tag object {}",
                    signed.tag.object
                )
            })?;
            partitions[bucket as usize] = Some(semver_str.clone());
            if let Ok(version) = semver::Version::parse(semver_str) {
                if frontier.as_ref().is_none_or(|f| version > *f) {
                    frontier = Some(version);
                }
            }
        }
        if present {
            channels.push(ChannelSummary {
                name: channel_name.clone(),
                frontier: frontier.map(|v| v.to_string()),
                partitions,
            });
        }
    }
    Ok(channels)
}

/// Probe the per-release `objects/info/packs` listing for pack presence.
///
/// Per `docs/registry/http-layout.md`, release `X.Y.Z[-pre][+build]`
/// lives under `releases/<X>/<Y>/<Z[-pre][+build]>/` and its full packs
/// are listed in `objects/info/packs` inside it.
async fn probe_pack_presence(fetch: &dyn SurfaceFetch, semver_str: &str) -> Result<bool> {
    let mut parts = semver_str.splitn(3, '.');
    let (Some(major), Some(minor), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(false);
    };
    let path = format!("releases/{major}/{minor}/{rest}/objects/info/packs");
    Ok(fetch.fetch(&path).await?.is_some())
}

/// Reject any channel whose frontier fell below its recorded floor.
fn enforce_floors(db: &Database, registry_id: i64, channels: &[ChannelSummary]) -> Result<()> {
    for channel in channels {
        let Some(frontier) = &channel.frontier else {
            continue;
        };
        let Some(floor) = db.channel_floor(registry_id, &channel.name)? else {
            continue;
        };
        let (Ok(frontier_v), Ok(floor_v)) = (
            semver::Version::parse(frontier),
            semver::Version::parse(&floor),
        ) else {
            continue;
        };
        if frontier_v < floor_v {
            bail!(
                "channel '{}' frontier {frontier} is below the recorded floor {floor}: \
                 refusing rollback",
                channel.name
            );
        }
    }
    Ok(())
}

/// Raise (never lower) each channel's floor to its new frontier.
fn raise_floors(db: &Database, registry_id: i64, channels: &[ChannelSummary]) -> Result<()> {
    for channel in channels {
        let Some(frontier) = &channel.frontier else {
            continue;
        };
        let raise = match db.channel_floor(registry_id, &channel.name)? {
            None => true,
            Some(floor) => match (
                semver::Version::parse(frontier),
                semver::Version::parse(&floor),
            ) {
                (Ok(frontier_v), Ok(floor_v)) => frontier_v > floor_v,
                _ => false,
            },
        };
        if raise {
            db.set_channel_floor(registry_id, &channel.name, frontier)?;
        }
    }
    Ok(())
}

/// Parse a tag payload without verification (`require_signatures = false`),
/// still enforcing name binding so even unverified display stays
/// path-consistent.
fn lenient_tag(payload: &[u8], expected_name: &str) -> Result<crate::surface::tag::SignedTag> {
    let signed = parse_signed_tag(payload)?;
    aos_package::registry::verify::verify_name_binding(&signed.tag, expected_name)?;
    Ok(signed)
}

/// Extract the signer's base64 key from an armored signature, when parseable.
fn sshsig_signer(armored: &str) -> Option<String> {
    sshsig::parse_armored(armored)
        .ok()
        .map(|s| s.public_key_base64())
}

#[cfg(test)]
mod tests {
    #[test]
    fn pack_path_splits_semver_components() {
        // Mirrors the worked example in docs/registry/http-layout.md:
        // prerelease/build metadata stays in the third path component.
        let mut parts = "1.0.0-beta+exp.sha.5114f85".splitn(3, '.');
        assert_eq!(parts.next(), Some("1"));
        assert_eq!(parts.next(), Some("0"));
        assert_eq!(parts.next(), Some("0-beta+exp.sha.5114f85"));
    }
}
