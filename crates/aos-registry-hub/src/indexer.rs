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

use aos_package::types::RegistryRootConfig;

use crate::db::{ChannelSummary, Database, IndexSnapshot, RegistryRecord, ReleaseRow};
use crate::fetch::SurfaceFetch;
use crate::stack;
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
    // Snapshot the release set before indexing so a successful run can raise a
    // `release.published` webhook for each newly indexed release.
    let prior_releases: std::collections::HashSet<String> = db
        .list_releases(registry.id)
        .map(|rows| rows.into_iter().map(|r| r.semver).collect())
        .unwrap_or_default();

    match index_registry(db, fetch, registry).await {
        Ok(outcome) => {
            dispatch_index_events(db, registry, &outcome, &prior_releases);
            Ok(outcome)
        }
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

/// Fan out the webhook events a successful index raises: one `index.completed`
/// plus a `release.published` for each release newly present since `prior`.
///
/// Only org-owned registries have webhook subscriptions, so this is a no-op
/// for unowned phase-1 registries. Dispatch failures are logged, never
/// propagated — a webhook problem must not fail or roll back an index.
fn dispatch_index_events(
    db: &Database,
    registry: &RegistryRecord,
    outcome: &IndexOutcome,
    prior: &std::collections::HashSet<String>,
) {
    let Some(org_id) = registry.org_id else {
        return;
    };
    let now = unix_now();
    let event = crate::webhook::WebhookEvent::IndexCompleted {
        registry: registry.slug.clone(),
        commit: outcome.commit.clone(),
        packages: outcome.packages,
        releases: outcome.releases,
        channels: outcome.channels,
        incremental: outcome.incremental,
        at: now,
    };
    if let Err(err) = crate::webhook::dispatch(db, org_id, &event) {
        tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "dispatching index.completed webhook");
    }

    // `release.published` for each newly indexed release.
    if let Ok(releases) = db.list_releases(registry.id) {
        for release in releases {
            if prior.contains(&release.semver) {
                continue;
            }
            let event = crate::webhook::WebhookEvent::ReleasePublished {
                registry: registry.slug.clone(),
                semver: release.semver.clone(),
                commit: release.commit_oid.clone(),
                at: now,
            };
            if let Err(err) = crate::webhook::dispatch(db, org_id, &event) {
                tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "dispatching release.published webhook");
            }
        }
    }
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

    // A committed [cache_stack] (RFC-0004) is parsed into the nestable
    // try/mirror model: its JSON is stored for stack-aware validation, and
    // its flattened endpoints are folded into the [[caches]] union so
    // stack-unaware clients and the display table keep working unchanged. A
    // malformed stack is logged and ignored (the flat [[caches]] list still
    // applies) rather than failing the whole index.
    let (caches, cache_stack) = resolve_cache_layout(registry, &tree.root);

    let snapshot = IndexSnapshot {
        commit: commit_oid.to_hex(),
        name: tree.root.registry.name.clone(),
        description: tree.root.registry.description.clone(),
        caches,
        cache_stack,
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

    // Cross-reference the verified HEAD commit with the change-set log
    // (RFC-0004 "Configuration management"): a commit carrying an
    // `AOS-Change-Id` trailer that names a known draft change request marks it
    // applied (a maintainer promoted the draft via `apr change merge`); a
    // verified commit *without* a known trailer is an out-of-band publish, for
    // which we synthesize one idempotent `external` audit entry so the feed is
    // complete over managed and direct changes alike.
    record_commit_provenance(
        db,
        registry,
        &commit,
        &snapshot.commit,
        &roster_lookup(&snapshot.roster),
    );

    Ok(outcome)
}

/// A roster public-key → key-id map for resolving a commit signer to a roster
/// identity (RFC-0004: the external audit entry resolves the signing-key
/// fingerprint to a roster id where possible).
///
/// `roster` is the `(key_id, trusted-key-line, status)` set the index built;
/// only active entries with key material contribute, keyed on the base64 blob
/// (what [`sshsig_signer`] returns from a signature).
fn roster_lookup(roster: &[(String, String, String)]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (key_id, line, status) in roster {
        if status != "active" || line.is_empty() {
            continue;
        }
        if let Some(base64) = line.rsplit(':').next() {
            map.insert(base64.to_string(), key_id.clone());
        }
    }
    map
}

/// Match the verified HEAD commit to the change-set log and record provenance.
///
/// Failures here are logged, never propagated: provenance recording is an
/// audit-completeness nicety layered over a snapshot that already committed —
/// a database hiccup must not fail the index or roll back the snapshot.
fn record_commit_provenance(
    db: &Database,
    registry: &RegistryRecord,
    commit: &crate::surface::object::Commit,
    commit_oid_hex: &str,
    roster: &BTreeMap<String, String>,
) {
    let message = commit_message(&commit.signed_payload);
    if let Some(change_id) = crate::gitwrite::extract_change_id_trailer(&message) {
        // A trailer naming a known change request: mark it applied, linking
        // the promoting commit. An unknown id is treated as a no-trailer
        // commit (external) below.
        match db.changeset(&change_id) {
            Ok(Some(_)) => {
                if let Err(err) = db.mark_changeset_applied_commit(&change_id, commit_oid_hex) {
                    tracing::warn!(
                        slug = %registry.slug,
                        %change_id,
                        error = %format!("{err:#}"),
                        "marking change request applied from trailer"
                    );
                }
                return;
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(
                slug = %registry.slug,
                %change_id,
                error = %format!("{err:#}"),
                "looking up change request from trailer"
            ),
        }
    }

    // No known trailer: synthesize an idempotent `external` audit entry.
    synthesize_external_audit(db, registry, commit, commit_oid_hex, roster);
}

/// Synthesize one `index.external_commit` audit row for an out-of-band commit.
///
/// Idempotent: skipped when an audit row already records this commit, so
/// re-indexing the same surface never duplicates the entry.
fn synthesize_external_audit(
    db: &Database,
    registry: &RegistryRecord,
    commit: &crate::surface::object::Commit,
    commit_oid_hex: &str,
    roster: &BTreeMap<String, String>,
) {
    const ACTION: &str = "index.external_commit";
    match db.audit_exists_for_commit(ACTION, commit_oid_hex) {
        Ok(true) => return,
        Ok(false) => {}
        Err(err) => {
            tracing::warn!(
                slug = %registry.slug,
                error = %format!("{err:#}"),
                "checking for an existing external-commit audit row"
            );
            return;
        }
    }

    // Resolve the signer to a roster id where possible; otherwise label by the
    // signing-key fingerprint (its base64 blob), or `unsigned`.
    let signer_base64 = commit.signature.as_deref().and_then(sshsig_signer);
    let actor_label = match &signer_base64 {
        Some(base64) => match roster.get(base64) {
            Some(key_id) => format!("roster:{key_id}"),
            None => format!("key:{base64}"),
        },
        None => "unsigned".to_string(),
    };
    let detail = serde_json::json!({
        "observed": "surface",
        "note": "out-of-band commit (not authored via the hub)",
    })
    .to_string();
    if let Err(err) = db.record_audit(
        "key",
        None,
        &actor_label,
        ACTION,
        &registry.slug,
        None,
        Some(commit_oid_hex),
        None,
        Some(&detail),
    ) {
        tracing::warn!(
            slug = %registry.slug,
            error = %format!("{err:#}"),
            "synthesizing external-commit audit row"
        );
    }
}

/// Extract the commit message body from a commit's signed payload.
///
/// The payload is `headers\n\nmessage`; the message is everything after the
/// first blank line.
fn commit_message(signed_payload: &[u8]) -> String {
    let text = String::from_utf8_lossy(signed_payload);
    match text.split_once("\n\n") {
        Some((_headers, message)) => message.to_string(),
        None => String::new(),
    }
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

/// Resolve a registry's committed cache layout into the `[[caches]]` union
/// and the optional stored cache-stack JSON.
///
/// The flat committed `[[caches]]` entries always contribute. When a
/// `[cache_stack]` section is present and parses, its flattened endpoints are
/// merged in (the highest priority among the flat entry and the stack's
/// descending order wins per URL), and the parsed stack is serialized to JSON
/// for [`Database::registry_cache_stack`]. A malformed `[cache_stack]` is
/// logged and ignored — the flat list still applies, so an authoring mistake
/// never strands a registry's index.
///
/// The stack's base priority is one above the highest flat `[[caches]]`
/// priority (or its [`aos_package::types`] default when there are none), so a
/// committed stack is consulted ahead of bare flat entries by a stack-unaware
/// client.
fn resolve_cache_layout(
    registry: &RegistryRecord,
    root: &RegistryRootConfig,
) -> (Vec<(String, u32)>, Option<String>) {
    use std::collections::BTreeMap;

    // Start from the flat [[caches]] union, keeping the highest priority per
    // URL.
    let mut by_url: BTreeMap<String, u32> = BTreeMap::new();
    for cache in &root.caches {
        by_url
            .entry(cache.url.clone())
            .and_modify(|p| *p = (*p).max(cache.priority))
            .or_insert(cache.priority);
    }

    let mut cache_stack_json = None;
    if let Some(value) = &root.cache_stack {
        match stack::parse_cache_stack(value.clone()) {
            Ok(node) => {
                let base = by_url
                    .values()
                    .copied()
                    .max()
                    .unwrap_or(100)
                    .saturating_add(1);
                for (url, priority) in stack::to_priority_caches(&node, base) {
                    by_url
                        .entry(url)
                        .and_modify(|p| *p = (*p).max(priority))
                        .or_insert(priority);
                }
                match node.to_json() {
                    Ok(json) => cache_stack_json = Some(json),
                    Err(err) => tracing::warn!(
                        slug = %registry.slug,
                        error = %format!("{err:#}"),
                        "serializing committed cache_stack; storing flat caches only"
                    ),
                }
            }
            Err(err) => tracing::warn!(
                slug = %registry.slug,
                error = %format!("{err:#}"),
                "ignoring malformed committed [cache_stack]; using flat [[caches]]"
            ),
        }
    }

    // Highest priority first, ties broken by URL for determinism.
    let mut caches: Vec<(String, u32)> = by_url.into_iter().collect();
    caches.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    (caches, cache_stack_json)
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
