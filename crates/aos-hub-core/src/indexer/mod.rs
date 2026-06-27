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
//!
//! # One indexer, both shells
//!
//! This module is the single canonical indexer. It is pure logic over the
//! [`SurfaceFetch`](crate::fetch::SurfaceFetch) read port and the core
//! [`Database`](crate::db::Database) write side — no async runtime, filesystem,
//! or HTTP client of its own — so it compiles to `wasm32-unknown-unknown` and
//! runs identically on the native hub (over a `LocalFsFetch`/`HttpFetch`) and in
//! the Cloudflare Worker's Cron job (over an `R2SurfaceFetch`). The accept/reject
//! channel-partition decisions and the anti-rollback floor logic live inline in
//! [`resolve_channels`]/[`enforce_floors`]/[`raise_floors`]; both shells share
//! exactly these rules, so the Worker's eventual index is byte-identical to the
//! native hub's.

pub mod load;

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use aos_registry_surface::manifest::{self, RegistryRootConfig};
use aos_registry_surface::object::{Commit, ObjectKind};
use aos_registry_surface::refs::{parse_head, parse_info_refs, Refs};
use aos_registry_surface::sshsig;
use aos_registry_surface::tag::{parse_signed_tag, verify_signed_tag, SignedTag};
use aos_registry_surface::tagobject::{verify_name_binding, TagTarget};
use sha2::{Digest, Sha256};

use crate::db::{ChannelSummary, Database, IndexSnapshot, RegistryRecord, ReleaseRow};
use crate::fetch::SurfaceFetch;

use self::load::{load_registry_tree, ObjectReader};

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
    /// Whether the registry has no readable surface yet (no `info/refs`, or a
    /// transiently-unavailable backend): a freshly-created registry, or one whose
    /// object store is briefly erroring. A pending run indexes nothing and raises
    /// no events; it is recorded as the benign `pending` state, never `failed`.
    pub pending: bool,
}

/// The [`IndexOutcome`] for a run that indexed nothing because the surface is
/// not (yet) readable — a registry with no published `info/refs`, or one whose
/// backend is transiently unavailable.
fn pending_outcome() -> IndexOutcome {
    IndexOutcome {
        commit: String::new(),
        packages: 0,
        releases: 0,
        channels: 0,
        incremental: false,
        pending: true,
    }
}

/// The [`IndexOutcome`] for a run that *successfully* indexed an empty registry
/// — no surface published yet, so nothing to index, and the run is complete.
///
/// Shaped like [`pending_outcome`] (it indexed nothing, so it raises no
/// `index.completed`/`release.published` events), but it is recorded as the
/// terminal `empty` state rather than `pending`: it is done, not awaiting a
/// retry.
fn empty_outcome() -> IndexOutcome {
    IndexOutcome {
        commit: String::new(),
        packages: 0,
        releases: 0,
        channels: 0,
        incremental: false,
        pending: true,
    }
}

/// Reports whether `err` is a *transient* surface-backend error the platform
/// asks callers to retry, rather than a permanent failure.
///
/// The motivating case is Cloudflare R2 error **10001** ("We encountered an
/// internal error. Please try again."), which the Worker's R2 binding can return
/// for a `get` — including, on some buckets, for an object that is merely absent.
/// Such an error must never be recorded as a permanent `failed` index state (it
/// would leave the registry stuck showing "index failed" until a manual
/// re-index); the indexer treats it like an unavailable surface and retries on
/// the next pass. The match is on the error message because the backend error
/// crosses the [`SurfaceFetch`] boundary as an opaque `anyhow` error.
fn is_transient_backend_error(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}");
    msg.contains("(10001)") || msg.contains("Please try again") || msg.contains("please try again")
}

/// Index one registered registry, recording failure state on error.
///
/// This is the entry point callers should use: it wraps [`index_registry`]
/// so that any failure is persisted as the registry's index state instead
/// of being lost with the returned error. Transport-level fetch failures
/// (classified via [`crate::url_guard::is_fetch_error`]) mark the index
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
        .await
        .map(|rows| rows.into_iter().map(|r| r.semver).collect())
        .unwrap_or_default();

    match index_registry(db, fetch, registry).await {
        Ok(outcome) => {
            // A pending run (no surface published yet) indexed nothing, so it
            // raises no `index.completed`/`release.published` events.
            if !outcome.pending {
                dispatch_index_events(db, registry, &outcome, &prior_releases).await;
            }
            Ok(outcome)
        }
        Err(err) => {
            let detail = format!("{err:#}");
            if crate::url_guard::is_fetch_error(&err) {
                db.mark_index_stale(registry.id, &detail).await?;
            } else {
                db.mark_index_failed(registry.id, &detail).await?;
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
async fn dispatch_index_events(
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
    if let Err(err) = crate::webhook::dispatch(db, org_id, &event).await {
        tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "dispatching index.completed webhook");
    }

    // `release.published` for each newly indexed release.
    if let Ok(releases) = db.list_releases(registry.id).await {
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
            if let Err(err) = crate::webhook::dispatch(db, org_id, &event).await {
                tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "dispatching release.published webhook");
            }
        }
    }
}

/// Current Unix time in seconds.
///
/// Routed through [`crate::clock::now_unix_secs`] so the indexer reads the wall
/// clock on both the native hub (`std::time`) and the Cloudflare Worker (the JS
/// `Date.now()`), where `std::time::SystemTime::now()` panics.
fn unix_now() -> i64 {
    crate::clock::now_unix_secs()
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
    let refs_bytes = match fetch.fetch("info/refs").await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            // No `info/refs` object: the registry has no published surface yet (a
            // freshly-created registry nobody has pushed to). Indexing an empty
            // registry is a *successful, complete* run — it's done, there's just
            // nothing in it — so record the terminal `empty` state (stamped with
            // `indexed_at`), NOT `pending`. `pending` is reserved below for a
            // transient backend error that genuinely warrants a retry. The home
            // page reads "nothing published yet" either way; the difference is
            // that `empty` no longer masquerades as in-progress work.
            db.mark_index_empty(registry.id).await?;
            return Ok(empty_outcome());
        }
        Err(err) if is_transient_backend_error(&err) => {
            // The surface backend is *transiently* unavailable — e.g. Cloudflare
            // R2 error 10001 ("We encountered an internal error. Please try
            // again."), which the platform explicitly asks callers to retry. This
            // is NOT a permanent index failure, so it must never be recorded as
            // `failed` (which would leave the registry stuck showing "index
            // failed: ... (10001)" until a manual re-index). Record the benign
            // `pending` state so the next scheduled pass retries — but do not
            // regress a registry that already holds a *terminal* index: a `fresh`
            // index (don't hide a healthy registry's releases on a hiccup) or an
            // `empty` one. The latter matters because R2 throws this same 10001
            // for a *missing* key, so an empty registry's `info/refs` read flaps
            // between a clean "absent" (→ `empty`) and a 10001 (→ here): without
            // this guard it would oscillate empty↔pending pass to pass. Once
            // empty, it stays empty until a surface is actually read.
            let already_terminal = db
                .index_status(registry.id)
                .await?
                .is_some_and(|status| status.state == "fresh" || status.state == "empty");
            if !already_terminal {
                db.mark_index_pending(registry.id).await?;
            }
            return Ok(pending_outcome());
        }
        Err(err) => return Err(err),
    };
    let refs = parse_info_refs(std::str::from_utf8(&refs_bytes).context("info/refs not UTF-8")?)?;
    let refs_digest = hex::encode(Sha256::digest(&refs_bytes));

    // Incremental fast path: an unchanged ref advertisement over a fresh
    // index means the immutable object graph is already verified — only
    // the mutable channel partitions need re-checking.
    let state_fresh = db
        .index_status(registry.id)
        .await?
        .is_some_and(|status| status.state == "fresh");
    if state_fresh && db.refs_digest(registry.id).await?.as_deref() == Some(refs_digest.as_str()) {
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
    let branch_names = capped_branch_names(&refs).await;
    let tag_to_semver: BTreeMap<String, String> = releases
        .iter()
        .map(|release| (release.tag_oid.clone(), release.semver.clone()))
        .collect();
    let channels =
        resolve_channels(fetch, registry, &branch_names, &trusted, &tag_to_semver).await?;
    enforce_floors(db, registry.id, &channels).await?;

    // The committed [caches] cache stack (RFC-0004) is flattened into the
    // priority list stack-unaware clients and the display table resolve; when
    // it is in stack form its JSON is also stored for stack-aware validation.
    // A malformed stack flattens to an empty list (logged) rather than failing
    // the whole index.
    let (caches, cache_stack) = resolve_cache_layout(registry, &tree.root);

    let snapshot = IndexSnapshot {
        commit: commit_oid.to_hex(),
        name: tree.root.registry.name.clone(),
        description: tree.root.registry.description.clone(),
        readme: tree.root.registry.readme.clone(),
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
        pending: false,
    };
    db.apply_snapshot(registry.id, &snapshot).await?;
    raise_floors(db, registry.id, &snapshot.channels).await?;

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
    )
    .await;

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
async fn record_commit_provenance(
    db: &Database,
    registry: &RegistryRecord,
    commit: &Commit,
    commit_oid_hex: &str,
    roster: &BTreeMap<String, String>,
) {
    let message = commit_message(&commit.signed_payload);
    if let Some(change_id) = crate::git::extract_change_id_trailer(&message) {
        // A trailer naming a known change request: mark it applied, linking
        // the promoting commit. An unknown id — *or* a change-set whose target
        // scope is not within this registry — is treated as a no-trailer
        // (external) commit below, so a commit on registry B cannot mark a
        // change request scoped to registry A as applied by carrying A's id.
        match db.changeset(&change_id).await {
            Ok(Some(changeset))
                if crate::domain::Scope::parse(&registry.slug)
                    .contains(&crate::domain::Scope::parse(&changeset.scope)) =>
            {
                if let Err(err) = db
                    .mark_changeset_applied_commit(&change_id, commit_oid_hex)
                    .await
                {
                    tracing::warn!(
                        slug = %registry.slug,
                        %change_id,
                        error = %format!("{err:#}"),
                        "marking change request applied from trailer"
                    );
                }
                return;
            }
            Ok(Some(changeset)) => {
                // The trailer references a real change-set scoped outside this
                // registry: do not apply it; fall through to the external-commit
                // audit so the foreign change request is untouched.
                tracing::warn!(
                    slug = %registry.slug,
                    %change_id,
                    changeset_scope = %changeset.scope,
                    "ignoring change-id trailer whose scope is not within this registry"
                );
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
    synthesize_external_audit(db, registry, commit, commit_oid_hex, roster).await;
}

/// Synthesize one `index.external_commit` audit row for an out-of-band commit.
///
/// Idempotent: skipped when an audit row already records this commit, so
/// re-indexing the same surface never duplicates the entry.
async fn synthesize_external_audit(
    db: &Database,
    registry: &RegistryRecord,
    commit: &Commit,
    commit_oid_hex: &str,
    roster: &BTreeMap<String, String>,
) {
    const ACTION: &str = "index.external_commit";
    match db.audit_exists_for_commit(ACTION, commit_oid_hex).await {
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
    if let Err(err) = db
        .record_audit(
            "key",
            None,
            &actor_label,
            ACTION,
            &registry.slug,
            None,
            Some(commit_oid_hex),
            None,
            Some(&detail),
        )
        .await
    {
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
    for (_key_id, public_key, status) in db.list_roster(registry.id).await? {
        if status == "active" && !public_key.is_empty() && !trusted.contains(&public_key) {
            trusted.push(public_key);
        }
    }

    let releases = db.list_releases(registry.id).await?;
    let tag_to_semver: BTreeMap<String, String> = releases
        .iter()
        .map(|release| (release.tag_oid.clone(), release.semver.clone()))
        .collect();

    let branch_names = capped_branch_names(refs).await;
    let channels =
        resolve_channels(fetch, registry, &branch_names, &trusted, &tag_to_semver).await?;
    enforce_floors(db, registry.id, &channels).await?;
    db.update_channels(registry.id, &channels).await?;
    raise_floors(db, registry.id, &channels).await?;

    let commit = db
        .index_status(registry.id)
        .await?
        .and_then(|status| status.last_indexed_commit)
        .unwrap_or_default();
    Ok(IndexOutcome {
        commit,
        packages: db.list_packages(registry.id).await?.len(),
        releases: releases.len(),
        channels: channels.len(),
        incremental: true,
        pending: false,
    })
}

/// The advertised branch names in deterministic order, capped at
/// [`MAX_BRANCHES`] with a warning.
async fn capped_branch_names(refs: &Refs) -> Vec<String> {
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
async fn enforce_floors(
    db: &Database,
    registry_id: i64,
    channels: &[ChannelSummary],
) -> Result<()> {
    for channel in channels {
        let Some(frontier) = &channel.frontier else {
            continue;
        };
        let Some(floor) = db.channel_floor(registry_id, &channel.name).await? else {
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
async fn raise_floors(db: &Database, registry_id: i64, channels: &[ChannelSummary]) -> Result<()> {
    for channel in channels {
        let Some(frontier) = &channel.frontier else {
            continue;
        };
        let raise = match db.channel_floor(registry_id, &channel.name).await? {
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
            db.set_channel_floor(registry_id, &channel.name, frontier)
                .await?;
        }
    }
    Ok(())
}

/// Resolve a registry's committed `[caches]` cache stack into the flattened
/// priority union and the optional stored cache-stack JSON.
///
/// The unified `[caches]` value is the single source of truth: its flattened
/// `(url, priority)` entries always contribute. When `[caches]` is in stack
/// form (a bare endpoint or a `kind`/`members` node) the parsed stack is also
/// serialized to JSON for [`Database::registry_cache_stack`] so coverage
/// validation can recover its mirror groups. A legacy `[[caches]]` array
/// contributes its entries but has no stack JSON. A malformed `[caches]`
/// stack flattens to an empty list (logged here), so an authoring mistake
/// never strands a registry's index.
fn resolve_cache_layout(
    registry: &RegistryRecord,
    root: &RegistryRootConfig,
) -> (Vec<(String, u32)>, Option<String>) {
    use std::collections::BTreeMap;

    // Flatten the unified [caches] value, keeping the highest priority per URL.
    let mut by_url: BTreeMap<String, u32> = BTreeMap::new();
    for cache in root.cache_entries() {
        by_url
            .entry(cache.url)
            .and_modify(|p| *p = (*p).max(cache.priority))
            .or_insert(cache.priority);
    }
    if matches!(root.caches, Some(manifest::CachesConfig::Stack(_))) && by_url.is_empty() {
        tracing::warn!(
            slug = %registry.slug,
            "ignoring malformed committed [caches] stack; advertising no caches"
        );
    }

    // Persist the parsed stack JSON when [caches] is in stack form.
    let cache_stack_json = match root.cache_stack() {
        Some(node) => match node.to_json() {
            Ok(json) => Some(json),
            Err(err) => {
                tracing::warn!(
                    slug = %registry.slug,
                    error = %format!("{err:#}"),
                    "serializing committed [caches] stack; storing flat caches only"
                );
                None
            }
        },
        None => None,
    };

    // Highest priority first, ties broken by URL for determinism.
    let mut caches: Vec<(String, u32)> = by_url.into_iter().collect();
    caches.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    (caches, cache_stack_json)
}

/// Parse a tag payload without verification (`require_signatures = false`),
/// still enforcing name binding so even unverified display stays
/// path-consistent.
fn lenient_tag(payload: &[u8], expected_name: &str) -> Result<SignedTag> {
    let signed = parse_signed_tag(payload)?;
    verify_name_binding(&signed.tag, expected_name)?;
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
    use super::*;
    use crate::db::Database;
    use crate::fetch::SurfaceFetch;

    #[test]
    fn pack_path_splits_semver_components() {
        // Mirrors the worked example in docs/registry/http-layout.md:
        // prerelease/build metadata stays in the third path component.
        let mut parts = "1.0.0-beta+exp.sha.5114f85".splitn(3, '.');
        assert_eq!(parts.next(), Some("1"));
        assert_eq!(parts.next(), Some("0"));
        assert_eq!(parts.next(), Some("0-beta+exp.sha.5114f85"));
    }

    #[test]
    fn transient_backend_errors_are_recognized() {
        let r2_10001 = anyhow::anyhow!(
            "R2 get andyl/demo/info/refs: get: We encountered an internal error. \
             Please try again. (10001)"
        );
        assert!(is_transient_backend_error(&r2_10001));
        // A genuine parse/corruption error is not transient.
        assert!(!is_transient_backend_error(&anyhow::anyhow!(
            "surface advertises no branches"
        )));
        assert!(!is_transient_backend_error(&anyhow::anyhow!(
            "info/refs not UTF-8"
        )));
    }

    /// A [`SurfaceFetch`] whose `info/refs` read fails with a given error, to
    /// exercise the indexer's transient-vs-permanent classification.
    struct FailingFetch {
        error: String,
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for FailingFetch {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            Err(anyhow::anyhow!("{}", self.error))
        }
        fn describe(&self) -> String {
            "failing".into()
        }
    }

    #[tokio::test]
    async fn transient_surface_error_records_pending_not_failed() {
        let db = Database::open_in_memory().await.unwrap();
        let id = db
            .register_registry("acme/app", "", &[], false)
            .await
            .unwrap();
        let registry = db.registry_by_slug("acme/app").await.unwrap().unwrap();
        let fetch = FailingFetch {
            error: "R2 get acme/app/info/refs: get: We encountered an internal error. \
                    Please try again. (10001)"
                .into(),
        };

        // A freshly-created registry starts `empty`. A retryable R2 10001 on the
        // surface read must NOT mark it `failed`, and must NOT regress it off the
        // terminal `empty` state — R2 throws this same 10001 for a missing key,
        // so an empty registry's read flaps; the guard keeps it empty.
        let outcome = index_and_record(&db, &fetch, &registry).await.unwrap();
        assert!(
            outcome.pending,
            "a transient backend error is a no-content run"
        );
        let status = db.index_status(id).await.unwrap().unwrap();
        assert_eq!(
            status.state, "empty",
            "empty must survive a transient error"
        );
        assert!(status.error.is_none());

        // From a non-terminal state (here, a prior hard failure), the same
        // transient error records the benign `pending` retry state — still never
        // leaving the index stuck on `failed`.
        db.mark_index_failed(id, "boom").await.unwrap();
        let outcome = index_and_record(&db, &fetch, &registry).await.unwrap();
        assert!(outcome.pending);
        let status = db.index_status(id).await.unwrap().unwrap();
        assert_eq!(status.state, "pending");
        assert!(status.error.is_none(), "pending carries no error message");
    }

    #[tokio::test]
    async fn permanent_surface_error_still_fails() {
        let db = Database::open_in_memory().await.unwrap();
        db.register_registry("acme/bad", "", &[], false)
            .await
            .unwrap();
        let registry = db.registry_by_slug("acme/bad").await.unwrap().unwrap();
        // A non-transient error (e.g. a malformed surface) is a real failure.
        let fetch = FailingFetch {
            error: "objects/ab/cd is corrupt".into(),
        };
        let result = index_and_record(&db, &fetch, &registry).await;
        assert!(result.is_err(), "a permanent error propagates");
        let status = db.index_status(registry.id).await.unwrap().unwrap();
        assert!(matches!(status.state.as_str(), "failed" | "stale"));
    }
}
