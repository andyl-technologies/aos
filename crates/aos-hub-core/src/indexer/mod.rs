//! Fetch → verify → load → index orchestration.
//!
//! [`index_registry`] re-walks one registry surface exactly as an `apm`
//! client would and replaces its rebuildable index atomically:
//!
//! 1. Fetch `HEAD` + `info/refs` and pick the default branch's commit.
//!    If both the advertised commit and the `info/refs` digest match the
//!    current fresh index, only the mutable channel partitions are re-verified
//!    (the incremental fast path); otherwise the full walk runs.
//! 2. Read the commit loose object; with `require_signatures`, verify its
//!    `gpgsig` SSH signature against the registry's pinned trust anchors
//!    (fail closed — an unverifiable surface is never displayed as fresh).
//! 3. Load the committed tree (`registry.toml`, `keys.toml`, packages,
//!    closures) and extend the trusted set with the verified roster's
//!    active keys, mirroring `apm`'s in-band rotation semantics.
//! 4. Verify every release tag (signature + name binding), rejecting an
//!    advertisement above [`MAX_RELEASE_TAGS`], and probe each release's per-release
//!    `objects/info/packs` for pack presence.
//! 5. Resolve every channel (rejecting more than [`MAX_BRANCHES`]) by
//!    probing all 256 partition payloads, verifying each, and mapping its
//!    target tag object to a release.
//! 6. Enforce the anti-rollback floor: a channel whose frontier dropped
//!    below the highest frontier ever indexed is rejected.
//! 7. Write the snapshot and webhook event intents in one transaction, then
//!    raise the floors.
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
use aos_registry_surface::manifest::RegistryRootConfig;
use aos_registry_surface::object::{Commit, ObjectKind};
use aos_registry_surface::refs::{parse_head, parse_info_refs, Refs};
use aos_registry_surface::sshsig;
use aos_registry_surface::tag::{parse_signed_tag, verify_signed_tag, SignedTag};
use aos_registry_surface::tagobject::{verify_name_binding, TagTarget};
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use futures_util::{future::try_join_all, TryStreamExt as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::db::{
    ChannelSummary, Database, IndexSnapshot, RegistryRecord, ReleaseArtifactSnapshot,
    ReleaseImageSnapshot, ReleaseRow, ReleaseSnapshotArtifact,
};
use crate::fetch::SurfaceFetch;

use self::load::{load_registry_tree, ObjectReader};

/// Maximum branches (channels) processed per index run.
///
/// A hostile or runaway surface advertising thousands of branches would
/// otherwise cost 256 partition fetches each; larger advertisements fail
/// closed rather than publishing incomplete retention inputs.
pub const MAX_BRANCHES: usize = 64;

/// Maximum release tags processed per index run.
///
/// Larger advertisements fail closed rather than publishing incomplete
/// retention inputs.
pub const MAX_RELEASE_TAGS: usize = 1024;

/// Maximum concurrent channel-partition reads during one index pass.
///
/// Each channel has exactly 256 independent signed partitions. Bounded fanout
/// avoids making a complete channel cost hundreds of serial object-store round
/// trips while remaining below Worker subrequest and memory limits.
const CHANNEL_FETCH_CONCURRENCY: usize = 32;

/// Maximum release trees loaded concurrently during a full index pass.
///
/// A release tree contains hundreds of independently addressable package and
/// store records. Loading releases serially multiplies that object-store
/// latency by the retention depth; a small outer fanout keeps Worker memory
/// and subrequests bounded while overlapping independent release generations.
const RELEASE_TREE_FETCH_CONCURRENCY: usize = 4;

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
        pending: false,
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
    index_and_record_from_placement(db, fetch, registry, None).await
}

/// Indexes a registry from one known placement and records the resulting state.
///
/// # Errors
///
/// Returns the indexing error after recording it.
pub async fn index_and_record_from_placement(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
    indexed_placement_id: Option<i64>,
) -> Result<IndexOutcome> {
    if db.registry_has_active_publication(registry.id).await? {
        return Ok(pending_outcome());
    }
    let starting_generation = db
        .index_status(registry.id)
        .await?
        .map_or(0, |status| status.generation);
    match index_registry(db, fetch, registry, indexed_placement_id).await {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            let detail = format!("{err:#}");
            if crate::url_guard::is_fetch_error(&err) {
                db.mark_index_stale(registry.id, &detail).await?;
            } else {
                db.mark_index_failed_if_generation(registry.id, starting_generation, &detail)
                    .await?;
            }
            Err(err)
        }
    }
}

/// Reconciles one replica against the already-published signed registry generation.
///
/// This path never mutates global package, release, channel, event, or index
/// visibility. It first proves that the replica advertises the exact indexed
/// refs digest, then re-hashes every signed image root from that placement and
/// records only placement-local presence evidence.
///
/// # Errors
///
/// Returns an error when the replica does not match the published generation,
/// an image object is unavailable or corrupt, or persistence fails.
pub async fn reconcile_registry_replica(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
    placement_id: i64,
) -> Result<usize> {
    let expected_refs = db
        .refs_digest(registry.id)
        .await?
        .context("registry has no published refs digest")?;
    let refs = fetch
        .fetch("info/refs")
        .await?
        .context("replica has no info/refs")?;
    let observed_refs = hex::encode(Sha256::digest(&refs));
    anyhow::ensure!(
        observed_refs == expected_refs,
        "replica refs do not match the published registry generation"
    );

    let mut leases = Vec::new();
    let outcome = async {
        let roots = db.list_system_image_roots(registry.id).await?;
        let mut objects = Vec::with_capacity(roots.len());
        for (object_key, sha256, byte_size) in roots {
            objects.push(
                verify_system_image_object(fetch, object_key, sha256, byte_size, &mut leases)
                    .await?,
            );
        }
        if !objects.is_empty() {
            db.record_registry_image_presence(
                registry.id,
                placement_id,
                &objects,
                crate::clock::now_unix_secs(),
            )
            .await?;
        }
        Ok::<usize, anyhow::Error>(objects.len())
    }
    .await;
    let release = db.release_image_snapshot_leases(&leases).await;
    match (outcome, release) {
        (Ok(count), Ok(())) => Ok(count),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("releasing replica snapshot leases")),
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
    indexed_placement_id: Option<i64>,
) -> Result<IndexOutcome> {
    let mut snapshot_leases = Vec::new();
    let outcome = index_registry_inner(
        db,
        fetch,
        registry,
        indexed_placement_id,
        &mut snapshot_leases,
    )
    .await;
    let release = db.release_image_snapshot_leases(&snapshot_leases).await;
    match (outcome, release) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("releasing image snapshot index leases")),
    }
}

async fn index_registry_inner(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
    indexed_placement_id: Option<i64>,
    snapshot_leases: &mut Vec<String>,
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
            let placement_id = indexed_placement_id
                .context("empty registry indexing requires an authoritative placement")?;
            db.mark_index_empty_from_placement(registry.id, placement_id)
                .await?;
            return Ok(empty_outcome());
        }
        Err(err) if is_transient_backend_error(&err) => {
            // The surface backend is *transiently* unavailable — e.g. Cloudflare
            // R2 error 10001 ("We encountered an internal error. Please try
            // again."), which the platform explicitly asks callers to retry. This
            // is NOT a permanent index failure, so it must never be recorded as
            // `failed` (which would leave the registry stuck showing "index
            // failed: ... (10001)" until a manual re-index). Metadata-only
            // registries record the benign `pending` state so the next scheduled
            // pass retries, without regressing a terminal `fresh` or `empty`
            // index. Image-bearing registries are the exception: a failed byte
            // revalidation makes their index stale and hides direct downloads.
            // The empty guard matters because R2 throws this same 10001
            // for a *missing* key, so an empty registry's `info/refs` read flaps
            // between a clean "absent" (→ `empty`) and a 10001 (→ here): without
            // this guard it would oscillate empty↔pending pass to pass. Once
            // empty, it stays empty until a surface is actually read.
            // Direct image discovery is stricter than metadata-only package
            // browsing: an unsuccessful refresh cannot attest that both the
            // signed catalog and its exact disk bytes are still readable.
            // Hide the last-good image rows until a complete revalidation
            // succeeds. Package-only registries retain the historical benign
            // pending behavior below.
            if db.has_system_image_catalog(registry.id).await? {
                db.mark_index_stale(registry.id, &format!("{err:#}"))
                    .await?;
                return Ok(pending_outcome());
            }
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

    // The refs digest alone is not sufficient evidence that every derived row
    // belongs to the advertised graph if a prior refresh was interrupted or
    // persisted state drifted. Require the recorded commit to agree with the
    // default branch before skipping the full verification walk.
    let status = db.index_status(registry.id).await?;
    let advertised_commit = commit_oid.to_hex();
    let refs_digest_matches =
        db.refs_digest(registry.id).await?.as_deref() == Some(refs_digest.as_str());
    let has_images = db.has_system_image_catalog(registry.id).await?;
    if incremental_preconditions(
        status.as_ref().map(|status| status.state.as_str()),
        status
            .as_ref()
            .and_then(|status| status.last_indexed_commit.as_deref()),
        refs_digest_matches,
        has_images,
        &advertised_commit,
    ) {
        return index_incremental(db, fetch, registry, &refs, indexed_placement_id).await;
    }

    let reader = ObjectReader::new(fetch);
    let commit = reader.read_commit(commit_oid).await?;
    let mut trusted: Vec<String> = registry.trust_keys.clone();
    let typed_publication = append_signing_usage_key(
        db,
        &mut trusted,
        &registry.stable_id,
        "registry_publication",
    )
    .await?;
    if registry.require_signatures || typed_publication {
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

    // Releases are retention and GC roots. Refuse an incomplete index instead
    // of silently publishing a prefix of the advertised tag set.
    validate_ref_cardinality(&refs)?;
    let release_tags: Vec<_> = refs.tags.iter().collect();
    let mut releases = Vec::new();
    let mut release_artifact_snapshots = Vec::new();
    let mut release_images = Vec::new();
    let mut image_presence = Vec::new();
    let mut image_release_tag_oids = std::collections::BTreeSet::new();
    for batch in release_tags.chunks(RELEASE_TREE_FETCH_CONCURRENCY) {
        let loaded = try_join_all(batch.iter().copied().map(|(tag_name, tag_oid)| {
            let reader = &reader;
            async move {
                let payload = reader.read_kind(*tag_oid, ObjectKind::Tag).await?;
                let lenient = lenient_tag(&payload, tag_name)?;
                if lenient.tag.target_type != TagTarget::Commit {
                    bail!("release tag '{tag_name}' does not target a commit");
                }
                let source_commit = lenient.tag.object.clone();
                let release_tree = load_registry_tree(
                    fetch,
                    aos_registry_surface::object::Oid::from_hex(&source_commit)?,
                )
                .await
                .with_context(|| format!("loading release artifact snapshot for '{tag_name}'"))?;
                Ok::<_, anyhow::Error>((
                    tag_name.clone(),
                    *tag_oid,
                    payload,
                    lenient,
                    source_commit,
                    release_tree,
                ))
            }
        }))
        .await?;
        for (tag_name, tag_oid, payload, lenient, source_commit, release_tree) in loaded {
            let has_image_catalog = release_tree.packages.iter().any(|package| {
                package.package.sysroot
                    && package.versions.iter().any(|version| {
                        version.platforms.values().any(|platform| {
                            platform
                                .images
                                .iter()
                                .any(|image| !image.delivery.is_store_only())
                        })
                    })
            });
            let (signed, signer) =
                if registry.require_signatures || typed_publication || has_image_catalog {
                    // An image catalog is always authenticated by its release tag,
                    // even for registries that otherwise permit unsigned package
                    // metadata. An unsigned HEAD roster cannot delegate image trust.
                    let image_trusted = if registry.require_signatures || typed_publication {
                        trusted.as_slice()
                    } else {
                        registry.trust_keys.as_slice()
                    };
                    let signed = verify_signed_tag(&payload, &tag_name, image_trusted)
                        .with_context(|| format!("signed image release tag '{tag_name}'"))?;
                    let signer = parse_signed_tag(&payload)
                        .ok()
                        .and_then(|signed| sshsig_signer(&signed.signature));
                    (signed, signer)
                } else {
                    (lenient, None)
                };
            if has_image_catalog {
                let catalog = verify_system_image_objects(
                    db,
                    fetch,
                    registry.id,
                    indexed_placement_id,
                    &advertised_commit,
                    &refs_digest,
                    &source_commit,
                    &release_tree.root.registry.name,
                    &release_tree.packages,
                    snapshot_leases,
                )
                .await
                .with_context(|| format!("verifying signed image release '{tag_name}'"))?;
                let images = catalog
                    .images
                    .into_iter()
                    .filter(|image| image.release == tag_name.as_str())
                    .collect::<Vec<_>>();
                if !images.is_empty() {
                    let selected_keys = images
                        .iter()
                        .filter(|image| !image.delivery.is_store_backed())
                        .flat_map(|image| {
                            [
                                image.delivery.object_key.clone(),
                                image.delivery.image_info.object_key.clone(),
                            ]
                        })
                        .collect::<std::collections::BTreeSet<_>>();
                    image_release_tag_oids.insert(tag_oid.to_hex());
                    release_images.push(ReleaseImageSnapshot {
                        release_tag: tag_name.clone(),
                        source_commit: source_commit.clone(),
                        verified_tag_oid: tag_oid.to_hex(),
                        catalog_digest: catalog.digest,
                        images,
                    });
                    image_presence.extend(
                        catalog
                            .objects
                            .into_iter()
                            .filter(|object| selected_keys.contains(object.object_key.as_str())),
                    );
                }
            }
            let artifacts = release_snapshot_artifacts(&release_tree.packages);
            let manifest_digest = hex::encode(Sha256::digest(serde_json::to_vec(&artifacts)?));
            release_artifact_snapshots.push(ReleaseArtifactSnapshot {
                release_tag: tag_name.clone(),
                source_commit: source_commit.clone(),
                verified_tag_oid: tag_oid.to_hex(),
                manifest_digest,
                artifacts,
            });
            releases.push(ReleaseRow {
                semver: tag_name.clone(),
                tag_oid: tag_oid.to_hex(),
                commit_oid: source_commit,
                signer,
                tagged_at: signed.tag.tagger_when,
                pack_present: probe_pack_presence(fetch, &tag_name).await?,
            });
        }
    }

    // Channels: branches are channel names; each resolves through 256
    // partition payloads pointing at release tag objects.
    let branch_names = complete_branch_names(&refs)?;
    let tag_to_semver: BTreeMap<String, String> = releases
        .iter()
        .map(|release| (release.tag_oid.clone(), release.semver.clone()))
        .collect();
    let channels = resolve_channels(
        db,
        fetch,
        registry,
        &branch_names,
        &trusted,
        typed_publication,
        &tag_to_semver,
        &image_release_tag_oids,
    )
    .await?;

    // The committed [caches] cache stack (RFC-0004) is flattened into the
    // priority list stack-unaware clients and the display table resolve; when
    // it is in stack form its JSON is also stored for stack-aware validation.
    // A malformed stack flattens to an empty list (logged) rather than failing
    // the whole index.
    let (caches, cache_stack) = resolve_cache_layout(registry, &tree.root);

    image_presence.sort_by(|left, right| left.object_key.cmp(&right.object_key));
    let mut deduplicated_presence: Vec<crate::db::VerifiedRegistryImageObject> =
        Vec::with_capacity(image_presence.len());
    for object in image_presence {
        if let Some(previous) = deduplicated_presence.last() {
            anyhow::ensure!(
                previous.object_key != object.object_key
                    || (previous.sha256 == object.sha256
                        && previous.byte_size == object.byte_size
                        && previous.strong_etag == object.strong_etag),
                "signed image object '{}' has conflicting release identities",
                object.object_key
            );
            if previous.object_key == object.object_key {
                continue;
            }
        }
        deduplicated_presence.push(object);
    }
    let image_presence = deduplicated_presence;

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
        release_artifact_snapshots,
        release_images,
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
    if let Some(placement_id) = indexed_placement_id {
        db.apply_snapshot_with_image_presence(
            registry.id,
            &snapshot,
            placement_id,
            &image_presence,
            crate::clock::now_unix_secs(),
        )
        .await?;
    } else if !image_presence.is_empty() {
        bail!("signed system images require an exact indexed placement");
    } else {
        db.apply_snapshot_from_placement(registry.id, &snapshot, None)
            .await?;
    }

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

/// Returns whether the index state proves the immutable graph is unchanged.
fn incremental_preconditions(
    state: Option<&str>,
    last_indexed_commit: Option<&str>,
    refs_digest_matches: bool,
    has_images: bool,
    advertised_commit: &str,
) -> bool {
    state == Some("fresh")
        && last_indexed_commit == Some(advertised_commit)
        && refs_digest_matches
        && !has_images
}

fn release_snapshot_artifacts(
    packages: &[aos_registry_surface::manifest::PackageToml],
) -> Vec<ReleaseSnapshotArtifact> {
    let mut artifacts = Vec::new();
    for package in packages {
        for version in &package.versions {
            for (platform, entry) in &version.platforms {
                artifacts.push(ReleaseSnapshotArtifact {
                    package_name: package.package.name.clone(),
                    package_version: version.version.clone(),
                    platform: platform.clone(),
                    artifact_kind: "output".to_string(),
                    store_hash: store_hash_component(&entry.store_path),
                    store_path: entry.store_path.clone(),
                });
                if !entry.source_drv.is_empty() {
                    artifacts.push(ReleaseSnapshotArtifact {
                        package_name: package.package.name.clone(),
                        package_version: version.version.clone(),
                        platform: platform.clone(),
                        artifact_kind: "source_derivation".to_string(),
                        store_hash: store_hash_component(&entry.source_drv),
                        store_path: entry.source_drv.clone(),
                    });
                }
                for image in &entry.images {
                    artifacts.push(ReleaseSnapshotArtifact {
                        package_name: package.package.name.clone(),
                        package_version: version.version.clone(),
                        platform: platform.clone(),
                        artifact_kind: "image".to_string(),
                        store_hash: store_hash_component(&image.store_path),
                        store_path: image.store_path.clone(),
                    });
                    if image.delivery.is_store_backed() {
                        artifacts.push(ReleaseSnapshotArtifact {
                            package_name: package.package.name.clone(),
                            package_version: version.version.clone(),
                            platform: platform.clone(),
                            artifact_kind: "image".to_string(),
                            store_hash: store_hash_component(&image.delivery.image_info.store_path),
                            store_path: image.delivery.image_info.store_path.clone(),
                        });
                        if let Some(payload) = &image.delivery.update_payload {
                            artifacts.push(ReleaseSnapshotArtifact {
                                package_name: package.package.name.clone(),
                                package_version: version.version.clone(),
                                platform: platform.clone(),
                                artifact_kind: "image".to_string(),
                                store_hash: store_hash_component(&payload.store_path),
                                store_path: payload.store_path.clone(),
                            });
                        }
                    }
                }
            }
        }
    }
    artifacts.sort_by(|left, right| {
        (
            &left.package_name,
            &left.package_version,
            &left.platform,
            &left.artifact_kind,
            &left.store_path,
            &left.store_hash,
        )
            .cmp(&(
                &right.package_name,
                &right.package_version,
                &right.platform,
                &right.artifact_kind,
                &right.store_path,
                &right.store_hash,
            ))
    });
    artifacts.dedup();
    artifacts
}

fn store_hash_component(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    base.split('-').next().unwrap_or(base).to_string()
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
        let registry_scope = db.registry_authorization_scope(registry.id).await;
        match (db.changeset(&change_id).await, registry_scope) {
            (Ok(Some(changeset)), Ok(registry_scope))
                if crate::domain::Scope::try_parse(&changeset.scope).as_ref()
                    == crate::domain::Scope::try_parse(&registry_scope).as_ref() =>
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
            (Ok(Some(changeset)), _) => {
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
            (Ok(None), _) => {}
            (Err(err), _) => tracing::warn!(
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
    let scope = match db.registry_authorization_scope(registry.id).await {
        Ok(scope) => scope,
        Err(err) => {
            tracing::warn!(
                slug = %registry.slug,
                error = %format!("{err:#}"),
                "resolving registry scope for external-commit audit"
            );
            return;
        }
    };
    if let Err(err) = db
        .record_audit(
            "key",
            None,
            &actor_label,
            ACTION,
            &scope,
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

#[derive(Debug)]
struct VerifiedSystemImageCatalog {
    digest: String,
    images: Vec<crate::db::IndexedSystemImage>,
    objects: Vec<crate::db::VerifiedRegistryImageObject>,
}

/// Proves that every signed direct-delivery object exists with its exact identity.
async fn verify_system_image_objects(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry_id: i64,
    indexed_placement_id: Option<i64>,
    advertised_commit: &str,
    refs_digest: &str,
    commit: &str,
    registry_identity: &str,
    packages: &[aos_registry_surface::manifest::PackageToml],
    snapshot_leases: &mut Vec<String>,
) -> Result<VerifiedSystemImageCatalog> {
    let mut expected = BTreeMap::<String, ExpectedImageObject>::new();
    let mut catalog_artifacts = BTreeMap::<String, ExpectedImageObject>::new();
    let mut images = Vec::new();
    for package in packages.iter().filter(|package| package.package.sysroot) {
        for version in &package.versions {
            for (platform, artifact) in &version.platforms {
                for image in &artifact.images {
                    if image.delivery.is_store_only() {
                        continue;
                    }
                    image.validate_delivery(&version.version, platform)?;
                    images.push(crate::db::IndexedSystemImage {
                        package: package.package.name.clone(),
                        release: version.version.clone(),
                        platform: platform.clone(),
                        format: image.format.clone(),
                        store_path: image.store_path.clone(),
                        nar_hash: image.nar_hash.clone(),
                        nar_size: image.nar_size,
                        delivery: image.delivery.clone(),
                    });
                    if image.delivery.is_store_backed() {
                        let mut store_artifacts = vec![
                            (
                                image.store_path.as_str(),
                                image.nar_hash.as_str(),
                                image.nar_size,
                                ImageObjectRole::Disk,
                            ),
                            (
                                image.delivery.image_info.store_path.as_str(),
                                image.delivery.image_info.nar_hash.as_str(),
                                image.delivery.image_info.nar_size,
                                ImageObjectRole::ImageInfo,
                            ),
                        ];
                        if let Some(payload) = &image.delivery.update_payload {
                            store_artifacts.push((
                                payload.store_path.as_str(),
                                payload.nar_hash.as_str(),
                                payload.nar_size,
                                ImageObjectRole::UpdatePayload,
                            ));
                        }
                        for (path, hash, size, role) in store_artifacts {
                            insert_expected_image_artifact(
                                &mut catalog_artifacts,
                                path,
                                ExpectedImageObject {
                                    sha256: aos_registry_surface::store::normalize_digest(hash)?,
                                    byte_size: i64::try_from(size)
                                        .context("signed image NAR size exceeds database range")?,
                                    role,
                                },
                            )?;
                        }
                        continue;
                    }
                    for (key, hash, size, role) in [
                        (
                            image.delivery.object_key.as_str(),
                            image.delivery.sha256.as_str(),
                            image.delivery.byte_size,
                            ImageObjectRole::Disk,
                        ),
                        (
                            image.delivery.image_info.object_key.as_str(),
                            image.delivery.image_info.sha256.as_str(),
                            image.delivery.image_info.byte_size,
                            ImageObjectRole::ImageInfo,
                        ),
                    ] {
                        let size = i64::try_from(size)
                            .context("signed image object size exceeds database range")?;
                        let identity = ExpectedImageObject {
                            sha256: hash.to_string(),
                            byte_size: size,
                            role,
                        };
                        insert_expected_image_artifact(&mut expected, key, identity.clone())?;
                        insert_expected_image_artifact(&mut catalog_artifacts, key, identity)?;
                    }
                }
            }
        }
    }

    let publication = current_verified_publication(
        db,
        registry_id,
        indexed_placement_id,
        advertised_commit,
        refs_digest,
    )
    .await?;
    verify_system_image_cache_objects(db, fetch, publication.as_ref(), &images, snapshot_leases)
        .await?;

    if expected.is_empty() {
        return Ok(VerifiedSystemImageCatalog {
            digest: image_catalog_digest(registry_identity, &catalog_artifacts)?,
            images,
            objects: Vec::new(),
        });
    }
    verify_image_publication_receipt(fetch, commit, registry_identity, &expected).await?;
    let digest = image_catalog_digest(registry_identity, &catalog_artifacts)?;

    let mut verified = Vec::with_capacity(expected.len());
    for (object_key, identity) in expected {
        let object = match &publication {
            Some((publication_id, placement_id)) => {
                verify_published_system_image_object(
                    db,
                    fetch,
                    publication_id,
                    *placement_id,
                    object_key,
                    identity.sha256,
                    identity.byte_size,
                )
                .await?
            }
            None => {
                verify_system_image_object(
                    fetch,
                    object_key,
                    identity.sha256,
                    identity.byte_size,
                    snapshot_leases,
                )
                .await?
            }
        };
        verified.push(object);
    }
    Ok(VerifiedSystemImageCatalog {
        digest,
        images,
        objects: verified,
    })
}

fn insert_expected_image_artifact(
    artifacts: &mut BTreeMap<String, ExpectedImageObject>,
    key: &str,
    identity: ExpectedImageObject,
) -> Result<()> {
    match artifacts.entry(key.to_string()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(identity);
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &identity => {}
        std::collections::btree_map::Entry::Occupied(_) => {
            bail!("signed image artifact '{key}' has conflicting identities");
        }
    }
    Ok(())
}

const MAX_IMAGE_NARINFO_BYTES: usize = 64 * 1024;

struct ImageNarInfo {
    store_path: String,
    url: String,
    file_hash: String,
    file_size: u64,
    nar_hash: String,
    nar_size: u64,
}

fn parse_image_narinfo(text: &str) -> Result<ImageNarInfo> {
    let mut fields = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if matches!(
            name,
            "StorePath" | "URL" | "FileHash" | "FileSize" | "NarHash" | "NarSize"
        ) && fields.insert(name, value.trim()).is_some()
        {
            bail!("image narinfo repeats {name}");
        }
    }
    let required = |name| {
        fields
            .get(name)
            .copied()
            .with_context(|| format!("image narinfo has no {name}"))
    };
    Ok(ImageNarInfo {
        store_path: required("StorePath")?.to_string(),
        url: required("URL")?.to_string(),
        file_hash: required("FileHash")?.to_string(),
        file_size: required("FileSize")?
            .parse()
            .context("image narinfo has an invalid FileSize")?,
        nar_hash: required("NarHash")?.to_string(),
        nar_size: required("NarSize")?
            .parse()
            .context("image narinfo has an invalid NarSize")?,
    })
}

async fn verify_system_image_cache_objects(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    publication: Option<&(String, i64)>,
    images: &[crate::db::IndexedSystemImage],
    snapshot_leases: &mut Vec<String>,
) -> Result<()> {
    let mut verified_store_paths = std::collections::BTreeSet::new();
    for image in images {
        let mut artifacts = vec![(
            image.store_path.as_str(),
            image.nar_hash.as_str(),
            image.nar_size,
            "image disk",
        )];
        if image.delivery.is_store_backed() {
            artifacts.push((
                image.delivery.image_info.store_path.as_str(),
                image.delivery.image_info.nar_hash.as_str(),
                image.delivery.image_info.nar_size,
                "image metadata",
            ));
            if let Some(payload) = &image.delivery.update_payload {
                artifacts.push((
                    payload.store_path.as_str(),
                    payload.nar_hash.as_str(),
                    payload.nar_size,
                    "image update payload",
                ));
            }
        }
        for (store_path, signed_nar_hash, signed_nar_size, label) in artifacts {
            if !verified_store_paths.insert(store_path) {
                continue;
            }
            let store_hash = aos_registry_surface::store::store_path_hash(store_path)?;
            let narinfo_key = format!("{store_hash}.narinfo");
            let narinfo_bytes = fetch
                .fetch_bounded(&narinfo_key, MAX_IMAGE_NARINFO_BYTES)
                .await?
                .with_context(|| format!("{label} narinfo '{narinfo_key}' is unavailable"))?;
            let narinfo_text = std::str::from_utf8(&narinfo_bytes)
                .with_context(|| format!("image narinfo '{narinfo_key}' is not UTF-8"))?;
            let narinfo = parse_image_narinfo(narinfo_text)
                .with_context(|| format!("parsing image narinfo '{narinfo_key}'"))?;
            anyhow::ensure!(
                narinfo.store_path == store_path
                    && aos_registry_surface::store::normalize_digest(&narinfo.nar_hash)?
                        == aos_registry_surface::store::normalize_digest(signed_nar_hash)?
                    && narinfo.nar_size == signed_nar_size,
                "{label} narinfo '{narinfo_key}' disagrees with the signed store identity"
            );
            anyhow::ensure!(
                narinfo.url.starts_with("nar/")
                    && !narinfo.url.starts_with('/')
                    && narinfo.url.split('/').all(|component| !component.is_empty()
                        && component != "."
                        && component != ".."),
                "image narinfo '{narinfo_key}' carries an unsafe NAR URL"
            );
            let file_hash = aos_registry_surface::store::canonical_digest_hex(&narinfo.file_hash)?;
            let file_size = narinfo.file_size;
            let file_size =
                i64::try_from(file_size).context("image NAR size exceeds database range")?;
            let narinfo_hash = hex::encode(Sha256::digest(&narinfo_bytes));
            let narinfo_size = i64::try_from(narinfo_bytes.len())
                .context("image narinfo size exceeds database range")?;

            if let Some((publication_id, placement_id)) = publication {
                verify_published_system_image_object(
                    db,
                    fetch,
                    publication_id,
                    *placement_id,
                    narinfo_key,
                    narinfo_hash,
                    narinfo_size,
                )
                .await?;
                verify_published_system_image_object(
                    db,
                    fetch,
                    publication_id,
                    *placement_id,
                    narinfo.url,
                    file_hash,
                    file_size,
                )
                .await?;
            } else {
                verify_system_image_object(
                    fetch,
                    narinfo_key,
                    narinfo_hash,
                    narinfo_size,
                    snapshot_leases,
                )
                .await?;
                verify_system_image_object(
                    fetch,
                    narinfo.url,
                    file_hash,
                    file_size,
                    snapshot_leases,
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// Resolves the exact ready publication that supplied this index generation.
async fn current_verified_publication(
    db: &Database,
    registry_id: i64,
    indexed_placement_id: Option<i64>,
    advertised_commit: &str,
    refs_digest: &str,
) -> Result<Option<(String, i64)>> {
    let Some(placement_id) = indexed_placement_id else {
        return Ok(None);
    };
    let Some(state) = db.registry_publication_state(registry_id).await? else {
        return Ok(None);
    };
    let Some(publication_id) = state.current_publication_id else {
        return Ok(None);
    };
    let publication = db
        .registry_publication(&publication_id)
        .await?
        .context("current registry publication is unavailable")?;
    anyhow::ensure!(
        publication.state == "ready"
            && publication.default_commit.as_deref() == Some(advertised_commit)
            && publication.refs_digest == refs_digest,
        "current registry publication does not match the advertised generation"
    );
    Ok(Some((publication_id, placement_id)))
}

/// Revalidates a Hub-published image from durable upload evidence and version.
async fn verify_published_system_image_object(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    publication_id: &str,
    placement_id: i64,
    object_key: String,
    sha256: String,
    byte_size: i64,
) -> Result<crate::db::VerifiedRegistryImageObject> {
    let evidence = db
        .registry_publication_verified_object_at_placement(
            publication_id,
            placement_id,
            &object_key,
        )
        .await?
        .with_context(|| {
            format!("signed image object '{object_key}' has no exact publication evidence")
        })?;
    anyhow::ensure!(
        evidence.sha256 == sha256 && evidence.byte_size == byte_size,
        "signed image object '{object_key}' publication evidence does not match the catalog"
    );
    let current_etag = fetch
        .inventory_strong_etag(&object_key)
        .await?
        .with_context(|| {
            format!("signed image object '{object_key}' backend does not expose a strong version")
        })?;
    let current_etag = crate::surface_write::strong_if_match_etag(&current_etag)?;
    let published_etag = crate::surface_write::strong_if_match_etag(&evidence.strong_etag)?;
    anyhow::ensure!(
        current_etag == published_etag,
        "signed image object '{object_key}' changed after publication verification"
    );
    Ok(evidence)
}

const MAX_IMAGE_PUBLICATION_RECEIPT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageObjectRole {
    Disk,
    ImageInfo,
    UpdatePayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedImageObject {
    sha256: String,
    byte_size: i64,
    role: ImageObjectRole,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImagePublicationReceipt {
    schema_version: u32,
    commit: String,
    registry: String,
    catalog_digest: String,
    objects: Vec<ImagePublicationReceiptObject>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImagePublicationReceiptObject {
    key: String,
    role: String,
    byte_size: u64,
    sha256: String,
}

/// Requires a complete transaction marker for the exact signed image catalog.
///
/// `fetch` is already scoped to the placement selected for this index run. The
/// receipt and every object it names are therefore proven through one physical
/// placement, and the resulting presence rows retain that placement identity;
/// a receipt observed elsewhere cannot confer availability on this placement.
async fn verify_image_publication_receipt(
    fetch: &dyn SurfaceFetch,
    commit: &str,
    registry_identity: &str,
    expected: &BTreeMap<String, ExpectedImageObject>,
) -> Result<()> {
    let path = format!("publication-receipts/{commit}.json");
    let bytes = fetch
        .fetch_bounded(&path, MAX_IMAGE_PUBLICATION_RECEIPT_BYTES)
        .await?
        .with_context(|| format!("image publication receipt '{path}' is unavailable"))?;
    validate_image_publication_receipt(&bytes, commit, registry_identity, expected)
}

fn validate_image_publication_receipt(
    bytes: &[u8],
    commit: &str,
    registry_identity: &str,
    expected: &BTreeMap<String, ExpectedImageObject>,
) -> Result<()> {
    let receipt: ImagePublicationReceipt =
        serde_json::from_slice(bytes).context("parsing image publication receipt")?;
    if receipt.schema_version != 1 {
        bail!("unsupported image publication receipt schema");
    }
    if receipt.commit != commit {
        bail!("image publication receipt does not match the indexed commit");
    }
    if receipt.registry != registry_identity {
        bail!("image publication receipt does not match the signed registry identity");
    }
    let catalog_digest = image_catalog_digest(registry_identity, expected)?;
    if receipt.catalog_digest != catalog_digest {
        bail!("image publication receipt catalog digest does not match signed metadata");
    }
    if receipt.objects.len() != expected.len() {
        bail!("image publication receipt does not cover the signed image catalog");
    }

    let mut observed = BTreeMap::new();
    for object in receipt.objects {
        let byte_size = i64::try_from(object.byte_size)
            .context("publication receipt object size exceeds database range")?;
        let identity = ExpectedImageObject {
            sha256: object.sha256,
            byte_size,
            role: match object.role.as_str() {
                "disk" => ImageObjectRole::Disk,
                "image-info" => ImageObjectRole::ImageInfo,
                "update-payload" => ImageObjectRole::UpdatePayload,
                _ => bail!("image publication receipt contains an unknown object role"),
            },
        };
        if observed.insert(object.key.clone(), identity).is_some() {
            bail!(
                "image publication receipt repeats object key '{}'",
                object.key
            );
        }
    }
    if &observed != expected {
        bail!("image publication receipt identities do not match the signed image catalog");
    }
    Ok(())
}

fn image_catalog_digest(
    registry_identity: &str,
    expected: &BTreeMap<String, ExpectedImageObject>,
) -> Result<String> {
    let mut catalog_objects = Vec::with_capacity(expected.len());
    for (key, identity) in expected {
        catalog_objects.push((
            key.as_str(),
            match identity.role {
                ImageObjectRole::Disk => "disk",
                ImageObjectRole::ImageInfo => "image-info",
                ImageObjectRole::UpdatePayload => "update-payload",
            },
            u64::try_from(identity.byte_size)
                .context("signed image catalog contains a negative object size")?,
            identity.sha256.as_str(),
        ));
    }
    Ok(aos_registry_surface::manifest::image_catalog_digest(
        registry_identity,
        catalog_objects,
    ))
}

/// Streams one signed image object with a catalog-sized hard bound.
///
/// This intentionally does not use [`SurfaceFetch::inventory_evidence`]. That
/// generic inventory path trusts the backend-declared object length until the
/// stream ends, whereas an image catalog already supplies the exact signed
/// length. Rejecting a different declaration before polling the body and
/// stopping as soon as the stream exceeds the signed length prevents a hostile
/// placement from turning indexing into an unbounded transfer.
async fn verify_system_image_object(
    fetch: &dyn SurfaceFetch,
    object_key: String,
    sha256: String,
    byte_size: i64,
    snapshot_leases: &mut Vec<String>,
) -> Result<crate::db::VerifiedRegistryImageObject> {
    let expected_size =
        u64::try_from(byte_size).context("signed image object size cannot be negative")?;
    let before_etag = fetch.inventory_strong_etag(&object_key).await?;
    let read = fetch
        .fetch_stream(&object_key, None)
        .await?
        .with_context(|| format!("signed image object '{object_key}' is unavailable"))?;
    if let Some(lease_id) = read.snapshot_lease_id.clone() {
        snapshot_leases.push(lease_id);
    }
    if read.total != expected_size || read.range.is_some() {
        bail!(
            "signed image object '{object_key}' does not match catalog size: expected {expected_size} bytes, backend declared {}",
            read.total
        );
    }
    let streamed_etag = read.strong_etag.clone();

    let mut stream = read.body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut observed_size = 0_u64;
    while let Some(chunk) = stream.try_next().await? {
        observed_size = observed_size
            .checked_add(chunk.len() as u64)
            .with_context(|| format!("signed image object '{object_key}' size overflowed"))?;
        if observed_size > expected_size {
            bail!(
                "signed image object '{object_key}' exceeded its signed {expected_size} byte size"
            );
        }
        hasher.update(&chunk);
    }
    if observed_size != expected_size {
        bail!(
            "signed image object '{object_key}' ended at {observed_size} bytes, expected {expected_size}"
        );
    }
    let after_etag = fetch.inventory_strong_etag(&object_key).await?;
    if before_etag != after_etag || streamed_etag != after_etag {
        bail!("signed image object '{object_key}' changed while it was verified");
    }
    let observed_sha256 = hex::encode(hasher.finalize());
    if observed_sha256 != sha256 {
        bail!("signed image object '{object_key}' does not match catalog SHA-256");
    }
    let strong_etag = after_etag.context(format!(
        "signed image object '{object_key}' backend does not expose a strong version"
    ))?;

    Ok(crate::db::VerifiedRegistryImageObject {
        object_key,
        sha256,
        byte_size,
        strong_etag,
    })
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
    indexed_placement_id: Option<i64>,
) -> Result<IndexOutcome> {
    tracing::debug!(source = %fetch.describe(), "refs unchanged; incremental channel refresh");

    // Rebuild the trusted set exactly as the full walk would have left
    // it: pinned anchors plus the verified roster's active keys.
    let mut trusted: Vec<String> = registry.trust_keys.clone();
    let typed_publication = append_signing_usage_key(
        db,
        &mut trusted,
        &registry.stable_id,
        "registry_publication",
    )
    .await?;
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

    let branch_names = complete_branch_names(refs)?;
    let channels = resolve_channels(
        db,
        fetch,
        registry,
        &branch_names,
        &trusted,
        typed_publication,
        &tag_to_semver,
        &std::collections::BTreeSet::new(),
    )
    .await?;
    db.update_channels_from_placement(registry.id, &channels, indexed_placement_id)
        .await?;

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

/// Returns every advertised branch name or rejects an incomplete index.
fn complete_branch_names(refs: &Refs) -> Result<Vec<String>> {
    validate_ref_cardinality(refs)?;
    let names: Vec<String> = refs.branches.keys().cloned().collect();
    Ok(names)
}

/// Rejects ref advertisements that cannot be indexed completely.
fn validate_ref_cardinality(refs: &Refs) -> Result<()> {
    if refs.tags.len() > MAX_RELEASE_TAGS {
        bail!(
            "registry advertises {} release tags; complete indexing limit is {}",
            refs.tags.len(),
            MAX_RELEASE_TAGS
        );
    }
    if refs.branches.len() > MAX_BRANCHES {
        bail!(
            "registry advertises {} channels; complete indexing limit is {}",
            refs.branches.len(),
            MAX_BRANCHES
        );
    }
    Ok(())
}

/// Resolve channels by probing and verifying all 256 partitions each.
///
/// `tag_to_semver` maps release tag oids (hex) to their semver, so a
/// partition targeting an unknown tag object fails loudly.
async fn append_signing_usage_key(
    db: &Database,
    trusted: &mut Vec<String>,
    consumer_stable_id: &str,
    purpose: &str,
) -> Result<bool> {
    let Some(key) = db
        .active_signing_key_for_usage(consumer_stable_id, purpose)
        .await?
    else {
        return Ok(false);
    };
    let key_name = key.name.clone();
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&key.public_key)
        .context("typed signing usage contains invalid public-key base64")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("typed signing usage public key is not 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .context("typed signing usage public key is not valid Ed25519")?;
    let line = sshsig::trusted_key_line(&key_name, &key);
    if !trusted.contains(&line) {
        trusted.push(line);
    }
    Ok(true)
}

async fn resolve_channels(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    registry: &RegistryRecord,
    branch_names: &[String],
    trusted: &[String],
    require_publication_signatures: bool,
    tag_to_semver: &BTreeMap<String, String>,
    image_release_tag_oids: &std::collections::BTreeSet<String>,
) -> Result<Vec<ChannelSummary>> {
    let mut channels = Vec::new();
    for channel_name in branch_names {
        let mut channel_trusted = trusted.to_vec();
        let mut image_channel_trusted = registry.trust_keys.clone();
        let consumer_stable_id = format!("channel:{}:{channel_name}", registry.stable_id);
        let channel_usage = append_signing_usage_key(
            db,
            &mut channel_trusted,
            &consumer_stable_id,
            "channel_frontier",
        )
        .await?;
        let _ = append_signing_usage_key(
            db,
            &mut image_channel_trusted,
            &consumer_stable_id,
            "channel_frontier",
        )
        .await?;
        let buckets = (0u16..=255).collect::<Vec<_>>();
        let mut resolved = Vec::with_capacity(buckets.len());
        for batch in buckets.chunks(CHANNEL_FETCH_CONCURRENCY) {
            let channel_name = channel_name.as_str();
            let channel_trusted = channel_trusted.as_slice();
            let image_channel_trusted = image_channel_trusted.as_slice();
            resolved.extend(
                try_join_all(batch.iter().copied().map(|bucket| async move {
                    let path = format!("channels/{channel_name}/{bucket:02x}");
                    let Some(payload) = fetch.fetch(&path).await? else {
                        return Ok::<_, anyhow::Error>((bucket, None));
                    };
                    let lenient = lenient_tag(&payload, channel_name)?;
                    let signed = if registry.require_signatures
                        || require_publication_signatures
                        || channel_usage
                        || image_release_tag_oids.contains(&lenient.tag.object)
                    {
                        let trusted =
                            if registry.require_signatures || require_publication_signatures {
                                channel_trusted
                            } else {
                                // Image-bearing channels remain rooted in the configured
                                // catalog anchors plus their exact typed channel usage.
                                image_channel_trusted
                            };
                        verify_signed_tag(&payload, channel_name, trusted)
                            .with_context(|| format!("signed image channel partition {path}"))?
                    } else {
                        lenient
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
                    Ok((bucket, Some(semver_str.clone())))
                }))
                .await?,
            );
        }

        let mut partitions: Vec<Option<String>> = vec![None; 256];
        let mut frontier: Option<semver::Version> = None;
        let mut present = false;
        for (bucket, semver_str) in resolved {
            let Some(semver_str) = semver_str else {
                continue;
            };
            present = true;
            partitions[bucket as usize] = Some(semver_str.clone());
            if let Ok(version) = semver::Version::parse(&semver_str) {
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

/// Resolve a registry's committed `[caches]` cache stack into the flattened
/// priority union and the optional stored cache-stack JSON.
///
/// The unified `[caches]` value is the single source of truth: its flattened
/// `(url, priority)` entries always contribute. When `[caches]` is in stack
/// form (a bare endpoint or a `kind`/`members` node), the parsed stack is also
/// serialized to JSON for [`Database::registry_cache_stack`] so coverage
/// validation can recover its mirror groups. A malformed `[caches]` stack
/// flattens to an empty list (logged here), so an authoring mistake never
/// strands a registry's index.
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
    if root.caches.is_some() && by_url.is_empty() {
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
    use crate::fetch::{StreamedRead, SurfaceFetch};

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

    #[test]
    fn retention_ref_caps_fail_closed_at_cap_plus_one() {
        let oid = aos_registry_surface::object::Oid::from_hex(&"a".repeat(64)).unwrap();
        let mut releases = Refs::default();
        for index in 0..=MAX_RELEASE_TAGS {
            releases.tags.insert(format!("1.0.{index}"), oid);
        }
        assert!(validate_ref_cardinality(&releases).is_err());

        let mut channels = Refs::default();
        for index in 0..=MAX_BRANCHES {
            channels.branches.insert(format!("channel-{index}"), oid);
        }
        assert!(validate_ref_cardinality(&channels).is_err());
    }

    #[test]
    fn incremental_refresh_requires_the_recorded_commit_to_match() {
        let advertised = "b".repeat(64);

        assert!(incremental_preconditions(
            Some("fresh"),
            Some(advertised.as_str()),
            true,
            false,
            &advertised,
        ));
        assert!(!incremental_preconditions(
            Some("fresh"),
            Some(&"a".repeat(64)),
            true,
            false,
            &advertised,
        ));
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

    struct MissingFetch;

    #[async_trait::async_trait]
    impl SurfaceFetch for MissingFetch {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn describe(&self) -> String {
            "missing-replica".into()
        }
    }

    #[tokio::test]
    async fn missing_replica_cannot_clear_the_authoritative_index() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("replica-safety", &[], false)
            .await
            .unwrap();
        let snapshot = IndexSnapshot {
            commit: "c".repeat(64),
            name: "Authoritative registry".into(),
            refs_digest: Some(hex::encode(Sha256::digest(b"authoritative refs"))),
            ..Default::default()
        };
        db.apply_snapshot(registry_id, &snapshot).await.unwrap();
        let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();

        assert!(index_registry(&db, &MissingFetch, &registry, Some(999))
            .await
            .is_err());
        assert!(
            reconcile_registry_replica(&db, &MissingFetch, &registry, 999)
                .await
                .is_err()
        );

        let status = db.index_status(registry_id).await.unwrap().unwrap();
        assert_eq!(status.state, "fresh");
        assert_eq!(
            status.last_indexed_commit.as_deref(),
            Some(snapshot.commit.as_str())
        );
        assert_eq!(status.name.as_deref(), Some("Authoritative registry"));
        assert_eq!(
            db.refs_digest(registry_id).await.unwrap(),
            snapshot.refs_digest
        );
    }

    struct ImageObjectFetch {
        declared_size: u64,
        body: Vec<u8>,
        strong_etag: Option<String>,
    }

    fn expected_receipt_objects() -> BTreeMap<String, ExpectedImageObject> {
        BTreeMap::from([
            (
                "images/disk".to_string(),
                ExpectedImageObject {
                    sha256: "a".repeat(64),
                    byte_size: 3,
                    role: ImageObjectRole::Disk,
                },
            ),
            (
                "images/info".to_string(),
                ExpectedImageObject {
                    sha256: "b".repeat(64),
                    byte_size: 2,
                    role: ImageObjectRole::ImageInfo,
                },
            ),
        ])
    }

    fn expected_receipt_digest(registry: &str) -> String {
        let expected = expected_receipt_objects();
        aos_registry_surface::manifest::image_catalog_digest(
            registry,
            expected.iter().map(|(key, identity)| {
                (
                    key.as_str(),
                    match identity.role {
                        ImageObjectRole::Disk => "disk",
                        ImageObjectRole::ImageInfo => "image-info",
                        ImageObjectRole::UpdatePayload => "update-payload",
                    },
                    identity.byte_size as u64,
                    identity.sha256.as_str(),
                )
            }),
        )
    }

    #[test]
    fn publication_receipt_must_exactly_cover_signed_catalog() {
        let commit = "c".repeat(40);
        let registry = "andyl";
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "commit": commit.as_str(),
            "registry": registry,
            "catalogDigest": expected_receipt_digest(registry),
            "objects": [
                {
                    "key": "images/disk",
                    "role": "disk",
                    "byteSize": 3,
                    "sha256": "a".repeat(64),
                },
                {
                    "key": "images/info",
                    "role": "image-info",
                    "byteSize": 2,
                    "sha256": "b".repeat(64),
                }
            ]
        }))
        .unwrap();
        validate_image_publication_receipt(&bytes, &commit, registry, &expected_receipt_objects())
            .unwrap();
    }

    #[test]
    fn publication_receipt_rejects_missing_duplicate_and_wrong_identity() {
        let commit = "c".repeat(40);
        let registry = "andyl";
        for objects in [
            serde_json::json!([{
                "key": "images/disk",
                "role": "disk",
                "byteSize": 3,
                "sha256": "a".repeat(64),
            }]),
            serde_json::json!([
                {
                    "key": "images/disk",
                    "role": "disk",
                    "byteSize": 3,
                    "sha256": "a".repeat(64),
                },
                {
                    "key": "images/disk",
                    "role": "disk",
                    "byteSize": 3,
                    "sha256": "a".repeat(64),
                }
            ]),
            serde_json::json!([
                {
                    "key": "images/disk",
                    "role": "disk",
                    "byteSize": 4,
                    "sha256": "a".repeat(64),
                },
                {
                    "key": "images/info",
                    "role": "image-info",
                    "byteSize": 2,
                    "sha256": "b".repeat(64),
                }
            ]),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "commit": commit.as_str(),
                "registry": registry,
                "catalogDigest": expected_receipt_digest(registry),
                "objects": objects,
            }))
            .unwrap();
            assert!(validate_image_publication_receipt(
                &bytes,
                &commit,
                registry,
                &expected_receipt_objects()
            )
            .is_err());
        }
    }

    #[test]
    fn publication_receipt_cannot_replay_across_commit_registry_or_catalog() {
        let commit = "c".repeat(40);
        let registry = "andyl";
        let value = serde_json::json!({
            "schemaVersion": 1,
            "commit": commit.as_str(),
            "registry": registry,
            "catalogDigest": expected_receipt_digest(registry),
            "objects": [
                {
                    "key": "images/disk",
                    "role": "disk",
                    "byteSize": 3,
                    "sha256": "a".repeat(64),
                },
                {
                    "key": "images/info",
                    "role": "image-info",
                    "byteSize": 2,
                    "sha256": "b".repeat(64),
                }
            ]
        });
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(validate_image_publication_receipt(
            &bytes,
            &"d".repeat(40),
            registry,
            &expected_receipt_objects(),
        )
        .is_err());
        assert!(validate_image_publication_receipt(
            &bytes,
            &commit,
            "different-registry",
            &expected_receipt_objects(),
        )
        .is_err());
        let mut wrong_digest = value;
        wrong_digest["catalogDigest"] = serde_json::json!("f".repeat(64));
        assert!(validate_image_publication_receipt(
            &serde_json::to_vec(&wrong_digest).unwrap(),
            &commit,
            registry,
            &expected_receipt_objects(),
        )
        .is_err());
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for ImageObjectFetch {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            unreachable!("signed image verification must use the streaming path")
        }

        async fn fetch_stream(
            &self,
            _path: &str,
            range: Option<(u64, u64)>,
        ) -> Result<Option<StreamedRead>> {
            assert!(range.is_none());
            Ok(Some(StreamedRead {
                body: axum::body::Body::from(self.body.clone()),
                total: self.declared_size,
                range: None,
                strong_etag: self.strong_etag.clone(),
                snapshot_lease_id: None,
            }))
        }

        async fn inventory_strong_etag(&self, _path: &str) -> Result<Option<String>> {
            Ok(self.strong_etag.clone())
        }

        fn describe(&self) -> String {
            "malicious-image-object".into()
        }
    }

    #[tokio::test]
    async fn signed_image_verifier_accepts_only_exact_bytes() {
        let bytes = b"raw";
        let mut leases = Vec::new();
        let verified = verify_system_image_object(
            &ImageObjectFetch {
                declared_size: bytes.len() as u64,
                body: bytes.to_vec(),
                strong_etag: Some("\"fixture-version\"".into()),
            },
            "images/raw".into(),
            hex::encode(Sha256::digest(bytes)),
            bytes.len() as i64,
            &mut leases,
        )
        .await
        .unwrap();
        assert_eq!(verified.object_key, "images/raw");
        assert_eq!(verified.byte_size, bytes.len() as i64);
    }

    #[tokio::test]
    async fn signed_image_verifier_rejects_backend_without_strong_version() {
        let bytes = b"raw";
        let mut leases = Vec::new();
        let error = verify_system_image_object(
            &ImageObjectFetch {
                declared_size: bytes.len() as u64,
                body: bytes.to_vec(),
                strong_etag: None,
            },
            "images/raw".into(),
            hex::encode(Sha256::digest(bytes)),
            bytes.len() as i64,
            &mut leases,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("strong version"));
    }

    #[tokio::test]
    async fn signed_image_verifier_rejects_oversized_declaration_before_streaming() {
        let mut leases = Vec::new();
        let error = verify_system_image_object(
            &ImageObjectFetch {
                declared_size: u64::MAX,
                body: vec![0; 1024],
                strong_etag: Some("\"fixture-version\"".into()),
            },
            "images/raw".into(),
            hex::encode(Sha256::digest(b"raw")),
            3,
            &mut leases,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("backend declared"));
    }

    #[tokio::test]
    async fn signed_image_verifier_stops_at_oversized_stream() {
        let mut leases = Vec::new();
        let error = verify_system_image_object(
            &ImageObjectFetch {
                declared_size: 3,
                body: b"raw-plus-unbounded-tail".to_vec(),
                strong_etag: Some("\"fixture-version\"".into()),
            },
            "images/raw".into(),
            hex::encode(Sha256::digest(b"raw")),
            3,
            &mut leases,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("exceeded its signed 3 byte size"));
    }

    #[tokio::test]
    async fn transient_surface_error_records_pending_not_failed() {
        let db = Database::open_in_memory().await.unwrap();
        let org_id = db.create_org("acme", "Acme").await.unwrap();
        let id = db
            .create_managed_registry(org_id, "", "app", "public", &[], false)
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
        let org_id = db.create_org("acme", "Acme").await.unwrap();
        db.create_managed_registry(org_id, "", "bad", "public", &[], false)
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
