//! Binary-cache physical inventory and normalized publication.
//!
//! A cache inventory is cache-wide, but its evidence is placement-scoped.
//! [`rescan_cache`] snapshots every non-offline placement, reuses previously
//! byte-verified evidence when a provider's strong version is unchanged,
//! hashes new or changed objects, publishes one manifest per placement, and
//! advances the cache-wide inventory only after the complete selected set
//! succeeds. Mirrors may have equal manifests; shards are expected to differ.

use std::collections::{BTreeMap, HashSet};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::clock;
use crate::db::{
    BinaryCache, CacheInventoryListedObject, CacheInventoryNarinfoCandidate,
    CacheObjectPresenceObservation, CacheWriteTicketRecord, Database, ReusablePlacementEvidence,
    SurfaceObjectRecord, SurfacePlacementRecord, SurfaceTarget, WriteObjectIdentity,
};
use crate::fetch::{
    SurfaceListedEvidence, SurfaceListingBudget, SurfaceObjectEvidence, SurfaceProvider,
};
use crate::surface_write::{MultipartAbortOutcome, SurfaceWriteProvider};

/// Maximum expired writes or tombstones cleaned by one scheduled pass.
pub const MAX_CLEANUP_ITEMS_PER_PASS: i64 = 128;

/// Initial keyset position for cache-write recovery across SQLite runtimes.
///
/// Cloudflare's JavaScript boundary preserves integers only through this
/// magnitude. The value remains far below every valid Unix expiration time.
pub(crate) const CACHE_WRITE_RECOVERY_CURSOR_START: i64 = -9_007_199_254_740_991;

/// Maximum placements captured by one atomic cache inventory generation.
pub const MAX_CACHE_INVENTORY_PLACEMENTS: usize = 128;

/// Duration of a cache-inventory ownership lease.
const CACHE_INVENTORY_LEASE_SECS: i64 = 15 * 60;
const CACHE_INVENTORY_HEARTBEAT_SECS: i64 = CACHE_INVENTORY_LEASE_SECS / 3;

const NATIVE_MAX_INVENTORY_RETAINED_BYTES: usize = 512 * 1024 * 1024;
const WORKER_MAX_INVENTORY_RETAINED_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Default)]
struct InventoryRetainedBudget {
    bytes: usize,
}

impl InventoryRetainedBudget {
    fn record(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("cache inventory retained-memory budget overflowed")?;
        let maximum = if cfg!(target_arch = "wasm32") {
            WORKER_MAX_INVENTORY_RETAINED_BYTES
        } else {
            NATIVE_MAX_INVENTORY_RETAINED_BYTES
        };
        anyhow::ensure!(
            self.bytes <= maximum,
            "cache inventory exceeded the {maximum} byte retained-memory budget"
        );
        Ok(())
    }
}

/// What a [`rescan_cache`] pass changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RescanStats {
    /// Newly activated logical narinfos.
    pub added: usize,
    /// Logical narinfos absent from every selected placement.
    pub removed: usize,
    /// Logical narinfos present on at least one selected placement.
    pub unchanged: usize,
}

/// Reaps a bounded set of old cache-object tombstones.
///
/// Candidate selection and the reap mutation both re-check physical absence,
/// reference safety, retention age, and the cache epoch. Each successful reap
/// advances the epoch, so it is re-read before the next item.
///
/// # Errors
///
/// Returns an error on database failure or if a selected tombstone becomes
/// ineligible before its guarded mutation commits.
pub async fn reap_due_cache_tombstones(db: &Database, now: i64) -> Result<usize> {
    let candidates = db
        .list_reapable_cache_object_tombstones(now, MAX_CLEANUP_ITEMS_PER_PASS)
        .await?;
    let mut reaped = 0;
    for candidate in candidates {
        let state = db
            .cache_gc_topology_state(candidate.cache_id)
            .await?
            .context("tombstone candidate references an uninitialized cache")?;
        db.reap_cache_object_tombstone(
            candidate.cache_id,
            candidate.cache_object_id,
            candidate.resource_version,
            state.epoch,
            &uuid::Uuid::new_v4().to_string(),
            now,
        )
        .await?;
        reaped += 1;
    }
    Ok(reaped)
}

struct PlacementScan {
    placement: SurfacePlacementRecord,
    content_digest: String,
    object_count: i64,
}

/// Publishes one structurally complete inventory across all online placements.
///
/// The selected placement set and each placement resource version are frozen
/// when the generation begins. Publication fails if topology changes during
/// the scan. Every `present` observation comes from bytes read from that exact
/// placement; expected database hashes are used only after the digest matches.
///
/// # Errors
///
/// Returns an error for topology churn, incomplete enumeration, immutable-key
/// drift, malformed object sizes, storage failures, or persistence failures.
pub async fn rescan_cache(
    db: &Database,
    surfaces: &dyn SurfaceProvider,
    cache: &BinaryCache,
) -> Result<RescanStats> {
    let now = clock::now_unix_secs();
    let placements = db
        .list_surface_placements(SurfaceTarget::BinaryCache(cache.id))
        .await?
        .into_iter()
        .filter(|placement| placement.desired_state != "offline")
        .collect::<Vec<_>>();
    if placements.is_empty() {
        bail!("cache inventory requires at least one non-offline placement");
    }
    if placements.len() > MAX_CACHE_INVENTORY_PLACEMENTS {
        bail!(
            "cache inventory exceeds the {} placement limit",
            MAX_CACHE_INVENTORY_PLACEMENTS
        );
    }

    let initial_state = db
        .cache_gc_topology_state(cache.id)
        .await?
        .context("cache GC topology is not initialized")?;
    let generation = initial_state
        .inventory_generation
        .checked_add(1)
        .context("cache inventory generation overflowed")?;
    let owner_token = uuid::Uuid::new_v4().simple().to_string();
    let lease_expires_at = inventory_lease_deadline(now)?;
    db.begin_cache_inventory_topology(
        cache.id,
        generation,
        initial_state.epoch,
        &owner_token,
        now,
        lease_expires_at,
    )
    .await?;

    let result = build_inventory(
        db,
        surfaces,
        cache,
        placements,
        generation,
        &owner_token,
        now,
    )
    .await;
    if result.is_err() {
        if let Err(cleanup_error) = db
            .fail_cache_inventory_topology(cache.id, generation, &owner_token)
            .await
        {
            tracing::warn!(
                cache_id = cache.id,
                generation,
                error = %format!("{cleanup_error:#}"),
                "cache inventory cleanup failed; the ownership lease will permit takeover"
            );
        }
    }
    result
}

fn inventory_lease_deadline(now: i64) -> Result<i64> {
    now.checked_add(CACHE_INVENTORY_LEASE_SECS)
        .context("cache inventory lease deadline overflowed")
}

/// Recovers at most `limit` expired cache writes across the whole instance.
///
/// A durable keyset cursor makes repeated native and Worker invocations fair
/// without multiplying the budget by the number of caches.
///
/// # Errors
///
/// Returns an error for an invalid limit, stale cursor, or page-level database
/// failure. Per-ticket failures retain their fence and are retried after backoff.
pub async fn recover_expired_cache_writes(
    db: &Database,
    surfaces: &dyn SurfaceProvider,
    writers: &dyn SurfaceWriteProvider,
    now: i64,
    limit: i64,
) -> Result<usize> {
    if !(1..=MAX_CLEANUP_ITEMS_PER_PASS).contains(&limit) {
        bail!("cache write recovery limit must be between 1 and 128");
    }
    let (after_expires_at, after_ticket_id, mut cursor_version) =
        db.cache_write_recovery_cursor().await?;
    let page = db
        .list_expired_cache_write_tickets_global(now, after_expires_at, &after_ticket_id, limit)
        .await?;
    if page.is_empty() {
        if after_expires_at != CACHE_WRITE_RECOVERY_CURSOR_START || !after_ticket_id.is_empty() {
            db.advance_cache_write_recovery_cursor(
                cursor_version,
                CACHE_WRITE_RECOVERY_CURSOR_START,
                "",
                now,
            )
            .await?;
        }
        return Ok(0);
    }
    let mut recovered = 0;
    for ticket in &page {
        match recover_one_cache_write(db, surfaces, writers, ticket, now).await {
            Ok(()) => recovered += 1,
            Err(error) => {
                if let Some(current) = db.cache_write_ticket(&ticket.ticket_id).await? {
                    if matches!(
                        current.state.as_str(),
                        "observing" | "active" | "completing"
                    ) {
                        let detail = format!("{error:#}");
                        if let Err(defer_error) = db
                            .defer_cache_write_recovery(
                                &ticket.ticket_id,
                                current.resource_version,
                                now,
                                &detail,
                            )
                            .await
                        {
                            tracing::warn!(ticket = %ticket.ticket_id, error = %format!("{defer_error:#}"), "deferring cache write recovery failed");
                        }
                    }
                }
                tracing::warn!(ticket = %ticket.ticket_id, error = %format!("{error:#}"), "cache write recovery deferred");
            }
        }
        db.advance_cache_write_recovery_cursor(
            cursor_version,
            ticket.expires_at,
            &ticket.ticket_id,
            now,
        )
        .await?;
        cursor_version += 1;
    }
    Ok(recovered)
}

async fn recover_one_cache_write(
    db: &Database,
    surfaces: &dyn SurfaceProvider,
    writers: &dyn SurfaceWriteProvider,
    ticket: &CacheWriteTicketRecord,
    now: i64,
) -> Result<()> {
    if ticket.state == "observing" {
        return db
            .abort_cache_write_ticket(&ticket.ticket_id, ticket.resource_version, "failed", now)
            .await;
    }
    let placement = db
        .surface_placement(ticket.placement_id)
        .await?
        .context("expired cache write ticket references a missing placement")?;
    if ticket.state == "completing" {
        let observed = surfaces
            .placement_fetcher(&placement)
            .await?
            .inventory_evidence(&ticket.object_key)
            .await?;
        let classification = classify_expired_write(
            ticket.prior_object.as_ref(),
            ticket.intended_object_hash.as_deref(),
            ticket.declared_size,
            observed.as_ref(),
        );
        let observed = completing_replacement_evidence(classification, observed.as_ref())
            .context("cache multipart completion remains ambiguous")?;
        let observed = db
            .observe_expired_cache_write_ticket_size(
                &ticket.ticket_id,
                ticket.resource_version,
                observed.size,
                now,
            )
            .await?;
        return db
            .recover_expired_cache_write_ticket(&ticket.ticket_id, observed.resource_version, now)
            .await;
    }
    let abort_outcome = if let Some(upload_id) = ticket.backend_upload_id.as_deref() {
        Some(
            writers
                .placement_writer(&placement)
                .await?
                .abort_multipart(&ticket.object_key, upload_id)
                .await
                .with_context(|| format!("aborting expired cache upload '{}'", ticket.ticket_id))?,
        )
    } else {
        None
    };
    let observed = if matches!(
        abort_outcome,
        Some(MultipartAbortOutcome::Aborted | MultipartAbortOutcome::Absent)
    ) {
        None
    } else {
        surfaces
            .placement_fetcher(&placement)
            .await?
            .inventory_evidence(&ticket.object_key)
            .await?
    };
    let classification = classify_expired_write(
        ticket.prior_object.as_ref(),
        ticket.intended_object_hash.as_deref(),
        ticket.declared_size,
        observed.as_ref(),
    );
    match abort_outcome {
        Some(MultipartAbortOutcome::Aborted | MultipartAbortOutcome::Absent) => {
            db.abort_cache_write_ticket(&ticket.ticket_id, ticket.resource_version, "failed", now)
                .await
        }
        Some(MultipartAbortOutcome::PossiblyCompleted) | None => {
            if classification == ExpiredWriteClassification::Replacement {
                if let Some(observed) = observed.as_ref() {
                    let observed = db
                        .observe_expired_cache_write_ticket_size(
                            &ticket.ticket_id,
                            ticket.resource_version,
                            observed.size,
                            now,
                        )
                        .await?;
                    return db
                        .recover_expired_cache_write_ticket(
                            &ticket.ticket_id,
                            observed.resource_version,
                            now,
                        )
                        .await;
                }
            }
            // Never release an attempted write from absence or an unchanged
            // prior object. Preserve the declaration and GC fence until a
            // complete placement inventory covers the ticket.
            db.mark_cache_write_ticket_uncertain(&ticket.ticket_id, ticket.resource_version, now)
                .await
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpiredWriteClassification {
    NoReplacement,
    Replacement,
}

/// Requires positive object evidence before resolving durable completion intent.
fn completing_replacement_evidence(
    classification: ExpiredWriteClassification,
    observed: Option<&SurfaceObjectEvidence>,
) -> Result<&SurfaceObjectEvidence> {
    if classification != ExpiredWriteClassification::Replacement {
        bail!("authoritative replacement evidence is unavailable");
    }
    observed.context("replacement classification has no object evidence")
}

fn classify_expired_write(
    prior: Option<&WriteObjectIdentity>,
    intended_sha256: Option<&str>,
    _declared_size: i64,
    observed: Option<&SurfaceObjectEvidence>,
) -> ExpiredWriteClassification {
    let Some(observed) = observed else {
        return ExpiredWriteClassification::NoReplacement;
    };
    let observed_sha256 = hex::encode(observed.sha256);
    if prior.is_some_and(|prior| {
        prior.size == observed.size
            && prior.sha256 == observed_sha256
            && match (&prior.strong_etag, &observed.strong_etag) {
                (Some(before), Some(after)) => before == after,
                _ => true,
            }
    }) {
        return ExpiredWriteClassification::NoReplacement;
    }
    if intended_sha256.is_some_and(|intended| intended == observed_sha256) {
        return ExpiredWriteClassification::Replacement;
    }
    // A same-size identity change can be the admitted write after an opaque
    // response or a concurrent replacement. Keep the conservative fence.
    ExpiredWriteClassification::Replacement
}

async fn build_inventory(
    db: &Database,
    surfaces: &dyn SurfaceProvider,
    cache: &BinaryCache,
    placements: Vec<SurfacePlacementRecord>,
    generation: i64,
    owner_token: &str,
    now: i64,
) -> Result<RescanStats> {
    let mut scans = Vec::with_capacity(placements.len());
    let mut aggregate_listing_budget = SurfaceListingBudget::default();
    let mut retained_budget = InventoryRetainedBudget::default();
    let surface_objects = db
        .list_cache_surface_objects(cache.id)
        .await?
        .into_iter()
        .map(|object| (object.object_key.clone(), object))
        .collect::<BTreeMap<_, _>>();
    for placement in placements {
        let reusable = db
            .reusable_placement_scan_evidence(placement.id)
            .await?
            .into_iter()
            .map(|evidence| (evidence.surface_object_id, evidence))
            .collect::<BTreeMap<_, _>>();
        let fetch = surfaces
            .placement_fetcher(&placement)
            .await
            .with_context(|| format!("opening cache placement '{}'", placement.name))?;
        let page_limit = if cfg!(target_arch = "wasm32") {
            crate::fetch::WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS
        } else {
            crate::fetch::MAX_SURFACE_LIST_PAGE_OBJECTS
        };
        let mut cursor: Option<String> = None;
        let mut prior_path: Option<String> = None;
        let mut pages = 0_usize;
        let mut object_count = 0_i64;
        let mut content_hasher = Sha256::new();
        let mut staged_surface_ids = HashSet::new();
        loop {
            let heartbeat_at = clock::now_unix_secs();
            db.heartbeat_cache_inventory_topology(
                cache.id,
                generation,
                owner_token,
                heartbeat_at,
                inventory_lease_deadline(heartbeat_at)?,
            )
            .await?;
            let mut next_heartbeat_at = heartbeat_at
                .checked_add(CACHE_INVENTORY_HEARTBEAT_SECS)
                .context("cache inventory heartbeat deadline overflowed")?;
            pages = pages
                .checked_add(1)
                .context("cache inventory page count overflowed")?;
            let max_pages = if cfg!(target_arch = "wasm32") {
                crate::fetch::WORKER_MAX_SURFACE_LIST_PAGES
            } else {
                crate::fetch::MAX_SURFACE_LIST_PAGES
            };
            anyhow::ensure!(
                pages <= max_pages,
                "cache inventory exceeded the page limit"
            );
            let page = fetch
                .list_page(cursor.as_deref(), page_limit)
                .await
                .with_context(|| format!("listing cache placement '{}'", placement.name))?;
            page.validate(page_limit, cursor.as_deref())?;
            let listed_evidence = &page.evidence;
            let mut page_observations = Vec::with_capacity(page.paths.len());
            for path in &page.paths {
                let heartbeat_at = clock::now_unix_secs();
                if heartbeat_at >= next_heartbeat_at {
                    db.heartbeat_cache_inventory_topology(
                        cache.id,
                        generation,
                        owner_token,
                        heartbeat_at,
                        inventory_lease_deadline(heartbeat_at)?,
                    )
                    .await?;
                    next_heartbeat_at = heartbeat_at
                        .checked_add(CACHE_INVENTORY_HEARTBEAT_SECS)
                        .context("cache inventory heartbeat deadline overflowed")?;
                }
                anyhow::ensure!(
                    prior_path.as_ref().is_none_or(|prior| prior < path),
                    "cache placement '{}' returned keys out of global order",
                    placement.name
                );
                aggregate_listing_budget.record(path).with_context(|| {
                    format!(
                        "cache-wide inventory exceeded its bound at placement '{}'",
                        placement.name
                    )
                })?;
                object_count = object_count
                    .checked_add(1)
                    .context("cache inventory object count overflowed")?;
                let observed = match surface_objects.get(path).and_then(|object| {
                    reusable_inventory_evidence(
                        object,
                        listed_evidence.get(path),
                        reusable.get(&object.id),
                    )
                }) {
                    Some(observed) => observed,
                    None => fetch
                        .inventory_evidence(path)
                        .await
                        .with_context(|| {
                            format!(
                                "observing '{path}' in cache placement '{}'",
                                placement.name
                            )
                        })?
                        .with_context(|| {
                            format!(
                                "cache placement '{}' listed '{path}' but it disappeared before observation",
                                placement.name
                            )
                        })?,
                };
                content_hasher.update(path.as_bytes());
                content_hasher.update(b":");
                content_hasher.update(hex::encode(observed.sha256).as_bytes());
                content_hasher.update(b":");
                content_hasher.update(observed.size.to_string().as_bytes());
                content_hasher.update(b":");
                content_hasher.update(observed.strong_etag.as_deref().unwrap_or("-").as_bytes());
                content_hasher.update(b"\n");
                prior_path = Some(path.clone());

                page_observations.push((path.clone(), observed));
            }

            let listed_objects = page_observations
                .iter()
                .map(|(path, observed)| CacheInventoryListedObject {
                    object_key: path.clone(),
                    observed_sha256: hex::encode(observed.sha256),
                    observed_size: observed.size,
                    etag: observed.strong_etag.clone(),
                })
                .collect::<Vec<_>>();
            db.stage_cache_inventory_listed_objects(
                cache.id,
                generation,
                placement.id,
                owner_token,
                &listed_objects,
            )
            .await?;

            for (path, observed) in &page_observations {
                let staged_surface_object = if let Some(surface_object) = surface_objects.get(path)
                {
                    Some(
                        stage_existing_cache_surface_object(
                            db,
                            cache.id,
                            generation,
                            placement.id,
                            owner_token,
                            &surface_object,
                        )
                        .await?,
                    )
                } else {
                    db.cache_staged_surface_object_identity(
                        cache.id,
                        generation,
                        placement.id,
                        owner_token,
                        path,
                    )
                    .await?
                    .map(|(content_hash, size)| StagedCacheSurfaceObject {
                        object_key: path.clone(),
                        content_hash,
                        size,
                    })
                };
                if let Some(staged) = staged_surface_object {
                    if staged_surface_ids.insert(staged.object_key.clone()) {
                        retained_budget.record(staged.object_key.len())?;
                        stage_observed_surface_object(
                            db,
                            cache.id,
                            generation,
                            now,
                            placement.id,
                            owner_token,
                            &staged,
                            &observed,
                        )
                        .await?;
                    }
                }

                if !path.ends_with(".narinfo") {
                    continue;
                }
                let Some(store_hash) = path.strip_suffix(".narinfo") else {
                    continue;
                };
                if store_hash.contains('/') {
                    continue;
                }
                let Some(bytes) = fetch
                    .fetch_bounded(path, crate::fetch::MAX_CACHE_NARINFO_BYTES)
                    .await?
                else {
                    bail!(
                        "cache placement '{}' lost narinfo '{path}' during its scan",
                        placement.name
                    );
                };
                let parsed_digest: [u8; 32] = Sha256::digest(&bytes).into();
                if observed.sha256 != parsed_digest
                    || observed.size
                        != i64::try_from(bytes.len()).context("narinfo is too large")?
                {
                    bail!(
                        "cache placement '{}' changed narinfo '{path}' during its scan",
                        placement.name
                    );
                }
                let Ok(text) = std::str::from_utf8(&bytes) else {
                    continue;
                };
                if let Some(object) =
                    crate::service::parse_cache_narinfo(cache.id, store_hash, text, now)
                {
                    let narinfo = stage_cache_surface_object(
                        db,
                        cache.id,
                        generation,
                        placement.id,
                        owner_token,
                        path,
                        &hex::encode(parsed_digest),
                        i64::try_from(bytes.len()).context("narinfo is too large")?,
                    )
                    .await?;
                    if staged_surface_ids.insert(narinfo.object_key.clone()) {
                        retained_budget.record(narinfo.object_key.len())?;
                        stage_observed_surface_object(
                            db,
                            cache.id,
                            generation,
                            now,
                            placement.id,
                            owner_token,
                            &narinfo,
                            &observed,
                        )
                        .await?;
                    }
                    let nar = stage_cache_surface_object(
                        db,
                        cache.id,
                        generation,
                        placement.id,
                        owner_token,
                        &object.nar_url,
                        &object.file_hash,
                        object.file_size,
                    )
                    .await?;
                    if let Some((nar_sha256, nar_size, nar_etag)) = db
                        .cache_inventory_listed_object_evidence(
                            cache.id,
                            generation,
                            placement.id,
                            owner_token,
                            &object.nar_url,
                        )
                        .await?
                    {
                        let nar_sha256 = hex::decode(nar_sha256)
                            .context("staged NAR evidence hash is not hexadecimal")?;
                        let nar_evidence = SurfaceObjectEvidence {
                            sha256: nar_sha256.try_into().map_err(|_| {
                                anyhow::anyhow!("staged NAR evidence hash is not SHA-256")
                            })?,
                            size: nar_size,
                            strong_etag: nar_etag,
                        };
                        if staged_surface_ids.insert(nar.object_key.clone()) {
                            retained_budget.record(nar.object_key.len())?;
                            stage_observed_surface_object(
                                db,
                                cache.id,
                                generation,
                                now,
                                placement.id,
                                owner_token,
                                &nar,
                                &nar_evidence,
                            )
                            .await?;
                        }
                    }
                    let identity_json = serde_json::json!({
                        "compression": &object.compression,
                        "contentAddress": &object.content_address,
                        "deriver": &object.deriver,
                        "fileHash": &object.file_hash,
                        "fileSize": object.file_size,
                        "narHash": &object.nar_hash,
                        "narSize": object.nar_size,
                        "narUrl": &object.nar_url,
                        "references": &object.references,
                        "signature": &object.signature,
                        "storeName": &object.store_name,
                    })
                    .to_string();
                    let identity_digest = hex::encode(Sha256::digest(identity_json.as_bytes()));
                    retained_budget.record(identity_json.len() + object.store_hash.len() + 256)?;
                    db.stage_cache_inventory_narinfo_candidate(
                        owner_token,
                        &CacheInventoryNarinfoCandidate {
                            cache_id: cache.id,
                            generation,
                            placement_id: placement.id,
                            store_hash: object.store_hash,
                            store_name: object.store_name,
                            identity_digest,
                            narinfo_object_key: narinfo.object_key,
                            nar_object_key: nar.object_key,
                            nar_hash: object.nar_hash,
                            nar_size: object.nar_size,
                            file_hash: object.file_hash,
                            file_size: object.file_size,
                            compression: object.compression,
                            deriver: object.deriver,
                            signature: object.signature,
                            content_address: object.content_address,
                            references: object.references,
                            published_at: object.published_at,
                        },
                    )
                    .await?;
                }
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        scans.push(PlacementScan {
            placement,
            content_digest: hex::encode(content_hasher.finalize()),
            object_count,
        });
    }

    let publication_time = clock::now_unix_secs();
    db.heartbeat_cache_inventory_topology(
        cache.id,
        generation,
        owner_token,
        publication_time,
        inventory_lease_deadline(publication_time)?,
    )
    .await?;
    let mut aggregate_entries = Vec::with_capacity(scans.len());
    for scan in &scans {
        db.stage_missing_cache_inventory_observations(
            cache.id,
            generation,
            scan.placement.id,
            owner_token,
            publication_time,
        )
        .await?;
        db.discard_unservable_cache_inventory_candidates(
            cache.id,
            generation,
            scan.placement.id,
            owner_token,
        )
        .await?;
        db.stage_cache_inventory_manifest(
            cache.id,
            generation,
            scan.placement.id,
            owner_token,
            &scan.content_digest,
            scan.object_count,
            publication_time,
        )
        .await?;
        aggregate_entries.push(format!(
            "{}:{}:{}",
            scan.placement.id, scan.placement.resource_version, scan.content_digest
        ));
    }
    aggregate_entries.sort();
    let aggregate_digest = hex::encode(Sha256::digest(aggregate_entries.join("\n").as_bytes()));
    let (added, removed, unchanged) = db
        .cache_inventory_change_counts(cache.id, generation, owner_token)
        .await?;
    let state = db
        .cache_gc_topology_state(cache.id)
        .await?
        .context("cache GC topology is not initialized")?;
    db.publish_cache_inventory_topology(
        cache.id,
        generation,
        owner_token,
        &aggregate_digest,
        state.epoch,
        &uuid::Uuid::new_v4().simple().to_string(),
        publication_time,
    )
    .await?;

    Ok(RescanStats {
        added: usize::try_from(added).context("inventory added count overflowed")?,
        removed: usize::try_from(removed).context("inventory removed count overflowed")?,
        unchanged: usize::try_from(unchanged).context("inventory unchanged count overflowed")?,
    })
}

async fn stage_observed_surface_object(
    db: &Database,
    cache_id: i64,
    generation: i64,
    observed_at: i64,
    placement_id: i64,
    owner_token: &str,
    object: &StagedCacheSurfaceObject,
    observed: &SurfaceObjectEvidence,
) -> Result<()> {
    let expected_hash = &object.content_hash;
    let expected_size = object.size;
    let valid =
        observed.size == expected_size && sha256_hash_matches(expected_hash, &observed.sha256);
    db.stage_cache_object_presence(
        owner_token,
        &CacheObjectPresenceObservation {
            cache_id,
            object_key: object.object_key.clone(),
            placement_id,
            state: if valid { "present" } else { "corrupt" }.to_string(),
            observed_hash: Some(if valid {
                expected_hash.to_string()
            } else {
                format!("sha256:{}", hex::encode(observed.sha256))
            }),
            observed_size: Some(observed.size),
            etag: observed.strong_etag.clone(),
            inventory_generation: generation,
            observed_at,
        },
    )
    .await
}

fn reusable_inventory_evidence(
    object: &SurfaceObjectRecord,
    listed: Option<&SurfaceListedEvidence>,
    prior: Option<&ReusablePlacementEvidence>,
) -> Option<SurfaceObjectEvidence> {
    let listed = listed?;
    let prior = prior?;
    if prior.state != "present"
        || object.content_hash.is_none()
        || prior.observed_hash != object.content_hash
        || prior.observed_size != object.size
        || object.size != Some(listed.size)
    {
        return None;
    }

    let listed_etag = crate::surface_write::strong_if_match_etag(&listed.strong_etag).ok()?;
    let prior_etag = crate::surface_write::strong_if_match_etag(prior.etag.as_deref()?).ok()?;
    if listed_etag != prior_etag {
        return None;
    }
    let sha256 = canonical_sha256_digest(prior.observed_hash.as_deref()?)?;

    Some(SurfaceObjectEvidence {
        sha256,
        size: listed.size,
        strong_etag: Some(listed_etag),
    })
}

fn canonical_sha256_digest(hash: &str) -> Option<[u8; 32]> {
    let hash = hash.trim();
    let bytes = if let Some(encoded) = hash.strip_prefix("sha256-") {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?
    } else {
        let encoded = hash.strip_prefix("sha256:").unwrap_or(hash);
        match encoded.len() {
            64 if encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
                hex::decode(encoded).ok()?
            }
            52 => decode_nix_base32(encoded)?,
            _ => return None,
        }
    };
    bytes.try_into().ok()
}

fn sha256_hash_matches(expected: &str, digest: &[u8; 32]) -> bool {
    if expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return expected.eq_ignore_ascii_case(&hex::encode(digest));
    }
    if let Some(encoded) = expected.strip_prefix("sha256:") {
        if encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return encoded.eq_ignore_ascii_case(&hex::encode(digest));
        }
        return encoded == encode_nix_base32(digest);
    }
    expected
        .strip_prefix("sha256-")
        .is_some_and(|encoded| encoded == base64::engine::general_purpose::STANDARD.encode(digest))
}

const NIX_BASE32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

fn decode_nix_base32(encoded: &str) -> Option<Vec<u8>> {
    let len = encoded.len() * 5 / 8;
    let mut out = vec![0u8; len];
    for (n, character) in encoded.chars().rev().enumerate() {
        let digit = NIX_BASE32
            .iter()
            .position(|byte| char::from(*byte) == character)? as u16;
        let bit = n * 5;
        let index = bit / 8;
        let shift = bit % 8;
        *out.get_mut(index)? |= (digit << shift) as u8;
        let carry = digit >> (8 - shift);
        match out.get_mut(index + 1) {
            Some(next) => *next |= carry as u8,
            None if carry != 0 => return None,
            None => {}
        }
    }
    Some(out)
}

fn encode_nix_base32(bytes: &[u8]) -> String {
    let len = (bytes.len() * 8).div_ceil(5);
    let mut out = String::with_capacity(len);
    for n in (0..len).rev() {
        let bit = n * 5;
        let index = bit / 8;
        let shift = bit % 8;
        let mut chunk = (bytes[index] >> shift) as u16;
        if index + 1 < bytes.len() {
            chunk |= (bytes[index + 1] as u16) << (8 - shift);
        }
        out.push(NIX_BASE32[(chunk & 0x1f) as usize] as char);
    }
    out
}

#[derive(Debug, Clone)]
struct StagedCacheSurfaceObject {
    object_key: String,
    content_hash: String,
    size: i64,
}

async fn stage_existing_cache_surface_object(
    db: &Database,
    cache_id: i64,
    generation: i64,
    placement_id: i64,
    owner_token: &str,
    object: &SurfaceObjectRecord,
) -> Result<StagedCacheSurfaceObject> {
    let content_hash = object
        .content_hash
        .clone()
        .context("cache surface object has no expected content hash")?;
    let size = object
        .size
        .context("cache surface object has no expected size")?;
    stage_cache_surface_object(
        db,
        cache_id,
        generation,
        placement_id,
        owner_token,
        &object.object_key,
        &content_hash,
        size,
    )
    .await
}

async fn stage_cache_surface_object(
    db: &Database,
    cache_id: i64,
    generation: i64,
    placement_id: i64,
    owner_token: &str,
    key: &str,
    content_hash: &str,
    size: i64,
) -> Result<StagedCacheSurfaceObject> {
    db.stage_cache_surface_object_identity(
        cache_id,
        generation,
        placement_id,
        owner_token,
        key,
        content_hash,
        size,
    )
    .await?;
    Ok(StagedCacheSurfaceObject {
        object_key: key.to_string(),
        content_hash: content_hash.to_string(),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::fetch::SurfaceFetch;
    use crate::surface_write::{SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite};

    struct RecoveryFetch {
        evidence: Option<SurfaceObjectEvidence>,
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for RecoveryFetch {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }

        async fn inventory_evidence(&self, _path: &str) -> Result<Option<SurfaceObjectEvidence>> {
            Ok(self.evidence.clone())
        }

        async fn list_page(
            &self,
            _cursor: Option<&str>,
            _limit: usize,
        ) -> Result<crate::fetch::SurfaceListPage> {
            Ok(crate::fetch::SurfaceListPage {
                paths: Vec::new(),
                evidence: Default::default(),
                next_cursor: None,
            })
        }

        fn describe(&self) -> String {
            "recovery-test".into()
        }
    }

    struct RecoverySurfaces {
        evidence: Mutex<VecDeque<Option<SurfaceObjectEvidence>>>,
    }

    #[async_trait::async_trait]
    impl SurfaceProvider for RecoverySurfaces {
        async fn placement_fetcher(
            &self,
            _placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceFetch>> {
            let evidence = self.evidence.lock().unwrap().pop_front().flatten();
            Ok(Box::new(RecoveryFetch { evidence }))
        }
    }

    struct RecoveryWriter;

    #[async_trait::async_trait]
    impl SurfaceWrite for RecoveryWriter {
        async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
            Ok(())
        }

        async fn delete(&self, _path: &str) -> Result<()> {
            Ok(())
        }

        async fn delete_if_matches(
            &self,
            _path: &str,
            _expected: &SurfaceDeletePrecondition,
        ) -> Result<SurfaceDeleteOutcome> {
            Ok(SurfaceDeleteOutcome::NotFound)
        }
    }

    struct RecoveryWriters;

    #[async_trait::async_trait]
    impl SurfaceWriteProvider for RecoveryWriters {
        async fn placement_writer(
            &self,
            _placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceWrite>> {
            Ok(Box::new(RecoveryWriter))
        }

        async fn placement_deleter(
            &self,
            _placement: &SurfacePlacementRecord,
            _expected_binding_resource_version: i64,
            _delete_credential_generation: i64,
        ) -> Result<Box<dyn SurfaceWrite>> {
            Ok(Box::new(RecoveryWriter))
        }
    }

    async fn run_recovery_page_and_wrap(db: &Database, surfaces: &RecoverySurfaces, now: i64) {
        let writers = RecoveryWriters;
        recover_expired_cache_writes(db, surfaces, &writers, now, 1)
            .await
            .unwrap();
        // The first call advances beyond the one-item page. The empty second
        // call exercises the durable cursor wrap needed before the next retry.
        recover_expired_cache_writes(db, surfaces, &writers, now, 1)
            .await
            .unwrap();
    }

    fn evidence(bytes: &[u8]) -> SurfaceObjectEvidence {
        SurfaceObjectEvidence {
            sha256: Sha256::digest(bytes).into(),
            size: i64::try_from(bytes.len()).unwrap(),
            strong_etag: None,
        }
    }

    #[test]
    fn expiry_distinguishes_same_size_replacement_from_unchanged_baseline() {
        let old = evidence(b"old");
        let replacement = evidence(b"new");
        let prior = WriteObjectIdentity {
            size: old.size,
            sha256: hex::encode(old.sha256),
            strong_etag: None,
        };
        assert_eq!(
            classify_expired_write(Some(&prior), None, 3, Some(&replacement)),
            ExpiredWriteClassification::Replacement
        );
        assert_eq!(
            classify_expired_write(Some(&prior), None, 3, Some(&old)),
            ExpiredWriteClassification::NoReplacement
        );
    }

    #[test]
    fn expiry_treats_transient_a_to_b_to_a_as_no_current_replacement() {
        let current_a = evidence(b"aaa");
        let prior = WriteObjectIdentity {
            size: current_a.size,
            sha256: hex::encode(current_a.sha256),
            strong_etag: None,
        };
        assert_eq!(
            classify_expired_write(
                Some(&prior),
                Some(&hex::encode(Sha256::digest(b"bbb"))),
                3,
                Some(&current_a)
            ),
            ExpiredWriteClassification::NoReplacement
        );
    }

    #[test]
    fn inventory_reuses_only_exact_strong_provider_versions() {
        let digest: [u8; 32] = Sha256::digest(b"unchanged-cache-object").into();
        let object = SurfaceObjectRecord {
            id: 7,
            registry_id: None,
            cache_id: Some(1),
            object_key: "nar/fixture.nar.zst".into(),
            content_hash: Some(format!("sha256:{}", hex::encode(digest))),
            size: Some(22),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
            lifecycle_state: "active".into(),
            tombstoned_at: None,
            created_at: 0,
            updated_at: 0,
            resource_version: 1,
        };
        let listed = SurfaceListedEvidence {
            size: 22,
            strong_etag: "provider-version".into(),
        };
        let mut prior = ReusablePlacementEvidence {
            surface_object_id: object.id,
            state: "present".into(),
            observed_hash: object.content_hash.clone(),
            observed_size: object.size,
            etag: Some("\"provider-version\"".into()),
        };

        let reused = reusable_inventory_evidence(&object, Some(&listed), Some(&prior)).unwrap();
        assert_eq!(reused.sha256, digest);
        assert_eq!(reused.strong_etag.as_deref(), Some("\"provider-version\""));

        prior.etag = Some("different-version".into());
        assert!(reusable_inventory_evidence(&object, Some(&listed), Some(&prior)).is_none());
    }

    #[test]
    fn completing_intent_fails_closed_without_positive_replacement_evidence() {
        assert!(
            completing_replacement_evidence(ExpiredWriteClassification::NoReplacement, None,)
                .is_err()
        );
        let replacement = evidence(b"replacement");
        assert_eq!(
            completing_replacement_evidence(
                ExpiredWriteClassification::Replacement,
                Some(&replacement),
            )
            .unwrap(),
            &replacement
        );
    }

    #[tokio::test]
    async fn recovery_controller_converges_when_completion_evidence_is_delayed() {
        let db = Database::open_in_memory().await.unwrap();
        db.install_write_failure_test_tickets().await.unwrap();
        db.prepare_ambiguous_recovery_test_tickets().await.unwrap();
        let replacement = evidence(b"x");
        let surfaces = RecoverySurfaces {
            evidence: Mutex::new([None, None, Some(replacement)].into_iter().collect()),
        };

        for attempt in 0..3 {
            run_recovery_page_and_wrap(&db, &surfaces, 1_000 + attempt * 4_000).await;
        }

        let cache = db
            .test_cache_write_ticket_settlement("cache-multipart-post")
            .await
            .unwrap();
        assert_eq!(cache.state, "completed");
        assert_eq!(cache.quota_state, "committed");
        assert_eq!(cache.active_slot, None);
        assert_eq!(cache.covered_inventory_generation, None);
        assert_eq!(cache.recovery_attempts, 2);
        assert_eq!(db.test_org_usage(1).await.unwrap(), (1, 1));

        let cache = db.binary_cache_by_id(1).await.unwrap().unwrap();
        rescan_cache(&db, &surfaces, &cache).await.unwrap();
        let cache = db
            .test_cache_write_ticket_settlement("cache-multipart-post")
            .await
            .unwrap();
        assert_eq!(cache.covered_inventory_generation, Some(2));
    }

    #[tokio::test]
    async fn recovery_controller_terminalizes_permanent_completion_ambiguity() {
        let db = Database::open_in_memory().await.unwrap();
        db.install_write_failure_test_tickets().await.unwrap();
        db.prepare_ambiguous_recovery_test_tickets().await.unwrap();
        let surfaces = RecoverySurfaces {
            evidence: Mutex::new(std::iter::repeat(None).take(16).collect()),
        };

        for attempt in 0..8 {
            run_recovery_page_and_wrap(&db, &surfaces, 1_000 + attempt * 4_000).await;
        }

        let cache = db
            .test_cache_write_ticket_settlement("cache-multipart-post")
            .await
            .unwrap();
        assert_eq!(cache.state, "completed");
        assert_eq!(cache.quota_state, "committed");
        assert_eq!(cache.active_slot, None);
        assert_eq!(cache.covered_inventory_generation, None);
        assert_eq!(cache.recovery_attempts, 8);
        assert_eq!(db.test_org_usage(1).await.unwrap(), (1, 1));
    }

    #[test]
    fn accepts_supported_narinfo_sha256_encodings() {
        let digest: [u8; 32] = Sha256::digest(b"cache-object").into();
        assert!(sha256_hash_matches(&hex::encode(digest), &digest));
        assert!(sha256_hash_matches(
            &format!("sha256:{}", hex::encode(digest)),
            &digest
        ));
        assert_eq!(
            canonical_sha256_digest(&format!("sha256:{}", encode_nix_base32(&digest))),
            Some(digest)
        );
        assert!(sha256_hash_matches(
            &format!("sha256:{}", encode_nix_base32(&digest)),
            &digest
        ));
        assert!(sha256_hash_matches(
            &format!(
                "sha256-{}",
                base64::engine::general_purpose::STANDARD.encode(digest)
            ),
            &digest
        ));
    }

    #[test]
    fn rejects_expected_hash_for_different_physical_bytes() {
        let first: [u8; 32] = Sha256::digest(b"first").into();
        let second: [u8; 32] = Sha256::digest(b"second").into();
        assert!(!sha256_hash_matches(
            &format!("sha256:{}", hex::encode(first)),
            &second
        ));
    }
}
