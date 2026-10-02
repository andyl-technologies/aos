//! Bounded provider enumeration for OCI garbage-collection inventories.
//!
//! Provider bytes, not the catalog, are authoritative. Each pass enumerates a
//! ready complete placement, hashes every canonical OCI blob key, requires a
//! strong provider ETag, and appends both tracked and untracked objects to a
//! durable generation. Database begin/seal operations freeze and recheck the
//! registry epoch and exact placement/binding topology around the read-only
//! provider walk.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_oci_types::Sha256Digest;
use futures_util::Future;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::db::{
    AppendOciProviderInventoryPage, BeginOciProviderInventory, CompleteOciProviderInventory,
    Database, OciProviderInventoryEntryInput, OciProviderInventoryGenerationRecord,
    OCI_GC_INVENTORY_BATCH_SIZE, OCI_GC_MAX_INVENTORY_KEY_BYTES, OCI_GC_MAX_INVENTORY_OBJECTS,
};
use crate::fetch::{
    SurfaceFetch, SurfaceListingBudget, SurfaceProvider, MAX_SURFACE_LIST_CURSOR_BYTES,
    MAX_SURFACE_LIST_OBJECTS, MAX_SURFACE_LIST_PATH_BYTES, WORKER_MAX_SURFACE_LIST_CURSOR_BYTES,
    WORKER_MAX_SURFACE_LIST_OBJECTS, WORKER_MAX_SURFACE_LIST_PATH_BYTES,
};
use crate::keymap::OCI_BLOB_KEY_PREFIX;

// An object may span many queue dispatches, but its total modeled size remains
// bounded. Each dispatch reads only small exact ranges and carries the existing
// portable OCI SHA-256 state in its server-internal continuation.
const MAX_OCI_INVENTORY_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PLACEMENTS_PER_PASS: usize = 100;
const INVENTORY_CLAIM_LEASE_SECONDS: i64 = 60 * 60;

// One listing page is one provider object. An `InventoryObjectContinuation`
// binds to the page's requested cursor and the object key, and a page's
// entries are appended only once every object on it is hashed, so a larger
// page would force a dispatch that stops mid-object either to rehash its
// finished siblings or to skip them. The listing is scoped to the blob
// namespace, so every page is a blob rather than a binary-cache or git key.
const INVENTORY_PAGE_SIZE: usize = 1;

// A durable provider cursor is meaningful only for the listing prefix that
// produced it. The tag records that the cursor came from a blob-scoped
// listing; a stored cursor without it belongs to a generation begun by an
// earlier release that walked the whole placement, and resuming it against a
// scoped listing would silently skip or repeat keys, so such a generation
// fails and a fresh one is collected.
const INVENTORY_CURSOR_SCOPE_TAG: &str = "oci-blobs-v1:";

// Bound on a stored (tagged) provider cursor and on the cursor carried by an
// object continuation. It matches the database page-checkpoint check.
const MAX_STORED_PROVIDER_CURSOR_BYTES: usize = 512;

/// Native provider work admitted by one maintenance dispatch.
pub const NATIVE_OCI_INVENTORY_DISPATCH_BUDGET: OciInventoryDispatchBudget =
    OciInventoryDispatchBudget {
        max_pages: 16,
        max_objects: 16,
        max_chunks: 16,
        max_chunk_bytes: 16 * 1024 * 1024,
        max_bytes: 256 * 1024 * 1024,
        max_duration: Duration::from_secs(60),
    };

/// Worker provider work admitted by one queue dispatch.
pub const WORKER_OCI_INVENTORY_DISPATCH_BUDGET: OciInventoryDispatchBudget =
    OciInventoryDispatchBudget {
        max_pages: 4,
        max_objects: 4,
        max_chunks: 8,
        max_chunk_bytes: 8 * 1024 * 1024,
        max_bytes: 64 * 1024 * 1024,
        max_duration: Duration::from_secs(30),
    };

/// Provider-I/O ceilings enforced by one inventory dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OciInventoryDispatchBudget {
    /// Maximum provider listing pages fetched and checkpointed.
    pub max_pages: usize,
    /// Maximum canonical OCI objects hashed.
    pub max_objects: usize,
    /// Maximum ranged object chunks fetched.
    pub max_chunks: usize,
    /// Maximum bytes fetched in one ranged chunk.
    pub max_chunk_bytes: u64,
    /// Maximum aggregate object bytes hashed.
    pub max_bytes: u64,
    /// Maximum wall time spent on a known durable generation.
    pub max_duration: Duration,
}

impl OciInventoryDispatchBudget {
    fn validate(self) -> Result<()> {
        anyhow::ensure!(
            self.max_pages > 0
                && self.max_pages <= OCI_GC_MAX_INVENTORY_OBJECTS
                && self.max_objects > 0
                && self.max_objects <= self.max_pages
                && self.max_chunks > 0
                && self.max_chunk_bytes > 0
                && self.max_chunk_bytes <= self.max_bytes
                && self.max_bytes > 0
                && self.max_bytes <= MAX_OCI_INVENTORY_OBJECT_BYTES
                && self.max_duration > Duration::ZERO
                && self.max_duration <= Duration::from_secs(15 * 60),
            "invalid OCI provider inventory dispatch budget"
        );
        Ok(())
    }
}

/// Aggregate result of one bounded provider-inventory pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OciInventoryControllerStats {
    /// Placements whose inventory generation was attempted.
    pub attempted: u64,
    /// Complete inventory heads published.
    pub completed: u64,
    /// Generations durably failed for a later fresh retry.
    pub failed: u64,
    /// Opaque exact-generation cursor for the next bounded dispatch.
    pub continuation: Option<String>,
}

#[derive(Debug)]
struct InventoryDispatchTracker {
    limits: OciInventoryDispatchBudget,
    started: crate::clock::Instant,
    pages: usize,
    objects: usize,
    chunks: usize,
    bytes: u64,
}

impl InventoryDispatchTracker {
    fn new(limits: OciInventoryDispatchBudget) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            started: crate::clock::Instant::now(),
            pages: 0,
            objects: 0,
            chunks: 0,
            bytes: 0,
        })
    }

    fn remaining_duration(&self) -> Option<Duration> {
        self.limits
            .max_duration
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero())
    }

    fn can_list_page(&self) -> bool {
        self.pages < self.limits.max_pages && self.remaining_duration().is_some()
    }

    fn record_page(&mut self) {
        self.pages = self.pages.saturating_add(1);
    }

    fn remaining_object_bytes(&self) -> u64 {
        self.limits.max_bytes.saturating_sub(self.bytes)
    }

    fn validate_object_size(&self, declared_size: u64) -> Result<()> {
        anyhow::ensure!(
            declared_size <= MAX_OCI_INVENTORY_OBJECT_BYTES,
            "OCI provider object exceeds the inventory object bound"
        );
        Ok(())
    }

    fn next_chunk_bytes(&self, remaining_object_bytes: u64) -> Option<u64> {
        (self.objects < self.limits.max_objects
            && self.chunks < self.limits.max_chunks
            && self.remaining_duration().is_some())
        .then(|| {
            remaining_object_bytes
                .min(self.remaining_object_bytes())
                .min(self.limits.max_chunk_bytes)
        })
        .filter(|bytes| *bytes > 0)
    }

    fn record_chunk(&mut self, observed_size: u64) -> Result<()> {
        self.chunks = self
            .chunks
            .checked_add(1)
            .context("OCI inventory dispatch chunk count overflowed")?;
        self.bytes = self
            .bytes
            .checked_add(observed_size)
            .context("OCI inventory dispatch byte count overflowed")?;
        anyhow::ensure!(
            self.chunks <= self.limits.max_chunks && self.bytes <= self.limits.max_bytes,
            "OCI provider inventory exceeded its chunk dispatch budget"
        );
        Ok(())
    }

    fn record_object(&mut self) -> Result<()> {
        self.objects = self
            .objects
            .checked_add(1)
            .context("OCI inventory dispatch object count overflowed")?;
        anyhow::ensure!(
            self.objects <= self.limits.max_objects,
            "OCI provider inventory exceeded its object dispatch budget"
        );
        Ok(())
    }
}

/// Progress of one bounded inventory dispatch for an exact placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciPlacementInventoryProgress {
    /// A complete inventory head was published for the placement.
    Completed,
    /// The dispatch budget ended; resume with this opaque continuation.
    Continue(String),
    /// The generation failed durably; a new attempt needs a new seed.
    Failed,
    /// Another collector holds a live lease on the placement's inventory.
    Busy,
}

/// Produces exact provider inventories for ready OCI placements.
pub struct OciProviderInventoryController {
    db: Arc<Database>,
    surfaces: Arc<dyn SurfaceProvider>,
}

impl OciProviderInventoryController {
    /// Builds an inventory controller over shared exact read ports.
    #[must_use]
    pub fn new(db: Arc<Database>, surfaces: Arc<dyn SurfaceProvider>) -> Self {
        Self { db, surfaces }
    }

    /// Inventories at most `limit` ready complete registry placements.
    ///
    /// `idempotency_seed` is stable for a durable job retry. A crash can replay
    /// the same begin and exact appended rows; a later maintenance dispatch
    /// supplies a new seed and creates a fresh generation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid bound/identity or a database failure
    /// that prevents durable failure recording.
    pub async fn run_due(
        &self,
        collector_id: &str,
        idempotency_seed: &str,
        now: i64,
        limit: usize,
    ) -> Result<OciInventoryControllerStats> {
        self.run_due_bounded(
            collector_id,
            idempotency_seed,
            now,
            limit,
            None,
            NATIVE_OCI_INVENTORY_DISPATCH_BUDGET,
        )
        .await
    }

    /// Runs one strictly bounded provider-inventory dispatch.
    ///
    /// `continuation` is an opaque cursor returned by the preceding dispatch.
    /// The cursor reopens only that durable generation and its exact collector
    /// receipt; it never selects a current placement or writer.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid selector, continuation, budget, or a
    /// database failure that prevents durable checkpoint or failure recording.
    pub async fn run_due_bounded(
        &self,
        collector_id: &str,
        idempotency_seed: &str,
        now: i64,
        limit: usize,
        continuation: Option<&str>,
        dispatch_budget: OciInventoryDispatchBudget,
    ) -> Result<OciInventoryControllerStats> {
        anyhow::ensure!(
            !collector_id.is_empty()
                && collector_id.len() <= 128
                && !idempotency_seed.is_empty()
                && idempotency_seed.len() <= 128
                && now >= 0
                && (1..=MAX_PLACEMENTS_PER_PASS).contains(&limit),
            "invalid OCI provider inventory execution selector"
        );
        let mut dispatch = InventoryDispatchTracker::new(dispatch_budget)?;
        let mut stats = OciInventoryControllerStats::default();
        if let Some(continuation) = continuation {
            let continuation = parse_inventory_continuation(continuation)?;
            let Some(generation) = self
                .db
                .oci_provider_inventory_generation(&continuation.generation_id)
                .await?
            else {
                return Ok(stats);
            };
            if !matches!(generation.state.as_str(), "collecting" | "sealing")
                || generation.collector_claim_token != continuation.claim_token
            {
                return Ok(stats);
            }
            continuation.validate_identity_for_generation(&generation)?;
            let generation = self
                .db
                .claim_oci_provider_inventory(
                    &generation.id,
                    collector_id,
                    &continuation.claim_token,
                    inventory_now(now),
                    INVENTORY_CLAIM_LEASE_SECONDS,
                )
                .await?;
            let object = continuation.resumable_object_for_generation(&generation)?;
            let placement = self
                .db
                .surface_placement(generation.placement_id)
                .await?
                .context("continued OCI inventory placement disappeared")?;
            stats.attempted = stats.attempted.saturating_add(1);
            stats.continuation = self
                .process_generation(
                    &placement,
                    &generation,
                    collector_id,
                    now,
                    &mut stats,
                    &mut dispatch,
                    object,
                )
                .await?;
            if stats.continuation.is_some() || dispatch.remaining_duration().is_none() {
                return Ok(stats);
            }
        }
        let recoverable_limit = limit.saturating_sub(usize::try_from(stats.attempted)?);
        let recoverable = if recoverable_limit == 0 {
            Vec::new()
        } else {
            self.db
                .list_recoverable_oci_provider_inventories(now, u32::try_from(recoverable_limit)?)
                .await?
        };
        for abandoned in recoverable {
            let placement = self
                .db
                .surface_placement(abandoned.placement_id)
                .await?
                .context("recoverable OCI inventory placement disappeared")?;
            let claim_token = inventory_claim_token(idempotency_seed, abandoned.placement_id);
            let generation = self
                .db
                .claim_oci_provider_inventory(
                    &abandoned.id,
                    collector_id,
                    &claim_token,
                    now,
                    INVENTORY_CLAIM_LEASE_SECONDS,
                )
                .await?;
            stats.attempted = stats.attempted.saturating_add(1);
            stats.continuation = self
                .process_generation(
                    &placement,
                    &generation,
                    collector_id,
                    now,
                    &mut stats,
                    &mut dispatch,
                    None,
                )
                .await?;
            if stats.continuation.is_some() || dispatch.remaining_duration().is_none() {
                return Ok(stats);
            }
        }
        let remaining = limit.saturating_sub(usize::try_from(stats.attempted)?);
        if remaining == 0 {
            return Ok(stats);
        }
        let due = self
            .db
            .list_due_oci_provider_inventory_placements(now, u32::try_from(remaining)?)
            .await?;
        for frozen in due {
            let placement = self
                .db
                .surface_placement(frozen.placement_id)
                .await?
                .context("due OCI inventory placement disappeared")?;
            anyhow::ensure!(
                placement.registry_id == Some(frozen.registry_id)
                    && placement.name == frozen.placement_name
                    && placement.resource_version == frozen.placement_resource_version
                    && placement.write_spec_version == frozen.placement_write_spec_version
                    && placement.observation_version == Some(frozen.placement_observation_version)
                    && placement.binding_id == frozen.binding_id,
                "due OCI inventory placement topology drifted before begin"
            );
            stats.attempted = stats.attempted.saturating_add(1);
            let collector_claim_token =
                inventory_claim_token(idempotency_seed, frozen.placement_id);
            let generation = self
                .db
                .begin_oci_provider_inventory(&BeginOciProviderInventory {
                    registry_id: frozen.registry_id,
                    placement_id: frozen.placement_id,
                    expected_placement_resource_version: frozen.placement_resource_version,
                    expected_placement_observation_version: frozen.placement_observation_version,
                    collector_id: collector_id.to_string(),
                    collector_claim_token,
                    collector_lease_seconds: INVENTORY_CLAIM_LEASE_SECONDS,
                    idempotency_key: inventory_idempotency_key(
                        idempotency_seed,
                        frozen.registry_id,
                        frozen.placement_id,
                        frozen.placement_resource_version,
                        frozen.placement_observation_version,
                    ),
                    now,
                })
                .await?;
            stats.continuation = self
                .process_generation(
                    &placement,
                    &generation,
                    collector_id,
                    now,
                    &mut stats,
                    &mut dispatch,
                    None,
                )
                .await?;
            if stats.continuation.is_some() || dispatch.remaining_duration().is_none() {
                return Ok(stats);
            }
        }
        Ok(stats)
    }

    /// Runs one bounded inventory dispatch for exactly one placement.
    ///
    /// Registry deletion uses this to collect the post-fence inventory of the
    /// registry's own placements on demand instead of waiting for the
    /// maintenance schedule. `idempotency_seed` identifies one attempt: the
    /// same seed reopens the same generation and receipt after response loss,
    /// and a new seed starts a fresh generation after a durable failure. A
    /// live generation owned by another collector is never taken over before
    /// its lease expires.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid selector, continuation, or budget, a
    /// placement that cannot be inventoried, or a database failure that
    /// prevents durable checkpoint or failure recording.
    pub async fn inventory_placement_bounded(
        &self,
        collector_id: &str,
        idempotency_seed: &str,
        now: i64,
        placement_id: i64,
        continuation: Option<&str>,
        dispatch_budget: OciInventoryDispatchBudget,
    ) -> Result<OciPlacementInventoryProgress> {
        anyhow::ensure!(
            !collector_id.is_empty()
                && collector_id.len() <= 128
                && !idempotency_seed.is_empty()
                && idempotency_seed.len() <= 128
                && now >= 0
                && placement_id > 0,
            "invalid OCI placement inventory selector"
        );
        let mut dispatch = InventoryDispatchTracker::new(dispatch_budget)?;
        let claim_token = inventory_claim_token(idempotency_seed, placement_id);

        let resumed = match continuation {
            Some(cursor) => {
                self.resume_placement_continuation(collector_id, now, placement_id, cursor)
                    .await?
            }
            None => None,
        };
        let (generation, object) = match resumed {
            Some(resumed) => resumed,
            None => match self
                .begin_or_claim_placement(
                    collector_id,
                    idempotency_seed,
                    &claim_token,
                    now,
                    placement_id,
                )
                .await?
            {
                Some(generation) => (generation, None),
                None => return Ok(OciPlacementInventoryProgress::Busy),
            },
        };
        match generation.state.as_str() {
            "complete" => return Ok(OciPlacementInventoryProgress::Completed),
            "failed" => return Ok(OciPlacementInventoryProgress::Failed),
            _ => {}
        }

        let placement = self
            .db
            .surface_placement(generation.placement_id)
            .await?
            .context("inventoried placement disappeared")?;
        let mut stats = OciInventoryControllerStats::default();
        let continuation = self
            .process_generation(
                &placement,
                &generation,
                collector_id,
                now,
                &mut stats,
                &mut dispatch,
                object,
            )
            .await?;
        Ok(match continuation {
            Some(cursor) => OciPlacementInventoryProgress::Continue(cursor),
            None if stats.completed > 0 => OciPlacementInventoryProgress::Completed,
            None => OciPlacementInventoryProgress::Failed,
        })
    }

    /// Reopens the generation named by a continuation, when it is still live.
    async fn resume_placement_continuation(
        &self,
        collector_id: &str,
        now: i64,
        placement_id: i64,
        cursor: &str,
    ) -> Result<
        Option<(
            OciProviderInventoryGenerationRecord,
            Option<InventoryObjectContinuation>,
        )>,
    > {
        let continuation = parse_inventory_continuation(cursor)?;
        anyhow::ensure!(
            continuation.placement_id == placement_id,
            "OCI inventory continuation names another placement"
        );
        let Some(generation) = self
            .db
            .oci_provider_inventory_generation(&continuation.generation_id)
            .await?
        else {
            return Ok(None);
        };
        if !matches!(generation.state.as_str(), "collecting" | "sealing")
            || generation.collector_claim_token != continuation.claim_token
        {
            return Ok(None);
        }
        continuation.validate_identity_for_generation(&generation)?;
        let generation = self
            .db
            .claim_oci_provider_inventory(
                &generation.id,
                collector_id,
                &continuation.claim_token,
                inventory_now(now),
                INVENTORY_CLAIM_LEASE_SECONDS,
            )
            .await?;
        let object = continuation.resumable_object_for_generation(&generation)?;
        Ok(Some((generation, object)))
    }

    /// Claims this attempt's live generation or begins a new one.
    ///
    /// Returns `Ok(None)` while another collector holds a live lease on the
    /// placement's active generation.
    async fn begin_or_claim_placement(
        &self,
        collector_id: &str,
        idempotency_seed: &str,
        claim_token: &str,
        now: i64,
        placement_id: i64,
    ) -> Result<Option<OciProviderInventoryGenerationRecord>> {
        if let Some(active) = self.db.active_oci_provider_inventory(placement_id).await? {
            let owned = active.collector_claim_token == claim_token;
            let expired = active
                .collector_lease_expires_at
                .is_some_and(|expires_at| expires_at <= now);
            if !owned && !expired {
                return Ok(None);
            }
            return self
                .db
                .claim_oci_provider_inventory(
                    &active.id,
                    collector_id,
                    claim_token,
                    inventory_now(now),
                    INVENTORY_CLAIM_LEASE_SECONDS,
                )
                .await
                .map(Some);
        }

        let placement = self
            .db
            .surface_placement(placement_id)
            .await?
            .context("OCI inventory placement does not exist")?;
        let registry_id = placement
            .registry_id
            .context("OCI inventory placement does not belong to a registry")?;
        let observation_version = placement
            .observation_version
            .context("OCI inventory placement has never been observed")?;
        self.db
            .begin_oci_provider_inventory(&BeginOciProviderInventory {
                registry_id,
                placement_id,
                expected_placement_resource_version: placement.resource_version,
                expected_placement_observation_version: observation_version,
                collector_id: collector_id.to_string(),
                collector_claim_token: claim_token.to_string(),
                collector_lease_seconds: INVENTORY_CLAIM_LEASE_SECONDS,
                idempotency_key: inventory_idempotency_key(
                    idempotency_seed,
                    registry_id,
                    placement_id,
                    placement.resource_version,
                    observation_version,
                ),
                now,
            })
            .await
            .map(Some)
    }

    async fn process_generation(
        &self,
        placement: &crate::db::SurfacePlacementRecord,
        generation: &OciProviderInventoryGenerationRecord,
        collector_id: &str,
        now: i64,
        stats: &mut OciInventoryControllerStats,
        dispatch: &mut InventoryDispatchTracker,
        object: Option<InventoryObjectContinuation>,
    ) -> Result<Option<String>> {
        let Some(_remaining) = dispatch.remaining_duration() else {
            return Ok(Some(inventory_continuation(generation, object)?));
        };
        let result = self
            .inventory_generation(placement, generation, collector_id, now, dispatch, object)
            .await;
        match result {
            Ok(InventoryGenerationProgress::Complete) => {
                stats.completed = stats.completed.saturating_add(1);
                Ok(None)
            }
            Ok(InventoryGenerationProgress::Continue(object)) => {
                // A dispatch may checkpoint complete pages before stopping in
                // the middle of the next object. Bind the continuation to the
                // durable post-append checkpoint, not the generation snapshot
                // that entered this dispatch.
                let current = self
                    .db
                    .oci_provider_inventory_generation(&generation.id)
                    .await?
                    .context("OCI provider inventory disappeared before continuation")?;
                anyhow::ensure!(
                    current.state == "collecting"
                        && current.collector_claim_token == generation.collector_claim_token,
                    "OCI provider inventory ownership changed before continuation"
                );
                Ok(Some(inventory_continuation(&current, object)?))
            }
            Err(error) => {
                let current = self
                    .db
                    .oci_provider_inventory_generation(&generation.id)
                    .await?
                    .context("OCI provider inventory disappeared during failure")?;
                if matches!(current.state.as_str(), "collecting" | "sealing") {
                    let failed_at = inventory_now(now);
                    self.db
                        .fail_oci_provider_inventory(
                            &current.id,
                            collector_id,
                            &current.collector_claim_token,
                            current.resource_version,
                            &crate::jobs::redacted_job_failure(&format!("{error:#}")),
                            failed_at,
                        )
                        .await?;
                }
                stats.failed = stats.failed.saturating_add(1);
                Ok(None)
            }
        }
    }

    async fn inventory_generation(
        &self,
        placement: &crate::db::SurfacePlacementRecord,
        generation: &OciProviderInventoryGenerationRecord,
        collector_id: &str,
        now: i64,
        dispatch: &mut InventoryDispatchTracker,
        object: Option<InventoryObjectContinuation>,
    ) -> Result<InventoryGenerationProgress> {
        anyhow::ensure!(
            placement.id == generation.placement_id
                && placement.registry_id == Some(generation.registry_id)
                && placement.resource_version == generation.placement_resource_version
                && placement.write_spec_version == generation.placement_write_spec_version
                && placement.observation_version == Some(generation.placement_observation_version)
                && placement.binding_id == generation.binding_id,
            "OCI provider inventory placement drifted after begin"
        );
        let binding = self
            .db
            .binding(generation.binding_id)
            .await?
            .context("OCI provider inventory binding disappeared")?;
        let write_state = self
            .db
            .binding_write_state(generation.binding_id)
            .await?
            .context("OCI provider inventory binding state disappeared")?;
        anyhow::ensure!(
            binding.resource_version == generation.binding_resource_version
                && write_state.current_write_revision == Some(generation.binding_write_revision),
            "OCI provider inventory binding drifted after begin"
        );

        let fetch = self.surfaces.placement_fetcher(placement).await?;
        let checkpoint_ordinal = match self
            .enumerate_and_append(
                fetch.as_ref(),
                generation,
                collector_id,
                now,
                dispatch,
                object,
            )
            .await?
        {
            InventoryEnumerationProgress::Complete(checkpoint_ordinal) => checkpoint_ordinal,
            InventoryEnumerationProgress::Continue(object) => {
                return Ok(InventoryGenerationProgress::Continue(object));
            }
        };
        let completed_at = inventory_now(now);
        self.db
            .complete_oci_provider_inventory(&CompleteOciProviderInventory {
                generation_id: generation.id.clone(),
                collector_id: collector_id.to_string(),
                collector_claim_token: generation.collector_claim_token.clone(),
                expected_checkpoint_ordinal: checkpoint_ordinal,
                observed_at: completed_at,
                now: completed_at,
            })
            .await?;
        Ok(InventoryGenerationProgress::Complete)
    }

    async fn enumerate_and_append(
        &self,
        fetch: &dyn SurfaceFetch,
        generation: &OciProviderInventoryGenerationRecord,
        collector_id: &str,
        started_at: i64,
        dispatch: &mut InventoryDispatchTracker,
        mut object: Option<InventoryObjectContinuation>,
    ) -> Result<InventoryEnumerationProgress> {
        if generation.state == "sealing" {
            anyhow::ensure!(
                generation.checkpoint_ordinal > 0 && generation.provider_cursor.is_none(),
                "sealing OCI provider inventory has an incomplete checkpoint"
            );
            return Ok(InventoryEnumerationProgress::Complete(
                generation.checkpoint_ordinal,
            ));
        }
        anyhow::ensure!(
            generation.state == "collecting",
            "OCI provider inventory is not resumable"
        );
        if generation.checkpoint_ordinal > 0 && generation.provider_cursor.is_none() {
            return Ok(InventoryEnumerationProgress::Complete(
                generation.checkpoint_ordinal,
            ));
        }
        // Fail a legacy unscoped checkpoint before any provider I/O or claim
        // heartbeat; the caller records the failure and due selection begins
        // a fresh generation.
        provider_cursor_for_listing(generation.provider_cursor.as_deref())?;

        let page_limit = INVENTORY_PAGE_SIZE.min(OCI_GC_INVENTORY_BATCH_SIZE);
        let page_bound = listing_page_bound(page_limit);
        let mut cursor = generation.provider_cursor.clone();
        let mut checkpoint_ordinal = generation.checkpoint_ordinal;
        let mut pages = usize::try_from(checkpoint_ordinal)
            .context("OCI provider inventory checkpoint count exceeds usize")?;
        let mut budget = SurfaceListingBudget::default();
        let mut inventory_budget = SurfaceListingBudget::with_limits(
            OCI_GC_MAX_INVENTORY_OBJECTS,
            OCI_GC_MAX_INVENTORY_KEY_BYTES,
        );
        let mut prior_path = generation.checkpoint_last_key.clone();

        loop {
            if !dispatch.can_list_page() {
                return Ok(InventoryEnumerationProgress::Continue(object));
            }
            pages += 1;
            anyhow::ensure!(
                pages <= page_bound,
                "OCI provider inventory exceeded page bound"
            );
            let heartbeat = inventory_now(started_at);
            self.db
                .claim_oci_provider_inventory(
                    &generation.id,
                    collector_id,
                    &generation.collector_claim_token,
                    heartbeat,
                    INVENTORY_CLAIM_LEASE_SECONDS,
                )
                .await?;
            // The durable checkpoint and the object continuation both carry
            // the tagged cursor; only the provider call sees the raw one.
            let requested_cursor = cursor.clone();
            let listing_cursor = provider_cursor_for_listing(requested_cursor.as_deref())?;
            let Some(page) = before_dispatch_deadline(
                dispatch,
                fetch.list_page(OCI_BLOB_KEY_PREFIX, listing_cursor, page_limit),
            )
            .await?
            else {
                return Ok(InventoryEnumerationProgress::Continue(object));
            };
            dispatch.record_page();
            page.validate(page_limit, OCI_BLOB_KEY_PREFIX, listing_cursor)?;
            let mut page_entries = Vec::new();
            for path in &page.paths {
                budget.record(path)?;
                anyhow::ensure!(
                    prior_path.as_ref().is_none_or(|prior| prior < path),
                    "OCI provider inventory pages are not globally ordered"
                );
                prior_path = Some(path.clone());
                let object_digest = canonical_oci_blob_digest(path)?
                    .context("provider listing returned a key outside the OCI blob namespace")?;
                inventory_budget.record(path)?;
                let progress = match object.take() {
                    Some(progress) => {
                        progress.validate_for(generation, requested_cursor.as_deref())?;
                        anyhow::ensure!(
                            progress.object_key == *path
                                && progress.object_digest == object_digest.to_string(),
                            "OCI inventory continuation object identity changed"
                        );
                        progress
                    }
                    None => {
                        let Some(declared_size) =
                            before_dispatch_deadline(dispatch, fetch.inventory_size(path)).await?
                        else {
                            return Ok(InventoryEnumerationProgress::Continue(None));
                        };
                        let declared_size = declared_size
                            .context("listed OCI provider object disappeared during inventory")?;
                        let declared_size = u64::try_from(declared_size)
                            .context("OCI provider object size is negative")?;
                        dispatch.validate_object_size(declared_size)?;
                        let Some(strong_etag) =
                            before_dispatch_deadline(dispatch, fetch.inventory_strong_etag(path))
                                .await?
                        else {
                            return Ok(InventoryEnumerationProgress::Continue(None));
                        };
                        let strong_etag = strong_etag
                            .context("listed OCI provider object has no strong entity tag")?;
                        let strong_etag = crate::surface_write::strong_if_match_etag(&strong_etag)?;
                        InventoryObjectContinuation::initial(
                            generation.placement_id,
                            checkpoint_ordinal,
                            requested_cursor.clone(),
                            path,
                            object_digest,
                            declared_size,
                            strong_etag,
                        )?
                    }
                };
                let entry = match self
                    .resume_inventory_object(
                        fetch,
                        generation,
                        collector_id,
                        started_at,
                        dispatch,
                        progress,
                    )
                    .await?
                {
                    InventoryObjectProgress::Complete(entry) => entry,
                    InventoryObjectProgress::Continue(progress) => {
                        return Ok(InventoryEnumerationProgress::Continue(Some(progress)));
                    }
                };
                dispatch.record_object()?;
                page_entries.push(entry);
            }
            let next_cursor = page
                .next_cursor
                .as_deref()
                .map(tag_provider_cursor)
                .transpose()?;
            let checkpoint = self
                .db
                .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
                    generation_id: generation.id.clone(),
                    collector_id: collector_id.to_string(),
                    collector_claim_token: generation.collector_claim_token.clone(),
                    expected_checkpoint_ordinal: checkpoint_ordinal,
                    expected_provider_cursor: requested_cursor,
                    next_provider_cursor: next_cursor.clone(),
                    last_listed_key: page.paths.last().cloned(),
                    entries: page_entries,
                    now: inventory_now(started_at),
                    lease_seconds: INVENTORY_CLAIM_LEASE_SECONDS,
                })
                .await?;
            checkpoint_ordinal = checkpoint.checkpoint_ordinal;
            cursor = checkpoint.provider_cursor;
            prior_path = checkpoint.checkpoint_last_key;
            if next_cursor.is_none() {
                return Ok(InventoryEnumerationProgress::Complete(checkpoint_ordinal));
            }
        }
    }

    async fn resume_inventory_object(
        &self,
        fetch: &dyn SurfaceFetch,
        generation: &OciProviderInventoryGenerationRecord,
        collector_id: &str,
        started_at: i64,
        dispatch: &mut InventoryDispatchTracker,
        mut progress: InventoryObjectContinuation,
    ) -> Result<InventoryObjectProgress> {
        let object_digest = Sha256Digest::parse(&progress.object_digest)?;
        let mut sha_state = progress.sha_state()?;
        while progress.next_offset < progress.expected_size {
            let remaining = progress
                .expected_size
                .checked_sub(progress.next_offset)
                .context("OCI inventory continuation offset exceeded object size")?;
            let Some(chunk_limit) = dispatch.next_chunk_bytes(remaining) else {
                return Ok(InventoryObjectProgress::Continue(progress));
            };
            let Some(current_size) =
                before_dispatch_deadline(dispatch, fetch.inventory_size(&progress.object_key))
                    .await?
            else {
                return Ok(InventoryObjectProgress::Continue(progress));
            };
            let Some(current_etag) = before_dispatch_deadline(
                dispatch,
                fetch.inventory_strong_etag(&progress.object_key),
            )
            .await?
            else {
                return Ok(InventoryObjectProgress::Continue(progress));
            };
            anyhow::ensure!(
                current_size.and_then(|size| u64::try_from(size).ok())
                    == Some(progress.expected_size)
                    && current_etag
                        .as_deref()
                        .map(crate::surface_write::strong_if_match_etag)
                        .transpose()?
                        .as_deref()
                        == Some(progress.strong_etag.as_str()),
                "OCI provider object identity changed between inventory chunks"
            );

            let heartbeat = inventory_now(started_at);
            self.db
                .claim_oci_provider_inventory(
                    &generation.id,
                    collector_id,
                    &generation.collector_claim_token,
                    heartbeat,
                    INVENTORY_CLAIM_LEASE_SECONDS,
                )
                .await?;
            let Some(chunk) = before_dispatch_deadline(
                dispatch,
                fetch.inventory_chunk_bounded(
                    &progress.object_key,
                    progress.next_offset,
                    progress.expected_size,
                    chunk_limit,
                ),
            )
            .await?
            else {
                return Ok(InventoryObjectProgress::Continue(progress));
            };
            let chunk = chunk.context("listed OCI provider object disappeared during inventory")?;
            anyhow::ensure!(
                chunk.total == progress.expected_size
                    && chunk.range.0 == progress.next_offset
                    && chunk.strong_etag == progress.strong_etag,
                "OCI provider inventory chunk did not match its continuation identity"
            );
            let chunk_len = u64::try_from(chunk.bytes.len())?;
            let expected_next = progress
                .next_offset
                .checked_add(chunk_len)
                .context("OCI provider inventory chunk offset overflowed")?;
            anyhow::ensure!(
                chunk_len > 0
                    && chunk.range.1.checked_add(1) == Some(expected_next)
                    && expected_next <= progress.expected_size,
                "OCI provider inventory chunk overlapped or left an offset gap"
            );
            sha_state.update(&chunk.bytes)?;
            progress.next_offset = expected_next;
            progress.set_sha_state(&sha_state)?;
            dispatch.record_chunk(chunk_len)?;
        }

        let Some(final_size) =
            before_dispatch_deadline(dispatch, fetch.inventory_size(&progress.object_key)).await?
        else {
            return Ok(InventoryObjectProgress::Continue(progress));
        };
        let Some(final_etag) =
            before_dispatch_deadline(dispatch, fetch.inventory_strong_etag(&progress.object_key))
                .await?
        else {
            return Ok(InventoryObjectProgress::Continue(progress));
        };
        anyhow::ensure!(
            final_size.and_then(|size| u64::try_from(size).ok()) == Some(progress.expected_size)
                && final_etag
                    .as_deref()
                    .map(crate::surface_write::strong_if_match_etag)
                    .transpose()?
                    .as_deref()
                    == Some(progress.strong_etag.as_str()),
            "OCI provider object identity changed after inventory hashing"
        );
        let observed_hash = sha_state.final_digest()?;
        anyhow::ensure!(
            sha_state.total_bytes == progress.expected_size && observed_hash == object_digest,
            "OCI provider object bytes do not match their canonical digest key"
        );
        Ok(InventoryObjectProgress::Complete(
            OciProviderInventoryEntryInput {
                object_key: progress.object_key,
                object_digest,
                observed_hash,
                byte_size: progress.expected_size,
                strong_etag: progress.strong_etag,
            },
        ))
    }
}

const INVENTORY_CONTINUATION_VERSION: u8 = 1;
const MAX_INVENTORY_CONTINUATION_BYTES: usize = 2_048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryContinuation {
    version: u8,
    generation_id: String,
    claim_token: String,
    placement_id: i64,
    object: Option<InventoryObjectContinuation>,
}

impl InventoryContinuation {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == INVENTORY_CONTINUATION_VERSION
                && self
                    .generation_id
                    .strip_prefix("ociinv-")
                    .is_some_and(|suffix| suffix.len() == 32 && is_lower_hex(suffix))
                && self.claim_token.len() == 64
                && is_lower_hex(&self.claim_token)
                && self.placement_id > 0,
            "OCI provider inventory continuation identity is invalid"
        );
        if let Some(object) = &self.object {
            object.validate()?;
            anyhow::ensure!(
                object.placement_id == self.placement_id,
                "OCI inventory continuation placement does not match its object"
            );
        }
        Ok(())
    }

    fn validate_for_generation(
        &self,
        generation: &OciProviderInventoryGenerationRecord,
    ) -> Result<()> {
        self.validate_identity_for_generation(generation)?;
        if let Some(object) = &self.object {
            object.validate_for(generation, generation.provider_cursor.as_deref())?;
        }
        Ok(())
    }

    fn validate_identity_for_generation(
        &self,
        generation: &OciProviderInventoryGenerationRecord,
    ) -> Result<()> {
        self.validate()?;
        anyhow::ensure!(
            self.generation_id == generation.id
                && self.claim_token == generation.collector_claim_token
                && self.placement_id == generation.placement_id,
            "OCI provider inventory continuation does not bind the active generation"
        );
        Ok(())
    }

    fn resumable_object_for_generation(
        &self,
        generation: &OciProviderInventoryGenerationRecord,
    ) -> Result<Option<InventoryObjectContinuation>> {
        self.validate_identity_for_generation(generation)?;
        let Some(object) = &self.object else {
            return Ok(None);
        };
        if object.checkpoint_ordinal < generation.checkpoint_ordinal {
            // A duplicate parent delivery may carry the prior partial-object
            // cursor after its child already committed that page. Durable DB
            // progress wins; the current provider page is reread from offset
            // zero instead of replaying stale hash state at the wrong key.
            return Ok(None);
        }
        object.validate_for(generation, generation.provider_cursor.as_deref())?;
        Ok(Some(object.clone()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryObjectContinuation {
    placement_id: i64,
    checkpoint_ordinal: u64,
    provider_cursor: Option<String>,
    object_key: String,
    object_digest: String,
    expected_size: u64,
    strong_etag: String,
    next_offset: u64,
    sha_version: u32,
    sha_words: [u32; 8],
    sha_total_bytes: u64,
    sha_tail_hex: String,
}

impl InventoryObjectContinuation {
    fn initial(
        placement_id: i64,
        checkpoint_ordinal: u64,
        provider_cursor: Option<String>,
        object_key: &str,
        object_digest: Sha256Digest,
        expected_size: u64,
        strong_etag: String,
    ) -> Result<Self> {
        let state = crate::db::OciSha256State::initial();
        let continuation = Self {
            placement_id,
            checkpoint_ordinal,
            provider_cursor,
            object_key: object_key.to_string(),
            object_digest: object_digest.to_string(),
            expected_size,
            strong_etag,
            next_offset: 0,
            sha_version: state.version,
            sha_words: state.words,
            sha_total_bytes: state.total_bytes,
            sha_tail_hex: state.tail_hex,
        };
        continuation.validate()?;
        Ok(continuation)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.placement_id > 0
                && self.object_key.len() <= 512
                && self.expected_size <= MAX_OCI_INVENTORY_OBJECT_BYTES
                && self.next_offset <= self.expected_size
                && self.sha_total_bytes == self.next_offset
                && self.strong_etag.len() <= 512
                && self.provider_cursor.as_ref().is_none_or(|cursor| {
                    !cursor.is_empty() && cursor.len() <= MAX_STORED_PROVIDER_CURSOR_BYTES
                }),
            "OCI inventory object continuation is invalid"
        );
        crate::surface_write::strong_if_match_etag(&self.strong_etag)?;
        let object_digest = Sha256Digest::parse(&self.object_digest)?;
        anyhow::ensure!(
            canonical_oci_blob_digest(&self.object_key)? == Some(object_digest),
            "OCI inventory continuation key and digest differ"
        );
        self.sha_state()?.validate()
    }

    fn validate_for(
        &self,
        generation: &OciProviderInventoryGenerationRecord,
        provider_cursor: Option<&str>,
    ) -> Result<()> {
        self.validate()?;
        anyhow::ensure!(
            self.placement_id == generation.placement_id
                && self.checkpoint_ordinal == generation.checkpoint_ordinal
                && self.provider_cursor.as_deref() == provider_cursor,
            "OCI inventory object continuation does not bind the durable checkpoint"
        );
        Ok(())
    }

    fn sha_state(&self) -> Result<crate::db::OciSha256State> {
        let state = crate::db::OciSha256State {
            version: self.sha_version,
            words: self.sha_words,
            total_bytes: self.sha_total_bytes,
            tail_hex: self.sha_tail_hex.clone(),
        };
        state.validate()?;
        Ok(state)
    }

    fn set_sha_state(&mut self, state: &crate::db::OciSha256State) -> Result<()> {
        state.validate()?;
        anyhow::ensure!(
            state.total_bytes == self.next_offset,
            "OCI inventory hash continuation offset differs from its byte count"
        );
        self.sha_version = state.version;
        self.sha_words = state.words;
        self.sha_total_bytes = state.total_bytes;
        self.sha_tail_hex.clone_from(&state.tail_hex);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InventoryGenerationProgress {
    Complete,
    Continue(Option<InventoryObjectContinuation>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InventoryEnumerationProgress {
    Complete(u64),
    Continue(Option<InventoryObjectContinuation>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InventoryObjectProgress {
    Complete(OciProviderInventoryEntryInput),
    Continue(InventoryObjectContinuation),
}

#[cfg(test)]
async fn enumerate_oci_inventory(
    fetch: &dyn SurfaceFetch,
) -> Result<Vec<OciProviderInventoryEntryInput>> {
    let page_limit = if cfg!(target_arch = "wasm32") {
        crate::fetch::WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS.min(OCI_GC_INVENTORY_BATCH_SIZE)
    } else {
        crate::fetch::MAX_SURFACE_LIST_PAGE_OBJECTS.min(OCI_GC_INVENTORY_BATCH_SIZE)
    };
    let page_bound = listing_page_bound(page_limit);
    let mut cursor = None;
    let mut pages = 0_usize;
    let mut budget = SurfaceListingBudget::default();
    // The retained vector and DB completion read are both capped at 2,000 OCI
    // entries / 1 MiB of keys, including on the Worker. Non-OCI placement keys
    // remain governed by the broader platform listing budget.
    let mut inventory_budget = SurfaceListingBudget::with_limits(
        OCI_GC_MAX_INVENTORY_OBJECTS,
        OCI_GC_MAX_INVENTORY_KEY_BYTES,
    );
    let mut prior_path: Option<String> = None;
    let mut entries = Vec::new();

    loop {
        pages += 1;
        anyhow::ensure!(
            pages <= page_bound,
            "OCI provider inventory exceeded page bound"
        );
        let page = fetch
            .list_page(OCI_BLOB_KEY_PREFIX, cursor.as_deref(), page_limit)
            .await?;
        page.validate(page_limit, OCI_BLOB_KEY_PREFIX, cursor.as_deref())?;
        for path in &page.paths {
            budget.record(path)?;
            anyhow::ensure!(
                prior_path.as_ref().is_none_or(|prior| prior < path),
                "OCI provider inventory pages are not globally ordered"
            );
            prior_path = Some(path.clone());
            let object_digest = canonical_oci_blob_digest(path)?
                .context("provider listing returned a key outside the OCI blob namespace")?;
            inventory_budget.record(path)?;
            entries.push(
                inventory_entry(fetch, path, object_digest, MAX_OCI_INVENTORY_OBJECT_BYTES).await?,
            );
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        cursor = Some(next);
    }
    Ok(entries)
}

fn listing_page_bound(page_limit: usize) -> usize {
    let (object_bound, path_byte_bound, maximum_key_bytes) = if cfg!(target_arch = "wasm32") {
        (
            WORKER_MAX_SURFACE_LIST_OBJECTS,
            WORKER_MAX_SURFACE_LIST_PATH_BYTES,
            WORKER_MAX_SURFACE_LIST_CURSOR_BYTES,
        )
    } else {
        (
            MAX_SURFACE_LIST_OBJECTS,
            MAX_SURFACE_LIST_PATH_BYTES,
            MAX_SURFACE_LIST_CURSOR_BYTES,
        )
    };
    // Checkpoint ordinal survives crashes, unlike an in-memory listing budget.
    // Derive a conservative page ceiling from worst-case full pages/keys so a
    // resumed walk cannot exceed either aggregate platform bound. The old
    // per-call page limit is deliberately absent: a generation may span many
    // small queue dispatches, while every dispatch has its own stricter page
    // ceiling.
    let object_page_bound = object_bound / page_limit;
    let path_page_bound = path_byte_bound / page_limit.saturating_mul(maximum_key_bytes);
    object_page_bound.min(path_page_bound).max(1)
}

#[cfg(test)]
async fn inventory_entry(
    fetch: &dyn SurfaceFetch,
    path: &str,
    object_digest: Sha256Digest,
    remaining_dispatch_bytes: u64,
) -> Result<OciProviderInventoryEntryInput> {
    let maximum_bytes = MAX_OCI_INVENTORY_OBJECT_BYTES.min(remaining_dispatch_bytes);
    let evidence = fetch
        .inventory_evidence_bounded(path, maximum_bytes)
        .await?
        .context("listed OCI provider object disappeared during inventory")?;
    let observed_hash = Sha256Digest::from_bytes(evidence.sha256);
    anyhow::ensure!(
        observed_hash == object_digest,
        "OCI provider object bytes do not match their canonical digest key"
    );
    let strong_etag = evidence
        .strong_etag
        .context("OCI provider object has no strong ETag")?;
    crate::surface_write::strong_if_match_etag(&strong_etag)?;
    Ok(OciProviderInventoryEntryInput {
        object_key: path.to_string(),
        object_digest,
        observed_hash,
        byte_size: u64::try_from(evidence.size).context("OCI provider object size is negative")?,
        strong_etag,
    })
}

fn inventory_now(floor: i64) -> i64 {
    crate::clock::now_unix_secs().max(floor)
}

async fn before_dispatch_deadline<T, F>(
    dispatch: &InventoryDispatchTracker,
    future: F,
) -> Result<Option<T>>
where
    F: Future<Output = Result<T>>,
{
    let Some(remaining) = dispatch.remaining_duration() else {
        return Ok(None);
    };
    let operation = Box::pin(future);
    let timeout = Box::pin(crate::clock::sleep(remaining));
    match futures_util::future::select(operation, timeout).await {
        futures_util::future::Either::Left((result, _)) => result.map(Some),
        futures_util::future::Either::Right(((), _)) => Ok(None),
    }
}

/// Tags a raw provider cursor for durable storage.
///
/// See [`INVENTORY_CURSOR_SCOPE_TAG`]; the tagged form is what the generation
/// checkpoint and the object continuation carry.
fn tag_provider_cursor(provider_cursor: &str) -> Result<String> {
    anyhow::ensure!(
        !provider_cursor.is_empty(),
        "provider listing returned an empty continuation cursor"
    );
    let tagged = format!("{INVENTORY_CURSOR_SCOPE_TAG}{provider_cursor}");
    anyhow::ensure!(
        tagged.len() <= MAX_STORED_PROVIDER_CURSOR_BYTES,
        "provider listing cursor exceeds the durable inventory cursor bound"
    );
    Ok(tagged)
}

/// Recovers the raw provider cursor from a stored (tagged) checkpoint cursor.
///
/// A stored cursor without the scope tag was produced by an unscoped
/// placement walk and cannot resume a blob-scoped listing.
fn provider_cursor_for_listing(stored: Option<&str>) -> Result<Option<&str>> {
    let Some(stored) = stored else {
        return Ok(None);
    };
    let provider_cursor = stored.strip_prefix(INVENTORY_CURSOR_SCOPE_TAG).context(
        "inventory generation predates blob-scoped listing; a fresh generation will be collected",
    )?;
    anyhow::ensure!(
        !provider_cursor.is_empty(),
        "stored OCI provider inventory cursor is empty"
    );
    Ok(Some(provider_cursor))
}

fn canonical_oci_blob_digest(path: &str) -> Result<Option<Sha256Digest>> {
    let Some(encoded) = path.strip_prefix(OCI_BLOB_KEY_PREFIX) else {
        return Ok(None);
    };
    anyhow::ensure!(
        encoded.len() == 64
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "provider contains a noncanonical key in the OCI blob namespace"
    );
    Ok(Some(Sha256Digest::parse(&format!("sha256:{encoded}"))?))
}

fn inventory_idempotency_key(
    seed: &str,
    registry_id: i64,
    placement_id: i64,
    placement_resource_version: i64,
    observation_version: i64,
) -> String {
    hex::encode(sha2::Sha256::digest(
        format!(
            "aos-oci-provider-inventory-v1\0{seed}\0{registry_id}\0{placement_id}\0{placement_resource_version}\0{observation_version}"
        )
        .as_bytes(),
    ))
}

fn inventory_claim_token(seed: &str, placement_id: i64) -> String {
    hex::encode(sha2::Sha256::digest(
        format!("aos-oci-provider-inventory-claim-v1\0{seed}\0{placement_id}").as_bytes(),
    ))
}

fn inventory_continuation(
    generation: &OciProviderInventoryGenerationRecord,
    object: Option<InventoryObjectContinuation>,
) -> Result<String> {
    let continuation = InventoryContinuation {
        version: INVENTORY_CONTINUATION_VERSION,
        generation_id: generation.id.clone(),
        claim_token: generation.collector_claim_token.clone(),
        placement_id: generation.placement_id,
        object,
    };
    continuation.validate_for_generation(generation)?;
    let encoded = serde_json::to_string(&continuation)?;
    anyhow::ensure!(
        encoded.len() <= MAX_INVENTORY_CONTINUATION_BYTES,
        "OCI provider inventory continuation exceeds the queue cursor bound"
    );
    Ok(encoded)
}

fn parse_inventory_continuation(cursor: &str) -> Result<InventoryContinuation> {
    anyhow::ensure!(
        !cursor.is_empty() && cursor.len() <= MAX_INVENTORY_CONTINUATION_BYTES,
        "OCI provider inventory continuation length is invalid"
    );
    let continuation: InventoryContinuation = serde_json::from_str(cursor)
        .context("OCI provider inventory continuation is not canonical JSON")?;
    continuation.validate()?;
    anyhow::ensure!(
        serde_json::to_string(&continuation)? == cursor,
        "OCI provider inventory continuation encoding is not canonical"
    );
    Ok(continuation)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aos_oci_types::RepositoryName;
    use async_trait::async_trait;
    use sha2::Sha256;

    use super::*;
    use crate::db::{
        NewBindingWriteRevision, NewSurfacePlacementSpec, SurfacePlacementRecord, SurfaceTarget,
    };
    use crate::fetch::{SurfaceInventoryChunk, SurfaceListPage, SurfaceObjectEvidence};

    struct MemoryInventory {
        pages: Vec<SurfaceListPage>,
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl SurfaceFetch for MemoryInventory {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.objects.lock().unwrap().get(path).cloned())
        }

        async fn size(&self, path: &str) -> Result<Option<u64>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(path)
                .map(|bytes| bytes.len() as u64))
        }

        async fn list_page(
            &self,
            _prefix: &str,
            cursor: Option<&str>,
            _limit: usize,
        ) -> Result<crate::fetch::SurfaceListPage> {
            let index = cursor.map_or(0, |cursor| cursor.parse().unwrap());
            Ok(self.pages[index].clone())
        }

        async fn inventory_evidence_bounded(
            &self,
            path: &str,
            _maximum_bytes: u64,
        ) -> Result<Option<SurfaceObjectEvidence>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(path)
                .map(|bytes| SurfaceObjectEvidence {
                    sha256: Sha256::digest(bytes).into(),
                    size: bytes.len() as i64,
                    strong_etag: Some(format!("\"{}\"", hex::encode(Sha256::digest(bytes)))),
                }))
        }

        fn describe(&self) -> String {
            "memory inventory".into()
        }
    }

    /// Provider double for the controller.
    ///
    /// With scripted `pages`, a cursor is the index of the next page. With no
    /// scripted pages, the double lists `objects` itself: keys under the
    /// requested prefix, after the cursor (the last key of the prior page),
    /// `limit` at a time, like a real bucket.
    #[derive(Clone)]
    struct SharedInventoryFetch {
        pages: Arc<Vec<SurfaceListPage>>,
        objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        requested_prefixes: Arc<Mutex<Vec<String>>>,
        requested_cursors: Arc<Mutex<Vec<Option<String>>>>,
        requested_ranges: Arc<Mutex<Vec<(u64, u64)>>>,
        evidence_delay_ms: Arc<AtomicU64>,
        evidence_calls: Arc<AtomicUsize>,
        evidence_started: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl SurfaceFetch for SharedInventoryFetch {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.objects.lock().unwrap().get(path).cloned())
        }

        async fn size(&self, path: &str) -> Result<Option<u64>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(path)
                .map(|bytes| bytes.len() as u64))
        }

        async fn list_page(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            limit: usize,
        ) -> Result<SurfaceListPage> {
            self.requested_prefixes
                .lock()
                .unwrap()
                .push(prefix.to_string());
            self.requested_cursors
                .lock()
                .unwrap()
                .push(cursor.map(str::to_string));
            if !self.pages.is_empty() {
                let index = cursor.map_or(0, |value| value.parse().unwrap());
                return Ok(self.pages[index].clone());
            }
            let mut paths = self
                .objects
                .lock()
                .unwrap()
                .keys()
                .filter(|key| {
                    key.starts_with(prefix) && cursor.is_none_or(|after| after < key.as_str())
                })
                .cloned()
                .collect::<Vec<_>>();
            let next_cursor = (paths.len() > limit).then(|| {
                paths.truncate(limit);
                paths.last().cloned().unwrap()
            });
            Ok(SurfaceListPage {
                paths,
                evidence: BTreeMap::new(),
                next_cursor,
            })
        }

        async fn inventory_evidence_bounded(
            &self,
            path: &str,
            _maximum_bytes: u64,
        ) -> Result<Option<SurfaceObjectEvidence>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(path)
                .map(|bytes| SurfaceObjectEvidence {
                    sha256: Sha256::digest(bytes).into(),
                    size: bytes.len() as i64,
                    strong_etag: Some(format!("\"{}\"", hex::encode(Sha256::digest(bytes)))),
                }))
        }

        async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(path)
                .map(|bytes| format!("\"{}\"", hex::encode(Sha256::digest(bytes)))))
        }

        async fn inventory_size(&self, path: &str) -> Result<Option<i64>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(path)
                .map(|bytes| bytes.len() as i64))
        }

        async fn inventory_chunk_bounded(
            &self,
            path: &str,
            offset: u64,
            expected_total: u64,
            maximum_bytes: u64,
        ) -> Result<Option<SurfaceInventoryChunk>> {
            self.evidence_calls.fetch_add(1, Ordering::SeqCst);
            self.evidence_started.notify_one();
            let delay_ms = self.evidence_delay_ms.load(Ordering::SeqCst);
            if delay_ms > 0 {
                crate::clock::sleep(Duration::from_millis(delay_ms)).await;
            }
            let objects = self.objects.lock().unwrap();
            let Some(bytes) = objects.get(path) else {
                return Ok(None);
            };
            anyhow::ensure!(bytes.len() as u64 == expected_total && maximum_bytes > 0);
            let end = offset
                .saturating_add(maximum_bytes)
                .min(expected_total)
                .saturating_sub(1);
            self.requested_ranges.lock().unwrap().push((offset, end));
            Ok(Some(SurfaceInventoryChunk {
                bytes: bytes[offset as usize..=end as usize].to_vec(),
                total: expected_total,
                range: (offset, end),
                strong_etag: format!("\"{}\"", hex::encode(Sha256::digest(bytes))),
            }))
        }

        fn describe(&self) -> String {
            "shared inventory".into()
        }
    }

    struct SharedInventoryProvider {
        fetch: SharedInventoryFetch,
        opened: AtomicUsize,
    }

    #[async_trait]
    impl SurfaceProvider for SharedInventoryProvider {
        async fn placement_fetcher(
            &self,
            _placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceFetch>> {
            self.opened.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(self.fetch.clone()))
        }
    }

    async fn inventory_fixture(
        pages: Vec<SurfaceListPage>,
        objects: BTreeMap<String, Vec<u8>>,
    ) -> (
        Arc<Database>,
        i64,
        SurfacePlacementRecord,
        Arc<SharedInventoryProvider>,
    ) {
        let db = Arc::new(Database::open_in_memory().await.unwrap());
        let org_id = db
            .create_org("inventory-controller", "Inventory Controller")
            .await
            .unwrap();
        let registry_id = db
            .create_managed_registry(org_id, "", "containers", "public", &[], false)
            .await
            .unwrap();
        db.ensure_oci_repository(
            registry_id,
            &RepositoryName::parse("seed").unwrap(),
            crate::clock::now_unix_secs(),
        )
        .await
        .unwrap();
        let owner = db.org_by_id(org_id).await.unwrap().unwrap();
        let binding_id = db
            .create_topology_binding(
                Some(org_id),
                "inventory-controller-binding",
                &owner.stable_id,
                "inventory-controller",
                "s3",
                None,
                Some("inventory-controller"),
                Some("registry"),
                Some("https"),
                Some("dns"),
                Some(b"storage.example.invalid"),
                Some(443),
                Some("auto"),
                Some("private"),
            )
            .await
            .unwrap();
        let placement = db
            .create_surface_placement(&NewSurfacePlacementSpec {
                surface: SurfaceTarget::Registry(registry_id),
                name: "primary".into(),
                binding_id,
                prefix: "registry".into(),
                kind: "complete".into(),
                desired_state: "active".into(),
                hash_range: None,
                desired_read_enabled: true,
                read_order: 0,
                requires_conditional_writes: false,
            })
            .await
            .unwrap();
        db.observe_surface_placement(placement.id, "ready", "complete", 1)
            .await
            .unwrap();
        let credential = db
            .set_binding_credential_revision(
                binding_id,
                "write",
                "secret://test/inventory-controller-write/v1",
                0,
                &"0".repeat(64),
                "test",
            )
            .await
            .unwrap();
        db.validate_binding_credential_revision(
            binding_id,
            "write",
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await
        .unwrap();
        let revision = db
            .create_binding_write_revision(&NewBindingWriteRevision {
                binding_id,
                write_credential_generation: credential.generation,
                writes_supported: true,
                conditional_writes_supported: true,
                revision_fingerprint: "inventory-controller-revision".into(),
                capability_fingerprint: "inventory-controller-capability".into(),
            })
            .await
            .unwrap();
        db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
            .await
            .unwrap();
        let state = db.binding_write_state(binding_id).await.unwrap().unwrap();
        db.set_current_binding_write_revision(
            binding_id,
            revision.revision,
            state.resource_version,
        )
        .await
        .unwrap();
        db.bind_surface_placement_write_capability(placement.id, revision.revision)
            .await
            .unwrap();
        let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
        let provider = Arc::new(SharedInventoryProvider {
            fetch: SharedInventoryFetch {
                pages: Arc::new(pages),
                objects: Arc::new(Mutex::new(objects)),
                requested_prefixes: Arc::new(Mutex::new(Vec::new())),
                requested_cursors: Arc::new(Mutex::new(Vec::new())),
                requested_ranges: Arc::new(Mutex::new(Vec::new())),
                evidence_delay_ms: Arc::new(AtomicU64::new(0)),
                evidence_calls: Arc::new(AtomicUsize::new(0)),
                evidence_started: Arc::new(tokio::sync::Notify::new()),
            },
            opened: AtomicUsize::new(0),
        });
        (db, registry_id, placement, provider)
    }

    fn provider_with_blob(bytes: &[u8]) -> (MemoryInventory, String) {
        let digest = hex::encode(Sha256::digest(bytes));
        let key = format!("oci/blobs/sha256/{digest}");
        let pages = vec![SurfaceListPage {
            paths: vec![key.clone()],
            evidence: BTreeMap::new(),
            next_cursor: None,
        }];
        let objects = Mutex::new(BTreeMap::from([(key.clone(), bytes.to_vec())]));
        (MemoryInventory { pages, objects }, key)
    }

    #[tokio::test]
    async fn enumeration_includes_canonical_bytes_without_catalog_inference() {
        let (provider, key) = provider_with_blob(b"untracked provider bytes");
        let entries = enumerate_oci_inventory(&provider).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].object_key, key);
        assert_eq!(entries[0].object_digest, entries[0].observed_hash);
    }

    #[tokio::test]
    async fn enumeration_rejects_noncanonical_oci_namespace_keys() {
        let provider = MemoryInventory {
            pages: vec![SurfaceListPage {
                paths: vec!["oci/blobs/sha256/ABC".into()],
                evidence: BTreeMap::new(),
                next_cursor: None,
            }],
            objects: Mutex::new(BTreeMap::new()),
        };
        assert!(enumerate_oci_inventory(&provider).await.is_err());
    }

    #[tokio::test]
    async fn enumeration_rejects_object_mutation_or_wrong_key_digest() {
        let (mut provider, key) = provider_with_blob(b"bytes");
        provider
            .objects
            .get_mut()
            .unwrap()
            .insert(key, b"replacement".to_vec());
        assert!(enumerate_oci_inventory(&provider).await.is_err());
    }

    #[tokio::test]
    async fn enumeration_rejects_reordered_pages() {
        // Two valid blobs whose pages arrive in descending key order.
        let (pages, objects) = two_page_inventory();
        let provider = MemoryInventory {
            pages: vec![
                SurfaceListPage {
                    paths: pages[1].paths.clone(),
                    evidence: BTreeMap::new(),
                    next_cursor: Some("1".into()),
                },
                SurfaceListPage {
                    paths: pages[0].paths.clone(),
                    evidence: BTreeMap::new(),
                    next_cursor: None,
                },
            ],
            objects: Mutex::new(objects),
        };
        assert!(enumerate_oci_inventory(&provider).await.is_err());
    }

    #[tokio::test]
    async fn enumeration_rejects_keys_outside_the_blob_namespace() {
        let (provider, key) = provider_with_blob(b"scoped bytes");
        let page = SurfaceListPage {
            paths: vec!["nar/aaaa.nar.zst".into(), key],
            evidence: BTreeMap::new(),
            next_cursor: None,
        };
        let provider = MemoryInventory {
            pages: vec![page],
            objects: provider.objects,
        };
        assert!(enumerate_oci_inventory(&provider).await.is_err());
    }

    #[tokio::test]
    async fn current_head_skips_provider_reads_and_epoch_or_topology_drift_is_due() {
        let bytes = b"untracked bytes".to_vec();
        let digest = hex::encode(Sha256::digest(&bytes));
        let key = format!("oci/blobs/sha256/{digest}");
        let pages = vec![SurfaceListPage {
            paths: vec![key.clone()],
            evidence: BTreeMap::new(),
            next_cursor: None,
        }];
        let (db, registry_id, placement, provider) =
            inventory_fixture(pages, BTreeMap::from([(key, bytes)])).await;
        let controller = OciProviderInventoryController::new(db.clone(), provider.clone());
        let now = crate::clock::now_unix_secs();

        let first = controller
            .run_due("worker", "first", now, 10)
            .await
            .unwrap();
        assert_eq!(first.attempted, 1);
        assert_eq!(first.completed, 1);
        let opens = provider.opened.load(Ordering::SeqCst);
        let reads = provider.fetch.requested_cursors.lock().unwrap().len();

        let current = controller
            .run_due("worker", "current", now + 1, 10)
            .await
            .unwrap();
        assert_eq!(current.attempted, 0);
        assert_eq!(provider.opened.load(Ordering::SeqCst), opens);
        assert_eq!(
            provider.fetch.requested_cursors.lock().unwrap().len(),
            reads
        );

        db.ensure_oci_repository(
            registry_id,
            &RepositoryName::parse("changed").unwrap(),
            now + 2,
        )
        .await
        .unwrap();
        let epoch_drift = controller
            .run_due("worker", "epoch", now + 2, 10)
            .await
            .unwrap();
        assert_eq!(epoch_drift.attempted, 1);
        assert_eq!(epoch_drift.completed, 1);

        db.observe_surface_placement(placement.id, "ready", "complete", 2)
            .await
            .unwrap();
        let topology_drift = controller
            .run_due("worker", "topology", now + 3, 10)
            .await
            .unwrap();
        assert_eq!(topology_drift.attempted, 1);
        assert_eq!(topology_drift.completed, 1);
    }

    fn test_dispatch_budget(
        max_pages: usize,
        max_objects: usize,
        max_bytes: u64,
        max_duration: Duration,
    ) -> OciInventoryDispatchBudget {
        OciInventoryDispatchBudget {
            max_pages,
            max_objects,
            max_chunks: max_objects,
            max_chunk_bytes: max_bytes,
            max_bytes,
            max_duration,
        }
    }

    #[test]
    fn native_and_worker_use_the_same_strict_dispatch_contract() {
        NATIVE_OCI_INVENTORY_DISPATCH_BUDGET.validate().unwrap();
        WORKER_OCI_INVENTORY_DISPATCH_BUDGET.validate().unwrap();
        assert!(
            WORKER_OCI_INVENTORY_DISPATCH_BUDGET.max_pages
                <= NATIVE_OCI_INVENTORY_DISPATCH_BUDGET.max_pages
        );
        assert!(
            WORKER_OCI_INVENTORY_DISPATCH_BUDGET.max_bytes
                <= NATIVE_OCI_INVENTORY_DISPATCH_BUDGET.max_bytes
        );
        assert!(
            WORKER_OCI_INVENTORY_DISPATCH_BUDGET.max_duration
                <= NATIVE_OCI_INVENTORY_DISPATCH_BUDGET.max_duration
        );
    }

    fn two_page_inventory() -> (Vec<SurfaceListPage>, BTreeMap<String, Vec<u8>>) {
        let mut blobs = [
            b"first bounded page".to_vec(),
            b"second bounded page".to_vec(),
        ]
        .into_iter()
        .map(|bytes| {
            let digest = hex::encode(Sha256::digest(&bytes));
            (format!("oci/blobs/sha256/{digest}"), bytes)
        })
        .collect::<Vec<_>>();
        blobs.sort_by(|left, right| left.0.cmp(&right.0));
        (
            vec![
                SurfaceListPage {
                    paths: vec![blobs[0].0.clone()],
                    evidence: BTreeMap::new(),
                    next_cursor: Some("1".into()),
                },
                SurfaceListPage {
                    paths: vec![blobs[1].0.clone()],
                    evidence: BTreeMap::new(),
                    next_cursor: None,
                },
            ],
            BTreeMap::from([blobs[0].clone(), blobs[1].clone()]),
        )
    }

    #[tokio::test]
    async fn page_budget_checkpoints_and_continues_the_exact_generation() {
        let (pages, objects) = two_page_inventory();
        let (db, _registry_id, placement, provider) = inventory_fixture(pages, objects).await;
        let controller = OciProviderInventoryController::new(db.clone(), provider.clone());
        let now = crate::clock::now_unix_secs();
        let budget =
            test_dispatch_budget(1, 1, MAX_OCI_INVENTORY_OBJECT_BYTES, Duration::from_secs(5));

        let first = controller
            .run_due_bounded("worker", "bounded", now, 1, None, budget)
            .await
            .unwrap();
        assert_eq!((first.attempted, first.completed, first.failed), (1, 0, 0));
        let continuation = first.continuation.unwrap();
        let active = db
            .active_oci_provider_inventory(placement.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.checkpoint_ordinal, 1);
        assert_eq!(active.provider_cursor.as_deref(), Some("oci-blobs-v1:1"));

        let second = controller
            .run_due_bounded(
                "worker",
                "ignored-on-continuation",
                now + 1,
                1,
                Some(&continuation),
                budget,
            )
            .await
            .unwrap();
        assert_eq!((second.attempted, second.completed), (1, 1));
        assert!(second.continuation.is_none());
        assert_eq!(
            *provider.fetch.requested_cursors.lock().unwrap(),
            vec![None, Some("1".into())]
        );
    }

    #[tokio::test]
    async fn byte_budget_carries_partial_hash_state_to_the_next_dispatch() {
        let bytes = [b"12345678".to_vec(), b"abcdefgh".to_vec()];
        let mut blobs = bytes
            .into_iter()
            .map(|bytes| {
                let digest = hex::encode(Sha256::digest(&bytes));
                (format!("oci/blobs/sha256/{digest}"), bytes)
            })
            .collect::<Vec<_>>();
        blobs.sort_by(|left, right| left.0.cmp(&right.0));
        let pages = vec![
            SurfaceListPage {
                paths: vec![blobs[0].0.clone()],
                evidence: BTreeMap::new(),
                next_cursor: Some("1".into()),
            },
            SurfaceListPage {
                paths: vec![blobs[1].0.clone()],
                evidence: BTreeMap::new(),
                next_cursor: None,
            },
        ];
        let (db, _registry_id, _placement, provider) =
            inventory_fixture(pages, BTreeMap::from([blobs[0].clone(), blobs[1].clone()])).await;
        let controller = OciProviderInventoryController::new(db, provider.clone());
        let now = crate::clock::now_unix_secs();
        let budget = test_dispatch_budget(2, 2, 10, Duration::from_secs(5));

        let first = controller
            .run_due_bounded("worker", "bytes", now, 1, None, budget)
            .await
            .unwrap();
        let continuation = first.continuation.unwrap();
        assert_eq!(first.completed, 0);
        let decoded = parse_inventory_continuation(&continuation).unwrap();
        assert_eq!(decoded.object.as_ref().unwrap().next_offset, 2);
        assert!(continuation.len() <= MAX_INVENTORY_CONTINUATION_BYTES);
        let second = controller
            .run_due_bounded(
                "worker",
                "ignored-on-continuation",
                now + 1,
                1,
                Some(&continuation),
                budget,
            )
            .await
            .unwrap();
        assert_eq!(second.completed, 1);
        assert_eq!(
            *provider.fetch.requested_ranges.lock().unwrap(),
            vec![(0, 7), (0, 1), (2, 7)]
        );
        assert_eq!(
            *provider.fetch.requested_cursors.lock().unwrap(),
            vec![None, Some("1".into()), Some("1".into())]
        );
    }

    #[tokio::test]
    async fn duplicate_parent_cursor_resumes_from_newer_durable_page_checkpoint() {
        let bytes = [b"12345678".to_vec(), b"abcdefgh".to_vec()];
        let mut blobs = bytes
            .into_iter()
            .map(|bytes| {
                let digest = hex::encode(Sha256::digest(&bytes));
                (format!("oci/blobs/sha256/{digest}"), bytes)
            })
            .collect::<Vec<_>>();
        blobs.sort_by(|left, right| left.0.cmp(&right.0));
        let pages = vec![
            SurfaceListPage {
                paths: vec![blobs[0].0.clone()],
                evidence: BTreeMap::new(),
                next_cursor: Some("1".into()),
            },
            SurfaceListPage {
                paths: vec![blobs[1].0.clone()],
                evidence: BTreeMap::new(),
                next_cursor: None,
            },
        ];
        let (db, _registry_id, _placement, provider) =
            inventory_fixture(pages, BTreeMap::from([blobs[0].clone(), blobs[1].clone()])).await;
        let controller = OciProviderInventoryController::new(db, provider.clone());
        let now = crate::clock::now_unix_secs();

        let first = controller
            .run_due_bounded(
                "worker",
                "duplicate-parent",
                now,
                1,
                None,
                test_dispatch_budget(2, 2, 2, Duration::from_secs(5)),
            )
            .await
            .unwrap();
        let stale_parent_cursor = first.continuation.unwrap();
        let stale = parse_inventory_continuation(&stale_parent_cursor).unwrap();
        assert_eq!(stale.object.as_ref().unwrap().checkpoint_ordinal, 0);

        let advanced = controller
            .run_due_bounded(
                "worker",
                "ignored",
                now + 1,
                1,
                Some(&stale_parent_cursor),
                test_dispatch_budget(2, 2, 8, Duration::from_secs(5)),
            )
            .await
            .unwrap();
        let advanced_cursor = advanced.continuation.unwrap();
        let advanced = parse_inventory_continuation(&advanced_cursor).unwrap();
        assert_eq!(advanced.object.as_ref().unwrap().checkpoint_ordinal, 1);

        // A retry of the parent delivery carries the older object cursor. The
        // DB checkpoint is authoritative, so the current second page is
        // rehashed from offset zero and the stale first-page SHA state is not
        // applied at the new provider key.
        let replay = controller
            .run_due_bounded(
                "worker",
                "ignored",
                now + 2,
                1,
                Some(&stale_parent_cursor),
                test_dispatch_budget(2, 2, 8, Duration::from_secs(5)),
            )
            .await
            .unwrap();
        assert_eq!(replay.completed, 1);
        assert!(replay.continuation.is_none());
        assert_eq!(
            *provider.fetch.requested_ranges.lock().unwrap(),
            vec![(0, 1), (2, 7), (0, 1), (0, 7)]
        );
    }

    #[tokio::test]
    async fn large_object_hash_resumes_across_multiple_bounded_dispatches() {
        let bytes = b"three-eight-byte-segments".to_vec();
        assert_eq!(bytes.len(), 25);
        let digest = hex::encode(Sha256::digest(&bytes));
        let key = format!("oci/blobs/sha256/{digest}");
        let pages = vec![SurfaceListPage {
            paths: vec![key.clone()],
            evidence: BTreeMap::new(),
            next_cursor: None,
        }];
        let (db, _registry_id, _placement, provider) =
            inventory_fixture(pages, BTreeMap::from([(key, bytes)])).await;
        let controller = OciProviderInventoryController::new(db, provider.clone());
        let budget = test_dispatch_budget(1, 1, 8, Duration::from_secs(5));
        let now = crate::clock::now_unix_secs();

        let first = controller
            .run_due_bounded("worker", "large", now, 1, None, budget)
            .await
            .unwrap();
        let first_cursor = first.continuation.unwrap();
        assert_eq!(
            parse_inventory_continuation(&first_cursor)
                .unwrap()
                .object
                .unwrap()
                .next_offset,
            8
        );
        let second = controller
            .run_due_bounded("worker", "ignored", now + 1, 1, Some(&first_cursor), budget)
            .await
            .unwrap();
        let second_cursor = second.continuation.unwrap();
        assert_eq!(
            parse_inventory_continuation(&second_cursor)
                .unwrap()
                .object
                .unwrap()
                .next_offset,
            16
        );
        let third = controller
            .run_due_bounded(
                "worker",
                "ignored",
                now + 2,
                1,
                Some(&second_cursor),
                budget,
            )
            .await
            .unwrap();
        let third_cursor = third.continuation.unwrap();
        assert_eq!(
            parse_inventory_continuation(&third_cursor)
                .unwrap()
                .object
                .unwrap()
                .next_offset,
            24
        );
        let final_pass = controller
            .run_due_bounded("worker", "ignored", now + 3, 1, Some(&third_cursor), budget)
            .await
            .unwrap();
        assert_eq!(final_pass.completed, 1);
        assert!(final_pass.continuation.is_none());
        assert_eq!(
            *provider.fetch.requested_ranges.lock().unwrap(),
            vec![(0, 7), (8, 15), (16, 23), (24, 24)]
        );
    }

    #[tokio::test]
    async fn continuation_rejects_offset_tamper_before_provider_io() {
        let bytes = b"tamper-resistant-object".to_vec();
        let digest = hex::encode(Sha256::digest(&bytes));
        let key = format!("oci/blobs/sha256/{digest}");
        let pages = vec![SurfaceListPage {
            paths: vec![key.clone()],
            evidence: BTreeMap::new(),
            next_cursor: None,
        }];
        let (db, _registry_id, _placement, provider) =
            inventory_fixture(pages, BTreeMap::from([(key, bytes)])).await;
        let controller = OciProviderInventoryController::new(db, provider.clone());
        let budget = test_dispatch_budget(1, 1, 8, Duration::from_secs(5));
        let now = crate::clock::now_unix_secs();
        let first = controller
            .run_due_bounded("worker", "tamper", now, 1, None, budget)
            .await
            .unwrap();
        let mut decoded = parse_inventory_continuation(&first.continuation.unwrap()).unwrap();
        decoded.object.as_mut().unwrap().next_offset += 1;
        let tampered = serde_json::to_string(&decoded).unwrap();
        let ranges_before = provider.fetch.requested_ranges.lock().unwrap().clone();

        assert!(controller
            .run_due_bounded("worker", "ignored", now + 1, 1, Some(&tampered), budget,)
            .await
            .is_err());
        assert_eq!(
            *provider.fetch.requested_ranges.lock().unwrap(),
            ranges_before
        );
    }

    #[tokio::test]
    async fn supplied_hash_state_cannot_bypass_terminal_digest_equality() {
        let bytes = b"hash-state-terminal-proof".to_vec();
        let digest = hex::encode(Sha256::digest(&bytes));
        let key = format!("oci/blobs/sha256/{digest}");
        let pages = vec![SurfaceListPage {
            paths: vec![key.clone()],
            evidence: BTreeMap::new(),
            next_cursor: None,
        }];
        let (db, _registry_id, placement, provider) =
            inventory_fixture(pages, BTreeMap::from([(key, bytes)])).await;
        let controller = OciProviderInventoryController::new(db.clone(), provider);
        let first_budget = test_dispatch_budget(1, 1, 8, Duration::from_secs(5));
        let now = crate::clock::now_unix_secs();
        let first = controller
            .run_due_bounded("worker", "hash-tamper", now, 1, None, first_budget)
            .await
            .unwrap();
        let mut decoded = parse_inventory_continuation(&first.continuation.unwrap()).unwrap();
        decoded.object.as_mut().unwrap().sha_words[0] ^= 1;
        let generation_id = decoded.generation_id.clone();
        let tampered = serde_json::to_string(&decoded).unwrap();

        let resumed = controller
            .run_due_bounded(
                "worker",
                "ignored",
                now + 1,
                1,
                Some(&tampered),
                test_dispatch_budget(1, 1, 1024, Duration::from_secs(5)),
            )
            .await
            .unwrap();
        assert_eq!((resumed.completed, resumed.failed), (0, 1));
        assert!(resumed.continuation.is_none());
        assert_eq!(
            db.oci_provider_inventory_generation(&generation_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "failed"
        );
        assert_eq!(
            db.active_oci_provider_inventory(placement.id)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn object_mutation_between_chunks_fails_before_reading_the_new_bytes() {
        let bytes = b"mutation-between-ranges".to_vec();
        let digest = hex::encode(Sha256::digest(&bytes));
        let key = format!("oci/blobs/sha256/{digest}");
        let pages = vec![SurfaceListPage {
            paths: vec![key.clone()],
            evidence: BTreeMap::new(),
            next_cursor: None,
        }];
        let (db, _registry_id, placement, provider) =
            inventory_fixture(pages, BTreeMap::from([(key.clone(), bytes.clone())])).await;
        let controller = OciProviderInventoryController::new(db.clone(), provider.clone());
        let budget = test_dispatch_budget(1, 1, 8, Duration::from_secs(5));
        let now = crate::clock::now_unix_secs();
        let first = controller
            .run_due_bounded("worker", "mutation", now, 1, None, budget)
            .await
            .unwrap();
        let continuation = first.continuation.unwrap();
        provider
            .fetch
            .objects
            .lock()
            .unwrap()
            .insert(key, vec![b'x'; bytes.len()]);

        let resumed = controller
            .run_due_bounded("worker", "ignored", now + 1, 1, Some(&continuation), budget)
            .await
            .unwrap();
        assert_eq!((resumed.completed, resumed.failed), (0, 1));
        assert_eq!(
            *provider.fetch.requested_ranges.lock().unwrap(),
            vec![(0, 7)]
        );
        assert!(db
            .active_oci_provider_inventory(placement.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn expired_range_owner_is_taken_over_and_rehashes_from_zero() {
        let bytes = b"takeover-restarts-exact-bytes".to_vec();
        let digest = hex::encode(Sha256::digest(&bytes));
        let key = format!("oci/blobs/sha256/{digest}");
        let pages = vec![SurfaceListPage {
            paths: vec![key.clone()],
            evidence: BTreeMap::new(),
            next_cursor: None,
        }];
        let (db, _registry_id, _placement, provider) =
            inventory_fixture(pages, BTreeMap::from([(key, bytes.clone())])).await;
        let controller = OciProviderInventoryController::new(db, provider.clone());
        let now = crate::clock::now_unix_secs();
        let first = controller
            .run_due_bounded(
                "worker-a",
                "takeover-a",
                now,
                1,
                None,
                test_dispatch_budget(1, 1, 8, Duration::from_secs(5)),
            )
            .await
            .unwrap();
        let stale_cursor = first.continuation.unwrap();

        let takeover = controller
            .run_due(
                "worker-b",
                "takeover-b",
                now + INVENTORY_CLAIM_LEASE_SECONDS + 1,
                1,
            )
            .await
            .unwrap();
        assert_eq!((takeover.attempted, takeover.completed), (1, 1));
        assert_eq!(
            *provider.fetch.requested_ranges.lock().unwrap(),
            vec![(0, 7), (0, bytes.len() as u64 - 1)]
        );

        let stale = controller
            .run_due_bounded(
                "worker-a",
                "ignored",
                now + INVENTORY_CLAIM_LEASE_SECONDS + 2,
                1,
                Some(&stale_cursor),
                test_dispatch_budget(1, 1, 8, Duration::from_secs(5)),
            )
            .await
            .unwrap();
        assert_eq!(stale, OciInventoryControllerStats::default());
    }

    #[tokio::test]
    async fn slow_object_timeout_keeps_the_generation_resumable() {
        let bytes = b"slow provider object".to_vec();
        let digest = hex::encode(Sha256::digest(&bytes));
        let key = format!("oci/blobs/sha256/{digest}");
        let pages = vec![SurfaceListPage {
            paths: vec![key.clone()],
            evidence: BTreeMap::new(),
            next_cursor: None,
        }];
        let (db, _registry_id, placement, provider) =
            inventory_fixture(pages, BTreeMap::from([(key, bytes)])).await;
        provider
            .fetch
            .evidence_delay_ms
            .store(60_000, Ordering::SeqCst);
        let controller = OciProviderInventoryController::new(db.clone(), provider.clone());
        let now = crate::clock::now_unix_secs();

        let dispatch = controller.run_due_bounded(
            "worker",
            "slow",
            now,
            1,
            None,
            test_dispatch_budget(1, 1, 1024, Duration::from_secs(30)),
        );
        tokio::pin!(dispatch);
        tokio::select! {
            () = provider.fetch.evidence_started.notified() => {}
            result = &mut dispatch => panic!("dispatch finished before fetching an object: {result:?}"),
        }

        // Enter the provider operation before advancing its deadline. Database
        // setup uses real time; leave time paused only while the fetch is pending
        // so SQLite worker scheduling cannot consume the test's timer budget.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::time::resume();
        let timed_out = dispatch.await.unwrap();
        let continuation = timed_out.continuation.unwrap();
        let active = db
            .active_oci_provider_inventory(placement.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.checkpoint_ordinal, 0);
        assert_eq!(active.provider_cursor, None);
        assert_eq!(provider.fetch.evidence_calls.load(Ordering::SeqCst), 1);

        provider.fetch.evidence_delay_ms.store(0, Ordering::SeqCst);
        let resumed = controller
            .run_due_bounded(
                "worker",
                "ignored-on-continuation",
                now + 1,
                1,
                Some(&continuation),
                test_dispatch_budget(1, 1, 1024, Duration::from_secs(5)),
            )
            .await
            .unwrap();
        assert_eq!(resumed.completed, 1);
        assert!(resumed.continuation.is_none());
        assert_eq!(provider.fetch.evidence_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *provider.fetch.requested_cursors.lock().unwrap(),
            vec![None, None]
        );
    }

    #[tokio::test]
    async fn expired_partial_checkpoint_is_taken_over_and_resumed_from_its_cursor() {
        let mut blobs = [b"first page".to_vec(), b"second page".to_vec()]
            .into_iter()
            .map(|bytes| {
                let digest = hex::encode(Sha256::digest(&bytes));
                (format!("oci/blobs/sha256/{digest}"), bytes)
            })
            .collect::<Vec<_>>();
        blobs.sort_by(|left, right| left.0.cmp(&right.0));
        let pages = vec![
            SurfaceListPage {
                paths: vec![blobs[0].0.clone()],
                evidence: BTreeMap::new(),
                next_cursor: Some("1".into()),
            },
            SurfaceListPage {
                paths: vec![blobs[1].0.clone()],
                evidence: BTreeMap::new(),
                next_cursor: None,
            },
        ];
        let objects = BTreeMap::from([blobs[0].clone(), blobs[1].clone()]);
        let (db, registry_id, placement, provider) = inventory_fixture(pages, objects).await;
        let now = crate::clock::now_unix_secs();
        let frozen = db
            .list_due_oci_provider_inventory_placements(now, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let generation = db
            .begin_oci_provider_inventory(&BeginOciProviderInventory {
                registry_id,
                placement_id: placement.id,
                expected_placement_resource_version: frozen.placement_resource_version,
                expected_placement_observation_version: frozen.placement_observation_version,
                collector_id: "crashed".into(),
                collector_claim_token: "old-token".into(),
                collector_lease_seconds: 1,
                idempotency_key: inventory_idempotency_key(
                    "crash",
                    registry_id,
                    placement.id,
                    frozen.placement_resource_version,
                    frozen.placement_observation_version,
                ),
                now,
            })
            .await
            .unwrap();
        let fetch = provider.placement_fetcher(&placement).await.unwrap();
        let first_digest = canonical_oci_blob_digest(&blobs[0].0).unwrap().unwrap();
        let first_entry = inventory_entry(
            fetch.as_ref(),
            &blobs[0].0,
            first_digest,
            MAX_OCI_INVENTORY_OBJECT_BYTES,
        )
        .await
        .unwrap();
        db.append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            generation_id: generation.id.clone(),
            collector_id: "crashed".into(),
            collector_claim_token: "old-token".into(),
            expected_checkpoint_ordinal: 0,
            expected_provider_cursor: None,
            next_provider_cursor: Some("oci-blobs-v1:1".into()),
            last_listed_key: Some(blobs[0].0.clone()),
            entries: vec![first_entry.clone()],
            now,
            lease_seconds: 1,
        })
        .await
        .unwrap();

        let resume_token = inventory_claim_token("resume", placement.id);
        db.claim_oci_provider_inventory(&generation.id, "worker", &resume_token, now + 2, 1)
            .await
            .unwrap();
        assert!(db
            .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
                generation_id: generation.id.clone(),
                collector_id: "crashed".into(),
                collector_claim_token: "old-token".into(),
                expected_checkpoint_ordinal: 1,
                expected_provider_cursor: Some("oci-blobs-v1:1".into()),
                next_provider_cursor: None,
                last_listed_key: Some(blobs[1].0.clone()),
                entries: vec![first_entry],
                now: now + 2,
                lease_seconds: 1,
            })
            .await
            .is_err());
        provider.fetch.requested_cursors.lock().unwrap().clear();

        let controller = OciProviderInventoryController::new(db.clone(), provider.clone());
        let resumed = controller
            .run_due("worker", "resume", now + 4, 10)
            .await
            .unwrap();
        assert_eq!(resumed.attempted, 1);
        assert_eq!(resumed.completed, 1);
        assert_eq!(
            *provider.fetch.requested_cursors.lock().unwrap(),
            vec![Some("1".into())]
        );
        assert_eq!(
            db.oci_provider_inventory_generation(&generation.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "complete"
        );
        assert!(db
            .active_oci_provider_inventory(placement.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn listing_is_scoped_to_the_blob_namespace_one_object_per_page() {
        let blobs = [
            b"first blob".to_vec(),
            b"second blob".to_vec(),
            b"third blob".to_vec(),
        ]
        .into_iter()
        .map(|bytes| {
            let digest = hex::encode(Sha256::digest(&bytes));
            (format!("{OCI_BLOB_KEY_PREFIX}{digest}"), bytes)
        })
        .collect::<BTreeMap<_, _>>();
        // The placement also holds the binary cache and git objects, which
        // sort on both sides of the blob namespace.
        let mut objects = blobs.clone();
        for key in [
            "0000000000000000000000000000000.narinfo",
            "nar/0000-aaaa.nar.zst",
            "nar/zzzz-bbbb.nar.zst",
            "nix-cache-info",
            "objects/ab/cd",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.narinfo",
        ] {
            objects.insert(key.to_string(), b"not a blob".to_vec());
        }
        let (db, _registry_id, placement, provider) =
            inventory_fixture(Vec::new(), objects).await;
        let controller = OciProviderInventoryController::new(db.clone(), provider.clone());
        let now = crate::clock::now_unix_secs();
        let keys = blobs.keys().cloned().collect::<Vec<_>>();

        let first = controller
            .run_due_bounded(
                "worker",
                "scoped",
                now,
                1,
                None,
                test_dispatch_budget(1, 1, MAX_OCI_INVENTORY_OBJECT_BYTES, Duration::from_secs(5)),
            )
            .await
            .unwrap();
        let continuation = first.continuation.unwrap();
        let active = db
            .active_oci_provider_inventory(placement.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.checkpoint_ordinal, 1);
        assert_eq!(
            active.provider_cursor,
            Some(format!("oci-blobs-v1:{}", keys[0]))
        );

        let finished = controller
            .run_due_bounded(
                "worker",
                "ignored-on-continuation",
                now + 1,
                1,
                Some(&continuation),
                NATIVE_OCI_INVENTORY_DISPATCH_BUDGET,
            )
            .await
            .unwrap();
        assert_eq!((finished.completed, finished.failed), (1, 0));
        assert!(finished.continuation.is_none());

        let prefixes = provider.fetch.requested_prefixes.lock().unwrap().clone();
        assert_eq!(prefixes.len(), blobs.len());
        assert!(prefixes.iter().all(|prefix| prefix == OCI_BLOB_KEY_PREFIX));
        assert_eq!(
            *provider.fetch.requested_cursors.lock().unwrap(),
            vec![None, Some(keys[0].clone()), Some(keys[1].clone())]
        );
        let generation = db
            .oci_provider_inventory_generation(&active.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(generation.state, "complete");
        assert_eq!(generation.object_count, 3);
        assert_eq!(generation.checkpoint_ordinal, 3);
    }

    #[tokio::test]
    async fn legacy_unscoped_checkpoint_fails_and_a_fresh_generation_is_collected() {
        let (pages, objects) = two_page_inventory();
        let (db, registry_id, placement, provider) = inventory_fixture(pages, objects).await;
        let now = crate::clock::now_unix_secs();
        let frozen = db
            .list_due_oci_provider_inventory_placements(now, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let generation = db
            .begin_oci_provider_inventory(&BeginOciProviderInventory {
                registry_id,
                placement_id: placement.id,
                expected_placement_resource_version: frozen.placement_resource_version,
                expected_placement_observation_version: frozen.placement_observation_version,
                collector_id: "previous-release".into(),
                collector_claim_token: "legacy-token".into(),
                collector_lease_seconds: 1,
                idempotency_key: inventory_idempotency_key(
                    "legacy",
                    registry_id,
                    placement.id,
                    frozen.placement_resource_version,
                    frozen.placement_observation_version,
                ),
                now,
            })
            .await
            .unwrap();
        // A release that walked the whole placement checkpointed the raw
        // provider cursor after an empty page of binary-cache keys.
        db.append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            generation_id: generation.id.clone(),
            collector_id: "previous-release".into(),
            collector_claim_token: "legacy-token".into(),
            expected_checkpoint_ordinal: 0,
            expected_provider_cursor: None,
            next_provider_cursor: Some("1".into()),
            last_listed_key: Some("nar/aaaa.nar.zst".into()),
            entries: Vec::new(),
            now,
            lease_seconds: 1,
        })
        .await
        .unwrap();

        let controller = OciProviderInventoryController::new(db.clone(), provider.clone());
        let recovered = controller
            .run_due("worker", "recover", now + 4, 1)
            .await
            .unwrap();
        assert_eq!(
            (recovered.attempted, recovered.completed, recovered.failed),
            (1, 0, 1)
        );
        assert!(recovered.continuation.is_none());
        assert_eq!(
            db.oci_provider_inventory_generation(&generation.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "failed"
        );
        assert!(provider.fetch.requested_cursors.lock().unwrap().is_empty());
        assert!(db
            .active_oci_provider_inventory(placement.id)
            .await
            .unwrap()
            .is_none());

        let fresh = controller
            .run_due("worker", "fresh", now + 5, 1)
            .await
            .unwrap();
        assert_eq!((fresh.attempted, fresh.completed, fresh.failed), (1, 1, 0));
        assert_eq!(
            *provider.fetch.requested_cursors.lock().unwrap(),
            vec![None, Some("1".into())]
        );
    }

    #[test]
    fn durable_cursors_carry_the_listing_scope_tag() {
        let tagged = tag_provider_cursor("opaque-cursor").unwrap();
        assert_eq!(tagged, "oci-blobs-v1:opaque-cursor");
        assert_eq!(
            provider_cursor_for_listing(Some(&tagged)).unwrap(),
            Some("opaque-cursor")
        );
        assert_eq!(provider_cursor_for_listing(None).unwrap(), None);
        assert!(tag_provider_cursor("").is_err());
        assert!(provider_cursor_for_listing(Some("oci-blobs-v1:")).is_err());
        let legacy = provider_cursor_for_listing(Some("opaque-cursor")).unwrap_err();
        assert!(
            legacy.to_string().contains("predates blob-scoped listing"),
            "{legacy:#}"
        );

        // The tagged form fits every bound it crosses: the durable checkpoint
        // column, the object continuation, and the platform cursor limits.
        let longest =
            "c".repeat(MAX_STORED_PROVIDER_CURSOR_BYTES - INVENTORY_CURSOR_SCOPE_TAG.len());
        let tagged = tag_provider_cursor(&longest).unwrap();
        assert_eq!(tagged.len(), MAX_STORED_PROVIDER_CURSOR_BYTES);
        assert!(tagged.len() <= WORKER_MAX_SURFACE_LIST_CURSOR_BYTES);
        assert!(tagged.len() <= MAX_SURFACE_LIST_CURSOR_BYTES);
        assert!(tag_provider_cursor(&format!("{longest}c")).is_err());

        let key = format!("{OCI_BLOB_KEY_PREFIX}{}", hex::encode(Sha256::digest(b"")));
        let digest = canonical_oci_blob_digest(&key).unwrap().unwrap();
        let continuation = InventoryObjectContinuation::initial(
            1,
            1,
            Some(tagged.clone()),
            &key,
            digest,
            0,
            "\"etag\"".into(),
        )
        .unwrap();
        assert_eq!(continuation.provider_cursor, Some(tagged));
    }
}
