//! Exact, explainable readiness of a registry for reviewed deletion.
//!
//! Registry deletion is a self-driving operation, so readiness separates two
//! kinds of precondition:
//!
//! - *blocking* conditions that only an operator can resolve: OCI catalog
//!   content, active publication or GC work, provider objects in a current
//!   inventory, retained cache roots, snapshot references, and placements that
//!   can never be inventoried; and
//! - *automatic* steps that the deletion operation performs itself: abandoning
//!   never-applied GC plans, acquiring the registry purge fence, scanning
//!   unobserved placements, and collecting a provider inventory for every
//!   placement under that fence.
//!
//! The predicates mirror the final deletion transaction in
//! [`registry_delete`](super::registry_delete), which re-asserts them
//! atomically. This module only explains them; it never authorizes deletion on
//! its own.

use anyhow::{Context, Result};

use crate::value::Row;

use super::{Database, OCI_GC_MAX_INVENTORY_AGE_SECONDS};

/// Overall deletion verdict for one registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryDeletionVerdict {
    /// An operator must resolve at least one blocking condition first.
    Blocked,
    /// The deletion operation resolves every remaining precondition itself.
    Automatic,
    /// The final deletion transaction can commit immediately.
    Ready,
}

impl RegistryDeletionVerdict {
    /// Returns the stable wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Automatic => "automatic",
            Self::Ready => "ready",
        }
    }
}

/// Provider-inventory readiness of one registry placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementDeletionState {
    /// A complete empty inventory was collected under the current fence.
    Ready,
    /// The operation must collect a provider inventory under the fence.
    NeedsInventory,
    /// A provider inventory generation is in progress.
    Collecting,
    /// The placement has not been observed ready and complete; the operation
    /// scans it before inventorying it.
    NeedsScan,
    /// A current inventory still lists live provider objects.
    HasObjects,
    /// The placement can never be inventoried in its current configuration.
    Unavailable,
}

impl PlacementDeletionState {
    /// Returns the stable wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NeedsInventory => "needs_inventory",
            Self::Collecting => "collecting",
            Self::NeedsScan => "needs_scan",
            Self::HasObjects => "has_objects",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether the deletion operation must still scan or inventory the placement.
    #[must_use]
    pub fn needs_inventory(self) -> bool {
        matches!(self, Self::NeedsInventory | Self::Collecting | Self::NeedsScan)
    }
}

/// Deletion readiness of one registry placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryDeletionPlacement {
    /// Placement database id.
    pub placement_id: i64,
    /// Stable placement name within the registry.
    pub name: String,
    /// Classified inventory readiness.
    pub state: PlacementDeletionState,
    /// Human-readable explanation of `state`.
    pub detail: String,
    /// Live tracked objects in the placement's latest inventory head.
    pub tracked_provider_objects: u64,
    /// Live untracked objects in the placement's latest inventory head.
    pub untracked_provider_objects: u64,
    /// Observation time of the latest complete inventory head, when any.
    pub inventory_observed_at: Option<i64>,
}

/// Exact counts of every condition that prevents or delays registry deletion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryDeletionBlockers {
    /// OCI repositories that still exist.
    pub repositories: u64,
    /// OCI catalog blobs that remain.
    pub catalog_objects: u64,
    /// Active OCI sessions plus unexpired OCI leases.
    pub active_sessions: u64,
    /// Active registry publications, multipart uploads, and publish leases.
    pub active_publications: u64,
    /// Binary-cache retention roots supplied by the registry.
    pub retained_cache_roots: u64,
    /// Unretired staged-release objects holding container blobs.
    pub staged_container_objects: u64,
    /// OCI GC runs in the `applying` state.
    pub applying_gc_runs: u64,
    /// Pending, claimed, or failed placement actions of applied OCI GC runs.
    ///
    /// Actions frozen by a run that was never applied (`planned` or
    /// `aborted`) can never be claimed, so they are not GC work.
    pub pending_gc_actions: u64,
    /// Planned or in-progress untracked-object repairs.
    pub active_untracked_repairs: u64,
    /// Live tracked objects across the placements' latest inventory heads.
    pub tracked_provider_objects: u64,
    /// Live untracked objects across the placements' latest inventory heads.
    pub untracked_provider_objects: u64,
    /// Placements that still need a scan or an inventory under the fence.
    pub placements_needing_inventory: u64,
    /// Image snapshot references and snapshot lease holds.
    pub snapshot_references: u64,
    /// Planned, never-applied OCI GC runs that deletion abandons.
    ///
    /// Expired and unexpired plans alike: apply moves a run out of
    /// `planned` atomically, so no planned run has physical work in flight.
    pub abandonable_gc_runs: u64,
    /// Placements that can never be inventoried as configured.
    pub unavailable_placements: u64,
}

/// The current collecting purge fence of a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryDeletionFence {
    /// Actor that acquired the fence.
    pub actor_id: String,
    /// Reviewed plan or deletion operation that acquired the fence.
    pub idempotency_key: String,
    /// Registry resource version bound by the fence.
    pub registry_resource_version: i64,
    /// Registry mutation epoch frozen by the fence.
    pub captured_mutation_epoch: i64,
    /// Fence acquisition time.
    pub created_at: i64,
    /// Fence optimistic-concurrency version.
    pub resource_version: i64,
}

/// Complete deletion readiness of one registry at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryDeletionReadiness {
    /// Registry database id.
    pub registry_id: i64,
    /// Registry resource version observed with the readiness.
    pub registry_resource_version: i64,
    /// Current OCI mutation epoch, absent before any OCI state exists.
    pub mutation_epoch: Option<i64>,
    /// Current collecting purge fence, when any.
    pub fence: Option<RegistryDeletionFence>,
    /// Exact blocker and progress counts.
    pub blockers: RegistryDeletionBlockers,
    /// Per-placement inventory readiness, ordered by name.
    pub placements: Vec<RegistryDeletionPlacement>,
}

impl RegistryDeletionReadiness {
    /// Returns the overall verdict.
    #[must_use]
    pub fn verdict(&self) -> RegistryDeletionVerdict {
        if !self.blocking_reasons().is_empty() {
            RegistryDeletionVerdict::Blocked
        } else if self.is_deletable() {
            RegistryDeletionVerdict::Ready
        } else {
            RegistryDeletionVerdict::Automatic
        }
    }

    /// Whether the final deletion transaction's predicates hold now.
    #[must_use]
    pub fn is_deletable(&self) -> bool {
        self.blocking_reasons().is_empty()
            && self.fence.is_some()
            && self.blockers.abandonable_gc_runs == 0
            && self
                .placements
                .iter()
                .all(|placement| placement.state == PlacementDeletionState::Ready)
    }

    /// Returns one sentence per condition that only an operator can resolve.
    #[must_use]
    pub fn blocking_reasons(&self) -> Vec<String> {
        let blockers = &self.blockers;
        let mut reasons = Vec::new();
        if blockers.repositories > 0 {
            reasons.push(format!(
                "{} OCI repositories still exist; retire the container catalog first \
                 (aos hub registry container gc plan --retire-registry)",
                blockers.repositories
            ));
        }
        if blockers.catalog_objects > 0 {
            reasons.push(format!(
                "{} OCI catalog objects remain; finish the catalog retirement GC runs",
                blockers.catalog_objects
            ));
        }
        if blockers.active_sessions > 0 {
            reasons.push(format!(
                "{} OCI upload or publication sessions or leases are active",
                blockers.active_sessions
            ));
        }
        if blockers.active_publications > 0 {
            reasons.push(format!(
                "the registry has an active publication or upload ({})",
                blockers.active_publications
            ));
        }
        if blockers.retained_cache_roots > 0 {
            reasons.push(format!(
                "the registry still supplies {} retained binary-cache roots",
                blockers.retained_cache_roots
            ));
        }
        if blockers.staged_container_objects > 0 {
            reasons.push(format!(
                "{} unretired staged-release objects still hold container blobs",
                blockers.staged_container_objects
            ));
        }
        if blockers.applying_gc_runs > 0 {
            reasons.push(format!(
                "{} OCI GC runs are applying; wait for them to finish",
                blockers.applying_gc_runs
            ));
        }
        if blockers.pending_gc_actions > 0 {
            reasons.push(format!(
                "{} OCI GC placement actions are pending or failed; requeue or finish them",
                blockers.pending_gc_actions
            ));
        }
        if blockers.active_untracked_repairs > 0 {
            reasons.push(format!(
                "{} untracked-object repairs are planned or in progress",
                blockers.active_untracked_repairs
            ));
        }
        if blockers.snapshot_references > 0 {
            reasons.push(format!(
                "{} image snapshot references or snapshot leases still name the registry",
                blockers.snapshot_references
            ));
        }
        if let Some(reason) = self.fence_mismatch() {
            reasons.push(reason);
        }
        for placement in &self.placements {
            match placement.state {
                PlacementDeletionState::HasObjects | PlacementDeletionState::Unavailable => {
                    reasons.push(format!("placement '{}': {}", placement.name, placement.detail));
                }
                _ => {}
            }
        }
        reasons
    }

    /// Returns one sentence per step the deletion operation performs itself.
    ///
    /// The list is empty when deletion is blocked, because the operation
    /// refuses to start.
    #[must_use]
    pub fn automatic_steps(&self) -> Vec<String> {
        if !self.blocking_reasons().is_empty() {
            return Vec::new();
        }
        let mut steps = Vec::new();
        if self.blockers.abandonable_gc_runs > 0 {
            steps.push(format!(
                "abandon {} planned OCI GC runs that were never applied",
                self.blockers.abandonable_gc_runs
            ));
        }
        if self.fence.is_none() {
            steps.push(
                "acquire the registry purge fence, which blocks new registry writes".to_string(),
            );
        }
        for placement in &self.placements {
            match placement.state {
                PlacementDeletionState::NeedsScan => steps.push(format!(
                    "scan placement '{}', then collect its provider inventory",
                    placement.name
                )),
                PlacementDeletionState::NeedsInventory | PlacementDeletionState::Collecting => {
                    steps.push(format!(
                        "collect a fresh provider inventory for placement '{}' ({})",
                        placement.name, placement.detail
                    ));
                }
                _ => {}
            }
        }
        steps.push(
            "delete the registry identity, its routes and placements, and its terminal \
             publication metadata"
                .to_string(),
        );
        steps
    }

    /// Builds the operator-facing refusal message for a non-deletable registry.
    #[must_use]
    pub fn failure_message(&self) -> String {
        let reasons = self.blocking_reasons();
        if reasons.is_empty() {
            format!(
                "registry deletion preconditions are not yet satisfied: {}",
                self.automatic_steps().join("; ")
            )
        } else {
            format!("registry deletion is blocked: {}", reasons.join("; "))
        }
    }

    /// Explains a held fence that the final deletion transaction would reject.
    fn fence_mismatch(&self) -> Option<String> {
        let fence = self.fence.as_ref()?;
        if fence.registry_resource_version != self.registry_resource_version {
            return Some(format!(
                "a purge fence held by '{}' binds registry version {} instead of {}; abort it \
                 through the purge-fence workflow",
                fence.actor_id, fence.registry_resource_version, self.registry_resource_version
            ));
        }
        if Some(fence.captured_mutation_epoch) != self.mutation_epoch {
            return Some(format!(
                "the purge fence held by '{}' predates an OCI mutation; abort it through the \
                 purge-fence workflow",
                fence.actor_id
            ));
        }
        None
    }
}

/// Raw per-placement facts read in one statement.
struct PlacementFacts {
    placement_id: i64,
    name: String,
    desired_state: String,
    observation: Option<(String, String)>,
    has_write_revision: bool,
    active_generation: bool,
    head: Option<HeadFacts>,
}

/// Raw facts about one placement's latest complete inventory head.
struct HeadFacts {
    complete: bool,
    current: bool,
    observed_at: Option<i64>,
    started_at: i64,
    purge_fence_resource_version: Option<i64>,
    object_count: i64,
    live_tracked: u64,
    live_untracked: u64,
    failed_after: bool,
}

impl Database {
    /// Computes exact deletion readiness for one registry.
    ///
    /// Returns `Ok(None)` when the registry does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid selector, malformed persisted counts,
    /// or database failure.
    pub async fn registry_deletion_readiness(
        &self,
        registry_id: i64,
        now: i64,
    ) -> Result<Option<RegistryDeletionReadiness>> {
        anyhow::ensure!(
            registry_id > 0 && now >= 0,
            "registry deletion readiness selector is invalid"
        );
        let Some(row) = self
            .backend
            .query_opt(REGISTRY_FACTS_SQL, &vals![registry_id, now])
            .await?
        else {
            return Ok(None);
        };
        let registry_resource_version: i64 = row.get(0)?;
        let mutation_epoch: Option<i64> = row.get(1)?;
        let mut blockers = RegistryDeletionBlockers {
            repositories: count(&row, 2, "repository")?,
            catalog_objects: count(&row, 3, "catalog object")?,
            active_sessions: count(&row, 4, "active session")?,
            active_publications: count(&row, 5, "active publication")?,
            retained_cache_roots: count(&row, 6, "cache root")?,
            staged_container_objects: count(&row, 7, "staged object")?,
            applying_gc_runs: count(&row, 8, "applying GC run")?,
            pending_gc_actions: count(&row, 9, "GC action")?,
            active_untracked_repairs: count(&row, 10, "untracked repair")?,
            snapshot_references: count(&row, 11, "snapshot reference")?,
            abandonable_gc_runs: count(&row, 12, "planned GC run")?,
            ..RegistryDeletionBlockers::default()
        };

        let fence = self.registry_deletion_fence(registry_id).await?;
        let oldest = now.saturating_sub(OCI_GC_MAX_INVENTORY_AGE_SECONDS);
        let rows = self
            .backend
            .query(PLACEMENT_FACTS_SQL, &vals![registry_id, oldest])
            .await?;
        let mut placements = Vec::with_capacity(rows.len());
        for row in &rows {
            let facts = placement_facts(row)?;
            blockers.tracked_provider_objects += facts
                .head
                .as_ref()
                .map_or(0, |head| head.live_tracked);
            blockers.untracked_provider_objects += facts
                .head
                .as_ref()
                .map_or(0, |head| head.live_untracked);
            placements.push(classify_placement(facts, fence.as_ref()));
        }
        blockers.placements_needing_inventory = placements
            .iter()
            .filter(|placement| placement.state.needs_inventory())
            .count() as u64;
        blockers.unavailable_placements = placements
            .iter()
            .filter(|placement| placement.state == PlacementDeletionState::Unavailable)
            .count() as u64;

        Ok(Some(RegistryDeletionReadiness {
            registry_id,
            registry_resource_version,
            mutation_epoch,
            fence,
            blockers,
            placements,
        }))
    }

    /// Returns the registry's collecting purge fence, when one is held.
    async fn registry_deletion_fence(
        &self,
        registry_id: i64,
    ) -> Result<Option<RegistryDeletionFence>> {
        self.backend
            .query_opt(
                "SELECT actor_id, idempotency_key, registry_resource_version,
                        captured_mutation_epoch, created_at, resource_version
                 FROM oci_registry_purge_fences
                 WHERE registry_id = ?1 AND state = 'collecting'",
                &vals![registry_id],
            )
            .await?
            .map(|row| {
                Ok(RegistryDeletionFence {
                    actor_id: row.get(0)?,
                    idempotency_key: row.get(1)?,
                    registry_resource_version: row.get(2)?,
                    captured_mutation_epoch: row.get(3)?,
                    created_at: row.get(4)?,
                    resource_version: row.get(5)?,
                })
            })
            .transpose()
    }
}

/// Registry-wide blocker counts. `?2` is the current time for lease and
/// staged-object expiry; the predicates match the deletion transaction.
const REGISTRY_FACTS_SQL: &str = "SELECT registry.resource_version,
       (SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1),
       (SELECT COUNT(*) FROM oci_repositories WHERE registry_id = ?1),
       (SELECT COUNT(*) FROM oci_blobs WHERE registry_id = ?1),
       (SELECT COUNT(*) FROM oci_upload_sessions
         WHERE registry_id = ?1 AND state IN('active', 'completing'))
        + (SELECT COUNT(*) FROM oci_publication_sessions
            WHERE registry_id = ?1 AND state IN('preparing', 'committing'))
        + (SELECT COUNT(*) FROM oci_leases
            WHERE registry_id = ?1 AND expires_at > ?2),
       (SELECT COUNT(*) FROM registry_publications
         WHERE registry_id = ?1 AND state IN('preparing', 'writing_pointers'))
        + (SELECT COUNT(*) FROM registry_publication_multipart_uploads
            WHERE registry_id = ?1 AND active_object_slot = 1)
        + (SELECT COUNT(*) FROM publish_leases WHERE registry_id = ?1),
       (SELECT COUNT(*) FROM cache_root_reasons WHERE registry_id = ?1),
       (SELECT COUNT(*) FROM staged_release_objects staged_object
         JOIN staged_release_revisions staged_revision
           ON staged_revision.registry_id = staged_object.registry_id
          AND staged_revision.stage_id = staged_object.stage_id
          AND staged_revision.revision = staged_object.revision
         WHERE staged_object.registry_id = ?1
           AND staged_object.object_key LIKE 'oci/blobs/sha256/%'
           AND (staged_revision.retire_after IS NULL
             OR staged_revision.retire_after > ?2)),
       (SELECT COUNT(*) FROM oci_gc_runs WHERE registry_id = ?1 AND state = 'applying'),
       (SELECT COUNT(*) FROM oci_gc_placement_actions action
         WHERE action.registry_id = ?1 AND action.state IN('pending', 'claimed', 'failed')
           AND NOT EXISTS (SELECT 1 FROM oci_gc_runs action_run
             WHERE action_run.id = action.run_id
               AND action_run.state IN('planned', 'aborted'))),
       (SELECT COUNT(*) FROM oci_untracked_repair_plans
         WHERE registry_id = ?1
           AND state IN('planned', 'pending', 'claimed', 'failed')),
       (SELECT COUNT(*) FROM image_snapshot_references WHERE registry_id = ?1)
        + (SELECT COUNT(*) FROM oci_gc_snapshot_lease_holds WHERE registry_id = ?1),
       (SELECT COUNT(*) FROM oci_gc_runs WHERE registry_id = ?1 AND state = 'planned')
     FROM registries registry WHERE registry.id = ?1";

/// Per-placement facts. `?2` is the oldest acceptable inventory observation.
/// The `current` column is the deletion transaction's head predicate without
/// its purge-fence terms, which are evaluated against the fence in Rust.
const PLACEMENT_FACTS_SQL: &str = "SELECT placement.id, placement.name, placement.desired_state,
       observation.state, observation.completeness,
       CASE WHEN write_state.current_write_revision IS NULL THEN 0 ELSE 1 END,
       EXISTS (SELECT 1 FROM oci_provider_inventory_generations active
         WHERE active.placement_id = placement.id
           AND active.state IN('collecting', 'sealing')),
       head.generation_id, inventory.state, inventory.observed_at,
       inventory.started_at, inventory.purge_fence_resource_version,
       inventory.object_count,
       CASE WHEN inventory.state = 'complete'
         AND inventory.observed_at >= ?2
         AND inventory.captured_mutation_epoch = registry_state.mutation_epoch
         AND inventory.placement_resource_version = placement.resource_version
         AND inventory.placement_write_spec_version = placement.write_spec_version
         AND inventory.placement_observation_version = observation.observation_version
         AND inventory.binding_resource_version = binding.resource_version
         AND inventory.binding_write_revision = write_state.current_write_revision
       THEN 1 ELSE 0 END,
       (SELECT COUNT(*) FROM oci_provider_inventory_entries entry
         WHERE entry.generation_id = head.generation_id
           AND entry.placement_id = placement.id
           AND entry.deleted_at IS NULL AND entry.classification = 'tracked'),
       (SELECT COUNT(*) FROM oci_provider_inventory_entries entry
         WHERE entry.generation_id = head.generation_id
           AND entry.placement_id = placement.id
           AND entry.deleted_at IS NULL AND entry.classification = 'untracked'),
       EXISTS (SELECT 1 FROM oci_provider_inventory_generations failed
         WHERE failed.placement_id = placement.id AND failed.state = 'failed'
           AND failed.started_at > inventory.started_at)
     FROM surface_placements placement
     LEFT JOIN surface_placement_observations observation
       ON observation.placement_id = placement.id
     LEFT JOIN bindings binding ON binding.id = placement.binding_id
     LEFT JOIN binding_write_state write_state ON write_state.binding_id = placement.binding_id
     LEFT JOIN oci_registry_state registry_state
       ON registry_state.registry_id = placement.registry_id
     LEFT JOIN oci_provider_inventory_heads head ON head.placement_id = placement.id
     LEFT JOIN oci_provider_inventory_generations inventory
       ON inventory.id = head.generation_id
     WHERE placement.registry_id = ?1
     ORDER BY placement.name, placement.id";

fn placement_facts(row: &Row) -> Result<PlacementFacts> {
    let observation_state: Option<String> = row.get(3)?;
    let observation_completeness: Option<String> = row.get(4)?;
    let head_generation: Option<String> = row.get(7)?;
    let head = match head_generation {
        Some(_) => Some(HeadFacts {
            complete: row.get::<Option<String>>(8)?.as_deref() == Some("complete"),
            observed_at: row.get(9)?,
            started_at: row.get(10)?,
            purge_fence_resource_version: row.get(11)?,
            object_count: row.get(12)?,
            current: row.get::<i64>(13)? != 0,
            live_tracked: count(row, 14, "tracked provider object")?,
            live_untracked: count(row, 15, "untracked provider object")?,
            failed_after: row.get::<Option<i64>>(16)?.unwrap_or(0) != 0,
        }),
        None => None,
    };
    Ok(PlacementFacts {
        placement_id: row.get(0)?,
        name: row.get(1)?,
        desired_state: row.get(2)?,
        observation: observation_state.zip(observation_completeness),
        has_write_revision: row.get::<i64>(5)? != 0,
        active_generation: row.get::<i64>(6)? != 0,
        head,
    })
}

/// Classifies one placement against the deletion transaction's predicates.
fn classify_placement(
    facts: PlacementFacts,
    fence: Option<&RegistryDeletionFence>,
) -> RegistryDeletionPlacement {
    let (tracked, untracked, observed_at) = facts.head.as_ref().map_or((0, 0, None), |head| {
        (head.live_tracked, head.live_untracked, head.observed_at)
    });
    let (state, detail) = placement_state(&facts, fence);
    RegistryDeletionPlacement {
        placement_id: facts.placement_id,
        name: facts.name,
        state,
        detail,
        tracked_provider_objects: tracked,
        untracked_provider_objects: untracked,
        inventory_observed_at: observed_at,
    }
}

fn placement_state(
    facts: &PlacementFacts,
    fence: Option<&RegistryDeletionFence>,
) -> (PlacementDeletionState, String) {
    use PlacementDeletionState as State;

    // Inventory begin refuses offline placements and bindings without a
    // current writer revision, while the deletion transaction still requires
    // an inventory for every placement. Only an operator can change either.
    if facts.desired_state == "offline" {
        return (
            State::Unavailable,
            "the placement is offline and cannot be inventoried; restore or delete the placement"
                .to_string(),
        );
    }
    if !facts.has_write_revision {
        return (
            State::Unavailable,
            "the placement's binding has no current write revision; validate its credential or \
             delete the placement"
                .to_string(),
        );
    }
    match facts.observation.as_ref() {
        Some((state, completeness)) if state == "ready" && completeness == "complete" => {}
        Some((state, completeness)) => {
            return (
                State::NeedsScan,
                format!("the placement is observed {state}/{completeness}; it is scanned first"),
            );
        }
        None => {
            return (
                State::NeedsScan,
                "the placement has never been observed; it is scanned first".to_string(),
            );
        }
    }
    if facts.active_generation {
        return (
            State::Collecting,
            "a provider inventory is in progress".to_string(),
        );
    }

    let Some(head) = facts.head.as_ref() else {
        return (
            State::NeedsInventory,
            "no provider inventory has been collected".to_string(),
        );
    };
    let live_objects = head.live_tracked + head.live_untracked;
    if !head.complete || !head.current {
        let detail = if live_objects > 0 {
            format!(
                "the latest inventory is stale and listed {live_objects} provider objects; a \
                 fresh inventory fails closed if they remain"
            )
        } else {
            "the latest provider inventory is stale".to_string()
        };
        return (State::NeedsInventory, detail);
    }
    if live_objects > 0 {
        return (
            State::HasObjects,
            format!(
                "the current provider inventory lists {} tracked and {} untracked objects; \
                 collect or repair them through container GC first",
                head.live_tracked, head.live_untracked
            ),
        );
    }

    let Some(fence) = fence else {
        return (
            State::NeedsInventory,
            "the current inventory predates the purge fence".to_string(),
        );
    };
    let observed_after_fence = head
        .observed_at
        .is_some_and(|observed_at| observed_at >= fence.created_at);
    let collected_under_fence = head.purge_fence_resource_version == Some(fence.resource_version)
        && head.started_at >= fence.created_at
        && observed_after_fence
        && head.object_count == 0;
    if head.failed_after {
        (
            State::NeedsInventory,
            "a newer provider inventory attempt failed".to_string(),
        )
    } else if collected_under_fence {
        (
            State::Ready,
            "an empty provider inventory was collected under the purge fence".to_string(),
        )
    } else {
        (
            State::NeedsInventory,
            "the current inventory predates the purge fence".to_string(),
        )
    }
}

fn count(row: &Row, index: usize, kind: &str) -> Result<u64> {
    u64::try_from(row.get::<i64>(index)?)
        .with_context(|| format!("persisted {kind} count is negative"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_facts() -> PlacementFacts {
        PlacementFacts {
            placement_id: 1,
            name: "primary".to_string(),
            desired_state: "active".to_string(),
            observation: Some(("ready".to_string(), "complete".to_string())),
            has_write_revision: true,
            active_generation: false,
            head: Some(HeadFacts {
                complete: true,
                current: true,
                observed_at: Some(20),
                started_at: 15,
                purge_fence_resource_version: Some(1),
                object_count: 0,
                live_tracked: 0,
                live_untracked: 0,
                failed_after: false,
            }),
        }
    }

    fn fence() -> RegistryDeletionFence {
        RegistryDeletionFence {
            actor_id: "operator".to_string(),
            idempotency_key: "operation".to_string(),
            registry_resource_version: 3,
            captured_mutation_epoch: 0,
            created_at: 10,
            resource_version: 1,
        }
    }

    #[test]
    fn post_fence_empty_inventory_is_ready_and_pre_fence_inventory_is_recollected() {
        assert_eq!(
            placement_state(&ready_facts(), Some(&fence())).0,
            PlacementDeletionState::Ready
        );
        assert_eq!(
            placement_state(&ready_facts(), None).0,
            PlacementDeletionState::NeedsInventory
        );

        let mut pre_fence = ready_facts();
        if let Some(head) = pre_fence.head.as_mut() {
            head.started_at = 5;
        }
        assert_eq!(
            placement_state(&pre_fence, Some(&fence())).0,
            PlacementDeletionState::NeedsInventory
        );
    }

    #[test]
    fn unobserved_offline_and_object_holding_placements_are_classified_exactly() {
        let mut unobserved = ready_facts();
        unobserved.observation = None;
        unobserved.head = None;
        assert_eq!(
            placement_state(&unobserved, None).0,
            PlacementDeletionState::NeedsScan
        );

        let mut offline = ready_facts();
        offline.desired_state = "offline".to_string();
        assert_eq!(
            placement_state(&offline, None).0,
            PlacementDeletionState::Unavailable
        );

        let mut holding = ready_facts();
        if let Some(head) = holding.head.as_mut() {
            head.live_untracked = 2;
        }
        assert_eq!(
            placement_state(&holding, Some(&fence())).0,
            PlacementDeletionState::HasObjects
        );

        let mut stale_holding = ready_facts();
        if let Some(head) = stale_holding.head.as_mut() {
            head.current = false;
            head.live_tracked = 2;
        }
        assert_eq!(
            placement_state(&stale_holding, Some(&fence())).0,
            PlacementDeletionState::NeedsInventory,
            "a stale head's objects are re-verified rather than trusted"
        );
    }

    #[test]
    fn verdict_separates_operator_blockers_from_automatic_steps() {
        let mut readiness = RegistryDeletionReadiness {
            registry_id: 1,
            registry_resource_version: 3,
            mutation_epoch: Some(0),
            fence: None,
            blockers: RegistryDeletionBlockers::default(),
            placements: Vec::new(),
        };
        assert_eq!(readiness.verdict(), RegistryDeletionVerdict::Automatic);
        assert!(readiness.automatic_steps()[0].contains("purge fence"));

        readiness.fence = Some(fence());
        assert_eq!(readiness.verdict(), RegistryDeletionVerdict::Ready);

        readiness.blockers.abandonable_gc_runs = 1;
        assert_eq!(readiness.verdict(), RegistryDeletionVerdict::Automatic);

        readiness.blockers.repositories = 27;
        assert_eq!(readiness.verdict(), RegistryDeletionVerdict::Blocked);
        assert!(readiness.automatic_steps().is_empty());
        assert!(readiness
            .failure_message()
            .contains("27 OCI repositories still exist; retire the container catalog first"));
    }
}
