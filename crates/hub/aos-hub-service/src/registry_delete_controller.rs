//! Self-driving execution of reviewed registry deletion operations.
//!
//! Applying a reviewed `DeleteRegistry` plan creates one durable
//! `delete_registry` topology operation. This controller advances it on
//! either runtime, one bounded pass at a time, through these phases:
//!
//! 1. **preparing** — abandon planned OCI GC runs that were never applied and
//!    acquire the registry purge fence, which blocks new registry writes;
//! 2. **scanning** — schedule a placement scan for every placement that has
//!    never been observed ready and complete, and wait for it;
//! 3. **inventorying** — collect a complete provider inventory of every
//!    placement under the fence, on demand rather than on the maintenance
//!    schedule; and
//! 4. **deleting** — run the atomic deletion transaction, which also marks
//!    the operation succeeded.
//!
//! Every pass recomputes [`RegistryDeletionReadiness`] first. A condition that
//! only an operator can resolve fails the operation with the exact blocker
//! breakdown in its detail and releases the fence the operation acquired. The
//! operation detail is camel-case JSON whose `readiness` field is the
//! ProtoJSON form of `aos.hub.v1.RegistryDeletionReadiness`, so the console and
//! CLI render the same breakdown as the plan:
//!
//! ```text
//! {"phase":"inventorying","message":"collecting a provider inventory for
//!  placement 'primary'","registry":"acme/scratch","planId":"...",
//!  "readiness":{"verdict":"automatic","blockers":{...},"placements":[...]},
//!  "abandonedGcRuns":[],"fenceAcquired":true,"placementScans":[],
//!  "inventories":[{"placement":"primary","placementId":"7","round":1,...}]}
//! ```

use std::sync::Arc;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::clock;
use crate::db::{
    Database, NewTopologyOperation, NewTopologyOperationTarget, NewTopologyOperationTargetRef,
    PlacementDeletionState, PrepareRegistryDeletion, RegistryDeletionCommit,
    RegistryDeletionOperationCompletion, RegistryDeletionOutcome, RegistryDeletionPlacement,
    RegistryDeletionReadiness, TopologyOperationRecord, TopologyPlanRecord,
};
use crate::domain::Permission;
use crate::fetch::SurfaceProvider;
use crate::oci_inventory_controller::{
    OciInventoryDispatchBudget, OciPlacementInventoryProgress, OciProviderInventoryController,
};

pub use crate::db::REGISTRY_DELETION_OPERATION_KIND;

/// Lease held by one controller pass; a pass is bounded well below it.
const CLAIM_LEASE_SECONDS: i64 = 300;
/// Readiness re-evaluations allowed in one pass before yielding.
const MAX_STEPS_PER_PASS: usize = 16;
/// Durable inventory failures tolerated per placement.
const MAX_INVENTORY_FAILURES: u32 = 3;
/// Inventory rounds per placement, bounding repeated staleness.
const MAX_INVENTORY_ROUNDS: u32 = 10;
/// Deletion transactions attempted before a changing precondition fails.
const MAX_DELETE_ATTEMPTS: u32 = 5;
/// Consecutive unexplained step failures tolerated before failing.
const MAX_TRANSIENT_FAILURES: u32 = 5;
/// Progress units: prepare, scan, inventory, delete.
const PROGRESS_TOTAL: i64 = 4;

/// Durable operation-specific status of one registry deletion.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RegistryDeletionDetail {
    /// `pending`, `preparing`, `scanning`, `inventorying`, `deleting`,
    /// `deleted`, `blocked`, or `failed`.
    pub phase: String,
    /// Human-readable description of the current step or terminal outcome.
    pub message: String,
    /// Registry path reviewed for deletion.
    pub registry: String,
    /// Reviewed plan whose actor and change id attribute the deletion.
    pub plan_id: String,
    /// Registry resource version bound by the reviewed plan.
    ///
    /// Registry operation targets carry no generation, so the reviewed
    /// version is kept here and every step re-checks it.
    pub registry_resource_version: i64,
    /// Latest readiness, in the ProtoJSON form of the API message.
    pub readiness: Option<aos_hub_api::RegistryDeletionReadiness>,
    /// Planned GC runs this operation abandoned.
    pub abandoned_gc_runs: Vec<String>,
    /// Whether this operation acquired the purge fence it holds.
    pub fence_acquired: bool,
    /// Placement scans this operation scheduled.
    pub placement_scans: Vec<RegistryDeletionScan>,
    /// Provider inventory attempts per placement.
    pub inventories: Vec<RegistryDeletionInventory>,
    /// Final deletion transactions attempted.
    pub delete_attempts: u32,
    /// Consecutive unexplained step failures.
    pub transient_failures: u32,
}

impl RegistryDeletionDetail {
    /// Creates the initial detail of a newly applied deletion.
    #[must_use]
    pub fn new(
        registry: &str,
        plan_id: &str,
        registry_resource_version: i64,
        readiness: &RegistryDeletionReadiness,
    ) -> Self {
        Self {
            phase: "pending".to_string(),
            message: "waiting for the registry deletion controller".to_string(),
            registry: registry.to_string(),
            plan_id: plan_id.to_string(),
            registry_resource_version,
            readiness: Some(readiness_message(readiness)),
            ..Self::default()
        }
    }

    fn inventory_mut(
        &mut self,
        placement: &RegistryDeletionPlacement,
    ) -> &mut RegistryDeletionInventory {
        let index = match self
            .inventories
            .iter()
            .position(|inventory| inventory.placement_id == placement.placement_id)
        {
            Some(index) => index,
            None => {
                self.inventories.push(RegistryDeletionInventory {
                    placement: placement.name.clone(),
                    placement_id: placement.placement_id,
                    round: 1,
                    ..RegistryDeletionInventory::default()
                });
                self.inventories.len() - 1
            }
        };
        &mut self.inventories[index]
    }
}

/// One placement scan scheduled by a deletion operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RegistryDeletionScan {
    /// Placement name.
    pub placement: String,
    /// Scan operation id, readable through the operation API.
    pub operation_id: String,
}

/// Provider inventory progress of one placement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RegistryDeletionInventory {
    /// Placement name.
    pub placement: String,
    /// Placement database id.
    pub placement_id: i64,
    /// Inventory round; each completed or failed round uses a fresh seed.
    pub round: u32,
    /// Durable failures observed so far.
    pub failures: u32,
    /// `collecting`, `complete`, `failed`, or `waiting`.
    pub state: String,
    /// Opaque continuation of a dispatch-bounded inventory.
    pub continuation: Option<String>,
}

/// Aggregate result of one controller pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryDeletionPassStats {
    /// Operations claimed and advanced.
    pub claimed: usize,
    /// Registries deleted.
    pub deleted: usize,
    /// Operations failed with a recorded reason.
    pub failed: usize,
    /// Fences released for cancelled operations.
    pub released_fences: u64,
    /// Whether an operation yielded with work that can continue at once.
    pub follow_up_due: bool,
}

/// How one claimed pass ended.
enum PassEnd {
    Deleted,
    Failed,
    Yielded { follow_up_due: bool },
    Lost,
}

/// One step's request to leave the pass loop.
enum StepExit {
    Fail(String),
    Yield { follow_up_due: bool },
    Deleted,
    Stale,
}

/// Executes reviewed registry deletion operations.
pub struct RegistryDeletionController {
    db: Arc<Database>,
    inventory: OciProviderInventoryController,
    collector_id: String,
    inventory_budget: OciInventoryDispatchBudget,
}

impl RegistryDeletionController {
    /// Creates a controller over one database and provider read port.
    ///
    /// `collector_id` identifies this runtime's inventory collector, and
    /// `inventory_budget` bounds the provider work of one pass.
    #[must_use]
    pub fn new(
        db: Arc<Database>,
        surfaces: Arc<dyn SurfaceProvider>,
        collector_id: impl Into<String>,
        inventory_budget: OciInventoryDispatchBudget,
    ) -> Self {
        Self {
            inventory: OciProviderInventoryController::new(Arc::clone(&db), surfaces),
            db,
            collector_id: collector_id.into(),
            inventory_budget,
        }
    }

    /// Claims and advances at most `limit` due deletion operations.
    ///
    /// # Errors
    ///
    /// Returns an error when the due inventory, a claim, or fence cleanup
    /// cannot be read or persisted. Failures inside one operation's pass are
    /// recorded on that operation instead.
    pub async fn run_due(&self, limit: usize) -> Result<RegistryDeletionPassStats> {
        let now = clock::now_unix_secs();
        let mut stats = RegistryDeletionPassStats {
            released_fences: self
                .db
                .release_orphaned_registry_deletion_fences(now)
                .await?,
            ..RegistryDeletionPassStats::default()
        };

        let due = self.db.due_registry_deletion_operations(now, limit).await?;
        for operation in due {
            let claim_token = uuid::Uuid::new_v4().simple().to_string();
            let Some(claimed) = self
                .db
                .claim_registry_deletion_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    &claim_token,
                    CLAIM_LEASE_SECONDS,
                )
                .await?
            else {
                continue;
            };
            stats.claimed += 1;
            match self.advance(&claimed, &claim_token).await? {
                PassEnd::Deleted => stats.deleted += 1,
                PassEnd::Failed => stats.failed += 1,
                PassEnd::Yielded { follow_up_due } => stats.follow_up_due |= follow_up_due,
                PassEnd::Lost => {}
            }
        }
        Ok(stats)
    }

    /// Runs one claimed pass and records its outcome on the operation.
    async fn advance(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
    ) -> Result<PassEnd> {
        let mut detail =
            match serde_json::from_str::<RegistryDeletionDetail>(&operation.detail_json) {
                Ok(detail) => detail,
                Err(error) => {
                    let mut detail = RegistryDeletionDetail::default();
                    let message = format!("registry deletion detail is malformed: {error}");
                    return self
                        .finish_failed(operation, claim_token, &mut detail, message)
                        .await;
                }
            };

        let exit = match self.drive(operation, claim_token, &mut detail).await {
            Ok(exit) => {
                detail.transient_failures = 0;
                exit
            }
            Err(error) => {
                // Unexplained failures (provider I/O, a lost race) are retried
                // by a later pass, but never indefinitely.
                detail.transient_failures += 1;
                detail.message = format!("retrying after: {error:#}");
                if detail.transient_failures >= MAX_TRANSIENT_FAILURES {
                    StepExit::Fail(format!(
                        "registry deletion step failed repeatedly: {error:#}"
                    ))
                } else {
                    StepExit::Yield {
                        follow_up_due: false,
                    }
                }
            }
        };

        match exit {
            StepExit::Deleted => Ok(PassEnd::Deleted),
            StepExit::Stale => {
                let message = "the registry changed after the deletion was reviewed; plan the \
                               deletion again"
                    .to_string();
                self.finish_failed(operation, claim_token, &mut detail, message)
                    .await
            }
            StepExit::Fail(message) => {
                self.finish_failed(operation, claim_token, &mut detail, message)
                    .await
            }
            StepExit::Yield { follow_up_due } => {
                let detail_json = serde_json::to_string(&detail)?;
                let kept = self
                    .db
                    .checkpoint_registry_deletion_operation(
                        &operation.operation_id,
                        operation.resource_version,
                        claim_token,
                        phase_progress(&detail.phase),
                        &detail_json,
                    )
                    .await?;
                Ok(if kept {
                    PassEnd::Yielded { follow_up_due }
                } else {
                    PassEnd::Lost
                })
            }
        }
    }

    /// Advances the operation until it finishes, fails, or must wait.
    async fn drive(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
        detail: &mut RegistryDeletionDetail,
    ) -> Result<StepExit> {
        let Some(plan) = self.db.topology_plan(&detail.plan_id).await? else {
            return Ok(StepExit::Fail(
                "the reviewed deletion plan no longer exists".to_string(),
            ));
        };
        let expected_version = detail.registry_resource_version;
        let Some(registry) = self
            .db
            .registry_by_stable_id(&operation.primary_target_stable_id)
            .await?
        else {
            return Ok(StepExit::Stale);
        };
        if registry.resource_version != expected_version {
            return Ok(StepExit::Stale);
        }

        for _ in 0..MAX_STEPS_PER_PASS {
            let now = clock::now_unix_secs();
            let Some(readiness) = self
                .db
                .registry_deletion_readiness(registry.id, now)
                .await?
            else {
                return Ok(StepExit::Stale);
            };
            detail.readiness = Some(readiness_message(&readiness));
            if !readiness.blocking_reasons().is_empty() {
                detail.phase = "blocked".to_string();
                return Ok(StepExit::Fail(format!(
                    "failed_precondition: {}",
                    readiness.failure_message()
                )));
            }

            if readiness.blockers.abandonable_gc_runs > 0 || readiness.fence.is_none() {
                detail.phase = "preparing".to_string();
                detail.message =
                    "abandoning planned GC runs and acquiring the purge fence".to_string();
                let prepared = self
                    .db
                    .prepare_registry_deletion(&PrepareRegistryDeletion {
                        registry_id: registry.id,
                        expected_version,
                        operation_id: &operation.operation_id,
                        actor_id: &plan.actor_label,
                        now,
                    })
                    .await?;
                detail.abandoned_gc_runs.extend(prepared.abandoned_gc_runs);
                detail.fence_acquired |= prepared.fence_acquired;
                continue;
            }

            let unscanned = readiness
                .placements
                .iter()
                .filter(|placement| placement.state == PlacementDeletionState::NeedsScan)
                .collect::<Vec<_>>();
            if !unscanned.is_empty() {
                detail.phase = "scanning".to_string();
                return self.ensure_scans(operation, detail, &unscanned).await;
            }

            if let Some(placement) = readiness
                .placements
                .iter()
                .find(|placement| placement.state.needs_inventory())
            {
                detail.phase = "inventorying".to_string();
                detail.message = format!(
                    "collecting a provider inventory for placement '{}'",
                    placement.name
                );
                match self
                    .inventory_step(&operation.operation_id, detail, placement, now)
                    .await?
                {
                    Some(exit) => return Ok(exit),
                    None => continue,
                }
            }

            detail.phase = "deleting".to_string();
            detail.message = "deleting the registry".to_string();
            detail.delete_attempts += 1;
            match self
                .commit(
                    operation,
                    claim_token,
                    detail,
                    &plan,
                    expected_version,
                    registry.id,
                )
                .await?
            {
                RegistryDeletionOutcome::Deleted => return Ok(StepExit::Deleted),
                RegistryDeletionOutcome::Stale => return Ok(StepExit::Stale),
                RegistryDeletionOutcome::Blocked(changed) => {
                    // A precondition changed between readiness and commit.
                    // Automatic steps are retried; operator blockers fail on
                    // the next readiness evaluation with the full breakdown.
                    detail.readiness = Some(readiness_message(&changed));
                    if detail.delete_attempts >= MAX_DELETE_ATTEMPTS {
                        return Ok(StepExit::Fail(format!(
                            "failed_precondition: {}",
                            changed.failure_message()
                        )));
                    }
                }
            }
        }
        Ok(StepExit::Yield {
            follow_up_due: true,
        })
    }

    /// Commits the deletion and the operation's success atomically.
    async fn commit(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
        detail: &RegistryDeletionDetail,
        plan: &TopologyPlanRecord,
        expected_version: i64,
        registry_id: i64,
    ) -> Result<RegistryDeletionOutcome> {
        let mut deleted = detail.clone();
        deleted.phase = "deleted".to_string();
        deleted.message = format!("registry '{}' deleted", detail.registry);
        let detail_json = serde_json::to_string(&deleted)?;
        self.db
            .commit_registry_deletion(&RegistryDeletionCommit {
                registry_id,
                expected_version,
                change_id: &plan.plan_id,
                actor_kind: &plan.actor_kind,
                actor_id: plan.actor_id,
                actor_label: &plan.actor_label,
                operation: Some(RegistryDeletionOperationCompletion {
                    operation_id: &operation.operation_id,
                    expected_version: operation.resource_version,
                    claim_token,
                    detail_json: &detail_json,
                    progress_total: PROGRESS_TOTAL,
                }),
            })
            .await
    }

    /// Schedules scans for unobserved placements and reports whether to wait.
    async fn ensure_scans(
        &self,
        operation: &TopologyOperationRecord,
        detail: &mut RegistryDeletionDetail,
        placements: &[&RegistryDeletionPlacement],
    ) -> Result<StepExit> {
        for placement in placements {
            let scan_id = scan_operation_id(&operation.operation_id, placement.placement_id);
            let scan = match self.db.topology_operation(&scan_id).await? {
                Some(scan) => scan,
                None => self.create_scan(&scan_id, placement).await?,
            };
            if !detail
                .placement_scans
                .iter()
                .any(|recorded| recorded.operation_id == scan_id)
            {
                detail.placement_scans.push(RegistryDeletionScan {
                    placement: placement.name.clone(),
                    operation_id: scan_id.clone(),
                });
            }
            match scan.state.as_str() {
                "pending" | "running" => {}
                "succeeded" => {
                    return Ok(StepExit::Fail(format!(
                        "failed_precondition: placement '{}' is still not ready and complete \
                         after scan {scan_id}: {}",
                        placement.name, placement.detail
                    )));
                }
                state => {
                    let error = scan.error.as_deref().unwrap_or("no error detail");
                    return Ok(StepExit::Fail(format!(
                        "failed_precondition: the scan of placement '{}' {state}: {error}",
                        placement.name
                    )));
                }
            }
        }
        detail.message = format!(
            "waiting for {} placement scans before collecting inventories",
            placements.len()
        );
        Ok(StepExit::Yield {
            follow_up_due: true,
        })
    }

    async fn create_scan(
        &self,
        scan_id: &str,
        placement: &RegistryDeletionPlacement,
    ) -> Result<TopologyOperationRecord> {
        let current = self
            .db
            .surface_placement(placement.placement_id)
            .await?
            .context("placement disappeared before its deletion scan")?;
        self.db
            .create_topology_operation(&NewTopologyOperation {
                operation_id: scan_id.to_string(),
                operation_kind: "scan_placement".to_string(),
                control_permission: Permission::StorageManage,
                targets: vec![NewTopologyOperationTarget {
                    role: "primary".to_string(),
                    target: NewTopologyOperationTargetRef::Placement(current.id),
                    generation_key: current.resource_version,
                    configuration_digest: String::new(),
                }],
                detail_json: serde_json::json!({"phase": "pending"}).to_string(),
                progress_total: None,
            })
            .await
    }

    /// Runs one bounded inventory dispatch; `None` re-evaluates readiness.
    async fn inventory_step(
        &self,
        operation_id: &str,
        detail: &mut RegistryDeletionDetail,
        placement: &RegistryDeletionPlacement,
        now: i64,
    ) -> Result<Option<StepExit>> {
        let inventory = detail.inventory_mut(placement);
        if inventory.round > MAX_INVENTORY_ROUNDS {
            return Ok(Some(StepExit::Fail(format!(
                "the provider inventory of placement '{}' went stale {MAX_INVENTORY_ROUNDS} times",
                placement.name
            ))));
        }
        let seed = format!("registry-delete:{operation_id}:{}", inventory.round);
        let progress = self
            .inventory
            .inventory_placement_bounded(
                &self.collector_id,
                &seed,
                now,
                placement.placement_id,
                inventory.continuation.as_deref(),
                self.inventory_budget,
            )
            .await?;

        Ok(match progress {
            OciPlacementInventoryProgress::Completed => {
                inventory.state = "complete".to_string();
                inventory.continuation = None;
                inventory.round += 1;
                None
            }
            OciPlacementInventoryProgress::Continue(cursor) => {
                inventory.state = "collecting".to_string();
                inventory.continuation = Some(cursor);
                Some(StepExit::Yield {
                    follow_up_due: true,
                })
            }
            OciPlacementInventoryProgress::Busy => {
                // Another collector holds a live lease on this placement's
                // generation; it is resumed or recovered by its owner.
                inventory.state = "waiting".to_string();
                Some(StepExit::Yield {
                    follow_up_due: true,
                })
            }
            OciPlacementInventoryProgress::Failed => {
                inventory.state = "failed".to_string();
                inventory.continuation = None;
                inventory.round += 1;
                inventory.failures += 1;

                // Retry on a later pass rather than at once, so a transient
                // provider outage does not exhaust the failure budget.
                Some(if inventory.failures >= MAX_INVENTORY_FAILURES {
                    StepExit::Fail(format!(
                        "the provider inventory of placement '{}' failed {} times",
                        placement.name, inventory.failures
                    ))
                } else {
                    StepExit::Yield {
                        follow_up_due: false,
                    }
                })
            }
        })
    }

    async fn finish_failed(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
        detail: &mut RegistryDeletionDetail,
        message: String,
    ) -> Result<PassEnd> {
        if detail.phase != "blocked" {
            detail.phase = "failed".to_string();
        }
        detail.message.clone_from(&message);
        let detail_json = serde_json::to_string(detail)?;
        let recorded = self
            .db
            .fail_registry_deletion_operation(
                &operation.operation_id,
                operation.resource_version,
                claim_token,
                &detail_json,
                &message,
            )
            .await?;
        Ok(if recorded {
            PassEnd::Failed
        } else {
            PassEnd::Lost
        })
    }
}

/// Returns the deterministic deletion operation id of one reviewed plan.
#[must_use]
pub fn registry_deletion_operation_id(plan_id: &str) -> String {
    hex::encode(Sha256::digest(
        format!("aos-registry-deletion-v1\0{plan_id}").as_bytes(),
    ))
}

/// Projects readiness into the shared API message.
#[must_use]
pub fn readiness_message(
    readiness: &RegistryDeletionReadiness,
) -> aos_proto_types::RegistryDeletionReadiness {
    let blockers = &readiness.blockers;
    aos_proto_types::RegistryDeletionReadiness {
        verdict: readiness.verdict().as_str().to_string(),
        blockers: Some(aos_proto_types::RegistryDeletionBlockers {
            repositories: blockers.repositories,
            catalog_objects: blockers.catalog_objects,
            active_sessions: blockers.active_sessions,
            active_publications: blockers.active_publications,
            retained_cache_roots: blockers.retained_cache_roots,
            staged_container_objects: blockers.staged_container_objects,
            applying_gc_runs: blockers.applying_gc_runs,
            pending_gc_actions: blockers.pending_gc_actions,
            active_untracked_repairs: blockers.active_untracked_repairs,
            tracked_provider_objects: blockers.tracked_provider_objects,
            untracked_provider_objects: blockers.untracked_provider_objects,
            placements_needing_inventory: blockers.placements_needing_inventory,
            snapshot_references: blockers.snapshot_references,
            abandonable_gc_runs: blockers.abandonable_gc_runs,
            unavailable_placements: blockers.unavailable_placements,
            enabled_oci_namespaces: blockers.enabled_oci_namespaces,
            instance_oci_route_defaults: blockers.instance_oci_route_defaults,
        }),
        placements: readiness
            .placements
            .iter()
            .map(|placement| aos_proto_types::RegistryDeletionPlacement {
                placement_name: placement.name.clone(),
                inventory_state: placement.state.as_str().to_string(),
                detail: placement.detail.clone(),
                tracked_provider_objects: placement.tracked_provider_objects,
                untracked_provider_objects: placement.untracked_provider_objects,
                inventory_observed_at: placement.inventory_observed_at.unwrap_or_default(),
            })
            .collect(),
        blocking_reasons: readiness.blocking_reasons(),
        automatic_steps: readiness.automatic_steps(),
        purge_fence_held: readiness.fence.is_some(),
    }
}

/// Deterministic scan operation id for one deletion and placement.
///
/// Keying on the placement rather than its version keeps a completed scan
/// from being rescheduled when it leaves the placement not ready.
fn scan_operation_id(operation_id: &str, placement_id: i64) -> String {
    hex::encode(Sha256::digest(
        format!("aos-registry-deletion-scan-v1\0{operation_id}\0{placement_id}").as_bytes(),
    ))
}

/// Monotonic progress units reached by a phase.
fn phase_progress(phase: &str) -> i64 {
    match phase {
        "preparing" | "scanning" => 1,
        "inventorying" => 2,
        "deleting" => 3,
        _ => 0,
    }
}
