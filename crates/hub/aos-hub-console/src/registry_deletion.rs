//! Presentation model of registry deletion readiness and progress.
//!
//! The deletion plan and the deletion operation's detail carry the same
//! `RegistryDeletionReadiness` message. These pure helpers turn it into
//! labeled rows for the registry Danger-zone page and compile natively so the
//! presentation rules are unit tested. The operation detail is camel-case
//! JSON whose `readiness` field is ProtoJSON:
//!
//! ```text
//! {"phase":"inventorying","message":"collecting a provider inventory ...",
//!  "readiness":{"verdict":"automatic","blockers":{"placementsNeedingInventory":"1"}}}
//! ```

use aos_hub_api::{RegistryDeletionBlockers, RegistryDeletionReadiness};
use serde::Deserialize;

/// Operation detail fields rendered while a deletion runs.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct DeletionProgress {
    /// Current or terminal phase.
    pub(crate) phase: String,
    /// Human-readable description of the current step.
    pub(crate) message: String,
    /// Latest readiness recorded by the deletion controller.
    pub(crate) readiness: Option<RegistryDeletionReadiness>,
}

/// Whether a blocker row stops the deletion or is resolved automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockerSeverity {
    /// Only an operator can resolve the condition.
    Blocking,
    /// The deletion operation resolves or re-verifies the condition itself.
    Automatic,
}

impl BlockerSeverity {
    /// Returns the visible table label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Blocking => "Blocks deletion",
            Self::Automatic => "Handled by the operation",
        }
    }
}

/// One non-zero blocker count with its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockerRow {
    /// Human-readable condition.
    pub(crate) label: &'static str,
    /// Exact count.
    pub(crate) count: u64,
    /// Who resolves the condition.
    pub(crate) severity: BlockerSeverity,
}

/// Parses deletion operation detail, reporting unreadable detail as a message.
pub(crate) fn deletion_progress(detail_json: &str) -> DeletionProgress {
    serde_json::from_str(detail_json).unwrap_or_else(|_| DeletionProgress {
        message: "The Hub returned unreadable deletion progress.".to_string(),
        ..DeletionProgress::default()
    })
}

/// Returns the headline for a readiness verdict.
pub(crate) fn verdict_label(verdict: &str) -> &'static str {
    match verdict {
        "blocked" => "Blocked: resolve the conditions below first",
        "automatic" => "Ready: the deletion operation completes the remaining steps",
        "ready" => "Ready to delete",
        _ => "Unknown readiness",
    }
}

/// Lists every non-zero blocker count in a stable order.
pub(crate) fn blocker_rows(readiness: &RegistryDeletionReadiness) -> Vec<BlockerRow> {
    let blockers = readiness.blockers.unwrap_or_default();
    // Provider objects listed by a current inventory block deletion; objects
    // listed by a stale inventory are re-verified by the operation.
    let provider_severity = if readiness
        .placements
        .iter()
        .any(|placement| placement.inventory_state == "has_objects")
    {
        BlockerSeverity::Blocking
    } else {
        BlockerSeverity::Automatic
    };
    let RegistryDeletionBlockers {
        repositories,
        catalog_objects,
        active_sessions,
        active_publications,
        retained_cache_roots,
        staged_container_objects,
        applying_gc_runs,
        pending_gc_actions,
        active_untracked_repairs,
        tracked_provider_objects,
        untracked_provider_objects,
        placements_needing_inventory,
        snapshot_references,
        abandonable_gc_runs,
        unavailable_placements,
        enabled_oci_namespaces,
        instance_oci_route_defaults,
    } = blockers;
    let blocking = BlockerSeverity::Blocking;
    let automatic = BlockerSeverity::Automatic;
    [
        ("OCI repositories", repositories, blocking),
        ("OCI catalog objects", catalog_objects, blocking),
        ("Active OCI sessions and leases", active_sessions, blocking),
        ("Active publications or uploads", active_publications, blocking),
        ("Retained binary-cache roots", retained_cache_roots, blocking),
        ("Staged container objects", staged_container_objects, blocking),
        ("Applying OCI GC runs", applying_gc_runs, blocking),
        ("Pending OCI GC placement actions", pending_gc_actions, blocking),
        ("Untracked-object repairs", active_untracked_repairs, blocking),
        ("Snapshot references", snapshot_references, blocking),
        ("Unavailable placements", unavailable_placements, blocking),
        ("Enabled OCI namespace", enabled_oci_namespaces, blocking),
        ("Instance OCI route defaults", instance_oci_route_defaults, blocking),
        ("Tracked provider objects", tracked_provider_objects, provider_severity),
        ("Untracked provider objects", untracked_provider_objects, provider_severity),
        ("Placements needing an inventory", placements_needing_inventory, automatic),
        ("Planned GC runs to abandon", abandonable_gc_runs, automatic),
    ]
    .into_iter()
    .filter(|(_, count, _)| *count > 0)
    .map(|(label, count, severity)| BlockerRow {
        label,
        count,
        severity,
    })
    .collect()
}

/// Returns the visible label of a placement inventory state.
pub(crate) fn placement_state_label(state: &str) -> &'static str {
    match state {
        "ready" => "Empty inventory under the fence",
        "needs_inventory" => "Needs a fresh inventory",
        "collecting" => "Inventory in progress",
        "needs_scan" => "Needs a scan first",
        "has_objects" => "Holds provider objects",
        "unavailable" => "Cannot be inventoried",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocker_rows_list_only_present_conditions_with_their_resolver() {
        let readiness = RegistryDeletionReadiness {
            verdict: "blocked".to_string(),
            blockers: Some(RegistryDeletionBlockers {
                repositories: 27,
                placements_needing_inventory: 1,
                ..RegistryDeletionBlockers::default()
            }),
            ..RegistryDeletionReadiness::default()
        };
        assert_eq!(
            blocker_rows(&readiness),
            vec![
                BlockerRow {
                    label: "OCI repositories",
                    count: 27,
                    severity: BlockerSeverity::Blocking,
                },
                BlockerRow {
                    label: "Placements needing an inventory",
                    count: 1,
                    severity: BlockerSeverity::Automatic,
                },
            ]
        );
    }

    #[test]
    fn provider_objects_block_only_when_a_current_inventory_lists_them() {
        let mut readiness = RegistryDeletionReadiness {
            blockers: Some(RegistryDeletionBlockers {
                untracked_provider_objects: 2,
                ..RegistryDeletionBlockers::default()
            }),
            ..RegistryDeletionReadiness::default()
        };
        assert_eq!(
            blocker_rows(&readiness)[0].severity,
            BlockerSeverity::Automatic
        );

        readiness
            .placements
            .push(aos_hub_api::RegistryDeletionPlacement {
                placement_name: "primary".to_string(),
                inventory_state: "has_objects".to_string(),
                ..aos_hub_api::RegistryDeletionPlacement::default()
            });
        assert_eq!(
            blocker_rows(&readiness)[0].severity,
            BlockerSeverity::Blocking
        );
    }

    #[test]
    fn operation_detail_parses_protojson_readiness() {
        let progress = deletion_progress(
            r#"{"phase":"blocked","message":"registry deletion is blocked",
                "readiness":{"verdict":"blocked","blockers":{"repositories":"3"},
                "blockingReasons":["3 OCI repositories still exist"]}}"#,
        );
        assert_eq!(progress.phase, "blocked");
        let Some(readiness) = progress.readiness else {
            panic!("operation detail omitted its readiness");
        };
        assert_eq!(readiness.blockers.unwrap_or_default().repositories, 3);
        assert_eq!(readiness.blocking_reasons, ["3 OCI repositories still exist"]);

        assert!(deletion_progress("not json").message.contains("unreadable"));
    }
}
