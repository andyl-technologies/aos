//! Pure closure/fence regressions; fixture claims do not qualify native EOF.

use super::*;
use crate::node_contract::{NativeTerminalDisposition, NativeTerminalInventory, RuntimeError};
use crate::node_scheduling::InputPayload;

fn inventories(scheduler: &CausalScheduler) -> BTreeMap<Id, NativeTerminalInventory> {
    scheduler
        .node_owners
        .iter()
        .map(|(node, owner)| {
            (
                node.clone(),
                NativeTerminalInventory {
                    node: node.clone(),
                    owners: scheduler.node_routes[node].clone(),
                    boundary: scheduler.owners[owner].cursor,
                    disposition: NativeTerminalDisposition::InputsDrained,
                    receipt: InputPayload {
                        reference: crucible_node_contract::canonical::content_ref(
                            b"fixture inventory",
                            "text/plain",
                        )
                        .unwrap(),
                        bytes: b"fixture inventory".to_vec(),
                    },
                },
            )
        })
        .collect()
}

#[test]
fn terminal_cycle_cannot_bootstrap_from_empty_queues_or_unknown_bounds() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, Some(0));
    scheduler
        .owners
        .get_mut(&id("owner/Z"))
        .unwrap()
        .inputs
        .push(InputPath {
            producer: id("A"),
            latency_ps: U64::new(0),
            external: false,
            external_endpoint: None,
        });
    let native = inventories(&scheduler);

    assert!(scheduler.pending.is_empty());
    assert!(
        scheduler
            .bounds
            .values()
            .all(|bound| *bound == OutputBound::Unknown)
    );
    assert_eq!(
        scheduler.terminal_closure(&native, 65_536),
        Err(RuntimeError::OutstandingObligations)
    );
}

#[test]
fn terminal_authentic_root_closes_drained_input_graph_at_actual_cut() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, Some(0));
    scheduler.owners.get_mut(&id("owner/A")).unwrap().cursor =
        position(17, 2, Phase::BoundaryControl);
    let mut native = inventories(&scheduler);
    native.get_mut(&id("Z")).unwrap().disposition = NativeTerminalDisposition::Unconditional;

    let (cut, bytes) = scheduler.terminal_closure(&native, 65_536).unwrap();

    assert_eq!(cut, position(17, 2, Phase::BoundaryControl));
    let value: serde_json::Value = serde_json::from_slice(bytes.as_slice()).unwrap();
    assert_eq!(value["format"], "crucible.world-terminal-coordinator");
    assert!(value.get("capture_ordinal").is_none());
}

#[test]
fn terminal_refuses_reserved_native_work_and_changed_local_cut() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let mut native = inventories(&scheduler);
    scheduler.owners.get_mut(&id("owner/A")).unwrap().reserved = Some(id("original-operation"));

    assert_eq!(
        scheduler.terminal_closure(&native, 65_536),
        Err(RuntimeError::OutstandingObligations)
    );
    scheduler.owners.get_mut(&id("owner/A")).unwrap().reserved = None;
    native.get_mut(&id("A")).unwrap().boundary = position(1, 0, Phase::BoundaryControl);
    assert_eq!(
        scheduler.terminal_closure(&native, 65_536),
        Err(RuntimeError::InvalidTiming)
    );
}

#[test]
fn terminal_refuses_roster_omission_and_bounded_record_overrun() {
    let scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, None);
    let mut native = inventories(&scheduler);
    native.remove(&id("Z"));

    assert_eq!(
        scheduler.terminal_closure(&native, 65_536),
        Err(RuntimeError::InvalidRoute)
    );
    let native = inventories(&scheduler);
    assert_eq!(
        scheduler.terminal_closure(&native, 1),
        Err(RuntimeError::ResourceLimit)
    );
}
