//! Keeps both monotonic node-entry writes behind all actual ledger lookups.

use super::*;

#[test]
fn absent_world_window_refuses_before_any_node_or_world_entry_mutation() {
    let (mut ledger, epoch) = selected_ledger();
    let initial = ledger.used;
    let world_index = ledger
        .worlds
        .iter()
        .position(|world| world.as_ref().is_some_and(|world| world.epoch == epoch))
        .unwrap();
    let window = ledger.worlds[world_index].as_mut().unwrap().window.take();
    assert!(window.is_some());

    assert!(ledger.take_node(epoch, requests()[0].node).is_err());

    assert_eq!(ledger.used, initial);
    assert!(
        !ledger.worlds[world_index]
            .as_ref()
            .unwrap()
            .node_constructor_entered
    );
    assert!(ledger.nodes.iter().flatten().all(|node| !node.issued));
    ledger.worlds[world_index].as_mut().unwrap().window = window;
}

#[test]
fn checked_node_entry_publishes_both_flags_once_under_the_same_ledger() {
    let (mut ledger, epoch) = selected_ledger();
    let initial = ledger.used;

    let (index, assignment) = ledger.take_node(epoch, requests()[0].node).unwrap();

    let row = ledger.nodes[index].as_ref().unwrap();
    assert!(row.issued);
    assert_eq!(row.assignment_epoch, assignment);
    assert!(
        ledger
            .worlds
            .iter()
            .flatten()
            .find(|world| world.epoch == epoch)
            .unwrap()
            .node_constructor_entered
    );
    assert!(ledger.take_node(epoch, requests()[0].node).is_err());
    assert_eq!(ledger.used, initial);
    assert_eq!(
        ledger
            .nodes
            .iter()
            .flatten()
            .filter(|node| node.issued)
            .count(),
        1
    );
}
