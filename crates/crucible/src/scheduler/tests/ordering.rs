//! Canonical scheduled-event ordering checks.

use super::*;

#[test]
fn scheduled_event_keys_define_total_order() {
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let mut keys = [
        event_key(2, &vm_b, &vm_a, 0),
        event_key(1, &vm_b, &disk_a, 1),
        event_key(1, &vm_a, &disk_a, 2),
        event_key(1, &vm_a, &disk_a, 1),
    ];

    keys.sort();

    assert_eq!(
        keys,
        [
            event_key(1, &vm_a, &disk_a, 1),
            event_key(1, &vm_a, &disk_a, 2),
            event_key(1, &vm_b, &disk_a, 1),
            event_key(2, &vm_b, &vm_a, 0),
        ]
    );
}
