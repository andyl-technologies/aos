//! Cross-codec conformance between production event encoding and diagnostics.

use crucible::{EventLog, Icount, MarkerId, NodeId, NodeLifecycle, ObservableEvent, VirtualTime};
use crucible_harness::native_event_segment;
use std::error::Error;

#[test]
fn collector_decodes_production_node_state_and_guest_marker() -> Result<(), Box<dyn Error>> {
    let node = NodeId {
        name: String::from("guest"),
    };
    let node_state = ObservableEvent::node_state(
        VirtualTime { ticks: 41 },
        node.clone(),
        NodeLifecycle::Started,
    );
    let guest_marker = ObservableEvent::guest_marker(
        Icount { retired: 42 },
        node,
        MarkerId::from_name("guest-ready"),
    );
    let entries = vec![
        crucible::test_support::condition_observation_entry_for_test(0, &node_state),
        crucible::test_support::condition_observation_entry_for_test(1, &guest_marker),
    ];
    let encoded = EventLog::new().append_entries(entries)?.segment_bytes;

    let decoded = native_event_segment::decode(&encoded, 2).map_err(std::io::Error::other)?;

    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].kind, "node_state");
    assert_eq!(decoded[0].sequence, 0);
    assert_eq!(decoded[0].virtual_ticks, 41);
    assert_eq!(decoded[1].kind, "guest_marker");
    assert_eq!(decoded[1].sequence, 1);
    assert_eq!(decoded[1].icount_retired, 42);
    assert!(
        decoded[1]
            .material
            .contains("event_payload.attribute.marker.value.value=guest-ready")
    );

    Ok(())
}
