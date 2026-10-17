//! Delivery ledger sharing, pruning, and canonical encoding tests.

use super::super::*;
use super::DeliveryLedger;
use crucible_device::FrameDeliveryKey;

fn node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}

fn delivery(icount: u64, seq: u32, published: bool) -> (FrameDeliveryKey, ImportedIoDelivery) {
    let physical = FrameDeliveryKey {
        delivery_icount: icount,
        src_node: 3,
        seq,
    };
    let disk = node("disk", SchedulingNodeKind::Disk);
    let consumer = node("a", SchedulingNodeKind::Vm);
    let at = SimInstant { ticks: icount };
    let completion = IoCompletion {
        sub_node: disk.clone(),
        target: consumer.node.clone(),
        delivery_tick: at,
        source_delivery: physical,
        payload: vec![u8::try_from(seq % 251).unwrap_or_default()],
    };
    let key = ScheduledEventKey::new(
        SharedTimelineKey {
            virtual_time: at,
            node: consumer,
            sequence: u64::from(seq),
        },
        disk,
    );
    (
        physical,
        ImportedIoDelivery {
            completion,
            key,
            published,
        },
    )
}

/// Builds a ledger by importing every entry and then publishing some of them.
fn ledger(entries: &[(u64, u32, bool)]) -> DeliveryLedger {
    let mut ledger = DeliveryLedger::default();
    for &(icount, seq, _) in entries {
        let (physical, live) = delivery(icount, seq, false);
        ledger.insert_live(physical, live);
    }
    for &(icount, seq, published) in entries {
        if published {
            assert!(ledger.retire(&delivery(icount, seq, true).0));
        }
    }
    ledger
}

fn owned(entries: &[(u64, u32, bool)]) -> BTreeMap<FrameDeliveryKey, ImportedIoDelivery> {
    entries
        .iter()
        .map(|&(icount, seq, published)| delivery(icount, seq, published))
        .collect()
}

fn cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .unwrap_or_else(|error| panic!("ledger encoding: {error}"));
    bytes
}

#[test]
fn split_ledger_encodes_byte_identically_to_one_ordered_map_and_round_trips() {
    // Live and retired keys interleave so the merge order is exercised.
    let entries = [
        (5, 1, true),
        (5, 2, false),
        (7, 0, true),
        (9, 4, false),
        (9, 5, true),
        (12, 0, false),
    ];
    let ledger = ledger(&entries);

    let bytes = cbor(&ledger);
    assert_eq!(bytes, cbor(&owned(&entries)));

    let decoded: DeliveryLedger = ciborium::de::from_reader(bytes.as_slice())
        .unwrap_or_else(|error| panic!("ledger decoding: {error}"));
    assert_eq!(decoded, ledger);
    assert_eq!(cbor(&DeliveryLedger::default()), cbor(&owned(&[])));
}

#[test]
fn clones_share_retired_deliveries_until_one_publishes() {
    let base = ledger(&[(4, 0, true), (6, 0, true), (8, 0, false)]);
    let mut staged = base.clone();
    assert!(staged.shares_retired_with(&base));

    assert!(staged.retire(&delivery(8, 0, true).0));

    assert!(!staged.shares_retired_with(&base));
    assert_eq!(base, ledger(&[(4, 0, true), (6, 0, true), (8, 0, false)]));
    assert_eq!(staged, ledger(&[(4, 0, true), (6, 0, true), (8, 0, true)]));
    assert!(!staged.retire(&delivery(8, 0, true).0));
    assert!(!staged.retire(&delivery(99, 0, true).0));
}

#[test]
fn prune_drops_only_published_deliveries_below_the_floor() {
    let mut pruned = ledger(&[
        (3, 0, true),
        (3, 1, false),
        (5, 0, true),
        (6, 0, true),
        (6, 1, false),
    ]);
    let untouched = pruned.clone();

    pruned.prune_retired_below(3);
    assert!(pruned.shares_retired_with(&untouched));

    pruned.prune_retired_below(6);
    assert_eq!(
        pruned,
        ledger(&[(3, 1, false), (6, 0, true), (6, 1, false)])
    );
    assert_eq!(pruned.len(), 3);
    assert_eq!(untouched.len(), 5);
}
