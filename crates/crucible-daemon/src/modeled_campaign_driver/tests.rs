//! Golden campaign evidence retained across the semantic driver extraction.

use super::savepoint_event_prefix_digest;

#[test]
fn empty_event_prefix_retains_the_legacy_campaign_digest() {
    // Captured with the parent revision's savepoint prefix domain and encoding.
    // Moving the semantic driver must not invalidate existing checkpoint proofs.
    assert_eq!(
        savepoint_event_prefix_digest(&[]),
        [
            77, 204, 100, 231, 244, 198, 100, 23, 247, 197, 122, 227, 214, 12, 83, 238, 28, 43, 35,
            100, 61, 199, 225, 220, 87, 23, 161, 162, 195, 211, 14, 43,
        ],
    );
}

#[test]
fn retained_event_prefix_preserves_sequence_and_content_commitment() {
    let entries = [
        crucible::SchedulerEventLogEntry::execution_budget_exhausted(
            0,
            crucible::VirtualTime { ticks: 200 },
            "execution-quanta",
        ),
        crucible::SchedulerEventLogEntry::execution_budget_exhausted(
            1,
            crucible::VirtualTime { ticks: 400 },
            "virtual-time",
        ),
    ];

    // The parent revision commits to the count, sequence and content of both
    // entries under this digest. No backend-specific evidence is constructed.
    assert_eq!(
        savepoint_event_prefix_digest(&entries),
        [
            98, 134, 222, 189, 159, 44, 203, 5, 87, 136, 42, 70, 149, 254, 184, 96, 91, 71, 183,
            51, 165, 88, 187, 72, 96, 197, 61, 229, 154, 56, 212, 240,
        ],
    );
}
