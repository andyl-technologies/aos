//! Trigger unit tests separated from production condition and event-graph code.

use std::collections::BTreeMap;

use super::*;
use crate::model::RngDecision;
use crate::scheduler::EventDiagnosticPayload;

#[test]
fn causal_projection_comparison_ignores_observational_entries() {
    let causal = SchedulerEventLogEntry::with_payload_for_test(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("causal-projection"),
            value: 11,
        })),
    );
    let diagnostic = SchedulerEventLogEntry::with_payload_for_test(
        1,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            "executor.poll",
            EventLevel::Warn,
            BTreeMap::new(),
        )),
    );

    let expected = vec![causal.clone()];
    let reproduced = vec![diagnostic, causal];

    assert_ne!(expected, reproduced);
    assert!(event_log_causal_projections_match(&expected, &reproduced));
}

#[test]
fn facts_through_point_preserves_resumed_event_log_base_sequence() {
    let first = SchedulerEventLogEntry::with_payload_for_test(
        5,
        VirtualTime { ticks: 5 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("resumed-prefix-a"),
            value: 17,
        })),
    );
    let second = SchedulerEventLogEntry::with_payload_for_test(
        6,
        VirtualTime { ticks: 7 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("resumed-prefix-b"),
            value: 23,
        })),
    );
    let prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries_with_base(
        vec![first.clone(), second],
        5,
    )
    .expect("resumed nonzero event-log sequence should build");

    let through_first = prefix
        .with_facts_through_point(EventEvaluationPoint::event_log_entry(&first))
        .expect("resumed prefix through first entry should be retained");

    assert_eq!(through_first.scheduler_entries.len(), 1);
    assert_eq!(through_first.scheduler_entries[0].sequence(), 5);
    assert_eq!(through_first.base_sequence, 5);
    assert_eq!(through_first.event_log_offset().events, 6);
}
