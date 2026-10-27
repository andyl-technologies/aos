//! Tests the event-log budget diagnostic attribution.

use std::collections::BTreeMap;

use crucible_engine::{
    EventAttributeValue, EventLevel, EventLogTime, EventPayload, EventSource,
    SchedulerEventLogClass, SchedulerEventLogEntry, VirtualTime,
};

use super::event_log_budget_summary;

fn entry(
    sequence: u64,
    kind: &str,
    class: SchedulerEventLogClass,
    text: &str,
) -> SchedulerEventLogEntry {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("text"),
        EventAttributeValue::String(text.to_owned()),
    );
    SchedulerEventLogEntry::from_retained_open_event(
        sequence,
        EventLogTime::from_virtual_time(VirtualTime {
            ticks: 1_000 * sequence,
        }),
        EventSource::Engine,
        EventLevel::Info,
        class,
        EventPayload::new(kind, attributes),
    )
    .unwrap_or_else(|error| panic!("fixture event should build: {error}"))
}

#[test]
fn summary_ranks_event_kinds_by_retained_and_pending_bytes() {
    let console = entry(
        0,
        "console_output",
        SchedulerEventLogClass::Observational,
        &"x".repeat(4096),
    );
    let small = entry(1, "campaign_selection", SchedulerEventLogClass::Causal, "a");
    let pending = entry(
        2,
        "console_output",
        SchedulerEventLogClass::Observational,
        "b",
    );
    let console_bytes = console.canonical_material_len() + pending.canonical_material_len();
    let retained_bytes = console.canonical_material_len() + small.canonical_material_len();

    let summary = event_log_budget_summary(
        "fresh-campaign-event-log-bytes",
        &[console.clone(), small.clone()],
        std::slice::from_ref(&pending),
    );

    assert!(summary.starts_with(
        "CRUCIBLE-EVENT-LOG-BUDGET-EXHAUSTED-V1 limit=fresh-campaign-event-log-bytes retained_entries=2 "
    ));
    assert!(summary.contains(&format!(
        "retained_bytes={retained_bytes} pending_entries=1 "
    )));
    assert!(summary.contains("last_event_ps=2000 omitted_kinds=0 "));
    assert!(summary.contains(&format!(
        "kinds=[console_output:entries=2/bytes={console_bytes}/largest={},campaign_selection:entries=1/",
        console.canonical_material_len()
    )));
}
