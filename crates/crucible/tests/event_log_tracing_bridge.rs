//! Checks T-OBS-12 `tracing` bridge non-perturbation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crucible::{
    Decision, EventAttributeValue, EventClass, EventDiagnosticPayload, EventLevel, EventLog,
    RngDecision, RngStreamId, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry,
    SchedulerEventLogPayload, TracingBridge, TracingBridgeConfig, VirtualTime,
    compare_event_log_determinism, event_log_causal_projection,
};
use tracing::dispatcher::{self, Dispatch};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

#[test]
fn tracing_bridge_is_disabled_by_default() {
    let bridge = TracingBridge::default();

    assert!(!bridge.is_enabled());
    assert_eq!(
        bridge.mirror_diagnostic(
            0,
            time(0),
            EventDiagnosticPayload::new("default.off", EventLevel::Info, BTreeMap::new()),
        ),
        None
    );
    assert_eq!(
        TracingBridgeConfig::default(),
        TracingBridgeConfig::disabled()
    );
}

#[test]
fn tracing_bridge_entries_are_observational_diagnostics() {
    let mut details = BTreeMap::new();
    details.insert(String::from("polls"), EventAttributeValue::U64(7));
    let entry = TracingBridge::enabled()
        .mirror_diagnostic(
            0,
            time(3),
            EventDiagnosticPayload::new("tracing.bridge", EventLevel::Warn, details),
        )
        .unwrap_or_else(|| panic!("enabled bridge should produce a diagnostic entry"));

    assert_eq!(entry.class(), EventClass::Observational);
    assert_eq!(entry.source(), &crucible::EventSource::Engine);
    assert_eq!(entry.level(), EventLevel::Warn);
    assert_eq!(entry.event_payload().kind(), "diagnostic");
    assert_eq!(entry.event_payload().string("name"), Some("tracing.bridge"));
    assert_eq!(entry.event_payload().u64("polls"), Some(7));
    assert!(entry.has_valid_content_hash());
}

#[test]
fn tracing_subscriber_modes_do_not_change_causal_subsequence() {
    let disabled = bridge_run_entries(TracingBridge::disabled());
    let no_subscriber = bridge_run_entries(TracingBridge::enabled());
    let captured_events = Arc::new(Mutex::new(Vec::new()));
    let capturing_dispatch = Dispatch::new(CaptureSubscriber {
        captures_events: true,
        events: Arc::clone(&captured_events),
    });
    let capturing = dispatcher::with_default(&capturing_dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        bridge_run_entries(TracingBridge::enabled())
    });
    let filtered_events = Arc::new(Mutex::new(Vec::new()));
    let filtering_dispatch = Dispatch::new(CaptureSubscriber {
        captures_events: false,
        events: Arc::clone(&filtered_events),
    });
    let filtering = dispatcher::with_default(&filtering_dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        bridge_run_entries(TracingBridge::enabled())
    });

    assert!(
        !captured_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    );
    assert!(
        filtered_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    );
    assert_eq!(disabled.len(), 2);
    assert_eq!(no_subscriber.len(), 3);
    assert_eq!(capturing, no_subscriber);
    assert_eq!(filtering, no_subscriber);

    let no_subscriber_projection = event_log_causal_projection(&no_subscriber);
    assert_eq!(
        event_log_causal_projection(&disabled).canonical_bytes(),
        no_subscriber_projection.canonical_bytes()
    );
    assert_eq!(
        event_log_causal_projection(&capturing).canonical_bytes(),
        no_subscriber_projection.canonical_bytes()
    );
    assert_eq!(
        event_log_causal_projection(&filtering).canonical_bytes(),
        no_subscriber_projection.canonical_bytes()
    );
    assert!(compare_event_log_determinism(&disabled, &no_subscriber).passes());
    assert!(compare_event_log_determinism(&no_subscriber, &capturing).passes());
    assert!(compare_event_log_determinism(&no_subscriber, &filtering).passes());

    let mut log = EventLog::new();
    let append = log
        .append_entries(no_subscriber)
        .unwrap_or_else(|error| panic!("tracing bridge entries should append: {error}"));
    assert_eq!(append.offset.events, 3);
    assert!(append.segment_text.contains("entry.class=observational"));
    assert!(
        append
            .segment_text
            .contains("event_payload.kind=diagnostic")
    );
}

#[test]
fn tracing_subscriber_panics_do_not_escape_bridge() {
    let no_subscriber = bridge_run_entries(TracingBridge::enabled());
    let panicking_dispatch = Dispatch::new(PanickingSubscriber);
    let panicking = dispatcher::with_default(&panicking_dispatch, || {
        bridge_run_entries(TracingBridge::enabled())
    });

    assert_eq!(panicking, no_subscriber);
    assert_eq!(
        event_log_causal_projection(&panicking).canonical_bytes(),
        event_log_causal_projection(&no_subscriber).canonical_bytes()
    );
    assert!(compare_event_log_determinism(&no_subscriber, &panicking).passes());
}

fn bridge_run_entries(bridge: TracingBridge) -> Vec<SchedulerEventLogEntry> {
    let mut entries = Vec::new();
    let mut sequence = 0_u64;

    entries.push(rng_entry(sequence, 1));
    sequence = sequence.saturating_add(1);

    let mut details = BTreeMap::new();
    details.insert(
        String::from("worker"),
        EventAttributeValue::String(String::from("bridge")),
    );
    if let Some(entry) = bridge.mirror_diagnostic(
        sequence,
        time(1),
        EventDiagnosticPayload::new("tracing.bridge", EventLevel::Debug, details),
    ) {
        entries.push(entry);
        sequence = sequence.saturating_add(1);
    }

    entries.push(boundary_entry(sequence, 2));
    entries
}

fn rng_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("tracing-bridge-causal"),
            value: 41,
        })),
    )
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

#[derive(Debug)]
struct CaptureSubscriber {
    captures_events: bool,
    events: Arc<Mutex<Vec<String>>>,
}

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        self.captures_events
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        events.push(format!(
            "{}:{}",
            event.metadata().target(),
            event.metadata().level()
        ));
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Debug)]
struct PanickingSubscriber;

impl Subscriber for PanickingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {
        panic!("tracing subscriber panic should not escape bridge");
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}
