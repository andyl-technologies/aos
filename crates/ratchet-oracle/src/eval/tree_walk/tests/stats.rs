//! Tree-walk evaluator tests: mirrored statistics.

use std::sync::{Arc, Mutex};

use super::*;
use tracing::field::{Field, Visit};
use tracing::metadata::LevelFilter;
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber, span};

#[derive(Clone)]
struct RecordingSubscriber {
    events: Arc<Mutex<Vec<String>>>,
}

impl Subscriber for RecordingSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "aos_nix::eval::stats" && *metadata.level() <= Level::DEBUG
    }

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if self.enabled(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::DEBUG)
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}
    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}
    fn enter(&self, _span: &span::Id) {}
    fn exit(&self, _span: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = EventFields::default();
        event.record(&mut visitor);
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(visitor.render());
    }
}

#[derive(Default)]
struct EventFields {
    message: String,
    fields: Vec<String>,
}

impl EventFields {
    fn render(self) -> String {
        let mut output = self.message;
        for field in self.fields {
            if !output.is_empty() {
                output.push(' ');
            }
            output.push_str(&field);
        }
        output
    }
}

impl Visit for EventFields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.push(format!("{}={value}", field.name()));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }
}

#[test]
fn eval_outcome_reports_mirrored_stats() {
    let outcome =
        eval_whnf_owned(&lower("let x = 1 + 1; in x + x")).expect("thunked expression evaluates");
    let stats = outcome.stats();

    assert!(stats.thunks_allocated() > 0);
    assert!(stats.thunks_forced() > 0);
    assert!(stats.heap_chunks() > 0);
    assert!(stats.heap_reserved_bytes() >= stats.heap_used_bytes());
    assert!(stats.heap_used_bytes() > 0);
    assert_eq!(stats.thunks_elided(), 0);
    assert_eq!(stats.inline_cache_hits(), 0);
    assert_eq!(stats.inline_cache_misses(), 0);
    assert_eq!(stats.shape_transitions(), 0);
    assert_eq!(stats.gc_bytes(), 0);
    assert_eq!(stats.gc_pause_us(), 0);
    assert_eq!(stats.tier_promotions(), 0);
    assert_eq!(stats.deopts(), 0);
    assert_eq!(stats.force_cache_hits(), 0);
    assert_eq!(stats.force_cache_misses(), 0);
    assert_eq!(stats.force_cache_probes(), 0);
    assert_eq!(stats.force_cache_memoization_admits(), 0);
    assert_eq!(stats.force_cache_memoization_bypasses(), 0);
    assert_eq!(stats.force_cache_memoization_demands(), 0);
    assert_eq!(stats.force_cache_materialization_materializes(), 0);
    assert_eq!(stats.force_cache_materialization_keeps_in_memory(), 0);
    assert_eq!(stats.force_cache_materialization_decisions(), 0);
    assert_eq!(stats.early_cutoffs(), 0);
    assert_eq!(stats.derivation_aterm_path_reuses(), 0);
    assert_eq!(stats.static_derivation_output_path_reuses(), 0);
    assert_eq!(stats.derivation_hash_calculations(), 0);
    assert_eq!(stats.derivation_text_path_calculations(), 0);
}

#[test]
fn eval_stats_are_emitted_through_tracing() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let subscriber = RecordingSubscriber {
        events: Arc::clone(&events),
    };
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        TreeWalk::emit_stats_trace(&EvalStats::default());
    });
    tracing::callsite::rebuild_interest_cache();

    let events = events
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let stats_event = events
        .iter()
        .find(|event| event.contains("aos-nix tree-walk evaluation stats"))
        .expect("stats event recorded");
    assert!(stats_event.contains("thunks_allocated="));
    assert!(stats_event.contains("thunks_forced="));
    assert!(stats_event.contains("force_cache_hits="));
    assert!(stats_event.contains("force_cache_misses="));
    assert!(stats_event.contains("force_cache_probes="));
    assert!(stats_event.contains("force_cache_memoization_admits="));
    assert!(stats_event.contains("force_cache_memoization_bypasses="));
    assert!(stats_event.contains("force_cache_memoization_demands="));
    assert!(stats_event.contains("force_cache_materialization_materializes="));
    assert!(stats_event.contains("force_cache_materialization_keeps_in_memory="));
    assert!(stats_event.contains("force_cache_materialization_decisions="));
    assert!(stats_event.contains("cache_hits="));
    assert!(stats_event.contains("early_cutoffs=0"));
    assert!(stats_event.contains("derivation_aterm_path_reuses=0"));
    assert!(stats_event.contains("static_derivation_output_path_reuses=0"));
    assert!(stats_event.contains("derivation_hash_calculations=0"));
    assert!(stats_event.contains("derivation_text_path_calculations=0"));
    assert!(stats_event.contains("heap_used_bytes="));
}
