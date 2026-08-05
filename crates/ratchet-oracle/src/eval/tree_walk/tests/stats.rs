//! Tree-walk evaluator tests: mirrored statistics.

use std::sync::{Arc, Mutex};

use crate::runtime::alloc::RuntimeAllocatorTier;

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

fn assert_trace_field(event: &str, field: &str) {
    let prefix = format!("{field}=");
    assert!(
        event
            .split_whitespace()
            .any(|recorded| recorded.starts_with(&prefix)),
        "missing trace field {field}: {event}"
    );
}

fn assert_trace_field_value(event: &str, field: &str, value: u64) {
    let expected = format!("{field}={value}");
    assert!(
        event
            .split_whitespace()
            .any(|recorded| recorded == expected),
        "missing trace field value {expected}: {event}"
    );
}

#[test]
fn eval_outcome_reports_mirrored_stats() {
    let outcome =
        eval_whnf_owned(&lower("let x = 1 + 1; in x + x")).expect("thunked expression evaluates");
    let stats = outcome.stats();
    let worker_stats = outcome.heap().arena_stats();
    let permanent_stats = outcome.heap().permanent_arena_stats();

    assert_eq!(
        outcome.heap().allocator_tier(),
        RuntimeAllocatorTier::TierAOneShot
    );
    assert_eq!(
        outcome.heap().permanent_allocator_tier(),
        RuntimeAllocatorTier::PermanentShared
    );
    assert!(stats.thunks_allocated() > 0);
    assert!(stats.thunks_forced() > 0);
    assert_eq!(stats.heap_chunks(), worker_stats.chunks as u64);
    assert_eq!(
        stats.heap_reserved_bytes(),
        worker_stats.reserved_bytes as u64
    );
    assert_eq!(stats.heap_mapped_bytes(), worker_stats.mapped_bytes as u64);
    assert_eq!(stats.heap_used_bytes(), worker_stats.used_bytes as u64);
    assert_eq!(stats.permanent_heap_chunks(), permanent_stats.chunks as u64);
    assert_eq!(
        stats.permanent_heap_reserved_bytes(),
        permanent_stats.reserved_bytes as u64
    );
    assert_eq!(
        stats.permanent_heap_mapped_bytes(),
        permanent_stats.mapped_bytes as u64
    );
    assert_eq!(
        stats.permanent_heap_used_bytes(),
        permanent_stats.used_bytes as u64
    );
    assert_eq!(stats.heap_tier_b_admission_worker_records(), 0);
    assert_eq!(stats.heap_tier_b_admission_permanent_shared_records(), 0);
    assert_eq!(stats.heap_tier_b_admission_generation_rewrites(), 0);
    assert!(worker_stats.chunks > 0);
    assert!(worker_stats.mapped_bytes >= worker_stats.reserved_bytes);
    assert!(worker_stats.reserved_bytes >= worker_stats.used_bytes);
    assert!(worker_stats.used_bytes > 0);
    assert!(permanent_stats.mapped_bytes >= permanent_stats.reserved_bytes);
    assert!(permanent_stats.reserved_bytes >= permanent_stats.used_bytes);
    assert_eq!(stats.thunks_elided(), 0);
    assert_eq!(stats.force_cache_suppressed_lexical_alias_thunks(), 0);
    assert_eq!(stats.force_cache_suppressed_local_var_alias_thunks(), 0);
    assert_eq!(stats.force_cache_suppressed_upval_var_alias_thunks(), 0);
    assert_eq!(stats.absent_formal_missing_default_candidates(), 0);
    assert_eq!(stats.absent_formal_selected_value_candidates(), 0);
    assert_eq!(stats.absent_formal_missing_required(), 0);
    assert_eq!(stats.absent_formal_alias_declines(), 0);
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
    assert!(stats.source_thunk_region_plan_decisions() > 0);
    assert_eq!(
        stats.source_thunk_region_plan_lexical_subregion_decisions(),
        0
    );
    assert_eq!(
        stats.source_thunk_region_plan_conservative_fallbacks(),
        stats.source_thunk_region_plan_decisions()
    );
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
    assert_trace_field(stats_event, "thunks_allocated");
    assert_trace_field(stats_event, "thunks_forced");
    assert_trace_field(stats_event, "force_cache_suppressed_lexical_alias_thunks");
    assert_trace_field(stats_event, "force_cache_suppressed_local_var_alias_thunks");
    assert_trace_field(stats_event, "force_cache_suppressed_upval_var_alias_thunks");
    assert_trace_field(stats_event, "absent_formal_missing_default_candidates");
    assert_trace_field(stats_event, "absent_formal_selected_value_candidates");
    assert_trace_field(stats_event, "absent_formal_missing_required");
    assert_trace_field(stats_event, "absent_formal_alias_declines");
    assert_trace_field(stats_event, "force_cache_hits");
    assert_trace_field(stats_event, "force_cache_misses");
    assert_trace_field(stats_event, "force_cache_probes");
    assert_trace_field(stats_event, "force_cache_memoization_admits");
    assert_trace_field(stats_event, "force_cache_memoization_bypasses");
    assert_trace_field(stats_event, "force_cache_memoization_demands");
    assert_trace_field(stats_event, "force_cache_materialization_materializes");
    assert_trace_field(stats_event, "force_cache_materialization_keeps_in_memory");
    assert_trace_field(stats_event, "force_cache_materialization_decisions");
    assert_trace_field(stats_event, "source_thunk_region_plan_decisions");
    assert_trace_field(
        stats_event,
        "source_thunk_region_plan_lexical_subregion_decisions",
    );
    assert_trace_field(
        stats_event,
        "source_thunk_region_plan_conservative_fallbacks",
    );
    assert_trace_field(stats_event, "cache_hits");
    assert_trace_field_value(stats_event, "early_cutoffs", 0);
    assert_trace_field_value(stats_event, "derivation_aterm_path_reuses", 0);
    assert_trace_field_value(stats_event, "static_derivation_output_path_reuses", 0);
    assert_trace_field_value(stats_event, "derivation_hash_calculations", 0);
    assert_trace_field_value(stats_event, "derivation_text_path_calculations", 0);
    assert_trace_field(stats_event, "heap_chunks");
    assert_trace_field(stats_event, "heap_reserved_bytes");
    assert_trace_field(stats_event, "heap_mapped_bytes");
    assert_trace_field(stats_event, "heap_used_bytes");
    assert_trace_field(stats_event, "permanent_heap_chunks");
    assert_trace_field(stats_event, "permanent_heap_reserved_bytes");
    assert_trace_field(stats_event, "permanent_heap_mapped_bytes");
    assert_trace_field(stats_event, "permanent_heap_used_bytes");
    assert_trace_field(stats_event, "heap_tier_b_admission_worker_records");
    assert_trace_field(
        stats_event,
        "heap_tier_b_admission_permanent_shared_records",
    );
    assert_trace_field(stats_event, "heap_tier_b_admission_generation_rewrites");
}
