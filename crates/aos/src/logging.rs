//! Minimal stderr tracing subscriber for `aos serve`.
//!
//! `aos-server` is richly instrumented with `tracing::{info,warn,error}!`,
//! but the `aos` binary links no `tracing-subscriber`. With no subscriber
//! installed, every event is dropped on the floor — so the daemon's
//! request logs never reach `journald`.
//!
//! This module installs a small log-only `Subscriber`: no span storage,
//! no ANSI, INFO and above. Each event becomes a single
//! `LEVEL target: message k=v ...` line on stderr, which systemd-journald
//! captures for the `aos serve` unit. It deliberately avoids pulling in
//! `tracing-subscriber` (an extra vendored dependency) for what the
//! server needs: plain line-oriented logs.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber, span};

/// Install the stderr subscriber as the global default.
///
/// A second call is a no-op — `set_global_default` fails once a default
/// is already set, and we swallow that error.
pub fn init() {
    let _ = tracing::subscriber::set_global_default(StderrSubscriber::default());
}

#[derive(Default)]
struct StderrSubscriber {
    next_span: AtomicU64,
}

impl Subscriber for StderrSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // INFO and above — drop DEBUG/TRACE so request logs stay legible.
        *metadata.level() <= Level::INFO
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        // Spans aren't tracked; hand out unique, non-zero ids.
        let id = self.next_span.fetch_add(1, Ordering::Relaxed) + 1;
        span::Id::from_u64(id)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}
    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}
    fn enter(&self, _span: &span::Id) {}
    fn exit(&self, _span: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let mut line = String::with_capacity(128);
        let _ = write!(line, "{} {}:", meta.level(), meta.target());
        if !visitor.message.is_empty() {
            let _ = write!(line, " {}", visitor.message);
        }
        line.push_str(&visitor.fields);
        eprintln!("{line}");
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: String,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }
}
