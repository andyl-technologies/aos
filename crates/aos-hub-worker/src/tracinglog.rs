//! Forwards `tracing` events to the Workers runtime console.
//!
//! The shared [`aos_hub_core`] request handlers report failures with
//! `tracing::error!` (e.g. `aos_hub_core::web::console::internal`), but the
//! Workers runtime installs no `tracing` subscriber, so those events were
//! dropped: a `500` reached the client with no server-side trace, invisible even
//! to `wrangler tail`. [`init`] installs a process-global subscriber that
//! forwards each event to `console.error` / `console.warn` / `console.log` by
//! level, so handler errors are captured in Workers Logs once the deployment has
//! `[observability]` enabled (see `aos-hub worker --observability`).
//!
//! The subscriber is intentionally minimal — it records the level, target, the
//! `message`, and any structured fields, and ignores spans (the hub's handlers
//! log flat events, not span trees). It is not a substitute for a full
//! `tracing-subscriber`; it is the smallest bridge that makes production errors
//! observable on wasm without pulling a timestamp-dependent formatter (the
//! `wasm32-unknown-unknown` target has no wall clock).

use std::fmt::Write as _;
use std::sync::Once;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

static INIT: Once = Once::new();

/// Installs the console-forwarding subscriber once per isolate.
///
/// Idempotent and cheap to call on every request (guarded by a [`Once`]). A
/// failure to set the global default (e.g. one is already installed) is ignored
/// so initialization never aborts request handling.
pub fn init() {
    INIT.call_once(|| {
        let _ = tracing::subscriber::set_global_default(ConsoleSubscriber);
    });
}

/// A `tracing` [`Subscriber`] that writes each event to the Workers console.
struct ConsoleSubscriber;

impl Subscriber for ConsoleSubscriber {
    fn enabled(&self, _meta: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
        // Spans are not tracked; hand back a constant id.
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let mut line = format!("{} {}: ", meta.level(), meta.target());
        event.record(&mut MessageVisitor { line: &mut line });
        match *meta.level() {
            Level::ERROR => worker::console_error!("{line}"),
            Level::WARN => worker::console_warn!("{line}"),
            _ => worker::console_log!("{line}"),
        }
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Appends an event's `message` and structured fields to a console line.
///
/// The primary `message` field is written bare; every other field is appended as
/// ` name=value` so structured context survives into the log line.
struct MessageVisitor<'a> {
    line: &'a mut String,
}

impl Visit for MessageVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.line, "{value:?}");
        } else {
            let _ = write!(self.line, " {}={value:?}", field.name());
        }
    }
}
