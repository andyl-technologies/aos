//! Bounded test-helper capture of actual Native cleanup transport observations.
//!
//! The capture is tied to the helper invocation's subscriber. It contains no
//! raw request, reply, key or credential, and it grants no cleanup permission.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;

const MAX_EVENTS: usize = 64;

#[derive(Clone, Default)]
pub(super) struct Capture(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    events: Vec<BTreeMap<String, String>>,
    overflow: bool,
    encoded_bytes: usize,
}

impl Capture {
    pub(super) fn snapshot(&self) -> serde_json::Value {
        let state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        serde_json::json!({
            "version": 1,
            "scope": "actual_native_managed_cleanup_transport",
            "complete": !state.overflow,
            "events": state.events,
        })
    }
}

impl<S: Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let message = fields.0.get("message").map(String::as_str).unwrap_or("");
        let selected = message.starts_with("managed_oci_cleanup_authenticated ")
            || message
                .strip_prefix("storage_final_sql_checked ")
                .is_some_and(|encoded| {
                    serde_json::from_str::<serde_json::Value>(encoded).is_ok_and(|value| {
                        value["contextKind"] == "managed_oci_cleanup_delete_checked"
                    })
                })
            || (message == "hybrid storage exchange accounting"
                && fields
                    .0
                    .get("operation")
                    .is_some_and(|operation| operation == "managed_oci_cleanup"));
        if !selected {
            return;
        }
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let length = serde_json::to_vec(&fields.0)
            .map(|encoded| encoded.len())
            .unwrap_or(32 * 1024);
        if state.events.len() == MAX_EVENTS
            || state.encoded_bytes.saturating_add(length) > 32 * 1024
        {
            state.overflow = true;
            return;
        }
        state.encoded_bytes += length;
        // The ignored helper uses --nocapture, so actual failures retain these
        // bounded rows even when its final success receipt cannot be written.
        if let Ok(encoded) = serde_json::to_string(&fields.0) {
            println!("managed_cleanup_helper_observation {encoded}");
        }
        state.events.push(fields.0);
    }
}

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}
