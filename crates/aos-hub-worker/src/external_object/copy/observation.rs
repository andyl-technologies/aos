//! Opt-in do-e2e facts about one authenticated Copy invocation's local resources.
//!
//! Records describe participating pool markers, actual bytes/EOF, native abort
//! callbacks and local ownership release. They do not prove remote provider
//! drain, SQL cancellation, physical settlement, or other isolate activity.
//! A missing terminal or unhealthy bracket remains incomplete.
//!
//! ```json
//! {"version":1,"capture_id":"0123456789abcdef0123456789abcdef","source_prefix":"selected/source","destination_prefixes":["selected/destination"]}
//! ```
//!
//! Each bounded log record has version/scope/capture_id/trace_id/ordinal,
//! original_sha256/request_sha256/role/observed_at and a closed event. No keys,
//! credentials, provider versions, request bodies or lease tokens are logged.

use std::{cell::Cell, rc::Rc};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::direct_upload::provider_capacity::{self, Observation};

const MAX_CONFIGURATION_BYTES: usize = 4096;
const MAX_RECORD_BYTES: usize = 4096;
const MAX_RECORDS: usize = 12;
const MAX_TRACE_BYTES: usize = 32 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    version: u32,
    capture_id: String,
    source_prefix: String,
    destination_prefixes: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    DestinationExecutor,
    SourceGuard,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    Entry {
        pool: Observation,
    },
    Admission {
        owned_slots: u8,
        pool: Observation,
    },
    Transfer {
        ticket_id: String,
        origin_isolate: String,
        pool_generation: String,
        request_digest: String,
    },
    SourceProgress {
        bytes: u64,
        eof: bool,
    },
    Cleanup {
        cause: &'static str,
        owned_capacity_released: bool,
        source_gate_released: bool,
        native_cleanup_invocations: usize,
        pool: Observation,
    },
    Terminal {
        outcome: &'static str,
        healthy: bool,
        pool: Observation,
    },
}

/// Retains a bounded bracket without changing any authenticated operation.
pub(super) struct Trace {
    capture_id: String,
    trace_id: String,
    original_sha256: String,
    request_sha256: String,
    role: Role,
    sink: Rc<dyn Fn(&str) -> bool>,
    ordinal: Cell<usize>,
    bytes: Cell<usize>,
    healthy: Cell<bool>,
    finished: Cell<bool>,
    first_progress: Cell<bool>,
    eof: Cell<bool>,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.bytes().any(|b| b.is_ascii_control())
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

impl Trace {
    fn selected(
        raw: &str,
        source: &str,
        destination: &str,
        original_sha256: String,
        request_sha256: String,
        role: Role,
        sink: Rc<dyn Fn(&str) -> bool>,
    ) -> Option<Rc<Self>> {
        if raw.len() > MAX_CONFIGURATION_BYTES {
            return None;
        }
        let selection: Selection = serde_json::from_str(raw).ok()?;
        let unique: std::collections::BTreeSet<_> = selection.destination_prefixes.iter().collect();
        if selection.version != 1
            || selection.capture_id.len() != 32
            || !selection
                .capture_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !prefix(&selection.source_prefix)
            || !(1..=4).contains(&selection.destination_prefixes.len())
            || unique.len() != selection.destination_prefixes.len()
            || !selection
                .destination_prefixes
                .iter()
                .all(|value| prefix(value) && value != source)
            || selection.source_prefix != source
            || !selection
                .destination_prefixes
                .iter()
                .any(|value| value == destination)
            || !sha256(&original_sha256)
            || !sha256(&request_sha256)
        {
            return None;
        }
        let trace = Rc::new(Self {
            capture_id: selection.capture_id,
            trace_id: uuid::Uuid::new_v4().to_string(),
            original_sha256,
            request_sha256,
            role,
            sink,
            ordinal: Cell::new(0),
            bytes: Cell::new(0),
            healthy: Cell::new(true),
            finished: Cell::new(false),
            first_progress: Cell::new(false),
            eof: Cell::new(false),
        });
        trace.emit(Event::Entry {
            pool: provider_capacity::observation(),
        });
        Some(trace)
    }

    #[cfg(target_arch = "wasm32")]
    /// Selects the exact authenticated prefixes without changing admission.
    pub(super) fn from_env(
        env: &worker::Env,
        original: &aos_hub_core::storage_authority::external_object::copy::ExternalCopyOriginal,
        request: &[u8],
        role: Role,
    ) -> Option<Rc<Self>> {
        let raw = env
            .var("HUB_EXTERNAL_COPY_LIFETIME_OBSERVER")
            .ok()?
            .to_string();
        Self::selected(
            &raw,
            &original.source.prefix,
            &original.destination.prefix,
            original.fingerprint().ok()?,
            digest(request),
            role,
            Rc::new(|body| {
                worker::console_log!("external_copy_lifetime_observer {}", body);
                true
            }),
        )
    }

    fn emit(&self, event: Event) {
        let ordinal = self.ordinal.get().saturating_add(1);
        self.ordinal.set(ordinal);
        let record = serde_json::json!({
            "version": 1, "scope": "external_copy_local_lifetime",
            "capture_id": self.capture_id, "trace_id": self.trace_id,
            "ordinal": ordinal, "original_sha256": self.original_sha256,
            "request_sha256": self.request_sha256, "role": self.role,
            "observed_at": aos_hub_core::clock::now_unix_secs(), "event": event,
        });
        let Ok(body) = serde_json::to_string(&record) else {
            self.healthy.set(false);
            return;
        };
        let next = self.bytes.get().checked_add(body.len());
        if ordinal > MAX_RECORDS
            || body.len() > MAX_RECORD_BYTES
            || next.is_none_or(|value| value > MAX_TRACE_BYTES)
        {
            self.healthy.set(false);
            return;
        }
        self.bytes.set(next.unwrap_or(MAX_TRACE_BYTES));
        if !(self.sink)(&body) {
            self.healthy.set(false);
        }
    }

    /// Records the actual participating pool beside the retained local admission.
    pub(super) fn admitted(&self, owned_slots: u8) {
        self.emit(Event::Admission {
            owned_slots,
            pool: provider_capacity::observation(),
        });
    }

    /// Records the actual one-use ticket without consuming or granting capacity.
    pub(super) fn transfer(&self, ticket: &provider_capacity::transfer::Ticket) {
        self.emit(Event::Transfer {
            ticket_id: ticket.ticket_id.clone(),
            origin_isolate: ticket.origin_isolate.clone(),
            pool_generation: ticket.pool_generation.clone(),
            request_digest: ticket.request_digest.clone(),
        });
    }

    /// Records first bounded progress and actual EOF without asserting settlement.
    pub(super) fn progress(&self, bytes: u64, eof: bool) {
        self.eof.set(eof);
        if eof || bytes >= 65536 && !self.first_progress.replace(true) {
            self.emit(Event::SourceProgress { bytes, eof });
        }
    }

    /// Records local releases and actual registered cleanup method invocations.
    pub(super) fn cleanup(&self, cause: &'static str, capacity: bool, gate: bool, native: usize) {
        self.emit(Event::Cleanup {
            cause,
            owned_capacity_released: capacity,
            source_gate_released: gate,
            native_cleanup_invocations: native,
            pool: provider_capacity::observation(),
        });
        if self.role == Role::SourceGuard {
            self.finish(if self.eof.get() {
                "eof"
            } else if cause == "native_signal" {
                "incoming_abort"
            } else {
                "unknown"
            });
        } else if cause == "native_signal" {
            self.finish("incoming_abort");
        }
    }

    /// Closes the private bracket with an outcome, preserving incomplete recording.
    pub(super) fn finish(&self, outcome: &'static str) {
        if self.finished.replace(true) {
            return;
        }
        self.emit(Event::Terminal {
            outcome,
            healthy: self.healthy.get(),
            pool: provider_capacity::observation(),
        });
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        if !self.finished.get() {
            self.finish("unknown");
        }
    }
}

#[cfg(test)]
mod tests;
