//! Opt-in, request-scoped observations of actual Managed GC R2 calls.
//!
//! A closed request brackets its actual awaited SDK calls. Unknown results,
//! dropped calls, recorder failure and overflow make the bracket incomplete.
//! The trace grants no provider permission and never changes an SDK result.
//! It covers the instrumented GC guard and inventory-range callers only.
//!
//! Each bounded private console record has this shape:
//!
//! ```json
//! {"version":1,"capture_id":"selected-32-hex-id","request_id":"actual-request-id",
//!  "scope":"managed_gc_guard","key":"actual-full-key","subject_id":"actual-action-id",
//!  "event":{"kind":"call_result","ordinal":1,"method":"head",
//!           "outcome":{"kind":"object","size":42,"etag":"strong-ETag","version":"R2-version"}}}
//! ```

use std::cell::Cell;
use std::rc::Rc;

use serde::{Deserialize, Serialize};

const MAX_CALLS: usize = 32;
const MAX_RECORD_BYTES: usize = 4_096;
const MAX_REQUEST_BYTES: usize = 256 * 1024;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
mod runtime;

mod inspection;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
pub(crate) use inspection::fetch as inspect_guard;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
pub(crate) use runtime::{from_env, record_js_result};

#[cfg(test)]
mod tests;

/// Limits observations to two explicitly instrumented request paths.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Scope {
    ManagedGcGuard,
    ManagedInventoryRange,
}

/// Identifies an actual SDK method invocation.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Method {
    Head,
    Get,
    Delete,
}

/// Reports SDK metadata or a genuinely unresolved outcome, never object bytes.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Outcome {
    Object {
        size: u64,
        etag: String,
        version: String,
    },
    Absent,
    Resolved,
    Unknown,
}

/// Selects a dedicated capture without conferring mutation authority.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    version: u32,
    capture_id: String,
    prefix: String,
}

impl Configuration {
    fn accepts(&self, key: &str, subject_id: &str, request_id: &str) -> bool {
        self.version == 1
            && self.capture_id.len() == 32
            && self
                .capture_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && !self.prefix.is_empty()
            && self.prefix.len() <= 512
            && !self.prefix.starts_with('/')
            && !self.prefix.ends_with('/')
            && self
                .prefix
                .split('/')
                .all(|part| !matches!(part, "" | "." | ".."))
            && !self.prefix.chars().any(char::is_control)
            && key.len() <= 512
            && key.starts_with(&format!("{}/", self.prefix))
            && !key.chars().any(char::is_control)
            && !subject_id.is_empty()
            && subject_id.len() <= 128
            && request_id.len() == 32
            && request_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    RequestEntry,
    CallInvoke {
        ordinal: usize,
        method: Method,
        range: Option<(u64, u64)>,
    },
    CallResult {
        ordinal: usize,
        method: Method,
        outcome: Outcome,
    },
    RequestTerminal {
        healthy: bool,
        invoked: usize,
        completed: usize,
        pending: usize,
    },
}

#[derive(Serialize)]
struct Record<'a> {
    version: u32,
    capture_id: &'a str,
    request_id: &'a str,
    scope: Scope,
    key: &'a str,
    subject_id: &'a str,
    event: Event,
}

struct Inner {
    configuration: Configuration,
    request_id: String,
    scope: Scope,
    key: String,
    subject_id: String,
    sink: Rc<dyn Fn(&str) -> bool>,
    invoked: Cell<usize>,
    completed: Cell<usize>,
    pending: Cell<usize>,
    bytes: Cell<usize>,
    healthy: Cell<bool>,
    finished: Cell<bool>,
}

impl Inner {
    fn emit(&self, event: Event, terminal: bool) {
        let record = Record {
            version: 1,
            capture_id: &self.configuration.capture_id,
            request_id: &self.request_id,
            scope: self.scope,
            key: &self.key,
            subject_id: &self.subject_id,
            event,
        };
        let Ok(body) = serde_json::to_string(&record) else {
            self.healthy.set(false);
            return;
        };
        let limit = if terminal {
            MAX_REQUEST_BYTES
        } else {
            MAX_REQUEST_BYTES - MAX_RECORD_BYTES
        };
        let Some(next_bytes) = self.bytes.get().checked_add(body.len()) else {
            self.healthy.set(false);
            return;
        };
        if body.len() > MAX_RECORD_BYTES || next_bytes > limit {
            self.healthy.set(false);
            return;
        }
        self.bytes.set(next_bytes);
        if !(self.sink)(&body) {
            self.healthy.set(false);
        }
    }

    fn terminal(&self, acknowledged: bool) {
        if self.finished.replace(true) {
            return;
        }
        let healthy = acknowledged && self.healthy.get() && self.pending.get() == 0;
        self.emit(
            Event::RequestTerminal {
                healthy,
                invoked: self.invoked.get(),
                completed: self.completed.get(),
                pending: self.pending.get(),
            },
            true,
        );
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.terminal(false);
    }
}

/// Retains an explicit request bracket without a mutable async current context.
#[derive(Clone)]
pub(crate) struct RequestTrace(Rc<Inner>);

impl RequestTrace {
    /// Opens only a bounded, explicitly selected observation scope.
    fn new(
        configuration: Configuration,
        request_id: String,
        scope: Scope,
        key: String,
        subject_id: String,
        sink: Rc<dyn Fn(&str) -> bool>,
    ) -> Option<Self> {
        if !configuration.accepts(&key, &subject_id, &request_id) {
            return None;
        }
        let inner = Rc::new(Inner {
            configuration,
            request_id,
            scope,
            key,
            subject_id,
            sink,
            invoked: Cell::new(0),
            completed: Cell::new(0),
            pending: Cell::new(0),
            bytes: Cell::new(0),
            healthy: Cell::new(true),
            finished: Cell::new(false),
        });
        inner.emit(Event::RequestEntry, false);
        Some(Self(inner))
    }

    /// Records one imminent SDK call; overflow leaves coverage incomplete.
    pub(crate) fn call(&self, method: Method) -> Option<Call> {
        self.call_selected(method, None)
    }

    /// Records the actual half-open SDK offset/length arguments of one GET.
    pub(crate) fn call_range(&self, offset: u64, length: u64) -> Option<Call> {
        self.call_selected(Method::Get, Some((offset, length)))
    }

    fn call_selected(&self, method: Method, range: Option<(u64, u64)>) -> Option<Call> {
        let Some(ordinal) = self.0.invoked.get().checked_add(1) else {
            self.0.healthy.set(false);
            return None;
        };
        self.0.invoked.set(ordinal);
        if self.0.finished.get() {
            self.0.healthy.set(false);
            // A late call must make the captured bracket visibly invalid too.
            self.0.emit(
                Event::CallInvoke {
                    ordinal,
                    method,
                    range,
                },
                false,
            );
            return None;
        }
        if ordinal > MAX_CALLS {
            self.0.healthy.set(false);
            return None;
        }
        self.0.pending.set(self.0.pending.get() + 1);
        self.0.emit(
            Event::CallInvoke {
                ordinal,
                method,
                range,
            },
            false,
        );
        Some(Call {
            trace: self.clone(),
            ordinal,
            method,
            finished: false,
        })
    }

    /// Closes an acknowledged request after its real terminal branch.
    pub(crate) fn finish(&self) {
        self.0.terminal(true);
    }
}

/// Retains an actual invocation until its result or dropped future is observed.
pub(crate) struct Call {
    trace: RequestTrace,
    ordinal: usize,
    method: Method,
    finished: bool,
}

impl Call {
    /// Records only the awaited SDK result; failures remain unknown.
    pub(crate) fn finish(mut self, outcome: Outcome) {
        self.record(outcome);
    }

    fn record(&mut self, outcome: Outcome) {
        if matches!(outcome, Outcome::Unknown) {
            self.trace.0.healthy.set(false);
        }
        self.finished = true;
        if let Some(pending) = self.trace.0.pending.get().checked_sub(1) {
            self.trace.0.pending.set(pending);
        } else {
            self.trace.0.healthy.set(false);
        }
        self.trace.0.completed.set(self.trace.0.completed.get() + 1);
        self.trace.0.emit(
            Event::CallResult {
                ordinal: self.ordinal,
                method: self.method,
                outcome,
            },
            false,
        );
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if !self.finished {
            self.record(Outcome::Unknown);
        }
    }
}
