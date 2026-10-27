//! Opt-in handler observations for the two original publication children.
//!
//! Fixed method groups disclose no request values. Handler spans include body
//! consumption, server work and response creation; concurrent sums are not
//! additive wall time, CPU time or network-only measurements. An unfinished
//! child may leave only first-request edges, which cannot identify a later
//! stalled request. Dropped or absent rows are unavailable evidence.
//!
//! Runtime-monotonic host spans follow the CLI observation clock. They do not
//! define guest deadlines, canonical time or authoritative publication evidence.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

use axum::http::{Method, StatusCode};

const ROW_LIMIT: usize = 32;
const ROW_BYTES: usize = 512;
const GROUPS: [&str; 10] = [
    "manifest_begin",
    "manifest_append",
    "manifest_seal",
    "upload_object",
    "multipart_begin",
    "upload_part",
    "multipart_complete",
    "commit",
    "get",
    "parent_list",
];

#[derive(Clone, Copy, Default)]
struct Counts {
    started: u64,
    returned: u64,
    success: u64,
    failure: u64,
    sum_ns: u128,
    max_ns: u128,
}

struct Scope {
    ordinal: u8,
    start: Instant,
    rows: usize,
    groups: [Counts; 10],
}

#[derive(Default)]
struct State {
    next_ordinal: u8,
    scope: Option<Scope>,
}

pub(super) struct Observer {
    state: Mutex<State>,
    sink: Mutex<Box<dyn Write + Send>>,
    dropped: AtomicU64,
}

pub(super) struct RequestTiming {
    ordinal: u8,
    group: usize,
    start: Instant,
}

impl Observer {
    pub(super) fn from_environment() -> Option<Arc<Self>> {
        // The opt-in belongs to this test process, never the child CLI.
        let enabled =
            std::env::var_os("AOS_TEST_HUB_UPLOAD_TIMING").is_some_and(|value| value == "1");
        enabled.then(|| Arc::new(Self::new(Box::new(std::io::stderr()))))
    }

    fn new(sink: Box<dyn Write + Send>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            sink: Mutex::new(sink),
            dropped: AtomicU64::new(0),
        }
    }

    pub(super) fn begin_scope(&self) -> Option<u8> {
        let Ok(mut state) = self.state.try_lock() else {
            self.drop_observation();
            return None;
        };
        if state.scope.is_some() || state.next_ordinal == 2 {
            self.drop_observation();
            return None;
        }

        state.next_ordinal += 1;
        let ordinal = state.next_ordinal;
        state.scope = Some(Scope {
            ordinal,
            start: Instant::now(),
            rows: 1,
            groups: [Counts::default(); 10],
        });
        drop(state);
        self.emit(format!(
            "HUB-UPLOAD-TIMING ordinal={ordinal} phase=scope edge=begin\n"
        ));
        Some(ordinal)
    }

    pub(super) fn begin_request(&self, method: &Method, path: &str) -> Option<RequestTiming> {
        let group = classify(method, path)?;
        let Ok(mut state) = self.state.try_lock() else {
            self.drop_observation();
            return None;
        };
        let scope = state.scope.as_mut()?;
        let counts = &mut scope.groups[group];
        let first = counts.started == 0;
        counts.started = counts.started.saturating_add(1);
        let timing = RequestTiming {
            ordinal: scope.ordinal,
            group,
            start: Instant::now(),
        };
        let row = (first && reserve_row(scope)).then(|| {
            format!(
                "HUB-UPLOAD-TIMING ordinal={} phase={} edge=begin\n",
                scope.ordinal, GROUPS[group],
            )
        });
        drop(state);
        if let Some(row) = row {
            self.emit(row);
        }
        Some(timing)
    }

    pub(super) fn finish_request(&self, request: RequestTiming, status: StatusCode) {
        let elapsed_ns = request.start.elapsed().as_nanos();
        let Ok(mut state) = self.state.try_lock() else {
            self.drop_observation();
            return;
        };
        let Some(scope) = state.scope.as_mut() else {
            self.drop_observation();
            return;
        };
        if scope.ordinal != request.ordinal {
            self.drop_observation();
            return;
        }

        let counts = &mut scope.groups[request.group];
        let first = counts.returned == 0;
        counts.returned = counts.returned.saturating_add(1);
        if status.is_success() {
            counts.success = counts.success.saturating_add(1);
        } else {
            counts.failure = counts.failure.saturating_add(1);
        }
        counts.sum_ns = counts.sum_ns.saturating_add(elapsed_ns);
        counts.max_ns = counts.max_ns.max(elapsed_ns);
        let row = (first && reserve_row(scope)).then(|| {
            format!(
                "HUB-UPLOAD-TIMING ordinal={} phase={} edge=returned elapsed_ns={elapsed_ns} status={}\n",
                scope.ordinal, GROUPS[request.group], status.as_u16(),
            )
        });
        drop(state);
        if let Some(row) = row {
            self.emit(row);
        }
    }

    pub(super) fn finish_scope(&self, ordinal: u8) {
        let Ok(mut state) = self.state.try_lock() else {
            self.drop_observation();
            return;
        };
        if state
            .scope
            .as_ref()
            .is_none_or(|scope| scope.ordinal != ordinal)
        {
            self.drop_observation();
            return;
        }
        let Some(mut scope) = state.scope.take() else {
            return;
        };
        let mut rows = Vec::with_capacity(11);
        for (group, counts) in scope.groups.into_iter().enumerate() {
            if counts.started == 0 || !reserve_row(&mut scope) {
                continue;
            }
            rows.push(format!(
                "HUB-UPLOAD-TIMING ordinal={ordinal} phase={} edge=summary started={} returned={} in_flight={} success={} failure={} sum_ns={} max_ns={} dropped={}\n",
                GROUPS[group], counts.started, counts.returned,
                counts.started.saturating_sub(counts.returned), counts.success,
                counts.failure, counts.sum_ns, counts.max_ns,
                self.dropped.load(Ordering::Relaxed),
            ));
        }
        if reserve_row(&mut scope) {
            rows.push(format!(
                "HUB-UPLOAD-TIMING ordinal={ordinal} phase=scope edge=returned wall_ns={} dropped={}\n",
                scope.start.elapsed().as_nanos(), self.dropped.load(Ordering::Relaxed),
            ));
        }
        drop(state);
        for row in rows {
            self.emit(row);
        }
    }

    fn emit(&self, row: String) {
        if row.len() > ROW_BYTES {
            self.drop_observation();
            return;
        }
        let Ok(mut sink) = self.sink.try_lock() else {
            self.drop_observation();
            return;
        };
        // One bounded advisory write; no retries or diagnostic queue. Regular
        // capture files can still incur kernel I/O latency and perturb timing.
        if !matches!(sink.write(row.as_bytes()), Ok(written) if written == row.len()) {
            self.drop_observation();
        }
    }

    fn drop_observation(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn reserve_row(scope: &mut Scope) -> bool {
    if scope.rows == ROW_LIMIT {
        return false;
    }
    scope.rows += 1;
    true
}

fn classify(method: &Method, path: &str) -> Option<usize> {
    let suffix = path.strip_prefix("/aos.hub.v1.PublishService/")?;
    if method == Method::POST {
        return match suffix {
            "BeginRegistryPublicationManifest" => Some(0),
            "AppendRegistryPublicationManifest" => Some(1),
            "SealRegistryPublicationManifest" => Some(2),
            "BeginRegistryPublicationMultipartUpload" => Some(4),
            "CompleteRegistryPublicationMultipartUpload" => Some(6),
            "CommitRegistryPublication" => Some(7),
            "GetRegistryPublication" => Some(8),
            "ListRegistryPublications" => Some(9),
            _ => None,
        };
    }
    if method != Method::PUT {
        return None;
    }

    let mut segments = suffix.split('/');
    let operation = segments.next()?;
    let identity = segments.next()?;
    let number = segments.next()?;
    if identity.is_empty() || segments.next().is_some() {
        return None;
    }
    match operation {
        "UploadObject" if number.parse::<i64>().is_ok_and(|value| value > 0) => Some(3),
        "UploadPart" if number.parse::<u32>().is_ok_and(|value| value > 0) => Some(5),
        _ => None,
    }
}

#[path = "publication_timing_tests.rs"]
mod tests;
