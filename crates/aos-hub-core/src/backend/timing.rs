//! Per-statement query timing, for diagnosing the per-request DB latency floor.
//!
//! RFC-0004 chapter 14 traced the deployed Worker's ~150–300 ms per-request
//! floor to the cost of *opening/using* the Worker database session — the
//! first statement of a request pays ~120 ms, each later one ~10 ms — even
//! though the engine reports <1 ms query execution. The provider's query-latency
//! metric excludes that round-trip, so it cannot be measured from the dashboard;
//! it has to be measured at the call site, in the Worker.
//!
//! [`TimingBackend`] wraps any [`Backend`] and records a [`QuerySpan`] — the
//! operation, a SQL snippet, and the wall-clock milliseconds — for every
//! statement, into a per-request [`QueryTimings`] accumulator the request shares
//! (`Rc<RefCell<…>>` on the single-threaded Worker, `Arc<Mutex<…>>` on the
//! native server). At the end of the request the accumulator is rendered into a
//! `Server-Timing` response header (see [`QueryTimings::server_timing_header`]),
//! so `wrangler tail` / the browser network panel show per-statement ms rather
//! than the inferred aggregate.
//!
//! This is **feature-gated** (`query-timing`, off by default): the wrapper is a
//! thin pass-through with one [`Instant`] read per call, but it is only compiled
//! and wired when a deployment opts in (the preview Worker), so production pays
//! nothing.
//!
//! ```text
//! Server-Timing: db_total;dur=140;desc="4 stmts",
//!                db0;dur=120;desc="query SELECT slug, name FROM registries",
//!                db1;dur=8;desc="query SELECT … FROM channel_floors WHERE …",
//!                …
//! ```

use anyhow::Result;

use crate::backend::{Backend, CheckedStatement, Statement};
use crate::clock::Instant;
use crate::dialect::Dialect;
use crate::value::{Row, Value};

/// A shared handle to the per-request span accumulator.
///
/// Interior-mutable and cheaply cloneable so the [`TimingBackend`] and the
/// request handler that reads the spans back share one list. The concrete
/// container differs by target — the native server is multi-threaded
/// (`Arc<Mutex>`), the Worker is single-threaded (`Rc<RefCell>`) — exactly like
/// [`BackendBounds`](crate::backend::BackendBounds).
#[cfg(not(target_arch = "wasm32"))]
type Shared = std::sync::Arc<std::sync::Mutex<Vec<QuerySpan>>>;
/// See the native definition above — `Rc<RefCell>` on the single-threaded Worker.
#[cfg(target_arch = "wasm32")]
type Shared = std::rc::Rc<std::cell::RefCell<Vec<QuerySpan>>>;

/// One timed backend statement: the operation, a SQL snippet, and its duration.
#[derive(Clone, Debug)]
pub struct QuerySpan {
    /// The [`Backend`] method that ran: `query`, `execute`, `execute_insert`,
    /// `execute_batch`, or `batch`.
    pub op: &'static str,
    /// A leading snippet of the source SQL (truncated; see [`snippet`]), for the
    /// `Server-Timing` description. Empty for `batch` (a statement list).
    pub sql: String,
    /// Wall-clock milliseconds the statement took, end to end (including the Worker
    /// session round-trip this whole module exists to surface).
    pub millis: u64,
}

/// A per-request accumulator of [`QuerySpan`]s, shared by the request's
/// [`TimingBackend`] and the handler that renders them.
///
/// Clone is shallow (it shares the underlying list), so the request opens one
/// [`QueryTimings`], hands a clone to the [`TimingBackend`], and reads the spans
/// back from its own clone after dispatch.
#[derive(Clone, Default)]
pub struct QueryTimings {
    spans: Shared,
}

impl QueryTimings {
    /// Creates an empty accumulator.
    #[must_use]
    pub fn new() -> QueryTimings {
        QueryTimings::default()
    }

    /// Records one span. Never panics: a poisoned native mutex is recovered, and
    /// a re-entrant `RefCell` borrow (impossible on the single-threaded Worker)
    /// is silently dropped rather than aborting the request.
    fn record(&self, op: &'static str, sql: &str, started: Instant) {
        let span = QuerySpan {
            op,
            sql: snippet(sql),
            millis: started.elapsed().as_millis() as u64,
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(mut v) = self.spans.lock() {
                v.push(span);
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            if let Ok(mut v) = self.spans.try_borrow_mut() {
                v.push(span);
            }
        }
    }

    /// Returns a snapshot of the recorded spans, in execution order.
    #[must_use]
    pub fn spans(&self) -> Vec<QuerySpan> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.spans.lock().map(|v| v.clone()).unwrap_or_default()
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.spans
                .try_borrow()
                .map(|v| v.clone())
                .unwrap_or_default()
        }
    }

    /// Renders the recorded spans as a [`Server-Timing`] header *value*, or
    /// `None` when no statement ran (so the caller omits the header entirely).
    ///
    /// The first metric, `db_total`, carries the summed duration and the
    /// statement count; each subsequent `db{N}` carries one statement's duration
    /// and a description (op + SQL snippet). Descriptions are quoted and
    /// sanitized so the value is a well-formed header (no `"`, newline, or `;`).
    ///
    /// [`Server-Timing`]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Server-Timing
    #[must_use]
    pub fn server_timing_header(&self) -> Option<String> {
        let spans = self.spans();
        if spans.is_empty() {
            return None;
        }
        let total: u64 = spans.iter().map(|s| s.millis).sum();
        let mut parts = vec![format!(
            "db_total;dur={total};desc=\"{} stmts\"",
            spans.len()
        )];
        for (i, span) in spans.iter().enumerate() {
            let desc = sanitize_desc(&format!("{} {}", span.op, span.sql));
            parts.push(format!("db{i};dur={};desc=\"{desc}\"", span.millis));
        }
        Some(parts.join(", "))
    }
}

/// A [`Backend`] decorator that times every statement into a [`QueryTimings`].
///
/// Wraps a concrete backend (HubDb on the Worker, the `SqlxBackend`
/// natively) and forwards each call unchanged, recording its wall-clock duration
/// first. The dialect and all results are the inner backend's, verbatim — the
/// wrapper is observationally transparent apart from the timing side effect.
pub struct TimingBackend<B> {
    inner: B,
    timings: QueryTimings,
}

impl<B> TimingBackend<B> {
    /// Wraps `inner`, recording spans into `timings`.
    pub fn new(inner: B, timings: QueryTimings) -> TimingBackend<B> {
        TimingBackend { inner, timings }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<B: Backend> Backend for TimingBackend<B> {
    fn dialect(&self) -> Dialect {
        self.inner.dialect()
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        let started = Instant::now();
        let r = self.inner.execute(sql, params).await;
        self.timings.record("execute", sql, started);
        r
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        let started = Instant::now();
        let r = self.inner.execute_insert(sql, params).await;
        self.timings.record("execute_insert", sql, started);
        r
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let started = Instant::now();
        let r = self.inner.query(sql, params).await;
        self.timings.record("query", sql, started);
        r
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        let started = Instant::now();
        let r = self.inner.execute_batch(sql).await;
        self.timings.record("execute_batch", sql, started);
        r
    }

    async fn batch(&self, stmts: &[Statement]) -> Result<()> {
        let started = Instant::now();
        let r = self.inner.batch(stmts).await;
        self.timings.record("batch", "", started);
        r
    }

    async fn migration_batch(
        &self,
        expected_current: i64,
        target: i64,
        stmts: &[Statement],
    ) -> Result<()> {
        let started = Instant::now();
        let r = self
            .inner
            .migration_batch(expected_current, target, stmts)
            .await;
        self.timings.record("migration_batch", "", started);
        r
    }

    async fn checked_batch(&self, stmts: &[CheckedStatement]) -> Result<()> {
        let started = Instant::now();
        let r = self.inner.checked_batch(stmts).await;
        self.timings.record("checked_batch", "", started);
        r
    }
}

/// The maximum SQL snippet length kept in a [`QuerySpan`], in characters.
const SNIPPET_LEN: usize = 80;

/// Returns a single-line, length-capped snippet of `sql` for a span description.
///
/// Collapses runs of whitespace (the hub's SQL is multi-line) to single spaces
/// and truncates to [`SNIPPET_LEN`] characters with an ellipsis, so a span
/// description stays short and a header value bounded.
fn snippet(sql: &str) -> String {
    let collapsed = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > SNIPPET_LEN {
        let head: String = collapsed.chars().take(SNIPPET_LEN).collect();
        format!("{head}…")
    } else {
        collapsed
    }
}

/// Strips characters that would break a `Server-Timing` header value from a
/// description — the double-quote that delimits it, and the `;`/`,` that
/// separate parameters and metrics — plus control characters.
fn sanitize_desc(desc: &str) -> String {
    desc.chars()
        .map(|c| match c {
            '"' | ';' | ',' | '\n' | '\r' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{QueryTimings, TimingBackend};
    use crate::backend::{Backend, SqlxBackend};

    /// An in-memory sqlite backend wrapped in a `TimingBackend` sharing `timings`.
    async fn fixture() -> (TimingBackend<SqlxBackend>, QueryTimings) {
        let inner = SqlxBackend::connect_sqlite(":memory:")
            .await
            .expect("open in-memory sqlite");
        inner
            .execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);")
            .await
            .expect("create table");
        let timings = QueryTimings::new();
        (TimingBackend::new(inner, timings.clone()), timings)
    }

    #[tokio::test]
    async fn records_a_span_per_statement_in_order() {
        let (db, timings) = fixture().await;
        db.execute("INSERT INTO t (id, v) VALUES (?1, ?2)", &[])
            .await
            .ok();
        db.query("SELECT id FROM t", &[]).await.expect("select");
        let spans = timings.spans();
        assert_eq!(spans.len(), 2, "one span per statement");
        assert_eq!(spans[0].op, "execute");
        assert_eq!(spans[1].op, "query");
        assert!(spans[1].sql.starts_with("SELECT id FROM t"));
    }

    #[tokio::test]
    async fn server_timing_header_is_none_when_empty_and_well_formed_when_not() {
        let (db, timings) = fixture().await;
        assert!(
            timings.server_timing_header().is_none(),
            "no statements yet"
        );
        db.query("SELECT id FROM t WHERE v = ?1", &[]).await.ok();
        let header = timings.server_timing_header().expect("a header");
        assert!(header.starts_with("db_total;dur="));
        assert!(header.contains("desc=\"1 stmts\""));
        assert!(header.contains("db0;dur="));
        // The value must not contain a stray quote inside a description.
        assert!(!header.contains("\"\""), "descriptions are sanitized");
    }

    #[test]
    fn snippet_collapses_whitespace_and_caps_length() {
        let long = format!("SELECT {}", "x, ".repeat(60));
        let s = super::snippet(&long);
        assert!(
            s.chars().count() <= super::SNIPPET_LEN + 1,
            "capped with ellipsis"
        );
        assert!(!s.contains('\n'));
        assert_eq!(super::snippet("SELECT\n  a,\n  b"), "SELECT a, b");
    }
}
