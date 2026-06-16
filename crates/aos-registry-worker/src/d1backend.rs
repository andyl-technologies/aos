//! [`D1Backend`]: the Cloudflare D1 implementation of the shared
//! [`Backend`](aos_registry_core::backend::Backend) trait (wasm32-only).
//!
//! D1 is sqlite (RFC-0004: "D1 is the sqlite backend — same dialect, different
//! driver"), so this drives the *exact* `core::Database` read/write logic the
//! native hub runs, over `worker::D1Database` prepared statements instead of the
//! native `sqlx` pool. The Worker constructs
//! `Database::with_backend(Box::new(D1Backend::new(env.d1("DB")?)))` and from
//! there every query method, the migrations, and the auth/config/webhook logic
//! are the same compiled code as the native binary.
//!
//! # Marshalling
//!
//! Parameters cross as [`Value`] → [`JsValue`] ([`to_js`]); result rows come
//! back **positionally** via D1's `raw::<serde_json::Value>()` (a `Vec<Vec<_>>`
//! of column values per row) and are mapped column-by-column into a
//! [`Row`] ([`from_json`]). D1 reports `meta.changes`/`meta.last_row_id` for the
//! write paths, and its atomic `batch()` backs [`Backend::batch`] — exactly the
//! self-contained statement-list seam `core` was designed around (no
//! interactive transactions).

use async_trait::async_trait;
use wasm_bindgen::JsValue;
use worker::D1Database;

use aos_registry_core::backend::{prepare, split_statements, Backend, Statement};
use aos_registry_core::dialect::Dialect;
use aos_registry_core::value::{Row, Value};

/// A [`Backend`] over a bound Cloudflare D1 database.
pub struct D1Backend {
    db: D1Database,
}

impl D1Backend {
    /// Wraps a bound D1 database (`env.d1(binding)`) as a [`Backend`].
    #[must_use]
    pub fn new(db: D1Database) -> D1Backend {
        D1Backend { db }
    }
}

/// Maps a worker/D1 error into an `anyhow::Error` for the [`Backend`] contract.
fn d1_err(err: worker::Error) -> anyhow::Error {
    anyhow::anyhow!("D1: {err}")
}

/// Converts a bound [`Value`] into the `JsValue` D1 binds.
///
/// Integers cross as JS numbers (f64): every hub id/count is well under 2^53, so
/// this is lossless. Blobs cross as a `Uint8Array`.
fn to_js(value: &Value) -> JsValue {
    match value {
        Value::Null => JsValue::NULL,
        Value::Int(n) => JsValue::from_f64(*n as f64),
        Value::Real(f) => JsValue::from_f64(*f),
        Value::Text(s) => JsValue::from_str(s),
        Value::Bytes(b) => js_sys::Uint8Array::from(b.as_slice()).into(),
    }
}

/// Converts one D1 column value (deserialized as JSON) into a [`Value`].
///
/// D1 yields sqlite types as JSON: NULL→null, INTEGER→number (no fraction),
/// REAL→number (fraction), TEXT→string, BLOB→array of byte numbers. A JSON
/// boolean (not produced by sqlite, but tolerated) maps to the `0`/`1` integer
/// the schema stores.
fn from_json(value: serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Int(i64::from(b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Real(f)
            } else {
                // u64 past i64::MAX — saturate rather than lose the row.
                Value::Int(i64::MAX)
            }
        }
        serde_json::Value::String(s) => Value::Text(s),
        // A BLOB column arrives as a JSON array of byte numbers.
        serde_json::Value::Array(items) => {
            let bytes = items
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect();
            Value::Bytes(bytes)
        }
        // sqlite produces no nested objects; treat as NULL rather than panic.
        serde_json::Value::Object(_) => Value::Null,
    }
}

/// Prepares + binds a single source statement for D1 (sqlite dialect).
fn bind_stmt(db: &D1Database, sql: &str, params: &[Value]) -> anyhow::Result<worker::D1PreparedStatement> {
    let (translated, ordered) = prepare(Dialect::Sqlite, sql, params)?;
    let js: Vec<JsValue> = ordered.iter().map(to_js).collect();
    db.prepare(&translated).bind(&js).map_err(d1_err)
}

#[async_trait(?Send)]
impl Backend for D1Backend {
    fn dialect(&self) -> Dialect {
        // D1 is sqlite: the source dialect, no translation beyond placeholders.
        Dialect::Sqlite
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> anyhow::Result<u64> {
        let stmt = bind_stmt(&self.db, sql, params)?;
        let result = stmt.run().await.map_err(d1_err)?;
        let changes = result
            .meta()
            .map_err(d1_err)?
            .and_then(|m| m.changes)
            .unwrap_or(0);
        Ok(changes as u64)
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> anyhow::Result<i64> {
        let stmt = bind_stmt(&self.db, sql, params)?;
        let result = stmt.run().await.map_err(d1_err)?;
        result
            .meta()
            .map_err(d1_err)?
            .and_then(|m| m.last_row_id)
            .ok_or_else(|| anyhow::anyhow!("D1 INSERT returned no last_row_id"))
    }

    async fn query(&self, sql: &str, params: &[Value]) -> anyhow::Result<Vec<Row>> {
        let stmt = bind_stmt(&self.db, sql, params)?;
        // `raw` returns each row as a positional array of column values, exactly
        // the shape `Row` wants (column order matches the SELECT list).
        let rows: Vec<Vec<serde_json::Value>> = stmt.raw().await.map_err(d1_err)?;
        Ok(rows
            .into_iter()
            .map(|cols| Row::new(cols.into_iter().map(from_json).collect()))
            .collect())
    }

    async fn execute_batch(&self, sql: &str) -> anyhow::Result<()> {
        // A migration script is multiple `;`-separated DDL statements with no
        // bound parameters; run each translated statement in turn.
        for statement in split_statements(sql) {
            let (translated, _) = prepare(Dialect::Sqlite, &statement, &[])?;
            self.db
                .prepare(&translated)
                .run()
                .await
                .map_err(d1_err)?;
        }
        Ok(())
    }

    async fn batch(&self, stmts: &[Statement]) -> anyhow::Result<()> {
        // D1's `batch` runs a fixed statement list as one atomic unit — the
        // exact primitive `core`'s batch seam targets (no interactive tx).
        let mut prepared = Vec::with_capacity(stmts.len());
        for statement in stmts {
            prepared.push(bind_stmt(&self.db, &statement.sql, &statement.params)?);
        }
        self.db.batch(prepared).await.map_err(d1_err)?;
        Ok(())
    }
}
