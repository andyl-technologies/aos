//! Byte-oriented wire types for the seal-gated remote SQL protocol.
//!
//! Queue and resource-shard isolates serialize these requests as JSON before
//! sending them to the authoritative database Durable Object. The receiver
//! decodes the raw bytes with [`decode_request`] so JavaScript value coercion
//! cannot turn SQL `NULL` or 64-bit integers into a different Rust value.

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use aos_hub_core::value::{Row, Value};

/// One serialized SQL operation sent to the database Durable Object.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum RemoteSqlRequest {
    /// Executes one mutation and returns its affected-row count.
    Execute { sql: String, params: Vec<Value> },
    /// Executes one mutation without reading its affected-row count.
    ExecuteDiscardingCount { sql: String, params: Vec<Value> },
    /// Executes one insert and returns its generated relational id.
    ExecuteInsert { sql: String, params: Vec<Value> },
    /// Executes one query and returns all rows.
    Query { sql: String, params: Vec<Value> },
    /// Applies a DDL script.
    ExecuteBatch { sql: String },
    /// Applies one ordinary or checked atomic statement batch.
    Batch { statements: Vec<RemoteStatement> },
}

/// One statement and optional row-count assertion in a remote batch.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RemoteStatement {
    pub(crate) sql: String,
    pub(crate) params: Vec<Value>,
    pub(crate) expected_rows: Option<u64>,
}

/// Result union returned by the internal SQL endpoint.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct RemoteSqlResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inserted_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rows: Option<Vec<Row>>,
}

/// Decodes an internal SQL request directly from its JSON wire bytes.
///
/// # Errors
///
/// Returns an error when `body` is not a valid [`RemoteSqlRequest`].
pub(crate) fn decode_request(body: &[u8]) -> Result<RemoteSqlRequest> {
    serde_json::from_slice(body).context("decoding remote SQL request JSON")
}

#[cfg(test)]
mod tests {
    use super::{decode_request, RemoteSqlRequest};
    use aos_hub_core::value::Value;

    #[test]
    fn wire_decoder_preserves_query_parameters_and_sql_null() {
        let body = br#"{
            "operation":"query",
            "sql":"SELECT ?1, ?2",
            "params":[{"Int":7},"Null"]
        }"#;

        let request = decode_request(body).unwrap();
        let RemoteSqlRequest::Query { sql, params } = request else {
            panic!("expected a query request");
        };
        assert_eq!(sql, "SELECT ?1, ?2");
        assert_eq!(params, vec![Value::Int(7), Value::Null]);
    }
}
