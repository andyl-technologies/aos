//! Byte-oriented wire types for the seal-gated remote SQL protocol.
//!
//! Queue and resource-shard isolates serialize these requests as JSON before
//! sending them to the authoritative database Durable Object. The receiver
//! decodes the raw bytes with [`decode_request`] so JavaScript value coercion
//! cannot turn SQL `NULL` or 64-bit integers into a different Rust value.

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use aos_hub_db::value::{Row, Value};

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
    // Internally tagged enum decoding buffers every field before selecting a
    // variant. Borrow the large batch first so its statement strings are only
    // allocated once within the Durable Object's memory limit.
    #[derive(Deserialize)]
    struct Envelope<'a> {
        operation: String,
        #[serde(borrow)]
        statements: Option<&'a serde_json::value::RawValue>,
    }

    let envelope: Envelope<'_> =
        serde_json::from_slice(body).context("decoding remote SQL envelope")?;
    if envelope.operation == "batch" {
        let statements = envelope
            .statements
            .context("remote SQL batch omitted statements")?;
        return Ok(RemoteSqlRequest::Batch {
            statements: serde_json::from_str(statements.get())
                .context("decoding remote SQL batch statements")?,
        });
    }

    serde_json::from_slice(body).context("decoding remote SQL request JSON")
}

#[cfg(test)]
mod tests {
    use super::{decode_request, RemoteSqlRequest};
    use aos_hub_db::value::Value;

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

    #[test]
    fn wire_decoder_preserves_large_checked_batches_with_reordered_fields() {
        let text = "release metadata ".repeat(131_072);
        let statements = vec![super::RemoteStatement {
            sql: "INSERT INTO catalog VALUES (?1, ?2, ?3)".to_string(),
            params: vec![
                Value::Text(text.clone()),
                Value::Int(9_007_199_254_740_991),
                Value::Null,
            ],
            expected_rows: Some(1),
        }];
        let statements_json = serde_json::to_string(&statements).unwrap();
        let body =
            format!(r#"{{"statements":{statements_json},"operation":"batch"}}"#).into_bytes();

        let RemoteSqlRequest::Batch { statements } = decode_request(&body).unwrap() else {
            panic!("expected a batch request");
        };

        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].expected_rows, Some(1));
        assert_eq!(
            statements[0].params,
            vec![
                Value::Text(text),
                Value::Int(9_007_199_254_740_991),
                Value::Null
            ]
        );
    }

    #[test]
    fn wire_decoder_rejects_incomplete_batch_envelopes() {
        for body in [
            br#"{"operation":"batch"}"#.as_slice(),
            br#"{"operation":"batch","statements":null}"#.as_slice(),
            br#"{"operation":"batch","statements":[{"sql":"SELECT 1"}]}"#.as_slice(),
            br#"{"operation":"batch","statements":[]} trailing"#.as_slice(),
        ] {
            assert!(decode_request(body).is_err());
        }
    }
}
