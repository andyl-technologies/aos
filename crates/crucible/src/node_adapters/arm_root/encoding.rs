//! Preflights canonical common records before allocating intermediate JSON.
//!
//! Native packets remain opaque original bytes. Only this selected common codec
//! generates administrative records, after charging ordinary and canonical JSON
//! geometry beneath the installed finite evidence budget.

use std::io::{self, Write};

use serde::Serialize;

use crate::node_contract::OperationFailure;

use super::refusal;

pub(super) fn record(
    value: &impl Serialize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, OperationFailure> {
    let mut count = CountWriter {
        bytes: 0,
        maximum: maximum_bytes,
    };
    serde_json::to_writer(&mut count, value)
        .map_err(|_| refusal("ARM canonical record exceeds its reserved expansion budget"))?;
    let value = serde_json::to_value(value).map_err(|error| refusal(&error.to_string()))?;
    let mut canonical_count = CountWriter {
        bytes: 0,
        maximum: maximum_bytes,
    };
    count_canonical(&value, &mut canonical_count, 0)
        .map_err(|_| refusal("ARM canonical record exceeds its reserved body budget"))?;
    let bytes = crucible_node_contract::canonical::canonical_json(&value)
        .map_err(|error| refusal(&error.to_string()))?;
    if bytes.len() > maximum_bytes {
        return Err(refusal(
            "ARM canonical record exceeds its reserved body budget",
        ));
    }
    Ok(bytes)
}

struct CountWriter {
    bytes: usize,
    maximum: usize,
}

impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= self.maximum)
            .ok_or_else(|| io::Error::other("ARM canonical record byte reservation exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Sorting changes key order, not encoded length. Count the exact canonical
// scalar spelling and separators before allocating the complete canonical body.
fn count_canonical(
    value: &serde_json::Value,
    count: &mut CountWriter,
    depth: usize,
) -> io::Result<()> {
    use serde_json::Value;
    match value {
        Value::Null => count.write_all(b"null"),
        Value::Bool(value) => count.write_all(if *value { b"true" } else { b"false" }),
        Value::String(value) => serde_json::to_writer(count, value).map_err(io::Error::other),
        Value::Number(_) => {
            let scalar = crucible_node_contract::canonical::canonical_json(value)
                .map_err(io::Error::other)?;
            count.write_all(&scalar)
        }
        Value::Array(values) => {
            if depth >= 64 || values.len() > 65_536 {
                return Err(io::Error::other(
                    "ARM record exceeds canonical container bounds",
                ));
            }
            count.write_all(b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    count.write_all(b",")?;
                }
                count_canonical(value, count, depth + 1)?;
            }
            count.write_all(b"]")
        }
        Value::Object(values) => {
            if depth >= 64 {
                return Err(io::Error::other("ARM record exceeds canonical depth"));
            }
            count.write_all(b"{")?;
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    count.write_all(b",")?;
                }
                serde_json::to_writer(&mut *count, key).map_err(io::Error::other)?;
                count.write_all(b":")?;
                count_canonical(value, count, depth + 1)?;
            }
            count.write_all(b"}")
        }
    }
}
