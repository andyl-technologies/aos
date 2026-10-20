//! Allocation-free complete native model encoding credit before body expansion.
//!
//! The selected DAG uses URL-safe unpadded base64 for opaque bodies. This
//! counter measures that exact grammar using borrowed references and byte
//! lengths; it never serializes or clones an original body to discover its size.

use super::*;
use crate::node_adapters::condition_debug_model::dag::Object;
use std::io::{self, Write};

pub(super) fn encoded_dag_length(
    root: &ContentRef,
    objects: &[&Object],
) -> Result<usize, OperationFailure> {
    let mut length =
        b"{\"format\":\"crucible.host-condition-dag\",\"objects\":[],\"roots\":[],\"version\":1}"
            .len();
    add(&mut length, json_length(root)?)?;
    for (index, object) in objects.iter().enumerate() {
        add(&mut length, usize::from(index != 0))?;
        add(
            &mut length,
            b"{\"bytes\":\"\",\"dependencies\":[],\"reference\":}".len(),
        )?;
        let body = object.bytes.as_slice().len();
        let encoded = body
            .checked_mul(4)
            .and_then(|value| value.checked_add(2))
            .map(|value| value / 3)
            .ok_or_else(|| failure("condition native encoded body size overflow"))?;
        add(&mut length, encoded)?;
        add(&mut length, json_length(&object.reference)?)?;
        for (index, dependency) in object.dependencies.iter().enumerate() {
            add(&mut length, usize::from(index != 0))?;
            add(&mut length, json_length(dependency)?)?;
        }
    }
    Ok(length)
}

fn add(total: &mut usize, amount: usize) -> Result<(), OperationFailure> {
    *total = total
        .checked_add(amount)
        .ok_or_else(|| failure("condition native encoded DAG size overflow"))?;
    Ok(())
}

fn json_length(reference: &ContentRef) -> Result<usize, OperationFailure> {
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, reference).map_err(|error| failure(&error.to_string()))?;
    Ok(counter.0)
}

struct Counter(usize);

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("condition native metadata size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "host_condition_geometry_tests.rs"]
mod tests;
