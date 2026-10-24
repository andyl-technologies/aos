//! Precharges the actual compiled schema helpers before their owning JSON work.
//!
//! Counts below describe every literal in the two fixed contract definitions,
//! including keys, arrays and canonical UTF-16 sorting. They are not a wire-byte
//! multiplier or arbitrary launch limit. A source change to either contract must
//! update the corresponding facts; controls recount the real emitted definition.

use super::*;
use crate::retained_metadata::MetadataObserver;
use serde_json::Value;
use std::mem::size_of;

struct LiteralFacts {
    objects: usize,
    entries: usize,
    arrays: usize,
    elements: usize,
    strings: usize,
    string_bytes: usize,
    sort_u16_elements: usize,
    encoded: usize,
}

const ORIGINAL: LiteralFacts = LiteralFacts {
    objects: 2,
    entries: 24,
    arrays: 6,
    elements: 42,
    strings: 82,
    string_bytes: 3258,
    sort_u16_elements: 1104,
    encoded: 3525,
};

const FRESH: LiteralFacts = LiteralFacts {
    objects: 5,
    entries: 42,
    arrays: 9,
    elements: 46,
    strings: 115,
    string_bytes: 4854,
    sort_u16_elements: 1740,
    encoded: 5237,
};

pub(super) fn requested_data() -> Result<usize, ProviderError> {
    // The two capture schema helpers and five fresh schema helpers each create
    // their own definition. Sum all seven phases rather than refunding their
    // sequential temporary allocations; returned reference owners coexist.
    sum(&[mul(2, one(&ORIGINAL)?)?, mul(5, one(&FRESH)?)?])
}

pub(super) fn fresh_requested_data() -> Result<usize, ProviderError> {
    // Actual constructor: generate five stored definitions, compare all five
    // full schemas, and validate the resulting installed policy. Summing these
    // sequential phases also retains every independent returned reference.
    mul(3, mul(5, one(&FRESH)?)?)
}

fn one(facts: &LiteralFacts) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    // One aggregate typed tree is conservative for the same set of actual
    // literal object roots and entries under the shared pinned B=6 bound.
    for _ in 0..facts.objects {
        observer.tree::<String, Value>(0)?;
        observer.tree::<Vec<u16>, (&str, &Value)>(0)?;
    }
    observer.tree::<String, Value>(facts.entries)?;
    observer.tree::<Vec<u16>, (&str, &Value)>(facts.entries)?;
    observer.vector::<Value>(facts.elements)?;
    observer.vector::<u16>(facts.sort_u16_elements)?;
    let backing =
        crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())?;
    sum(&[
        backing,
        facts.string_bytes,
        mul(facts.arrays, size_of::<Vec<Value>>())?,
        mul(facts.strings, 8)?,
        // Canonical output and the sum of per-string formatting buffers each
        // use the pinned RawVec growth request bound (4*n+4). The exact full
        // literal encoding dominates the sum of these string encodings.
        growth(facts.encoded)?,
        growth(facts.encoded)?,
        size_of::<Value>(),
        size_of::<crucible_node_format::SchemaRef>(),
        "blake3-256".len(),
        "cnp.blob.v1".len(),
        2 * blake3::OUT_LEN,
        "application/json".len(),
        128, // SchemaRef's actual closed Id maximum; each helper returns one.
        size_of::<blake3::Hasher>(),
        132, // Actual canonical numeric formatter's fixed buffer.
    ])
}

fn growth(length: usize) -> Result<usize, ProviderError> {
    length
        .checked_mul(4)
        .and_then(|n| n.checked_add(4))
        .ok_or_else(exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::service::{capture_allocation, fresh_restore_allocation};

    fn verify(bytes: &[u8], expected: &LiteralFacts) -> Result<(), Box<dyn std::error::Error>> {
        fn walk(value: &Value, actual: &mut LiteralFacts) {
            match value {
                Value::Object(fields) => {
                    actual.objects += 1;
                    actual.entries += fields.len();
                    for (key, value) in fields {
                        actual.strings += 1;
                        actual.string_bytes += key.len();
                        actual.sort_u16_elements += 4 * key.encode_utf16().count() + 4;
                        walk(value, actual);
                    }
                }
                Value::Array(values) => {
                    actual.arrays += 1;
                    actual.elements += values.len();
                    for value in values {
                        walk(value, actual);
                    }
                }
                Value::String(value) => {
                    actual.strings += 1;
                    actual.string_bytes += value.len();
                }
                _ => {}
            }
        }
        let value = crucible_node_format::canonical::parse_json(bytes, bytes.len())?;
        let mut actual = LiteralFacts {
            objects: 0,
            entries: 0,
            arrays: 0,
            elements: 0,
            strings: 0,
            string_bytes: 0,
            sort_u16_elements: 0,
            encoded: bytes.len(),
        };
        walk(&value, &mut actual);
        assert_eq!(
            (
                actual.objects,
                actual.entries,
                actual.arrays,
                actual.elements
            ),
            (
                expected.objects,
                expected.entries,
                expected.arrays,
                expected.elements
            )
        );
        assert_eq!(
            (
                actual.strings,
                actual.string_bytes,
                actual.sort_u16_elements,
                actual.encoded
            ),
            (
                expected.strings,
                expected.string_bytes,
                expected.sort_u16_elements,
                expected.encoded
            )
        );
        assert!(one(expected)? > bytes.len());
        Ok(())
    }

    #[test]
    fn fixed_schema_credit_matches_actual_full_contract_literals()
    -> Result<(), Box<dyn std::error::Error>> {
        verify(
            &capture_allocation::capture_allocation_contract()?,
            &ORIGINAL,
        )?;
        verify(
            &fresh_restore_allocation::fresh_restore_allocation_contract()?,
            &FRESH,
        )
    }
}
