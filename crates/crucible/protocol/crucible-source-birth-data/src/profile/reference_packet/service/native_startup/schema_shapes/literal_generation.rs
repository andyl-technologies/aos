//! Precharges the actual compiled schema helpers before their owning JSON work.
//!
//! Counts below describe every literal in the two fixed contract definitions,
//! including keys, arrays and canonical UTF-16 sorting. They are not a wire-byte
//! multiplier or arbitrary launch limit. A source change to either contract must
//! update the corresponding facts; controls recount the real emitted definition.

use crate::ProviderError;
use crate::profile::serialization_storage::RetainedProtocolMetadataFacts;
use serde_json::Value;
use std::mem::align_of;
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

/// Counts the actual fixed compiled schema-generation phase.
///
/// # Errors
/// Preserves original metadata, layout and compiled-report storage refusals.
pub fn requested_data() -> Result<usize, ProviderError> {
    // The two capture schema helpers and five fresh schema helpers each create
    // their own definition. Sum all seven phases rather than refunding their
    // sequential temporary allocations; returned reference owners coexist.
    sum(&[mul(2, one(&ORIGINAL)?)?, mul(5, one(&FRESH)?)?])
}

/// Counts the actual fixed compiled schema-generation phase.
///
/// # Errors
/// Preserves original metadata, layout and compiled-report storage refusals.
pub fn fresh_requested_data() -> Result<usize, ProviderError> {
    // Actual constructor: generate five stored definitions, compare all five
    // full schemas, and validate the resulting installed policy. Summing these
    // sequential phases also retains every independent returned reference.
    mul(3, mul(5, one(&FRESH)?)?)
}

fn one(facts: &LiteralFacts) -> Result<usize, ProviderError> {
    let mut population = RetainedProtocolMetadataFacts::default();
    // These are the original typed population operations in the same order.
    // Source-body sharing adds no callback or native observation authority.
    for _ in 0..facts.objects {
        let entries = 0usize;
        size_of::<String>()
            .checked_add(size_of::<Value>())
            .ok_or(crate::profile::metadata_population::overflow())?;
        literal_record(&mut population)?;
        let observed: Result<(), ProviderError> =
            crate::source_birth_metadata_tree_population!(population, entries, String, Value);
        observed?;
        size_of::<Vec<u16>>()
            .checked_add(size_of::<(&str, &Value)>())
            .ok_or(crate::profile::metadata_population::overflow())?;
        literal_record(&mut population)?;
        let observed: Result<(), ProviderError> = crate::source_birth_metadata_tree_population!(
            population,
            entries,
            Vec<u16>,
            (&str, &Value)
        );
        observed?;
    }
    {
        let entries = facts.entries;
        size_of::<String>()
            .checked_add(size_of::<Value>())
            .ok_or(crate::profile::metadata_population::overflow())?;
        literal_record(&mut population)?;
        let observed: Result<(), ProviderError> =
            crate::source_birth_metadata_tree_population!(population, entries, String, Value);
        observed?;
        size_of::<Vec<u16>>()
            .checked_add(size_of::<(&str, &Value)>())
            .ok_or(crate::profile::metadata_population::overflow())?;
        literal_record(&mut population)?;
        let observed: Result<(), ProviderError> = crate::source_birth_metadata_tree_population!(
            population,
            entries,
            Vec<u16>,
            (&str, &Value)
        );
        observed?;
    }
    {
        let capacity = facts.elements;
        literal_record(&mut population)?;
        let observed: Result<(), ProviderError> =
            crate::source_birth_metadata_vector_population!(population, capacity, Value);
        observed?;
    }
    {
        let capacity = facts.sort_u16_elements;
        literal_record(&mut population)?;
        let observed: Result<(), ProviderError> =
            crate::source_birth_metadata_vector_population!(population, capacity, u16);
        observed?;
    }
    let backing =
        crate::profile::requested_storage::requested_metadata_backing_storage_data(&population)?;
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

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(exhausted)
    })
}
fn mul(count: usize, slot: usize) -> Result<usize, ProviderError> {
    count.checked_mul(slot).ok_or_else(exhausted)
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("compiled native report startup storage")
}

// The original observer is freshly unprofiled, unrecorded and unaliased here.
// Preserve its checked record increment and ordinary work ceiling; active native
// capsule/record-bank handling remains solely in the actual upper observer.
fn literal_record(population: &mut RetainedProtocolMetadataFacts) -> Result<(), ProviderError> {
    use crate::profile::metadata_population::{MAXIMUM_ORDINARY_METADATA_ROWS, add, overflow};
    add(&mut population.capacity_records, 1)?;
    if population
        .capacity_records
        .checked_sub(0)
        .ok_or_else(overflow)?
        > MAXIMUM_ORDINARY_METADATA_ROWS
    {
        return Err(overflow());
    }
    Ok(())
}
