//! Definite canonical CBOR parsing with an admitted reusable byte buffer.
//!
//! The pinned parser's string/byte dispatch borrows this scratch before the
//! existing typed adapter admits the output visitor's owning copy. Ordinary
//! custom visitors keep their own format-specific allocation obligations.

use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::serde_budget::{BudgetDeserializer, CollectionHints};
use super::{DecodeBudget, current_budget};

struct OwnedCborSeed<T>(std::marker::PhantomData<T>);

impl<'de, T: Deserialize<'de>> serde::de::DeserializeSeed<'de> for OwnedCborSeed<T> {
    type Value = T;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<T, D::Error> {
        T::deserialize(decoder)
    }
}

fn refusal(
    budget: &DecodeBudget,
    error: super::DecodeAdmissionError,
) -> ciborium::de::Error<std::io::Error> {
    budget.record_failure(error);
    // No String is constructed for this relay. The actual typed carrier stays
    // sticky in the original account and is recovered by the opaque API entry.
    ciborium::de::Error::Io(std::io::ErrorKind::Interrupted.into())
}

/// Decodes a canonical derived CBOR value within the active original account.
///
/// Definite string and byte values borrow the admitted parser scratch before
/// any owning visitor copy. Collection admission uses the existing typed serde
/// adapter. Callers retain output custody and independently admit provider
/// diagnostic allocation; this helper does not certify arbitrary custom
/// visitor allocations or a complete parser-error envelope.
///
/// Without an active account, this preserves the ordinary CBOR parser. Format
/// owners still authenticate canonical reencoding and their own byte limits.
///
/// # Errors
/// Returns a malformed/unsupported CBOR value, a fixed original refusal relay,
/// or allocation failure before parser construction. Typed string/byte-buffer
/// dispatch rejects indefinite values. Generic `deserialize_any` parser
/// allocation remains the format owner's separate admission responsibility.
pub fn from_cbor_slice<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, ciborium::de::Error<std::io::Error>> {
    let Some(budget) = current_budget() else {
        return ciborium::de::from_reader(bytes);
    };
    // Resource admission itself can invoke the original authority. Preserve
    // the account selected at entry through that callback and the whole parse.
    from_cbor_slice_with_seed(bytes, OwnedCborSeed(std::marker::PhantomData), &budget)
}

struct OriginalCborSeed<'a, S> {
    seed: S,
    budget: &'a DecodeBudget,
}

impl<'de, S: serde::de::DeserializeSeed<'de>> serde::de::DeserializeSeed<'de>
    for OriginalCborSeed<'_, S>
{
    type Value = S::Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.seed.deserialize(BudgetDeserializer {
            inner: decoder,
            budget: self.budget.clone(),
            borrow_parser_bytes: true,
            collection_hints: CollectionHints::Suppress,
        })
    }
}

/// Decodes a supplied CBOR seed under its explicitly saved original account.
///
/// The parser borrows one admitted scratch buffer. Nested ordinary serde
/// admission carries this same account even if a custom visitor changes the
/// ambient decode scope. Format-specific seeds must independently admit their
/// own table allocations, conversions and diagnostics; they may borrow a
/// callback bound to this same original without depending on the model crate.
///
/// The caller retains actual output custody. This function grants no custom
/// allocation authority or ownership extraction and does not retain the seed.
///
/// # Errors
/// Returns the initiating parser or seed error unchanged, or a fixed original
/// refusal relay before scratch construction or healthy result acceptance.
/// The original account retains the exact typed refusal separately from any
/// format diagnostic. Typed string and byte-buffer dispatch uses borrowed
/// parser scratch and rejects indefinite values. A seed using generic
/// `deserialize_any` can reach upstream owning parser dispatch; its format
/// owner must separately admit that storage before parsing. This helper does
/// not certify that dispatch or all parser diagnostics.
pub fn from_cbor_slice_with_seed<'de, S>(
    bytes: &[u8],
    seed: S,
    budget: &DecodeBudget,
) -> Result<S::Value, ciborium::de::Error<std::io::Error>>
where
    S: serde::de::DeserializeSeed<'de>,
{
    budget
        .verify_live()
        .map_err(|error| refusal(budget, error))?;
    let _scratch_credit = budget
        .reserve_scratch_bytes(bytes.len() as u64)
        .map_err(|error| refusal(budget, error))?;
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(bytes.len())
        .map_err(|_| ciborium::de::Error::Io(std::io::ErrorKind::OutOfMemory.into()))?;
    scratch.resize(bytes.len(), 0);

    let value = ciborium::de::from_reader_with_buffer_seed(
        OriginalCborSeed { seed, budget },
        bytes,
        &mut scratch,
    )?;
    budget
        .verify_live()
        .map_err(|error| refusal(budget, error))?;
    Ok(value)
}

#[cfg(test)]
mod seed_tests;
