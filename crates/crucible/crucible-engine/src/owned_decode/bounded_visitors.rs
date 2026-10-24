//! Exact hints for custom tables with explicit allocation admission.
//!
//! The transparent names affect serde dispatch, never canonical bytes. Only
//! the immediate table keeps its hint; nested values return to ordinary typed
//! admission so an inner `Vec` cannot preallocate from an unchecked count.

use serde::de::Visitor;

use super::current_budget;

pub(super) const PREPAID_SEQUENCE: &str = "crucible.original.prepaid-sequence";
pub(super) const PREPAID_MAP: &str = "crucible.original.prepaid-map";

struct PrepaidSequenceVisitor<V>(V);

impl<'de, V: Visitor<'de>> Visitor<'de> for PrepaidSequenceVisitor<V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.expecting(formatter)
    }

    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> Result<Self::Value, D::Error> {
        decoder.deserialize_seq(self.0)
    }
}

struct PrepaidMapVisitor<V>(V);

impl<'de, V: Visitor<'de>> Visitor<'de> for PrepaidMapVisitor<V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.expecting(formatter)
    }

    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self.0)
    }
}

/// Preserves the exact hint for a sequence whose visitor prepays its table.
///
/// The visitor must enforce its own finite count and admit its complete typed
/// allocation before reserving storage. This helper does not pay a table or
/// authorize custom visitor allocation. Within original CBOR decoding, nested
/// seeds keep ordinary typed admission with suppressed preallocation hints.
/// Without an active original, ordinary sequence dispatch is unchanged.
///
/// # Errors
/// Returns the decoder or visitor error, including an original admission
/// refusal retained by the active account.
pub fn deserialize_prepaid_sequence<'de, D, V>(decoder: D, visitor: V) -> Result<V::Value, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Visitor<'de>,
{
    if current_budget().is_none() {
        return decoder.deserialize_seq(visitor);
    }
    decoder.deserialize_newtype_struct(PREPAID_SEQUENCE, PrepaidSequenceVisitor(visitor))
}

/// Preserves the exact hint for a map whose visitor prepays its table.
///
/// The visitor must enforce its own finite count and admit its complete typed
/// allocation before reserving storage. Nested keys and values keep ordinary
/// typed admission; this helper does not pay their custom allocations. Without
/// an active original, ordinary map dispatch is unchanged.
///
/// # Errors
/// Returns the decoder or visitor error, including an original admission
/// refusal retained by the active account.
pub fn deserialize_prepaid_map<'de, D, V>(decoder: D, visitor: V) -> Result<V::Value, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Visitor<'de>,
{
    if current_budget().is_none() {
        return decoder.deserialize_map(visitor);
    }
    decoder.deserialize_newtype_struct(PREPAID_MAP, PrepaidMapVisitor(visitor))
}
