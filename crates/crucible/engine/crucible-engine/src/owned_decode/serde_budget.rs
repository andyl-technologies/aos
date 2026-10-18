//! Typed serde allocation admission for scoped artifact codecs.
//!
//! Collection hints are suppressed so an untrusted count cannot preallocate a
//! container. Each typed seed is admitted before decoding its value, including
//! conservative Vec growth and B-tree entry storage. Owned strings and bytes
//! are admitted before visitors can copy them. Format owners admit parser
//! scratch separately; the JSON entry does so before serde_json starts.
//! Custom visitors with additional allocations need their
//! own explicit compact-codec charges.

use serde::Deserialize;
use serde::de::{DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};

use super::bounded_visitors::{PREPAID_MAP, PREPAID_SEQUENCE};
use super::{DecodeBudget, current_budget};

#[derive(Clone, Copy)]
pub(super) enum CollectionHints {
    Suppress,
    PrepaidTable,
}

/// Decodes a JSON leaf within the current original resource account.
///
/// The caller retains [`super::DecodeCustody`] with the resulting owner. This
/// adapter preserves JSON semantics and is not an admission for unrelated
/// custom visitor allocations or later clones. Its returned raw Serde error
/// remains an ordinary diagnostic; controlled service DTOs use
/// [`from_json_slice_closed`] to retain their diagnostic purpose.
///
/// # Errors
/// Rejects malformed or trailing JSON and exhausted original admission. The
/// account's [`DecodeBudget::failure`] retains the typed operational cause.
pub fn from_json_slice<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, serde_json::Error> {
    let Some(budget) = current_budget() else {
        return serde_json::from_slice(bytes);
    };
    // serde_json 1.0.150 SliceRead appends consumed string bytes to one reusable
    // scratch Vec. Escape decoding emits at most the consumed source extent;
    // push_wtf8 reserves four bytes. RawVec grows to max(2*old, required, 8).
    // Its retained capacity plus old/new growth overlap is bounded by three
    // source extents. The additional 16 bytes cover minimum capacity and the
    // fixed numeric token buffer. Numeric token input is disjoint from prior
    // string input, so simultaneous retained scratch and numeric growth share
    // this source bound. This applies to slice JSON, not a TOML parser AST.
    let scratch = (bytes.len() as u64)
        .checked_add(16)
        .and_then(|bytes| bytes.checked_mul(3))
        .ok_or_else(|| {
            <serde_json::Error as serde::de::Error>::custom("JSON scratch size overflow")
        })?;
    // Declared before the parser so its buffers close before the credit.
    let _parser_scratch = budget
        .reserve_scratch_bytes(scratch)
        .map_err(|error| refusal::<serde_json::Error>(&budget, error))?;
    admit_seed::<T, serde_json::Error>(&budget)?;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let result = T::deserialize(BudgetDeserializer {
        inner: &mut decoder,
        budget,
        borrow_parser_bytes: false,
        collection_hints: CollectionHints::Suppress,
    })?;
    decoder.end()?;
    Ok(result)
}

/// Decodes a sealed service DTO with an original-owned JSON diagnostic.
///
/// The same explicit budget reserves parser scratch, the concrete diagnostic
/// envelope and its holder before parser construction. The caller retains its
/// existing output custody. This entry accepts only the reviewed slice DTOs;
/// IO deserializers and caller-defined diagnostic formatters cannot enter it.
///
/// # Errors
/// Returns the same original admission error or an opaque paid syntax, data or
/// EOF error. New diagnostic and holder admission cuts precede parser birth.
/// Unsupported target layouts and checked extent overflow refuse without
/// constructing a Serde error.
pub fn from_json_slice_closed<'input, T>(
    bytes: &'input [u8],
    budget: &DecodeBudget,
) -> Result<T, super::ClosedJsonError>
where
    T: super::json_profiles::ClosedJsonProfile<'input>,
{
    use super::json_diagnostic::PreparedDiagnostic;

    budget.check()?;
    let diagnostic = PreparedDiagnostic::prepare::<T>(budget, bytes)?;
    let scratch = (bytes.len() as u64)
        .checked_add(16)
        .and_then(|bytes| bytes.checked_mul(3))
        .ok_or_else(|| PreparedDiagnostic::refusal(budget, "JSON scratch size overflow"))?;
    let parser_scratch = budget.reserve_scratch_bytes(scratch)?;

    // The parser and partially constructed DTO close inside this scope. A
    // returned error is already backed by diagnostic, independent of scratch.
    let result = (|| {
        admit_seed::<T, serde_json::Error>(budget)?;
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let value = T::deserialize(BudgetDeserializer {
            inner: &mut decoder,
            budget: budget.clone(),
            borrow_parser_bytes: false,
            collection_hints: CollectionHints::Suppress,
        })?;
        decoder.end()?;
        Ok(value)
    })();
    drop(parser_scratch);

    finish_closed_json(budget, diagnostic, result)
}

pub(super) fn finish_closed_json<T>(
    budget: &DecodeBudget,
    diagnostic: super::json_diagnostic::PreparedDiagnostic,
    result: Result<T, serde_json::Error>,
) -> Result<T, super::ClosedJsonError> {
    match result {
        Ok(value) => {
            if let Err(original) = budget.check() {
                drop(value);
                drop(diagnostic);
                return Err(original.into());
            }
            drop(diagnostic);
            Ok(value)
        }
        Err(source) if is_admission_relay(&source) => match budget.failure() {
            Ok(None) => Err(diagnostic.retain(source).into()),
            // Only the fixed admission marker yields to its actual original.
            // A later account failure cannot replace another JSON diagnostic.
            Ok(Some(original)) | Err(original) => {
                drop(source);
                drop(diagnostic);
                Err(original.into())
            }
        },
        Err(source) => Err(diagnostic.retain(source).into()),
    }
}

pub(super) struct AdmissionRelayPrefix {
    matched: bool,
    position: usize,
}

impl std::fmt::Write for AdmissionRelayPrefix {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let marker = b"original decoded metadata admission refused";
        let count = (marker.len() - self.position).min(text.len());
        self.matched &= text.as_bytes()[..count] == marker[self.position..self.position + count];
        self.position += count;
        Ok(())
    }
}

fn is_admission_relay(error: &serde_json::Error) -> bool {
    use std::fmt::Write;

    // In these sealed schemas, no user-derived message has this prefix. The
    // derived/identity errors use their distinct fixed templates. Display may
    // append only the actual line/column; it creates no formatting allocation.
    let mut prefix = AdmissionRelayPrefix {
        matched: true,
        position: 0,
    };
    error.is_data()
        && write!(&mut prefix, "{error}").is_ok()
        && prefix.matched
        && prefix.position == b"original decoded metadata admission refused".len()
}

fn admit_seed<T, E: serde::de::Error>(budget: &DecodeBudget) -> Result<(), E> {
    // Key and value seeds each admit their complete typed node contribution.
    // Their combined charges cover a map node; the same cumulative allowance
    // exceeds Vec's minimum capacity and old/new geometric growth overlap.
    budget
        .charge_btree_entry::<T, ()>()
        .map_err(|error| refusal::<E>(budget, error))
}

/// Applies typed allocation admission to an already admitted parser.
///
/// The parser's private scratch and diagnostic allocations must be admitted by
/// its format owner before this function runs. This supplies only typed visitor
/// admission and suppresses untrusted collection size hints.
///
/// # Errors
/// Returns the parser error or a fixed refusal marker; the account retains the
/// original typed admission cause independently of the parser's diagnostic.
pub fn deserialize_with_budget<'de, T, D>(decoder: D, budget: &DecodeBudget) -> Result<T, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    admit_seed::<T, D::Error>(budget)?;
    T::deserialize(BudgetDeserializer {
        inner: decoder,
        budget: budget.clone(),
        borrow_parser_bytes: false,
        collection_hints: CollectionHints::Suppress,
    })
}

fn refusal<E: serde::de::Error>(budget: &DecodeBudget, error: super::DecodeAdmissionError) -> E {
    budget.record_failure(error);
    // Provider diagnostics can own arbitrary data. The upstream parser only
    // receives this fixed marker; callers recover the original typed cause.
    E::custom("original decoded metadata admission refused")
}

pub(super) struct BudgetDeserializer<D> {
    pub(super) inner: D,
    pub(super) budget: DecodeBudget,
    pub(super) borrow_parser_bytes: bool,
    pub(super) collection_hints: CollectionHints,
}

macro_rules! forward {
    ($method:ident $(, $argument:ident: $kind:ty)*) => {
        fn $method<V>(self, $($argument: $kind,)* visitor: V) -> Result<V::Value, Self::Error>
        where V: Visitor<'de> {
            // Box and newtype Deserialize implementations may call their inner
            // type directly, without a collection seed. Admit the visitor's
            // actual owning value before that implementation can allocate it.
            admit_seed::<V::Value, D::Error>(&self.budget)?;
            self.inner.$method($($argument,)* BudgetVisitor { inner: visitor, budget: self.budget, borrow_parser_bytes: self.borrow_parser_bytes, collection_hints: self.collection_hints })
        }
    };
}

impl<'de, D: serde::Deserializer<'de>> serde::Deserializer<'de> for BudgetDeserializer<D> {
    type Error = D::Error;

    forward!(deserialize_any);
    forward!(deserialize_bool);
    forward!(deserialize_i8);
    forward!(deserialize_i16);
    forward!(deserialize_i32);
    forward!(deserialize_i64);
    forward!(deserialize_i128);
    forward!(deserialize_u8);
    forward!(deserialize_u16);
    forward!(deserialize_u32);
    forward!(deserialize_u64);
    forward!(deserialize_u128);
    forward!(deserialize_f32);
    forward!(deserialize_f64);
    forward!(deserialize_char);
    forward!(deserialize_str);
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        admit_seed::<V::Value, D::Error>(&self.budget)?;
        let wrapped = BudgetVisitor {
            inner: visitor,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: self.collection_hints,
        };
        if self.borrow_parser_bytes {
            self.inner.deserialize_str(wrapped)
        } else {
            self.inner.deserialize_string(wrapped)
        }
    }
    forward!(deserialize_bytes);
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        admit_seed::<V::Value, D::Error>(&self.budget)?;
        let wrapped = BudgetVisitor {
            inner: visitor,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: self.collection_hints,
        };
        if self.borrow_parser_bytes {
            self.inner.deserialize_bytes(wrapped)
        } else {
            self.inner.deserialize_byte_buf(wrapped)
        }
    }
    forward!(deserialize_option);
    forward!(deserialize_unit);
    forward!(deserialize_unit_struct, name: &'static str);
    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let collection_hints = if name == PREPAID_SEQUENCE || name == PREPAID_MAP {
            // The transparent dispatch owns no allocation. The actual sequence
            // or map entry below retains its ordinary typed-value admission.
            CollectionHints::PrepaidTable
        } else {
            admit_seed::<V::Value, D::Error>(&self.budget)?;
            self.collection_hints
        };
        self.inner.deserialize_newtype_struct(
            name,
            BudgetVisitor {
                inner: visitor,
                budget: self.budget,
                borrow_parser_bytes: self.borrow_parser_bytes,
                collection_hints,
            },
        )
    }
    forward!(deserialize_seq);
    forward!(deserialize_tuple, len: usize);
    forward!(deserialize_tuple_struct, name: &'static str, len: usize);
    forward!(deserialize_map);
    forward!(deserialize_struct, name: &'static str, fields: &'static [&'static str]);
    forward!(deserialize_enum, name: &'static str, variants: &'static [&'static str]);
    forward!(deserialize_identifier);
    forward!(deserialize_ignored_any);

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

struct BudgetSeed<S> {
    inner: S,
    budget: DecodeBudget,
    borrow_parser_bytes: bool,
    collection_hints: CollectionHints,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for BudgetSeed<S> {
    type Value = S::Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        admit_seed::<Self::Value, D::Error>(&self.budget)?;
        self.inner.deserialize(BudgetDeserializer {
            inner: decoder,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: self.collection_hints,
        })
    }
}

struct BudgetVisitor<V> {
    inner: V,
    budget: DecodeBudget,
    borrow_parser_bytes: bool,
    collection_hints: CollectionHints,
}

macro_rules! scalar {
    ($method:ident, $kind:ty) => {
        fn $method<E: serde::de::Error>(self, value: $kind) -> Result<Self::Value, E> {
            self.inner.$method(value)
        }
    };
}

impl<'de, V: Visitor<'de>> Visitor<'de> for BudgetVisitor<V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.expecting(formatter)
    }

    scalar!(visit_bool, bool);
    scalar!(visit_i8, i8);
    scalar!(visit_i16, i16);
    scalar!(visit_i32, i32);
    scalar!(visit_i64, i64);
    scalar!(visit_i128, i128);
    scalar!(visit_u8, u8);
    scalar!(visit_u16, u16);
    scalar!(visit_u32, u32);
    scalar!(visit_u64, u64);
    scalar!(visit_u128, u128);
    scalar!(visit_f32, f32);
    scalar!(visit_f64, f64);
    scalar!(visit_char, char);

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.budget
            .charge_bytes(2 * value.len() as u64)
            .map_err(|error| refusal::<E>(&self.budget, error))?;
        self.inner.visit_str(value)
    }

    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        self.budget
            .charge_bytes(2 * value.len() as u64)
            .map_err(|error| refusal::<E>(&self.budget, error))?;
        self.inner.visit_borrowed_str(value)
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.budget
            .charge_bytes(2 * value.capacity() as u64)
            .map_err(|error| refusal::<E>(&self.budget, error))?;
        self.inner.visit_string(value)
    }

    fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        self.budget
            .charge_bytes(2 * value.len() as u64)
            .map_err(|error| refusal::<E>(&self.budget, error))?;
        self.inner.visit_bytes(value)
    }

    fn visit_borrowed_bytes<E: serde::de::Error>(self, value: &'de [u8]) -> Result<Self::Value, E> {
        self.budget
            .charge_bytes(2 * value.len() as u64)
            .map_err(|error| refusal::<E>(&self.budget, error))?;
        self.inner.visit_borrowed_bytes(value)
    }

    fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        self.budget
            .charge_bytes(2 * value.capacity() as u64)
            .map_err(|error| refusal::<E>(&self.budget, error))?;
        self.inner.visit_byte_buf(value)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(BudgetDeserializer {
            inner: decoder,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: self.collection_hints,
        })
    }

    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(BudgetDeserializer {
            inner: decoder,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: self.collection_hints,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, sequence: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_seq(BudgetSequence {
            inner: sequence,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: self.collection_hints,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_map(BudgetMap {
            inner: map,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: self.collection_hints,
        })
    }

    fn visit_enum<A: EnumAccess<'de>>(self, value: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(BudgetEnum {
            inner: value,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: self.collection_hints,
        })
    }
}

struct BudgetSequence<A> {
    inner: A,
    budget: DecodeBudget,
    borrow_parser_bytes: bool,
    collection_hints: CollectionHints,
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for BudgetSequence<A> {
    type Error = A::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        self.inner.next_element_seed(BudgetSeed {
            inner: seed,
            budget: self.budget.clone(),
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: CollectionHints::Suppress,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        match self.collection_hints {
            CollectionHints::Suppress => Some(0),
            CollectionHints::PrepaidTable => self.inner.size_hint(),
        }
    }
}

struct BudgetMap<A> {
    inner: A,
    budget: DecodeBudget,
    borrow_parser_bytes: bool,
    collection_hints: CollectionHints,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for BudgetMap<A> {
    type Error = A::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        self.inner.next_key_seed(BudgetSeed {
            inner: seed,
            budget: self.budget.clone(),
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: CollectionHints::Suppress,
        })
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.next_value_seed(BudgetSeed {
            inner: seed,
            budget: self.budget.clone(),
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: CollectionHints::Suppress,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        match self.collection_hints {
            CollectionHints::Suppress => Some(0),
            CollectionHints::PrepaidTable => self.inner.size_hint(),
        }
    }
}

struct BudgetEnum<A> {
    inner: A,
    budget: DecodeBudget,
    borrow_parser_bytes: bool,
    collection_hints: CollectionHints,
}

impl<'de, A: EnumAccess<'de>> EnumAccess<'de> for BudgetEnum<A> {
    type Error = A::Error;
    type Variant = BudgetVariant<A::Variant>;
    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        let (value, variant) = self.inner.variant_seed(BudgetSeed {
            inner: seed,
            budget: self.budget.clone(),
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: CollectionHints::Suppress,
        })?;
        Ok((
            value,
            BudgetVariant {
                inner: variant,
                budget: self.budget,
                borrow_parser_bytes: self.borrow_parser_bytes,
                collection_hints: self.collection_hints,
            },
        ))
    }
}

struct BudgetVariant<A> {
    inner: A,
    budget: DecodeBudget,
    borrow_parser_bytes: bool,
    collection_hints: CollectionHints,
}

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for BudgetVariant<A> {
    type Error = A::Error;
    fn unit_variant(self) -> Result<(), Self::Error> {
        self.inner.unit_variant()
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        self.inner.newtype_variant_seed(BudgetSeed {
            inner: seed,
            budget: self.budget,
            borrow_parser_bytes: self.borrow_parser_bytes,
            collection_hints: CollectionHints::Suppress,
        })
    }
    fn tuple_variant<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.tuple_variant(
            len,
            BudgetVisitor {
                inner: visitor,
                budget: self.budget,
                borrow_parser_bytes: self.borrow_parser_bytes,
                collection_hints: self.collection_hints,
            },
        )
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.struct_variant(
            fields,
            BudgetVisitor {
                inner: visitor,
                budget: self.budget,
                borrow_parser_bytes: self.borrow_parser_bytes,
                collection_hints: self.collection_hints,
            },
        )
    }
}
