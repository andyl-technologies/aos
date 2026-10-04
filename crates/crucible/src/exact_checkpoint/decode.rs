//! Allocation-bounded decoding for canonical exact-checkpoint manifests.

use std::cell::Cell;
use std::marker::PhantomData;
use std::mem;

use serde::de::{Deserialize, DeserializeOwned, Deserializer, SeqAccess, Visitor};

use super::ExactCheckpointRelationError;

#[derive(Clone, Copy)]
struct DecodeBudget {
    limit: u64,
    owned: u64,
}

thread_local! {
    static ACTIVE_BUDGET: Cell<Option<DecodeBudget>> = const { Cell::new(None) };
}

struct DecodeBudgetGuard {
    prior: Option<DecodeBudget>,
}

impl DecodeBudgetGuard {
    fn enter(limit: u64) -> Self {
        let prior =
            ACTIVE_BUDGET.with(|active| active.replace(Some(DecodeBudget { limit, owned: 0 })));
        Self { prior }
    }
}

impl Drop for DecodeBudgetGuard {
    fn drop(&mut self) {
        ACTIVE_BUDGET.with(|active| active.set(self.prior));
    }
}

pub(super) fn decode_cbor_with_limit<T: DeserializeOwned>(
    bytes: &[u8],
    owned_byte_limit: u64,
) -> Result<T, ExactCheckpointRelationError> {
    let requested =
        u64::try_from(bytes.len()).map_err(|_| ExactCheckpointRelationError::ResourceExhausted)?;
    if requested > owned_byte_limit {
        return Err(ExactCheckpointRelationError::ResourceExhausted);
    }

    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(bytes.len())
        .map_err(|_| ExactCheckpointRelationError::ResourceExhausted)?;
    scratch.resize(bytes.len(), 0);

    let _budget = DecodeBudgetGuard::enter(owned_byte_limit - requested);
    ciborium::de::from_reader_with_buffer(bytes, &mut scratch).map_err(|error| match error {
        ciborium::de::Error::Semantic(_, message) if message == "resource exhausted" => {
            ExactCheckpointRelationError::ResourceExhausted
        }
        _ => ExactCheckpointRelationError::InvalidStructure,
    })
}

pub(super) fn deserialize_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct VecVisitor<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for VecVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a definite allocation-bounded checkpoint sequence")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let count = sequence
                .size_hint()
                .ok_or_else(|| serde::de::Error::custom("indefinite checkpoint sequence"))?;
            admit_allocation::<A::Error>(allocation_bytes::<T>(count))?;

            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| serde::de::Error::custom("resource exhausted"))?;
            for _ in 0..count {
                values.push(
                    sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("truncated checkpoint sequence"))?,
                );
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "checkpoint sequence exceeds its declared length",
                ));
            }

            Ok(values)
        }
    }

    deserializer.deserialize_seq(VecVisitor(PhantomData))
}

pub(super) fn deserialize_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringVisitor;

    impl Visitor<'_> for StringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("allocation-bounded checkpoint text")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            admit_allocation::<E>(u64::try_from(value.len()).unwrap_or(u64::MAX))?;

            let mut owned = String::new();
            owned
                .try_reserve_exact(value.len())
                .map_err(|_| E::custom("resource exhausted"))?;
            owned.push_str(value);
            Ok(owned)
        }
    }

    deserializer.deserialize_str(StringVisitor)
}

pub(super) fn deserialize_string_u64_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<(String, u64)>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_pair_vec(deserializer)
}

pub(super) fn deserialize_string_u8_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<(String, u8)>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_pair_vec(deserializer)
}

fn deserialize_string_pair_vec<'de, D, T>(deserializer: D) -> Result<Vec<(String, T)>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct PairVisitor<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for PairVisitor<T> {
        type Value = Vec<(String, T)>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a definite sequence of checkpoint text pairs")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let count = sequence
                .size_hint()
                .ok_or_else(|| serde::de::Error::custom("indefinite checkpoint sequence"))?;
            admit_allocation::<A::Error>(allocation_bytes::<(String, T)>(count))?;

            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| serde::de::Error::custom("resource exhausted"))?;
            for _ in 0..count {
                let (text, value) = sequence
                    .next_element::<(BoundedString, T)>()?
                    .ok_or_else(|| serde::de::Error::custom("truncated checkpoint sequence"))?;
                values.push((text.0, value));
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "checkpoint sequence exceeds its declared length",
                ));
            }

            Ok(values)
        }
    }

    deserializer.deserialize_seq(PairVisitor(PhantomData))
}

struct BoundedString(String);

impl<'de> Deserialize<'de> for BoundedString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_string(deserializer).map(Self)
    }
}

fn allocation_bytes<T>(count: usize) -> u64 {
    u64::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(u64::try_from(mem::size_of::<T>().max(1)).ok()?))
        .unwrap_or(u64::MAX)
}

fn admit_allocation<E: serde::de::Error>(requested: u64) -> Result<(), E> {
    ACTIVE_BUDGET.with(|active| {
        let Some(mut budget) = active.get() else {
            return Err(E::custom("checkpoint decoder has no active budget"));
        };
        budget.owned = budget
            .owned
            .checked_add(requested)
            .filter(|total| *total <= budget.limit)
            .ok_or_else(|| E::custom("resource exhausted"))?;
        active.set(Some(budget));
        Ok(())
    })
}
