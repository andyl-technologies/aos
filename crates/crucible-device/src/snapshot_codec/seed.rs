//! Borrowed allocation admission for bounded device snapshot tables.
//!
//! Each seed carries its enclosing callback directly. The transparent serde
//! marker preserves only the current table's count; nested seeds keep their
//! own admission. It has no account lookup and changes no encoded bytes.

use std::cell::RefCell;
use std::marker::PhantomData;

use serde::de::{DeserializeSeed, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::{BoundedVec, resource_message};

pub(crate) type TableAdmission<'a> = RefCell<&'a mut dyn FnMut(u64) -> Result<(), &'static str>>;

pub(crate) struct ValueSeed<T>(PhantomData<T>);

impl<T> ValueSeed<T> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> Clone for ValueSeed<T> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for ValueSeed<T> {
    type Value = T;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<T, D::Error> {
        T::deserialize(decoder)
    }
}

#[derive(Clone)]
pub(crate) struct BoundedVecSeed<'a, 'callback, S, const MAX: u64> {
    member: S,
    admission: &'a TableAdmission<'callback>,
}

impl<'a, 'callback, S, const MAX: u64> BoundedVecSeed<'a, 'callback, S, MAX> {
    pub(crate) fn new(member: S, admission: &'a TableAdmission<'callback>) -> Self {
        Self { member, admission }
    }
}

impl<'de, S: DeserializeSeed<'de> + Clone, const MAX: u64> DeserializeSeed<'de>
    for BoundedVecSeed<'_, '_, S, MAX>
{
    type Value = BoundedVec<S::Value, MAX>;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        // The parser treats this as a transparent newtype. The enclosing
        // original wrapper uses the exact same name to retain this hint only.
        decoder.deserialize_newtype_struct("crucible.original.prepaid-sequence", TableVisitor(self))
    }
}

struct TableVisitor<S>(S);

impl<'de, S: DeserializeSeed<'de> + Clone, const MAX: u64> Visitor<'de>
    for TableVisitor<BoundedVecSeed<'_, '_, S, MAX>>
{
    type Value = BoundedVec<S::Value, MAX>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "at most {MAX} device snapshot entries")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        decoder: D,
    ) -> Result<Self::Value, D::Error> {
        decoder.deserialize_seq(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let hint = sequence.size_hint().unwrap_or(0);
        let requested = u64::try_from(hint).unwrap_or(u64::MAX);
        if requested > MAX {
            return Err(serde::de::Error::custom(resource_message(
                "device snapshot sequence",
                0,
                requested,
                MAX,
                MAX,
            )));
        }

        let mut values = Vec::new();
        let initial = hint.min(1024);
        admit_table::<S::Value, A::Error>(self.0.admission, initial)?;
        values.try_reserve_exact(initial).map_err(|_| {
            serde::de::Error::custom(resource_message(
                "device snapshot sequence",
                0,
                initial as u64,
                MAX,
                MAX,
            ))
        })?;

        loop {
            let current = u64::try_from(values.len()).unwrap_or(u64::MAX);
            if current >= MAX {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom(resource_message(
                        "device snapshot sequence",
                        current,
                        1,
                        MAX,
                        MAX,
                    )));
                }
                break;
            }
            let Some(value) = sequence.next_element_seed(self.0.member.clone())? else {
                break;
            };

            if values.len() == values.capacity() {
                let target = values.capacity().saturating_mul(2).max(1);
                let target = u64::try_from(target).unwrap_or(u64::MAX).min(MAX);
                let target = usize::try_from(target).map_err(|_| {
                    serde::de::Error::custom(resource_message(
                        "device snapshot sequence",
                        current,
                        1,
                        MAX,
                        MAX,
                    ))
                })?;
                admit_table::<S::Value, A::Error>(self.0.admission, target)?;
                values
                    .try_reserve_exact(target - values.len())
                    .map_err(|_| {
                        serde::de::Error::custom(resource_message(
                            "device snapshot sequence",
                            current,
                            1,
                            MAX,
                            MAX,
                        ))
                    })?;
            }
            values.push(value);
        }

        Ok(BoundedVec { values })
    }
}

fn admit_table<T, E: serde::de::Error>(
    admission: &TableAdmission<'_>,
    entries: usize,
) -> Result<(), E> {
    let bytes = entries
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| E::custom("device snapshot table extent overflow"))?;
    let mut callback = admission
        .try_borrow_mut()
        .map_err(|_| E::custom("device snapshot admission is already borrowed"))?;
    callback(bytes).map_err(E::custom)
}

#[derive(Clone)]
pub(crate) struct PairSeed<A, B>(pub(crate) A, pub(crate) B);

impl<'de, A: DeserializeSeed<'de>, B: DeserializeSeed<'de>> DeserializeSeed<'de>
    for PairSeed<A, B>
{
    type Value = (A::Value, B::Value);

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_tuple(2, PairVisitor(self))
    }
}

struct PairVisitor<A, B>(PairSeed<A, B>);

impl<'de, A: DeserializeSeed<'de>, B: DeserializeSeed<'de>> Visitor<'de> for PairVisitor<A, B> {
    type Value = (A::Value, B::Value);

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a two-member device snapshot entry")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
        let first = sequence
            .next_element_seed(self.0.0)?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &"two members"))?;
        let second = sequence
            .next_element_seed(self.0.1)?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &"two members"))?;
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::invalid_length(3, &"two members"));
        }
        Ok((first, second))
    }
}

#[cfg(test)]
mod tests;
