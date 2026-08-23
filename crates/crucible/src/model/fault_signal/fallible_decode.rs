//! Fallible serde ownership used by authenticated fault artifacts.
//!
//! Canonical fault artifacts are admitted by encoded size before decoding, but
//! their owned Rust representation can be larger than the wire. This module
//! gives heap-bearing leaf values and sequences an explicit, scenario-bounded
//! allocation path while preserving their established serde representation.

use std::cell::Cell;
use std::marker::PhantomData;
use std::mem;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::FaultResourceLimits;

const RESOURCE_PREFIX: &str = "crucible-resource-limit";

#[derive(Clone, Copy)]
struct DecodeBudget {
    fat_configured: u64,
    fat_hard: u64,
    work_items_configured: u64,
    records_configured: u64,
    decoded_work_items: u64,
    decoded_records: u64,
    owned_bytes: u64,
}

thread_local! {
    static ACTIVE_BUDGET: Cell<Option<DecodeBudget>> = const { Cell::new(None) };
}

pub(super) struct DecodeBudgetGuard {
    prior: Option<DecodeBudget>,
}

impl DecodeBudgetGuard {
    pub(super) fn enter(limits: FaultResourceLimits) -> Self {
        let budget = DecodeBudget {
            fat_configured: limits.fat_checkpoint_bytes,
            fat_hard: FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
            work_items_configured: limits.thin_replay_events,
            records_configured: limits.resolved_effect_records,
            decoded_work_items: 0,
            decoded_records: 0,
            owned_bytes: 0,
        };
        let prior = ACTIVE_BUDGET.with(|active| active.replace(Some(budget)));
        Self { prior }
    }
}

impl Drop for DecodeBudgetGuard {
    fn drop(&mut self) {
        ACTIVE_BUDGET.with(|active| active.set(self.prior));
    }
}

pub(super) fn configured(field: &'static str, hard: u64) -> u64 {
    ACTIVE_BUDGET.with(|active| {
        let Some(budget) = active.get() else {
            return hard;
        };
        match field {
            "fat_checkpoint_bytes" => budget.fat_configured.min(hard),
            "thin_replay_events" => budget.work_items_configured.min(hard),
            "resolved_effect_records" => budget.records_configured.min(hard),
            _ => hard,
        }
    })
}

fn budget_active() -> bool {
    ACTIVE_BUDGET.with(|active| active.get().is_some())
}

pub(super) fn collection_current(field: &'static str) -> u64 {
    ACTIVE_BUDGET.with(|active| {
        active.get().map_or(0, |budget| match field {
            "thin_replay_events" => budget.decoded_work_items,
            "resolved_effect_records" => budget.decoded_records,
            _ => 0,
        })
    })
}

pub(super) fn commit_collection(field: &'static str, additional: u64) -> Result<(), String> {
    ACTIVE_BUDGET.with(|active| {
        let Some(mut budget) = active.get() else {
            return Ok(());
        };
        let slot = match field {
            "thin_replay_events" => &mut budget.decoded_work_items,
            "resolved_effect_records" => &mut budget.decoded_records,
            _ => return Ok(()),
        };
        *slot = slot.checked_add(additional).ok_or_else(|| {
            resource_message(
                field,
                *slot,
                additional,
                configured(field, u64::MAX),
                u64::MAX,
            )
        })?;
        active.set(Some(budget));
        Ok(())
    })
}

pub(super) fn resource_message(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> String {
    format!("{RESOURCE_PREFIX}|{field}|{current}|{requested}|{configured}|{hard}")
}

fn admit_owned_bytes(requested: u64) -> Result<(), String> {
    ACTIVE_BUDGET.with(|active| {
        let Some(mut budget) = active.get() else {
            return Ok(());
        };
        let total = budget.owned_bytes.checked_add(requested).ok_or_else(|| {
            resource_message(
                "fat_checkpoint_bytes",
                budget.owned_bytes,
                requested,
                budget.fat_configured,
                budget.fat_hard,
            )
        })?;
        if total > budget.fat_configured || total > budget.fat_hard {
            return Err(resource_message(
                "fat_checkpoint_bytes",
                budget.owned_bytes,
                requested,
                budget.fat_configured,
                budget.fat_hard,
            ));
        }
        budget.owned_bytes = total;
        active.set(Some(budget));
        Ok(())
    })
}

pub(super) fn deserialize_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringVisitor;

    impl Visitor<'_> for StringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a definite UTF-8 string")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            let requested = u64::try_from(value.len()).unwrap_or(u64::MAX);
            admit_owned_bytes(requested).map_err(E::custom)?;
            let mut owned = String::new();
            owned
                .try_reserve_exact(value.len())
                .map_err(|_| E::custom(allocation_message(requested)))?;
            owned.push_str(value);
            Ok(owned)
        }
    }

    deserializer.deserialize_str(StringVisitor)
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
            formatter.write_str("a definite, allocation-bounded sequence")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let Some(count) = sequence.size_hint() else {
                if budget_active() {
                    return Err(serde::de::Error::custom(
                        "indefinite fault-artifact sequence",
                    ));
                }
                let mut values = Vec::new();
                loop {
                    if values.len() == values.capacity() {
                        values
                            .try_reserve(1)
                            .map_err(|_| serde::de::Error::custom(allocation_message(1)))?;
                    }
                    let Some(value) = sequence.next_element()? else {
                        return Ok(values);
                    };
                    values.push(value);
                }
            };
            let element_bytes = mem::size_of::<T>().max(1);
            let requested = u64::try_from(count)
                .ok()
                .and_then(|count| {
                    count.checked_mul(u64::try_from(element_bytes).unwrap_or(u64::MAX))
                })
                .unwrap_or(u64::MAX);
            admit_owned_bytes(requested).map_err(serde::de::Error::custom)?;

            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| serde::de::Error::custom(allocation_message(requested)))?;
            for _ in 0..count {
                let value = sequence
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::custom("truncated fault-artifact sequence"))?;
                values.push(value);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "fault-artifact sequence exceeds its declared length",
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(VecVisitor(PhantomData))
}

fn allocation_message(requested: u64) -> String {
    ACTIVE_BUDGET.with(|active| {
        active.get().map_or_else(
            || {
                resource_message(
                    "fat_checkpoint_bytes",
                    0,
                    requested,
                    FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
                    FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
                )
            },
            |budget| {
                resource_message(
                    "fat_checkpoint_bytes",
                    budget.owned_bytes.saturating_sub(requested),
                    requested,
                    budget.fat_configured,
                    budget.fat_hard,
                )
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FallibleU64Vec(Vec<u64>);

    impl<'de> Deserialize<'de> for FallibleU64Vec {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserialize_vec(deserializer).map(Self)
        }
    }

    #[test]
    fn nested_sequence_allocation_uses_the_authored_fat_checkpoint_coordinate() {
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: 2,
            ..FaultResourceLimits::default()
        };
        let _guard = DecodeBudgetGuard::enter(limits);
        let mut scratch = [0_u8; 1];
        let error = ciborium::de::from_reader_with_buffer::<FallibleU64Vec, _>(
            [0x81, 0x00].as_slice(),
            &mut scratch,
        )
        .err()
        .unwrap_or_else(|| panic!("eight owned bytes must exceed a two-byte artifact budget"));
        let message = error.to_string();
        assert!(message.contains("crucible-resource-limit|fat_checkpoint_bytes|0|8|2|"));
    }

    #[test]
    fn nested_sequence_decoder_preserves_definite_wire_values() {
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: 16,
            ..FaultResourceLimits::default()
        };
        let _guard = DecodeBudgetGuard::enter(limits);
        let mut scratch = [0_u8; 1];
        let decoded = ciborium::de::from_reader_with_buffer::<FallibleU64Vec, _>(
            [0x82, 0x01, 0x02].as_slice(),
            &mut scratch,
        )
        .unwrap_or_else(|error| panic!("bounded vector should decode: {error}"));
        assert_eq!(decoded.0, vec![1, 2]);
    }

    #[test]
    fn non_artifact_deserializers_retain_streaming_sequence_compatibility() {
        let decoded = serde_json::from_str::<FallibleU64Vec>("[1,2]")
            .unwrap_or_else(|error| panic!("streaming JSON sequence should decode: {error}"));
        assert_eq!(decoded.0, vec![1, 2]);
    }
}
