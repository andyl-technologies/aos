//! Fallible owned decoding for exact-checkpoint CBOR envelopes.

use super::*;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::cell::Cell;
use std::marker::PhantomData;
use std::mem;

const RESOURCE_PREFIX: &str = "crucible-checkpoint-resource-limit";

#[derive(Clone, Copy)]
struct DecodeBudget {
    configured: u64,
    hard: u64,
    owned: u64,
}

thread_local! {
    static ACTIVE_BUDGET: Cell<Option<DecodeBudget>> = const { Cell::new(None) };
}

/// Restores the prior decoder budget when one bounded decode ends.
pub(super) struct DecodeBudgetGuard {
    prior: Option<DecodeBudget>,
}

impl DecodeBudgetGuard {
    /// Installs the scenario-authored owned-allocation budget for one decode.
    pub(super) fn enter(limits: FaultResourceLimits) -> Self {
        let budget = DecodeBudget {
            configured: limits.fat_checkpoint_bytes,
            hard: FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
            owned: 0,
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

/// Decodes and authenticates one canonical closure manifest under `limits`.
///
/// # Errors
///
/// Returns a typed resource-limit error before hostile owned collection
/// allocation, or a loop-factory error for version, shape, and canonical-byte
/// violations.
pub(super) fn decode_manifest_with_limits(
    bytes: &[u8],
    limits: FaultResourceLimits,
) -> Result<ClosureManifest, LifecycleApiError> {
    let payload = bytes
        .strip_prefix(MANIFEST_MAGIC)
        .ok_or_else(|| loop_factory_error("unsupported closure manifest version"))?;
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(loop_factory_error(
            "closure manifest exceeds its size limit",
        ));
    }

    let _budget = DecodeBudgetGuard::enter(limits);
    let manifest: ClosureManifest = ciborium::de::from_reader(payload).map_err(|error| {
        map_decode_resource_error(&error)
            .unwrap_or_else(|| loop_factory_error("malformed closure manifest"))
    })?;
    let canonical =
        encode_manifest(&manifest).map_err(|error| loop_factory_error(error.to_string()))?;
    if canonical != bytes {
        return Err(loop_factory_error("noncanonical closure manifest"));
    }
    validate_manifest_shape(&manifest).map_err(loop_factory_error)?;
    Ok(manifest)
}

/// Deserializes one definite sequence through explicit resource admission.
///
/// # Errors
///
/// Returns a serde error for indefinite, truncated, overlong, over-budget, or
/// allocation-refused sequences.
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
            let Some(count) = sequence.size_hint() else {
                return Err(serde::de::Error::custom(
                    "indefinite exact-checkpoint sequence",
                ));
            };
            let element_bytes = mem::size_of::<T>().max(1);
            let requested = u64::try_from(count)
                .ok()
                .and_then(|count| {
                    count.checked_mul(u64::try_from(element_bytes).unwrap_or(u64::MAX))
                })
                .unwrap_or(u64::MAX);
            let current = admit_owned(requested).map_err(serde::de::Error::custom)?;

            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| serde::de::Error::custom(resource_message(current, requested)))?;
            for _ in 0..count {
                let value = sequence.next_element()?.ok_or_else(|| {
                    serde::de::Error::custom("truncated exact-checkpoint sequence")
                })?;
                values.push(value);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "exact-checkpoint sequence exceeds its declared length",
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(VecVisitor(PhantomData))
}

/// Converts a semantic decoder resource marker into the public LIMIT-2 type.
pub(super) fn map_decode_resource_error<T>(
    error: &ciborium::de::Error<T>,
) -> Option<LifecycleApiError> {
    let ciborium::de::Error::Semantic(_, message) = error else {
        return None;
    };
    let mut fields = message.split('|');
    if fields.next() != Some(RESOURCE_PREFIX) || fields.next() != Some("fat_checkpoint_bytes") {
        return None;
    }
    let current = fields.next()?.parse().ok()?;
    let requested = fields.next()?.parse().ok()?;
    let configured = fields.next()?.parse().ok()?;
    let hard = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some(LifecycleApiError::ResourceLimit(
        crate::LifecycleResourceLimit {
            field: "fat_checkpoint_bytes",
            current,
            requested,
            configured,
            hard,
        },
    ))
}

fn admit_owned(requested: u64) -> Result<u64, String> {
    ACTIVE_BUDGET.with(|active| {
        let Some(mut budget) = active.get() else {
            return Ok(0);
        };
        let current = budget.owned;
        let Some(total) = current.checked_add(requested) else {
            return Err(resource_message(current, requested));
        };
        if total > budget.configured || total > budget.hard {
            return Err(resource_message(current, requested));
        }
        budget.owned = total;
        active.set(Some(budget));
        Ok(current)
    })
}

fn resource_message(current: u64, requested: u64) -> String {
    ACTIVE_BUDGET.with(|active| {
        let budget = active.get().unwrap_or(DecodeBudget {
            configured: FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
            hard: FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
            owned: current,
        });
        format!(
            "{RESOURCE_PREFIX}|fat_checkpoint_bytes|{current}|{requested}|{}|{}",
            budget.configured, budget.hard
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[derive(Debug)]
    struct FallibleVector(#[allow(dead_code)] Vec<u64>);

    impl<'de> Deserialize<'de> for FallibleVector {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserialize_vec(deserializer).map(Self)
        }
    }

    #[test]
    fn hostile_sequence_length_hint_is_rejected_before_owned_allocation() {
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: 7,
            ..FaultResourceLimits::default()
        };
        let _guard = DecodeBudgetGuard::enter(limits);
        let mut scratch = [0_u8; 1];
        let error = match ciborium::de::from_reader_with_buffer::<FallibleVector, _>(
            [0x9b, 0, 0, 0, 0, 0, 0, 0, 2].as_slice(),
            &mut scratch,
        ) {
            Ok(_) => panic!("two u64 slots must exceed a seven-byte owned budget"),
            Err(error) => error,
        };

        assert!(matches!(
            map_decode_resource_error(&error),
            Some(LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                field: "fat_checkpoint_bytes",
                current: 0,
                requested: 16,
                configured: 7,
                hard,
            })) if hard == FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes
        ));
    }

    #[test]
    fn production_manifest_decode_rejects_hostile_target_length_before_elements() {
        let manifest = ClosureManifest {
            scenario: ContentHash::default(),
            configuration: ContentHash::default(),
            schedule: ContentHash::default(),
            frontier: 0,
            scheduler: ContentHash::default(),
            event_log_segments: Vec::new(),
            signal_artifacts: Vec::new(),
            trigger_state: ContentHash::default(),
            assertion_state: ContentHash::default(),
            lifecycle_state: ContentHash::default(),
            fault_checkpoint: ContentHash::default(),
            targets: Vec::new(),
            node_generations: Vec::new(),
            node_service_states: Vec::new(),
            identity: ContentHash::default(),
        };
        let mut bytes = match encode_manifest(&manifest) {
            Ok(bytes) => bytes,
            Err(error) => panic!("encode manifest fixture: {error}"),
        };
        let key = b"targets";
        let Some(key_offset) = bytes.windows(key.len()).position(|window| window == key) else {
            panic!("locate targets key");
        };
        let value_offset = key_offset + key.len();
        assert_eq!(bytes[value_offset], 0x80, "targets must encode as []");
        bytes.splice(value_offset..=value_offset, [0x9b, 0, 0, 0, 0, 0, 0, 4, 0]);
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: 1_024,
            ..FaultResourceLimits::default()
        };
        let Ok(manifest_length) = u64::try_from(bytes.len()) else {
            panic!("manifest length is not representable");
        };
        assert!(manifest_length < limits.fat_checkpoint_bytes);

        let error = match decode_manifest_with_limits(&bytes, limits) {
            Ok(_) => panic!("hostile target length must fail before reading target elements"),
            Err(error) => error,
        };
        let Ok(target_size) = u64::try_from(mem::size_of::<TargetManifest>()) else {
            panic!("target size is not representable");
        };
        let requested = 1_024_u64 * target_size;
        assert!(matches!(
            error,
            LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                field: "fat_checkpoint_bytes",
                current: 0,
                requested: observed,
                configured: 1_024,
                hard,
            }) if observed == requested
                && hard == FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes
        ));
    }
}
