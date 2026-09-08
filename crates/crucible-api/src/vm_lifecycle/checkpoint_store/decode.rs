//! Fallible owned decoding for exact-checkpoint CBOR envelopes.

use super::*;
use serde::de::{DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::mem;

const RESOURCE_PREFIX: &str = "crucible-checkpoint-resource-limit";

#[derive(Debug)]
struct DecodeAdmissionError(String);

impl fmt::Display for DecodeAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DecodeAdmissionError {}

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

/// Allocation-bounded owned text used by the exact-checkpoint wire structs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub(super) struct FallibleString(String);

impl FallibleString {
    /// Wraps controller-owned text for canonical serialization.
    pub(super) fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrows the decoded text.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// Transfers the decoded text without another allocation.
    pub(super) fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for FallibleString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::ops::Deref for FallibleString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl<'de> Deserialize<'de> for FallibleString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringVisitor;

        impl Visitor<'_> for StringVisitor {
            type Value = FallibleString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("allocation-bounded exact-checkpoint text")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let requested = u64::try_from(value.len()).unwrap_or(u64::MAX);
                let current = admit_owned(requested).map_err(E::custom)?;
                let mut owned = String::new();
                owned
                    .try_reserve_exact(value.len())
                    .map_err(|_| E::custom(resource_message(current, requested)))?;
                owned.push_str(value);
                Ok(FallibleString(owned))
            }
        }

        deserializer.deserialize_str(StringVisitor)
    }
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
    let (format_version, payload) = if let Some(payload) = bytes.strip_prefix(MANIFEST_MAGIC) {
        (MANIFEST_VERSION, payload)
    } else if let Some(payload) = bytes.strip_prefix(PREVIOUS_MANIFEST_MAGIC) {
        (PREVIOUS_MANIFEST_VERSION, payload)
    } else if let Some(payload) = bytes.strip_prefix(OLDER_MANIFEST_MAGIC) {
        (OLDER_MANIFEST_VERSION, payload)
    } else if let Some(payload) = bytes.strip_prefix(LEGACY_MANIFEST_MAGIC) {
        (LEGACY_MANIFEST_VERSION, payload)
    } else {
        return Err(loop_factory_error("unsupported closure manifest version"));
    };
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(loop_factory_error(
            "closure manifest exceeds its size limit",
        ));
    }

    let mut manifest: ClosureManifest =
        decode_cbor_with_limits(payload, limits, "malformed closure manifest")?;
    manifest.format_version = format_version;
    let canonical =
        encode_manifest(&manifest).map_err(|error| loop_factory_error(error.to_string()))?;
    if canonical != bytes {
        return Err(loop_factory_error("noncanonical closure manifest"));
    }
    validate_manifest_shape(&manifest).map_err(loop_factory_error)?;
    Ok(manifest)
}

/// Decodes one admitted CBOR object without Ciborium-owned string growth.
///
/// The scratch buffer is bounded by the already-admitted envelope length. Wire
/// strings then deserialize through [`FallibleString`] and reserve their final
/// ownership against the same authored byte budget before copying.
///
/// # Errors
///
/// Returns an exact resource-limit error for envelope, scratch, collection, or
/// string allocation refusal, and a loop-factory error for malformed CBOR.
pub(super) fn decode_cbor_with_limits<T: DeserializeOwned>(
    bytes: &[u8],
    limits: FaultResourceLimits,
    malformed: &'static str,
) -> Result<T, LifecycleApiError> {
    let requested = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let hard = FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes;
    if requested > limits.fat_checkpoint_bytes || requested > hard {
        return Err(decode_resource_limit(0, requested, limits, hard));
    }

    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(bytes.len())
        .map_err(|_| decode_resource_limit(0, requested, limits, hard))?;
    scratch.resize(bytes.len(), 0);

    let _budget = DecodeBudgetGuard::enter(limits);
    ciborium::de::from_reader_with_buffer(bytes, &mut scratch).map_err(|error| {
        map_decode_resource_error(&error).unwrap_or_else(|| loop_factory_error(malformed))
    })
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

/// Deserializes one catalog plan without allocating beyond its protocol cap.
pub(super) fn deserialize_selectable_catalog_plan<'de, D>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct PlanVisitor;

    impl<'de> Visitor<'de> for PlanVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded selectable catalog plan byte string")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let Some(count) = sequence.size_hint() else {
                return Err(serde::de::Error::custom(
                    "indefinite selectable catalog plan",
                ));
            };
            let maximum =
                crucible_protocol::selectable_catalog_plan::SELECTABLE_CATALOG_PLAN_MAX_BYTES;
            if count > maximum {
                return Err(serde::de::Error::custom(
                    "selectable catalog plan exceeds its byte limit",
                ));
            }
            let requested = u64::try_from(count).unwrap_or(u64::MAX);
            let current = admit_owned(requested).map_err(serde::de::Error::custom)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(count)
                .map_err(|_| serde::de::Error::custom(resource_message(current, requested)))?;
            for _ in 0..count {
                bytes.push(sequence.next_element()?.ok_or_else(|| {
                    serde::de::Error::custom("truncated selectable catalog plan")
                })?);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "selectable catalog plan exceeds its declared length",
                ));
            }
            Ok(bytes)
        }

        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            let maximum =
                crucible_protocol::selectable_catalog_plan::SELECTABLE_CATALOG_PLAN_MAX_BYTES;
            if bytes.len() > maximum {
                return Err(E::custom("selectable catalog plan exceeds its byte limit"));
            }
            let requested = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            let current = admit_owned(requested).map_err(E::custom)?;
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(bytes.len())
                .map_err(|_| E::custom(resource_message(current, requested)))?;
            owned.extend_from_slice(bytes);
            Ok(owned)
        }
    }

    deserializer.deserialize_bytes(PlanVisitor)
}

/// Deserializes one campaign selection decision under its canonical byte cap.
pub(super) fn deserialize_selection_decision<'de, D>(
    deserializer: D,
) -> Result<crucible::SelectionDecision, D::Error>
where
    D: Deserializer<'de>,
{
    const MAX_SELECTION_BYTES: usize = 64 * 1024 * 1024;

    struct SelectionVisitor;

    impl<'de> Visitor<'de> for SelectionVisitor {
        type Value = crucible::SelectionDecision;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded canonical campaign selection")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let Some(count) = sequence.size_hint() else {
                return Err(serde::de::Error::custom(
                    "indefinite campaign selection decision",
                ));
            };
            if count > MAX_SELECTION_BYTES {
                return Err(serde::de::Error::custom(
                    "campaign selection decision exceeds its byte limit",
                ));
            }
            let requested = u64::try_from(count).unwrap_or(u64::MAX);
            let current = admit_owned(requested).map_err(serde::de::Error::custom)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(count)
                .map_err(|_| serde::de::Error::custom(resource_message(current, requested)))?;
            for _ in 0..count {
                bytes.push(sequence.next_element()?.ok_or_else(|| {
                    serde::de::Error::custom("truncated campaign selection decision")
                })?);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "campaign selection decision exceeds its declared length",
                ));
            }
            crucible::SelectionDecision::from_canonical_bytes(&bytes)
                .map_err(serde::de::Error::custom)
        }

        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.len() > MAX_SELECTION_BYTES {
                return Err(E::custom(
                    "campaign selection decision exceeds its byte limit",
                ));
            }
            let requested = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            admit_owned(requested).map_err(E::custom)?;
            crucible::SelectionDecision::from_canonical_bytes(bytes).map_err(E::custom)
        }
    }

    deserializer.deserialize_bytes(SelectionVisitor)
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

fn admit_owned(requested: u64) -> Result<u64, DecodeAdmissionError> {
    ACTIVE_BUDGET.with(|active| {
        let Some(mut budget) = active.get() else {
            return Ok(0);
        };
        let current = budget.owned;
        let Some(total) = current.checked_add(requested) else {
            return Err(DecodeAdmissionError(resource_message(current, requested)));
        };
        if total > budget.configured || total > budget.hard {
            return Err(DecodeAdmissionError(resource_message(current, requested)));
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

fn decode_resource_limit(
    current: u64,
    requested: u64,
    limits: FaultResourceLimits,
    hard: u64,
) -> LifecycleApiError {
    LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
        field: "fat_checkpoint_bytes",
        current,
        requested,
        configured: limits.fat_checkpoint_bytes,
        hard,
    })
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    #[derive(Debug)]
    struct FallibleVector;

    impl<'de> Deserialize<'de> for FallibleVector {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let _: Vec<u64> = deserialize_vec(deserializer)?;
            Ok(Self)
        }
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct FallibleStringVector(#[serde(deserialize_with = "deserialize_vec")] Vec<FallibleString>);

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
    fn nested_string_is_admitted_before_owned_copy_with_exact_coordinates() {
        let vector_bytes = u64::try_from(mem::size_of::<FallibleString>())
            .unwrap_or_else(|_| panic!("fallible string size is representable"));
        let configured = vector_bytes + 8;
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: configured,
            ..FaultResourceLimits::default()
        };
        let bytes = [
            0x81, 0x69, b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
        ];

        let error = match decode_cbor_with_limits::<FallibleStringVector>(
            &bytes,
            limits,
            "decode string fixture",
        ) {
            Ok(_) => panic!("the vector slot plus nested string must exceed the owned budget"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                field: "fat_checkpoint_bytes",
                current,
                requested: 9,
                configured: observed_configured,
                hard,
            }) if current == vector_bytes
                && observed_configured == configured
                && hard == FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes
        ));
    }

    #[test]
    fn string_larger_than_default_cbor_scratch_round_trips_canonically() {
        let model = vec!["x".repeat(5_000)];
        let original =
            FallibleStringVector(model.iter().cloned().map(FallibleString::new).collect());
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&original, &mut bytes)
            .unwrap_or_else(|error| panic!("encode long checkpoint string: {error}"));
        let mut model_bytes = Vec::new();
        ciborium::ser::into_writer(&model, &mut model_bytes)
            .unwrap_or_else(|error| panic!("encode model checkpoint string: {error}"));
        assert_eq!(bytes, model_bytes);
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: 16_384,
            ..FaultResourceLimits::default()
        };

        let decoded: FallibleStringVector =
            decode_cbor_with_limits(&bytes, limits, "decode long checkpoint string")
                .unwrap_or_else(|error| panic!("decode long checkpoint string: {error}"));
        let mut canonical = Vec::new();
        ciborium::ser::into_writer(&decoded, &mut canonical)
            .unwrap_or_else(|error| panic!("re-encode long checkpoint string: {error}"));

        assert_eq!(decoded.0[0].as_str().len(), 5_000);
        assert_eq!(canonical, bytes);
    }

    #[test]
    fn production_manifest_decode_rejects_hostile_target_length_before_elements() {
        let manifest = ClosureManifest {
            format_version: MANIFEST_VERSION,
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
