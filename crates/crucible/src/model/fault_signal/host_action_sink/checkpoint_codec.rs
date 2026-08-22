//! Canonical, bounded host fault-adapter continuation codec.

use std::io::{self, Write};

use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::*;

const MAGIC: &[u8] = b"crucible.host-fault-action-state.v3\0";
const HARD_ACTIONS: u64 = FaultResourceLimits::compiled_maximum().resolved_effect_records;

struct ActionEntriesRef<'a>(&'a BTreeMap<ActiveContributionKey, ResolvedBindingAction>);

impl Serialize for ActionEntriesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            sequence.serialize_element(&entry)?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct HostStateEncodeWire<'a> {
    active: ActionEntriesRef<'a>,
    impulses: &'a [ResolvedBindingAction],
    digest: ContentHash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostStateDecodeWire {
    active: BoundedVec<(ActiveContributionKey, ResolvedBindingAction), HARD_ACTIONS>,
    impulses: BoundedVec<ResolvedBindingAction, HARD_ACTIONS>,
    digest: ContentHash,
}

struct BoundedVec<T, const MAX: u64>(Vec<T>);

impl<'de, T: Deserialize<'de>, const MAX: u64> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, const MAX: u64>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const MAX: u64> Visitor<'de> for BoundedVisitor<T, MAX> {
            type Value = BoundedVec<T, MAX>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "at most {MAX} host action records")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let hint = sequence.size_hint().unwrap_or(0);
                let requested = u64::try_from(hint).unwrap_or(u64::MAX);
                if requested > MAX {
                    return Err(serde::de::Error::custom(resource_message(
                        "resolved_effect_records",
                        0,
                        requested,
                        MAX,
                        MAX,
                    )));
                }
                let mut values = Vec::new();
                let initial = hint.min(1024);
                values.try_reserve_exact(initial).map_err(|_| {
                    serde::de::Error::custom(resource_message(
                        "resolved_effect_records",
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
                                "resolved_effect_records",
                                current,
                                1,
                                MAX,
                                MAX,
                            )));
                        }
                        break;
                    }
                    let Some(value) = sequence.next_element()? else {
                        break;
                    };
                    if values.len() == values.capacity() {
                        values.try_reserve(1).map_err(|_| {
                            serde::de::Error::custom(resource_message(
                                "resolved_effect_records",
                                current,
                                1,
                                MAX,
                                MAX,
                            ))
                        })?;
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(std::marker::PhantomData))
    }
}

impl HostFaultActionState {
    /// Decodes host adapter state and authenticates its derived digest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] for malformed, unsupported, over-limit,
    /// noncanonical, or internally inconsistent state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FaultRuntimeError> {
        Self::from_canonical_bytes_with_limits(bytes, FaultResourceLimits::compiled_maximum())
    }

    /// Decodes host adapter state under an authored resource contract.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] under the same conditions as
    /// [`Self::from_canonical_bytes`], using `resource_limits` for byte and
    /// record admission.
    pub fn from_canonical_bytes_with_limits(
        bytes: &[u8],
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or(FaultRuntimeError::AdapterCheckpointCodec)?;
        admit_bytes(bytes.len(), resource_limits)?;
        let wire: HostStateDecodeWire =
            ciborium::de::from_reader(payload).map_err(map_decode_error)?;
        let total = wire
            .active
            .0
            .len()
            .checked_add(wire.impulses.0.len())
            .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
        resource_limits
            .reserve(
                "resolved_effect_records",
                0,
                u64::try_from(total)
                    .map_err(|_| FaultRuntimeError::CountOverflow("resolved_effect_records"))?,
            )
            .map_err(FaultRuntimeError::ResourceLimit)?;
        if wire.active.0.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(FaultRuntimeError::AdapterCheckpointCodec);
        }
        let mut state = Self {
            active: wire.active.0.into_iter().collect(),
            impulses: wire.impulses.0,
            digest: wire.digest,
        };
        state.validate_checkpoint()?;
        if state
            .canonical_bytes_with_limits(resource_limits)?
            .as_slice()
            != bytes
        {
            return Err(FaultRuntimeError::AdapterCheckpointCodec);
        }
        Ok(state)
    }

    /// Encodes host adapter state as deterministic, bounded CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when state exceeds the compiled checkpoint
    /// policy, allocation is refused, or serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FaultRuntimeError> {
        self.canonical_bytes_with_limits(FaultResourceLimits::compiled_maximum())
    }

    /// Encodes host adapter state under an authored resource contract.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] under the same conditions as
    /// [`Self::canonical_bytes`], using `resource_limits` for byte and record
    /// admission.
    pub fn canonical_bytes_with_limits(
        &self,
        resource_limits: FaultResourceLimits,
    ) -> Result<Vec<u8>, FaultRuntimeError> {
        let total = self
            .active
            .len()
            .checked_add(self.impulses.len())
            .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
        resource_limits
            .reserve(
                "resolved_effect_records",
                0,
                u64::try_from(total)
                    .map_err(|_| FaultRuntimeError::CountOverflow("resolved_effect_records"))?,
            )
            .map_err(FaultRuntimeError::ResourceLimit)?;
        let wire = HostStateEncodeWire {
            active: ActionEntriesRef(&self.active),
            impulses: &self.impulses,
            digest: self.digest,
        };
        encode(&wire, resource_limits)
    }

    fn validate_checkpoint(&mut self) -> Result<(), FaultRuntimeError> {
        if self.active.iter().any(|(key, action)| {
            action.kind != BindingActionKind::UpsertPersistent
                || action.binding != key.binding
                || action.target != key.target
                || action.phase != key.phase
                || action.effect.kind() != key.effect
        }) {
            return Err(FaultRuntimeError::IncompleteAdapterState);
        }
        let expected = self.digest;
        self.recompute_digest();
        if self.digest != expected {
            return Err(FaultRuntimeError::IncompleteAdapterState);
        }
        Ok(())
    }
}

fn encode<T: Serialize>(
    value: &T,
    resource_limits: FaultResourceLimits,
) -> Result<Vec<u8>, FaultRuntimeError> {
    let maximum = resource_limits.fat_checkpoint_bytes;
    let hard = FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes;
    let mut counter = CountingWriter::new(maximum, hard);
    ciborium::ser::into_writer(value, &mut counter).map_err(|_| {
        counter
            .failure
            .unwrap_or(FaultRuntimeError::CheckpointEncoding)
    })?;
    let magic = u64::try_from(MAGIC.len())
        .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
    let total = admit(magic, counter.length, maximum, hard)?;
    let total_usize = usize::try_from(total)
        .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total_usize)
        .map_err(|_| resource_error("fat_checkpoint_bytes", 0, total, maximum, hard))?;
    bytes.extend_from_slice(MAGIC);
    let mut writer = ReservedWriter::new(&mut bytes, total, hard);
    ciborium::ser::into_writer(value, &mut writer).map_err(|_| {
        writer
            .failure
            .unwrap_or(FaultRuntimeError::CheckpointEncoding)
    })?;
    if bytes.len() != total_usize {
        return Err(FaultRuntimeError::CheckpointEncoding);
    }
    Ok(bytes)
}

fn admit_bytes(
    length: usize,
    resource_limits: FaultResourceLimits,
) -> Result<(), FaultRuntimeError> {
    let requested = u64::try_from(length)
        .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
    resource_limits
        .reserve("fat_checkpoint_bytes", 0, requested)
        .map_err(FaultRuntimeError::ResourceLimit)
}

fn admit(
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> Result<u64, FaultRuntimeError> {
    let total = current.checked_add(requested).ok_or_else(|| {
        resource_error("fat_checkpoint_bytes", current, requested, configured, hard)
    })?;
    if total > configured || total > hard {
        return Err(resource_error(
            "fat_checkpoint_bytes",
            current,
            requested,
            configured,
            hard,
        ));
    }
    Ok(total)
}

fn resource_error(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> FaultRuntimeError {
    FaultRuntimeError::ResourceLimit(FaultResourceLimitError::Exceeded {
        field,
        current,
        requested,
        configured,
        hard,
    })
}

fn resource_message(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> String {
    format!("crucible-resource-limit|{field}|{current}|{requested}|{configured}|{hard}")
}

fn map_decode_error<T>(error: ciborium::de::Error<T>) -> FaultRuntimeError {
    let ciborium::de::Error::Semantic(_, message) = error else {
        return FaultRuntimeError::AdapterCheckpointCodec;
    };
    let mut fields = message.split('|');
    if fields.next() != Some("crucible-resource-limit")
        || fields.next() != Some("resolved_effect_records")
    {
        return FaultRuntimeError::AdapterCheckpointCodec;
    }
    let Some(current) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::AdapterCheckpointCodec;
    };
    let Some(requested) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::AdapterCheckpointCodec;
    };
    let Some(configured) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::AdapterCheckpointCodec;
    };
    let Some(hard) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::AdapterCheckpointCodec;
    };
    if fields.next().is_some() {
        return FaultRuntimeError::AdapterCheckpointCodec;
    }
    resource_error(
        "resolved_effect_records",
        current,
        requested,
        configured,
        hard,
    )
}

struct CountingWriter {
    configured: u64,
    hard: u64,
    length: u64,
    failure: Option<FaultRuntimeError>,
}

impl CountingWriter {
    const fn new(configured: u64, hard: u64) -> Self {
        Self {
            configured,
            hard,
            length: 0,
            failure: None,
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        self.length =
            admit(self.length, requested, self.configured, self.hard).map_err(|error| {
                self.failure = Some(error);
                io::Error::other("host adapter checkpoint exceeds its bound")
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ReservedWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: u64,
    hard: u64,
    failure: Option<FaultRuntimeError>,
}

impl<'a> ReservedWriter<'a> {
    fn new(bytes: &'a mut Vec<u8>, maximum: u64, hard: u64) -> Self {
        Self {
            bytes,
            maximum,
            hard,
            failure: None,
        }
    }
}

impl Write for ReservedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let current = u64::try_from(self.bytes.len()).unwrap_or(u64::MAX);
        let requested = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        admit(current, requested, self.maximum, self.hard).map_err(|error| {
            self.failure = Some(error);
            io::Error::other("host adapter checkpoint exceeded its reservation")
        })?;
        if buffer.len() > self.bytes.capacity().saturating_sub(self.bytes.len()) {
            self.failure = Some(resource_error(
                "fat_checkpoint_bytes",
                current,
                requested,
                self.maximum,
                self.hard,
            ));
            return Err(io::Error::other(
                "host adapter checkpoint allocation changed",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_host_state_codec_rejects_old_version_and_reports_authored_limit() {
        let state = HostFaultActionState::default();
        let bytes = state
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("encode host state: {error}"));

        let mut old_version = bytes.clone();
        old_version[..MAGIC.len()].copy_from_slice(b"crucible.host-fault-action-state.v2\0");
        assert_eq!(
            HostFaultActionState::from_canonical_bytes(&old_version),
            Err(FaultRuntimeError::AdapterCheckpointCodec)
        );

        let mut limits = FaultResourceLimits::compiled_maximum();
        limits.fat_checkpoint_bytes = (bytes.len() - 1) as u64;
        assert_eq!(
            HostFaultActionState::from_canonical_bytes_with_limits(&bytes, limits),
            Err(FaultRuntimeError::ResourceLimit(
                FaultResourceLimitError::Exceeded {
                    field: "fat_checkpoint_bytes",
                    current: 0,
                    requested: bytes.len() as u64,
                    configured: limits.fat_checkpoint_bytes,
                    hard: FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
                }
            ))
        );
    }
}
