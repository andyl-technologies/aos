//! Fallible, premeasured canonical-CBOR envelope encoding.
//!
//! Checkpoint owners can contain large but valid queues. Serializing directly
//! into a growing [`Vec`] would let allocator failure abort the host before the
//! post-encode size check ran. This module counts the exact representation,
//! admits it against the configured and compiled ceilings, reserves once with
//! a fallible operation, and then writes only into that reservation.

use std::io::{self, Write};

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// RFC-0014's compiled hard ceiling for one fat checkpoint artifact.
pub(crate) const HARD_FAT_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Failure to admit or serialize a bounded CBOR envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedCborError {
    /// Serialization encountered a value that CBOR cannot represent.
    Malformed,
    /// The encoded form or its allocation exceeds an active resource ceiling.
    ResourceLimit {
        field: &'static str,
        current: u64,
        requested: u64,
        configured: u64,
        hard: u64,
    },
}

/// A sequence whose decoder reserves fallibly and never grows beyond `MAX` entries.
///
/// Canonical CBOR normally supplies an exact sequence length, but the visitor
/// also handles indefinite hostile inputs by reserving each growth step before
/// asking `Vec` to append. Allocation refusal is therefore a decode error, not
/// a process abort.
pub(crate) struct BoundedVec<T, const MAX: u64> {
    values: Vec<T>,
}

impl<T, const MAX: u64> BoundedVec<T, MAX> {
    /// Wraps an already admitted vector.
    pub(crate) fn new(values: Vec<T>) -> Result<Self, BoundedCborError> {
        let requested = u64::try_from(values.len())
            .map_err(|_| resource("bounded CBOR sequence", 0, u64::MAX, MAX))?;
        if requested > MAX {
            return Err(resource("bounded CBOR sequence", 0, requested, MAX));
        }
        Ok(Self { values })
    }

    /// Borrows the admitted values.
    pub(crate) fn as_slice(&self) -> &[T] {
        &self.values
    }

    /// Returns the admitted vector.
    pub(crate) fn into_inner(self) -> Vec<T> {
        self.values
    }
}

impl<T: Serialize, const MAX: u64> Serialize for BoundedVec<T, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.values.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const MAX: u64> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, const MAX: u64>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const MAX: u64> Visitor<'de> for BoundedVisitor<T, MAX> {
            type Value = BoundedVec<T, MAX>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "at most {MAX} sequence entries")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let hint = sequence.size_hint().unwrap_or(0);
                let requested = u64::try_from(hint).unwrap_or(u64::MAX);
                if requested > MAX {
                    return Err(serde::de::Error::custom(format_args!(
                        "bounded sequence length {requested} exceeds {MAX}"
                    )));
                }
                let mut values = Vec::new();
                values.try_reserve_exact(hint).map_err(|_| {
                    serde::de::Error::custom(format_args!(
                        "bounded sequence allocation of {requested} entries failed"
                    ))
                })?;
                while let Some(value) = sequence.next_element()? {
                    if u64::try_from(values.len()).unwrap_or(u64::MAX) >= MAX {
                        return Err(serde::de::Error::custom(format_args!(
                            "bounded sequence exceeds {MAX} entries"
                        )));
                    }
                    if values.len() == values.capacity() {
                        values.try_reserve(1).map_err(|_| {
                            serde::de::Error::custom(
                                "bounded sequence incremental allocation failed",
                            )
                        })?;
                    }
                    values.push(value);
                }
                Ok(BoundedVec { values })
            }
        }

        deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(std::marker::PhantomData))
    }
}

/// Encodes `value` after `magic` without an unbounded intermediate buffer.
pub(crate) fn encode_prefixed<T: Serialize>(
    value: &T,
    magic: &[u8],
    field: &'static str,
    configured: u64,
) -> Result<Vec<u8>, BoundedCborError> {
    let configured = configured.min(HARD_FAT_CHECKPOINT_BYTES);
    let mut counter = CountingWriter::new(field, configured);
    if ciborium::ser::into_writer(value, &mut counter).is_err() {
        return Err(counter.failure.unwrap_or(BoundedCborError::Malformed));
    }
    let total = admit(
        field,
        u64::try_from(magic.len()).map_err(|_| resource(field, 0, u64::MAX, configured))?,
        counter.length,
        configured,
    )?;
    let total_usize = usize::try_from(total).map_err(|_| resource(field, 0, total, configured))?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total_usize)
        .map_err(|_| resource(field, 0, total, configured))?;
    bytes.extend_from_slice(magic);
    let mut writer = ReservedWriter::new(&mut bytes, field, total);
    if ciborium::ser::into_writer(value, &mut writer).is_err() {
        return Err(writer.failure.unwrap_or(BoundedCborError::Malformed));
    }
    if u64::try_from(bytes.len()).ok() != Some(total) {
        return Err(BoundedCborError::Malformed);
    }
    Ok(bytes)
}

/// Admits a complete encoded input before any nested decoding allocation.
pub(crate) fn admit_input(
    bytes: &[u8],
    field: &'static str,
    configured: u64,
) -> Result<(), BoundedCborError> {
    let configured = configured.min(HARD_FAT_CHECKPOINT_BYTES);
    let requested =
        u64::try_from(bytes.len()).map_err(|_| resource(field, 0, u64::MAX, configured))?;
    admit(field, 0, requested, configured).map(|_| ())
}

fn admit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
) -> Result<u64, BoundedCborError> {
    let total = current
        .checked_add(requested)
        .ok_or_else(|| resource(field, current, requested, configured))?;
    if total > configured {
        return Err(resource(field, current, requested, configured));
    }
    Ok(total)
}

fn resource(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
) -> BoundedCborError {
    BoundedCborError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard: HARD_FAT_CHECKPOINT_BYTES,
    }
}

struct CountingWriter {
    field: &'static str,
    configured: u64,
    length: u64,
    failure: Option<BoundedCborError>,
}

impl CountingWriter {
    const fn new(field: &'static str, configured: u64) -> Self {
        Self {
            field,
            configured,
            length: 0,
            failure: None,
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).map_err(|_| {
            self.failure = Some(resource(self.field, self.length, u64::MAX, self.configured));
            io::Error::other("CBOR length is not representable")
        })?;
        self.length =
            admit(self.field, self.length, requested, self.configured).map_err(|error| {
                self.failure = Some(error);
                io::Error::other("CBOR envelope exceeds its resource ceiling")
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ReservedWriter<'a> {
    bytes: &'a mut Vec<u8>,
    field: &'static str,
    maximum: u64,
    failure: Option<BoundedCborError>,
}

impl<'a> ReservedWriter<'a> {
    fn new(bytes: &'a mut Vec<u8>, field: &'static str, maximum: u64) -> Self {
        Self {
            bytes,
            field,
            maximum,
            failure: None,
        }
    }
}

impl Write for ReservedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let current = u64::try_from(self.bytes.len()).map_err(|_| {
            self.failure = Some(resource(self.field, u64::MAX, 0, self.maximum));
            io::Error::other("CBOR output length is not representable")
        })?;
        let requested = u64::try_from(buffer.len()).map_err(|_| {
            self.failure = Some(resource(self.field, current, u64::MAX, self.maximum));
            io::Error::other("CBOR write length is not representable")
        })?;
        admit(self.field, current, requested, self.maximum).map_err(|error| {
            self.failure = Some(error);
            io::Error::other("CBOR serializer exceeded its measured reservation")
        })?;
        if buffer.len() > self.bytes.capacity().saturating_sub(self.bytes.len()) {
            let error = resource(self.field, current, requested, self.maximum);
            self.failure = Some(error);
            return Err(io::Error::other("CBOR serializer exceeded its reservation"));
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
    fn bounded_sequence_rejects_hostile_declared_length_before_allocation() {
        let mut encoded = vec![0x9b];
        encoded.extend_from_slice(&u64::MAX.to_be_bytes());

        let decoded = ciborium::de::from_reader::<BoundedVec<u8, 4>, _>(encoded.as_slice());
        assert!(decoded.is_err());
    }

    #[test]
    fn bounded_sequence_round_trips_without_changing_cbor_shape() {
        let bounded = BoundedVec::<u8, 4>::new(vec![1, 2, 3])
            .unwrap_or_else(|error| panic!("admit fixture: {error:?}"));
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&bounded, &mut encoded)
            .unwrap_or_else(|error| panic!("encode fixture: {error}"));
        let decoded = ciborium::de::from_reader::<BoundedVec<u8, 4>, _>(encoded.as_slice())
            .unwrap_or_else(|error| panic!("decode fixture: {error}"));
        assert_eq!(decoded.into_inner(), vec![1, 2, 3]);
    }
}
