//! Fallible bounded encoding primitives for device checkpoint envelopes.
//!
//! Device snapshots can contain large page and protocol tables. The helpers in
//! this module premeasure canonical CBOR, reserve its exact output allocation
//! fallibly, and bound sequence allocation while decoding hostile input.

use std::io::{self, Write};

use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotResourceError {
    pub(crate) field: &'static str,
    pub(crate) current: u64,
    pub(crate) requested: u64,
    pub(crate) configured: u64,
    pub(crate) hard: u64,
}

pub(crate) struct BoundedVec<T, const MAX: u64> {
    values: Vec<T>,
}

impl<T, const MAX: u64> BoundedVec<T, MAX> {
    pub(crate) fn new(values: Vec<T>, field: &'static str) -> Result<Self, SnapshotResourceError> {
        let requested =
            u64::try_from(values.len()).map_err(|_| resource(field, 0, u64::MAX, MAX, MAX))?;
        if requested > MAX {
            return Err(resource(field, 0, requested, MAX, MAX));
        }
        Ok(Self { values })
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        &self.values
    }

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
                    let Some(value) = sequence.next_element()? else {
                        break;
                    };
                    if values.len() == values.capacity() {
                        values.try_reserve(1).map_err(|_| {
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

        deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(std::marker::PhantomData))
    }
}

pub(crate) fn admit_input(
    bytes: &[u8],
    field: &'static str,
    configured: u64,
    hard: u64,
) -> Result<(), SnapshotResourceError> {
    let requested =
        u64::try_from(bytes.len()).map_err(|_| resource(field, 0, u64::MAX, configured, hard))?;
    admit(field, 0, requested, configured, hard).map(|_| ())
}

pub(crate) fn map_decode_error<T>(error: ciborium::de::Error<T>) -> Option<SnapshotResourceError> {
    let ciborium::de::Error::Semantic(_, message) = error else {
        return None;
    };
    parse_resource_message(&message)
}

pub(crate) fn encode_prefixed<T: Serialize>(
    value: &T,
    magic: &[u8],
    field: &'static str,
    configured: u64,
    hard: u64,
) -> Result<Vec<u8>, SnapshotEncodeError> {
    let configured = configured.min(hard);
    let mut counter = CountingWriter::new(field, configured, hard);
    if ciborium::ser::into_writer(value, &mut counter).is_err() {
        return Err(counter.failure.map_or(
            SnapshotEncodeError::Malformed,
            SnapshotEncodeError::Resource,
        ));
    }
    let magic_len = u64::try_from(magic.len()).map_err(|_| {
        SnapshotEncodeError::Resource(resource(field, 0, u64::MAX, configured, hard))
    })?;
    let total = admit(field, magic_len, counter.length, configured, hard)
        .map_err(SnapshotEncodeError::Resource)?;
    let total_usize = usize::try_from(total)
        .map_err(|_| SnapshotEncodeError::Resource(resource(field, 0, total, configured, hard)))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total_usize)
        .map_err(|_| SnapshotEncodeError::Resource(resource(field, 0, total, configured, hard)))?;
    bytes.extend_from_slice(magic);
    let mut writer = ReservedWriter::new(&mut bytes, field, total, hard);
    if ciborium::ser::into_writer(value, &mut writer).is_err() {
        return Err(writer.failure.map_or(
            SnapshotEncodeError::Malformed,
            SnapshotEncodeError::Resource,
        ));
    }
    if u64::try_from(bytes.len()).ok() != Some(total) {
        return Err(SnapshotEncodeError::Malformed);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SnapshotEncodeError {
    Malformed,
    Resource(SnapshotResourceError),
}

fn admit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> Result<u64, SnapshotResourceError> {
    let total = current
        .checked_add(requested)
        .ok_or_else(|| resource(field, current, requested, configured, hard))?;
    if total > configured || total > hard {
        return Err(resource(field, current, requested, configured, hard));
    }
    Ok(total)
}

fn resource(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> SnapshotResourceError {
    SnapshotResourceError {
        field,
        current,
        requested,
        configured,
        hard,
    }
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

fn parse_resource_message(message: &str) -> Option<SnapshotResourceError> {
    let mut fields = message.split('|');
    if fields.next()? != "crucible-resource-limit" {
        return None;
    }
    let field = match fields.next()? {
        "device snapshot sequence" => "device snapshot sequence",
        _ => return None,
    };
    let current = fields.next()?.parse().ok()?;
    let requested = fields.next()?.parse().ok()?;
    let configured = fields.next()?.parse().ok()?;
    let hard = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some(SnapshotResourceError {
        field,
        current,
        requested,
        configured,
        hard,
    })
}

struct CountingWriter {
    field: &'static str,
    configured: u64,
    hard: u64,
    length: u64,
    failure: Option<SnapshotResourceError>,
}

impl CountingWriter {
    const fn new(field: &'static str, configured: u64, hard: u64) -> Self {
        Self {
            field,
            configured,
            hard,
            length: 0,
            failure: None,
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).map_err(|_| {
            self.failure = Some(resource(
                self.field,
                self.length,
                u64::MAX,
                self.configured,
                self.hard,
            ));
            io::Error::other("snapshot length is not representable")
        })?;
        self.length = admit(
            self.field,
            self.length,
            requested,
            self.configured,
            self.hard,
        )
        .map_err(|error| {
            self.failure = Some(error);
            io::Error::other("snapshot exceeds its resource ceiling")
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
    hard: u64,
    failure: Option<SnapshotResourceError>,
}

impl<'a> ReservedWriter<'a> {
    fn new(bytes: &'a mut Vec<u8>, field: &'static str, maximum: u64, hard: u64) -> Self {
        Self {
            bytes,
            field,
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
        admit(self.field, current, requested, self.maximum, self.hard).map_err(|error| {
            self.failure = Some(error);
            io::Error::other("snapshot serializer exceeded its reservation")
        })?;
        if buffer.len() > self.bytes.capacity().saturating_sub(self.bytes.len()) {
            self.failure = Some(resource(
                self.field,
                current,
                requested,
                self.maximum,
                self.hard,
            ));
            return Err(io::Error::other(
                "snapshot serializer exceeded its reservation",
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
    fn hostile_sequence_hint_is_typed_before_large_allocation() {
        let mut encoded = vec![0x9b];
        encoded.extend_from_slice(&u64::MAX.to_be_bytes());
        let error = match ciborium::de::from_reader::<BoundedVec<u8, 4>, _>(encoded.as_slice()) {
            Ok(_) => panic!("hostile declared length must be rejected"),
            Err(error) => map_decode_error(error)
                .unwrap_or_else(|| panic!("resource coordinates must survive serde")),
        };
        assert_eq!(
            error,
            SnapshotResourceError {
                field: "device snapshot sequence",
                current: 0,
                requested: u64::MAX,
                configured: 4,
                hard: 4,
            }
        );
    }
}
