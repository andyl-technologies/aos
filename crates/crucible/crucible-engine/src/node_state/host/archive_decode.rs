//! Context-bound archive decoding with finite registry and payload allocation.

use std::{cell::Cell, marker::PhantomData, rc::Rc};

use serde::{
    Deserialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};

use super::*;

pub(super) fn decode(bytes: &[u8], limits: StateLimits) -> Result<ArchiveBody, StateError> {
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let body = BodySeed { limits }
        .deserialize(&mut parser)
        .map_err(schema)?;
    parser.end().map_err(schema)?;
    Ok(body)
}

#[derive(Clone)]
struct ValueSeed<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for ValueSeed<T> {
    type Value = T;

    fn deserialize<D: de::Deserializer<'de>>(self, parser: D) -> Result<T, D::Error> {
        T::deserialize(parser)
    }
}

#[derive(Clone)]
struct SequenceSeed<S> {
    item: S,
    maximum: usize,
    remaining: Rc<Cell<usize>>,
}

impl<'de, S: DeserializeSeed<'de> + Clone> DeserializeSeed<'de> for SequenceSeed<S> {
    type Value = Vec<S::Value>;

    fn deserialize<D: de::Deserializer<'de>>(self, parser: D) -> Result<Self::Value, D::Error> {
        struct SequenceVisitor<S>(SequenceSeed<S>);

        impl<'de, S: DeserializeSeed<'de> + Clone> Visitor<'de> for SequenceVisitor<S> {
            type Value = Vec<S::Value>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a bounded archive inventory")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                loop {
                    let allowed = self
                        .0
                        .maximum
                        .saturating_sub(values.len())
                        .min(self.0.remaining.get());
                    if allowed == 0 {
                        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                            return Err(de::Error::custom(
                                "archive inventory preallocation ceiling exceeded",
                            ));
                        }
                        break;
                    }
                    let Some(value) = sequence.next_element_seed(self.0.item.clone())? else {
                        break;
                    };
                    if values.len() == values.capacity() {
                        values
                            .try_reserve_exact(allowed.min(128))
                            .map_err(de::Error::custom)?;
                    }
                    self.0.remaining.set(self.0.remaining.get() - 1);
                    values.push(value);
                }
                Ok(values)
            }
        }
        parser.deserialize_seq(SequenceVisitor(self))
    }
}

#[derive(Clone)]
struct ObjectSeed {
    limits: StateLimits,
    bytes: Rc<Cell<usize>>,
    edges: Rc<Cell<usize>>,
}

impl<'de> DeserializeSeed<'de> for ObjectSeed {
    type Value = Object;

    fn deserialize<D: de::Deserializer<'de>>(self, parser: D) -> Result<Object, D::Error> {
        struct ObjectVisitor(ObjectSeed);

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Object;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a closed bounded archive object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<Object, A::Error> {
                let mut reference = None;
                let mut dependencies = None;
                let mut bytes = None;
                while let Some(field) = fields.next_key::<String>()? {
                    match field.as_str() {
                        "reference" if reference.is_none() => {
                            let value: ContentRef = fields.next_value()?;
                            value.validate().map_err(de::Error::custom)?;
                            reference = Some(value);
                        }
                        "dependencies" if dependencies.is_none() => {
                            dependencies = Some(fields.next_value_seed(SequenceSeed {
                                item: ValueSeed::<ContentRef>(PhantomData),
                                maximum: self.0.limits.maximum_content_objects,
                                remaining: self.0.edges.clone(),
                            })?);
                        }
                        "bytes" if bytes.is_none() => {
                            bytes = Some(fields.next_value_seed(SequenceSeed {
                                item: ValueSeed::<u8>(PhantomData),
                                maximum: self.0.limits.maximum_content_bytes,
                                remaining: self.0.bytes.clone(),
                            })?);
                        }
                        _ => {
                            return Err(de::Error::custom(
                                "unknown or repeated archive object field",
                            ));
                        }
                    }
                }
                Ok(Object {
                    reference: reference.ok_or_else(|| de::Error::missing_field("reference"))?,
                    dependencies: dependencies
                        .ok_or_else(|| de::Error::missing_field("dependencies"))?,
                    bytes: bytes.ok_or_else(|| de::Error::missing_field("bytes"))?,
                })
            }
        }
        parser.deserialize_map(ObjectVisitor(self))
    }
}

struct BodySeed {
    limits: StateLimits,
}

impl<'de> DeserializeSeed<'de> for BodySeed {
    type Value = ArchiveBody;

    fn deserialize<D: de::Deserializer<'de>>(self, parser: D) -> Result<ArchiveBody, D::Error> {
        struct BodyVisitor(StateLimits);

        impl<'de> Visitor<'de> for BodyVisitor {
            type Value = ArchiveBody;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("the closed host archive edition")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<ArchiveBody, A::Error> {
                let mut version = None;
                let mut artifact = None;
                let mut objects = None;
                while let Some(field) = fields.next_key::<String>()? {
                    match field.as_str() {
                        "schema_version" if version.is_none() => {
                            version = Some(fields.next_value()?);
                        }
                        "artifact" if artifact.is_none() => {
                            artifact = Some(fields.next_value()?);
                        }
                        "objects" if objects.is_none() => {
                            objects = Some(fields.next_value_seed(SequenceSeed {
                                item: ObjectSeed {
                                    limits: self.0,
                                    bytes: Rc::new(Cell::new(self.0.maximum_total_content_bytes)),
                                    edges: Rc::new(Cell::new(self.0.maximum_dependency_edges)),
                                },
                                maximum: self.0.maximum_content_objects,
                                remaining: Rc::new(Cell::new(self.0.maximum_content_objects)),
                            })?);
                        }
                        _ => {
                            return Err(de::Error::custom(
                                "unknown or repeated archive body field",
                            ));
                        }
                    }
                }
                Ok(ArchiveBody {
                    schema_version: version
                        .ok_or_else(|| de::Error::missing_field("schema_version"))?,
                    artifact: artifact.ok_or_else(|| de::Error::missing_field("artifact"))?,
                    objects: objects.ok_or_else(|| de::Error::missing_field("objects"))?,
                })
            }
        }
        parser.deserialize_map(BodyVisitor(self.limits))
    }
}
