//! Bounds closed serializer inputs before any serializer can allocate or recurse.
//!
//! This allocation-free walk follows the same exhaustive field roster as the
//! vector projection. It charges a lower bound on serialized bytes, not an exact
//! wire extent. Every charge belongs to distinct syntax; omitted Option fields
//! cost zero. The ordinary sizing writer still decides the complete frame limit.
//! Literal JSON recursion is bounded before serialization, independently of the
//! fixed typed-record graph. Caller roots and call work remain separately funded.

use super::*;

pub(super) struct Preflight {
    remaining: usize,
}

/// Names the closed preflight's fixed state and borrowed container iterators.
pub(crate) fn counter_scratch_data() -> usize {
    size_of::<Preflight>()
        + packet_runtime_serialization_depth()
            * (size_of::<&Value>()
                + size_of::<&mut Preflight>()
                + size_of::<serde_json::map::Iter<'static>>()
                + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
                + size_of::<std::slice::Iter<'static, Value>>()
                + size_of::<Option<(&String, &Value)>>()
                + size_of::<Option<&Value>>()
                + size_of::<Result<(), ProviderError>>()
                + size_of::<Result<usize, crucible_node_format::ContractError>>()
                + 3 * size_of::<usize>())
}

impl Preflight {
    pub(super) fn new(maximum: usize) -> Self {
        Self { remaining: maximum }
    }

    pub(super) fn consume(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(refused)?;
        Ok(())
    }

    pub(super) fn container(&mut self, elements: usize) -> Result<(), ProviderError> {
        // One opening bracket plus N-1 separators for a nonempty container;
        // closing syntax and object key punctuation are deliberately omitted.
        self.consume(elements.max(1))
    }

    fn string(&mut self, value: &str) -> Result<(), ProviderError> {
        self.consume(2)?;
        self.consume(value.len())
    }

    fn value(&mut self, value: &Value, depth: usize) -> Result<(), ProviderError> {
        match value {
            Value::Array(values) => {
                Self::check_depth(depth)?;
                self.container(values.len())?;
                for value in values {
                    self.value(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                Self::check_depth(depth)?;
                self.object(values.len(), values.iter(), depth)
            }
            Value::String(value) => self.string(value),
            Value::Null | Value::Bool(_) | Value::Number(_) => self.consume(1),
        }
    }

    fn object<'a>(
        &mut self,
        length: usize,
        fields: impl Iterator<Item = (&'a String, &'a Value)>,
        depth: usize,
    ) -> Result<(), ProviderError> {
        Self::check_depth(depth)?;
        self.container(length)?;
        for (key, value) in fields {
            self.string(key)?;
            self.value(value, depth + 1)?;
        }
        Ok(())
    }

    fn check_depth(depth: usize) -> Result<(), ProviderError> {
        if depth >= 64 {
            return Err(ProviderError::ResourceExhausted(
                "packet runtime literal JSON preflight depth",
            ));
        }
        Ok(())
    }
}

impl HeapShape for String {
    const SHAPE: Shape = Shape::EMPTY;

    fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
        counter.string(self)
    }
}

impl HeapShape for Id {
    const SHAPE: Shape = Shape::EMPTY;

    fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
        counter.string(self.as_str())
    }
}

impl HeapShape for Bytes {
    const SHAPE: Shape = Shape::EMPTY;

    fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
        // The complete base64 String is allocated before serialize_str reaches
        // the general sizing sink. Check its exact quoted extent first.
        let encoded = Self::borrowed_serialization_temporary_bytes_data(self.as_slice())?;
        let quoted = encoded.checked_add(2).ok_or_else(refused)?;
        if quoted > counter.remaining {
            return Err(ProviderError::ResourceExhausted(
                "packet runtime BlobChunk encoder exceeds frame",
            ));
        }
        counter.consume(quoted)
    }
}

impl HeapShape for Value {
    const SHAPE: Shape = Shape::EMPTY;

    fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
        counter.value(self, 0)
    }
}

macro_rules! object_shapes {
    ($($type:ty),+ $(,)?) => {$(
        impl HeapShape for $type {
            const SHAPE: Shape = Shape::EMPTY;

            fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
                counter.object(self.len(), self.iter(), 0)
            }
        }
    )+};
}

object_shapes!(Map<String, Value>, BTreeMap<String, Value>);

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("packet runtime serializer preflight exceeds frame")
}
