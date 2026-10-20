//! Observes real raw capacities through the existing source metadata observer.
//!
//! A fixed raw64 spine visits actual source nodes; the shallow borrowed wrapper
//! reports each node's own backing without recursive Value reconstruction or a
//! changed metadata profile. Existing observer node/record ceilings still apply.

use super::*;

struct RawNode<'a>(&'a Value);

impl ObserveMetadata for RawNode<'_> {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self.0 {
            Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
            Value::String(value) => observer.observe(value),
            Value::Array(values) => observer.vector::<Value>(values.capacity()),
            Value::Object(values) => {
                observer.tree::<String, Value>(values.len())?;
                for key in values.keys() {
                    observer.observe(key)?;
                }
                Ok(())
            }
        }
    }
}

pub(super) fn frame_data(
    frame: &RetainedFrame,
    observer: &mut MetadataObserver<'_>,
) -> Result<usize, ProviderError> {
    let RetainedFrame { value, bytes } = frame;
    observer.vector::<u8>(bytes.capacity())?;
    let mut population = 0;
    let mut source = super::super::walk::Walk::new_data(value);
    while let Some((value, _)) = source.next_data()? {
        population = add(population, 1)?;
        observer.observe(&RawNode(value))?;
    }
    Ok(population)
}

pub(super) fn requested_data(
    inline: usize,
    facts: RetainedProtocolMetadataFacts,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let requested = add(inline, requested_metadata_backing_storage_data(&facts)?)?;
    if requested > maximum {
        return Err(exhausted());
    }
    Ok(requested)
}

pub(super) fn frozen_requested_data(
    inline: usize,
    bank: &NativeImport18ImmutableRawBankData,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    bank.observe_data(&mut observer)?;
    requested_data(inline, observer.finish(), maximum)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<MetadataObserver<'static>>() * 2
        + size_of::<&mut MetadataObserver<'static>>() * 2
        + size_of::<RetainedProtocolMetadataFacts>() * 2
        + size_of::<&RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<crate::retained_metadata::records::MetadataRecordKind>()
        + size_of::<std::alloc::Layout>()
        + size_of::<std::alloc::LayoutError>()
        + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 5]>()
        + size_of::<&[usize]>() * 2
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&mut usize>() * 2
        + size_of::<ProviderError>()
        + size_of::<RawNode<'static>>()
        + size_of::<&RawNode<'static>>()
        + size_of::<serde_json::map::Keys<'static>>()
        + size_of::<&String>()
        + size_of::<Option<&String>>()
        + size_of::<&Vec<Value>>()
        + size_of::<&serde_json::Map<String, Value>>()
        + size_of::<&Vec<u8>>()
        + size_of::<&Value>() * 2
        + size_of::<Option<(&Value, usize)>>()
        + size_of::<(&Value, usize)>()
        + size_of::<&RetainedFrame>() * 2
        + size_of::<&NativeImport18ImmutableRawBankData>()
        + size_of::<Result<(), ProviderError>>() * 2
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<usize>() * 12
        + super::super::walk::counter_scratch_data()
}
