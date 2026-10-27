//! Preserves actual private JSON backing with the original bounded-depth walk.
//!
//! Arrays retain their spare slots, objects retain their compiled key/value
//! layout even when empty, and strings retain their original byte capacity.
//! Capacity rows contain no pointers or alias discounts. Each visited JSON value
//! also reports work, including scalar leaves with no allocation. These facts
//! establish no admission for the enclosing Source's other owners.

use super::{StorageError, Value};
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
};
use std::mem::{align_of, size_of};

// Keep the established private-JSON restriction; the common owner's deeper
// limit must not silently widen this Source representation's admitted domain.
const MAXIMUM_DEPTH: usize = 64;

struct ValueCapacityCursor<'a> {
    value: &'a Value,
    depth: usize,
}

/// Returns actual capacity geometry or appends it to the admitted physical bank.
///
/// This borrows retained DATA, including incomplete or failed finalization
/// bodies. It establishes neither a complete Source census nor native custody.
/// The caller admits `value_capacity_counter_scratch_data` and any bank first.
/// Existing rows survive refusal; no replacement Value is encoded or allocated.
///
/// # Errors
/// Refuses the original depth restriction, checked work or geometry overflow,
/// unavailable physical backing or exhausted selected capacity rows.
pub(in crate::node_adapters::cnp::semantic) fn value_capacity_data_with_error<E: StorageError>(
    value: &Value,
    depth: usize,
    bank: Option<&mut PacketRuntimeMetadataRecordBank>,
) -> Result<RetainedProtocolMetadataFacts, E> {
    let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
    let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
    record_value_capacity_data_with_error::<E>(value, depth, &mut census)?;
    Ok(census.finish())
}

/// Includes one borrowed private JSON owner in the caller's existing census.
///
/// Enclosing Value headers stay in their actual parent allocation. Independent
/// calls retain every view's rows, and failures leave earlier rows appended.
///
/// # Errors
/// Refuses the original depth restriction, work overflow, invalid geometry, selected row
/// exhaustion or unavailable physical backing without changing the Value.
pub(in crate::node_adapters::cnp::semantic) fn record_value_capacity_data_with_error<
    E: StorageError,
>(
    value: &Value,
    depth: usize,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), E> {
    walk::<E>(ValueCapacityCursor { value, depth }, census)
}

fn walk<E: StorageError>(
    cursor: ValueCapacityCursor<'_>,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), E> {
    if cursor.depth > MAXIMUM_DEPTH {
        return Err(E::refused("retained private JSON depth unsupported"));
    }

    census.observe_work_data(1).map_err(E::runtime)?;

    match cursor.value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::String(text) => census.observe(text).map_err(E::runtime)?,
        Value::Array(values) => {
            census
                .record(MetadataCapacityRecord {
                    kind: MetadataRecordKind::Vector,
                    extent: values.capacity(),
                    element_bytes: size_of::<Value>(),
                    alignment: align_of::<Value>(),
                })
                .map_err(E::runtime)?;

            for value in values {
                walk::<E>(
                    ValueCapacityCursor {
                        value,
                        depth: cursor.depth + 1,
                    },
                    census,
                )?;
            }
        }
        Value::Object(values) => {
            census
                .record(MetadataCapacityRecord {
                    kind: MetadataRecordKind::Tree,
                    extent: values.len(),
                    element_bytes: size_of::<(String, Value)>(),
                    alignment: align_of::<(String, Value)>(),
                })
                .map_err(E::runtime)?;

            for (key, value) in values {
                census.observe(key).map_err(E::runtime)?;
                walk::<E>(
                    ValueCapacityCursor {
                        value,
                        depth: cursor.depth + 1,
                    },
                    census,
                )?;
            }
        }
    }
    Ok(())
}

/// Names actual census, result and bounded recursive cursor/iterator controls.
///
/// The 65 admitted levels and first refused child can retain 66 cursors. This
/// counts declared layouts, not compiler frames, allocator rounding or work.
pub(in crate::node_adapters::cnp::semantic) fn value_capacity_counter_scratch_data() -> usize {
    let per_level = size_of::<ValueCapacityCursor<'static>>()
        + size_of::<&mut OriginalOwnerCapacityMetadataData<'static>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<&String>()
        + size_of::<MetadataCapacityRecord>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), crate::node_contract::OperationFailure>>();

    OriginalOwnerCapacityMetadataData::counter_scratch_data()
        + (MAXIMUM_DEPTH + 2) * per_level
        + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
        + size_of::<Result<RetainedProtocolMetadataFacts, crate::node_contract::OperationFailure>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<usize, crate::node_contract::OperationFailure>>()
        + size_of::<usize>()
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
