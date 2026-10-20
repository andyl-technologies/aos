//! Shares passive reached protobuf representation geometry.
//!
//! Actual encoded lengths and compiled schema layouts produce checked byte
//! bounds only. These functions decode nothing and create no resource account,
//! grant, Journal, currentness proof or admission. Concrete owners must fund
//! the result under their own genuine original before typed growth.

use std::mem::size_of;
use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, BrokerDescriptorDispositionEntry, BrokerDescriptorEntry,
    Descriptor, Feature, StorageAtomicSnapshotCheckpoint, StorageLifecycleInventoryRecord,
    StorageLifecycleTransitionRecord, StorageOperatorRepairCommitRecordV1,
    StorageWorkspaceInventoryRecord,
};
use crate::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES;

/// Reports overflow or an invalid representation depth.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("protobuf representation geometry is invalid or overflows")]
pub struct ReceivingGeometryRefusalV1;

/// Bounds the actual reached repeated/unknown/raw protobuf carriers.
///
/// # Errors
/// Refuses overflow or an unrepresentable compiled layout.
pub fn protobuf_carriers_v1(bytes: u64, repeated_width: u64) -> Result<u64, ReceivingGeometryRefusalV1> {
    // A nested repeated message requires tag+length. Buffa's shared logical
    // element cap excludes Vec growth, unknown fields and packed scalars.
    let reached = mul(add(bytes / 2, 1)?, repeated_width)?;
    let elements = reached.min(as_u64(buffa::DEFAULT_ELEMENT_MEMORY_LIMIT)?);
    sum(&[
        mul(3, elements)?,
        mul(4, repeated_width)?,
        unknown_field_carriers_v1(bytes, 1)?,
        mul(12, bytes)?,
    ])
}

/// Bounds the existing HELLO, descriptor and Storage schema roster.
///
/// # Errors
/// Refuses zero depth, overflow or an unrepresentable compiled layout.
pub fn schema_protobuf_carriers_v1(bytes: u64, depth: u64) -> Result<u64, ReceivingGeometryRefusalV1> {
    // These are precisely the reached schema families: signed HELLO tables,
    // request/response descriptor tables and historical Storage Inventory.
    // A tiny physical prefix cannot materialize the full Buffa element cap.
    let width = inventory_repeated_width_v1()?
        .max(as_u64(size_of::<Feature>())?)
        .max(as_u64(size_of::<BrokerDescriptorEntry>())?)
        .max(as_u64(size_of::<BrokerDescriptorDispositionEntry>())?);
    let reached = bytes.min(as_u64(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)?);
    let proto = protobuf_carriers_v1(reached, width)?;
    let children = add(as_u64(size_of::<AssignmentFence>())?, as_u64(size_of::<Descriptor>())?)?;
    let nested = mul(add(mul(reached / 2, 3)?, 4)?, children)?;

    // Recursive recovery coordinates have no repeated messages. Their unknown
    // trees may remain live during predecessor checks, so retain every alias.
    let remaining_depth = depth.checked_sub(1).ok_or_else(invalid)?;
    let recursive_unknown = unknown_field_carriers_v1(bytes, remaining_depth)?;
    sum(&[proto, nested, recursive_unknown, mul(5 * 4, width)?])
}

/// Bounds reached unknown-field trees and their actual copy lanes.
///
/// # Errors
/// Refuses overflow or an unrepresentable unknown-field layout.
pub fn unknown_field_carriers_v1(bytes: u64, copies: u64) -> Result<u64, ReceivingGeometryRefusalV1> {
    // A minimum field or empty group takes two wire bytes. Eight slots cover
    // group child-Vec floors, growth and a canonical clone; payloads are separate.
    let fields = (bytes / 2).min(as_u64(buffa::DEFAULT_UNKNOWN_FIELD_LIMIT)?);
    let cells = add(mul(fields, 8)?, 8)?;
    mul(copies, mul(cells, as_u64(size_of::<buffa::UnknownField>())?)?)
}

/// Returns the actual largest repeated cell in the five Inventory tables.
///
/// # Errors
/// Refuses a compiled repeated-cell layout that cannot fit in `u64`.
pub fn inventory_repeated_width_v1() -> Result<u64, ReceivingGeometryRefusalV1> {
    let widths = [
        size_of::<StorageWorkspaceInventoryRecord>(),
        size_of::<StorageLifecycleInventoryRecord>(),
        size_of::<StorageLifecycleTransitionRecord>(),
        size_of::<StorageAtomicSnapshotCheckpoint>(),
        size_of::<StorageOperatorRepairCommitRecordV1>(),
    ];
    let mut width = 0;
    for value in widths {
        width = width.max(as_u64(value)?);
    }
    Ok(width)
}

fn add(left: u64, right: u64) -> Result<u64, ReceivingGeometryRefusalV1> {
    left.checked_add(right).ok_or_else(invalid)
}

fn mul(left: u64, right: u64) -> Result<u64, ReceivingGeometryRefusalV1> {
    left.checked_mul(right).ok_or_else(invalid)
}

fn sum(values: &[u64]) -> Result<u64, ReceivingGeometryRefusalV1> {
    values.iter().try_fold(0, |total, value| add(total, *value))
}

fn as_u64(value: usize) -> Result<u64, ReceivingGeometryRefusalV1> {
    u64::try_from(value).map_err(|_| invalid())
}

fn invalid() -> ReceivingGeometryRefusalV1 {
    ReceivingGeometryRefusalV1
}
