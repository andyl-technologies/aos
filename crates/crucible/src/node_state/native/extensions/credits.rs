//! Reserves known immutable and portable custody before native capture effects.
//!
//! Native record credits exclude the entire authenticated immutable closure,
//! actual serialized coordinator and queued payloads. Portable records generated
//! after capture reserve their existing per-record ceiling, including the signed
//! index. This conservative reservation never assumes that selected objects are
//! the only immutable reconstruction inputs.

use crate::node_admission::AdmittedGraph;
use crate::node_contract::NativeCaptureLimits;
use crate::node_state::{StateError, VerifiedStateContent, closure::bounded_record, schema};

use super::super::{NativeArchiveLimits, capture::Coordinator};

/// Computes native credits while retaining all known portable obligations.
///
/// # Errors
/// Refuses oversized coordinator bytes, arithmetic overflow, or an object/byte
/// budget that cannot retain the complete immutable and portable obligations.
pub(in crate::node_state::native) fn remaining_native(
    graph: &AdmittedGraph,
    content: &VerifiedStateContent,
    coordinator: &Coordinator,
    limits: NativeArchiveLimits,
) -> Result<NativeCaptureLimits, StateError> {
    bounded_record(coordinator, limits.state.maximum_record_bytes)?;
    let coordinator_bytes = crucible_node_contract::canonical::canonical_json(
        &serde_json::to_value(coordinator).map_err(schema)?,
    )
    .map_err(schema)?;

    let owners = graph.ownership_policy().capture_owners.len();
    // Each owner adds its receipt; guarantees, provenance and manifest add three
    // objects. The signed index also reserves bytes, but is not a content object.
    let portable_objects = owners
        .checked_add(3)
        .ok_or_else(|| limit("portable slots"))?;
    let portable_bytes = portable_objects
        .checked_add(1)
        .and_then(|records| records.checked_mul(limits.state.maximum_record_bytes))
        .ok_or_else(|| limit("portable record bytes"))?;
    let payload_bytes = coordinator
        .scheduler
        .payload_objects
        .iter()
        .try_fold(0usize, |total, payload| {
            total.checked_add(payload.bytes.len())
        })
        .ok_or_else(|| limit("queued coordinator payload bytes"))?;
    let reserved_bytes = content
        .total_bytes()
        .checked_add(coordinator_bytes.len())
        .and_then(|bytes| bytes.checked_add(payload_bytes))
        .and_then(|bytes| bytes.checked_add(portable_bytes))
        .ok_or_else(|| limit("complete known portable bytes"))?;
    let reserved_objects = content
        .object_count()
        .checked_add(1)
        .and_then(|objects| objects.checked_add(coordinator.scheduler.payload_objects.len()))
        .and_then(|objects| objects.checked_add(portable_objects))
        .ok_or_else(|| limit("complete known portable slots"))?;

    let mut native = limits.native;
    native.maximum_total_record_bytes = native
        .maximum_total_record_bytes
        .min(limits.state.maximum_total_content_bytes)
        .checked_sub(reserved_bytes)
        .filter(|remaining| *remaining != 0)
        .ok_or_else(|| limit("complete immutable and coordinator byte reservation"))?;
    native.maximum_objects = native
        .maximum_objects
        .min(limits.state.maximum_content_objects)
        .checked_sub(reserved_objects)
        .filter(|remaining| *remaining != 0)
        .ok_or_else(|| limit("complete immutable and coordinator object reservation"))?;
    native.maximum_record_bytes = native
        .maximum_record_bytes
        .min(native.maximum_total_record_bytes)
        .min(limits.state.maximum_content_bytes);
    Ok(native)
}

fn limit(subject: &'static str) -> StateError {
    crate::node_state::closure::limit(subject)
}
