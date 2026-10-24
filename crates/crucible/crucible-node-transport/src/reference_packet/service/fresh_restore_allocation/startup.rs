//! Projects fresh13 startup owners from the actual installed launch.
//!
//! No report, query, reference or native authority is fabricated here. Unknown
//! nonces/digests use their closed32-byte/base64url extents; assigned IDs and
//! sequences use the contract's128-byte/twenty-digit bounds. The real producer
//! must authenticate the inactive origin and reconcile initialized capacities.

use super::super::{PacketConnectedSourceProgram, PacketNative5SourceLaunch};
use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};
use std::mem::size_of;

pub(crate) struct FreshRestoreAllocationStartupShapes {
    pub(crate) original: OriginalSerializationStorageData,
    pub(crate) terminal: OriginalSerializationStorageData,
    pub(crate) query: OriginalSerializationStorageData,
    pub(crate) report: OriginalSerializationStorageData,
    pub(crate) receipt: OriginalSerializationStorageData,
    /// Includes the independently retained typed query and its actual headers.
    pub(crate) query_typed_requested_bytes: usize,
    /// Includes the complete typed report and its independent child backing.
    pub(crate) report_typed_requested_bytes: usize,
    /// Includes the independently retained typed receipt/reference backing.
    pub(crate) receipt_typed_requested_bytes: usize,
    /// Includes proof DATA and final report canonical/parser work conservatively.
    pub(crate) report_authentication_transient_requested_bytes: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
}

pub(crate) fn fresh_restore_allocation_startup_shapes(
    launch: &PacketNative5SourceLaunch,
    maximum_requested_bytes: usize,
) -> Result<FreshRestoreAllocationStartupShapes, ProviderError> {
    shapes(
        &launch.selection,
        Some(&launch.program),
        maximum_requested_bytes,
    )
}

/// Uses the longer actual inactive inventory domain for the host receive bound.
/// No prospective native program or launch is manufactured.
pub(crate) fn fresh_restore_allocation_host_shapes(
    selection: &crate::reference_packet::control::PacketControlSelection,
    maximum_requested_bytes: usize,
) -> Result<FreshRestoreAllocationStartupShapes, ProviderError> {
    shapes(selection, None, maximum_requested_bytes)
}

fn shapes(
    selection: &crate::reference_packet::control::PacketControlSelection,
    program: Option<&PacketConnectedSourceProgram>,
    maximum_requested_bytes: usize,
) -> Result<FreshRestoreAllocationStartupShapes, ProviderError> {
    let [binding] = selection.realization.bindings.as_slice() else {
        return Err(invalid());
    };
    let scope = ScopeFields {
        session: &binding.authority.session_id,
        incarnation: &binding.authority.incarnation_id,
        node: &binding.compatibility.node_id,
        owner: &binding.compatibility.execution_owner.id,
        owner_generation: binding.authority.owner_generation,
        world: &selection.world,
        prepared_token: &selection.prepared_token,
        admission: &selection.admission,
    };
    let original = count(maximum_requested_bytes, |p| original(p, &scope))?;
    let terminal = count(maximum_requested_bytes, |p| terminal(p, &scope, program))?;
    let query = byte_formatter_storage(
        count(maximum_requested_bytes, query)?,
        3,
        maximum_requested_bytes,
    )?;
    let report = byte_formatter_storage(
        count(maximum_requested_bytes, |p| report(p, &scope))?,
        7,
        maximum_requested_bytes,
    )?;
    let receipt = count(maximum_requested_bytes, receipt)?;
    if report.maximum_encoded_bytes > MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES
        || query.maximum_encoded_bytes > MAXIMUM_FRESH_RESTORE_ALLOCATION_QUERY_BYTES
    {
        return Err(invalid());
    }
    let query_typed = sum(&[
        size_of::<PacketNativeFreshRestoreAllocationQuery>(),
        string_bank(PACKET_FRESH_RESTORE_ALLOCATION_QUERY.len())?,
        mul(3, byte_bank(32)?)?,
    ])?;
    let scope_ids = [
        scope.session,
        scope.incarnation,
        scope.node,
        scope.owner,
        scope.prepared_token,
        scope.admission,
    ]
    .into_iter()
    .try_fold(0usize, |n, id| add(n, string_bank(id.as_str().len())?))?;
    let world = hash_backing(scope.world)?;
    let report_typed = sum(&[
        size_of::<PacketNativeFreshRestoreAllocationReport>(),
        scope_ids,
        world,
        hash_extent_backing("cnp.owner-binding.v1", 64)?,
        reference_backing("application/json")?,
        string_bank(PACKET_FRESH_RESTORE_ALLOCATION_REPORT.len())?,
        string_bank(PACKET_FRESH_RESTORE_ALLOCATION_PROOF.len())?,
        string_bank(FRESH_RESTORE_ALLOCATION_ALGORITHM.len())?,
        mul(7, byte_bank(32)?)?,
    ])?;
    let receipt_typed = sum(&[
        size_of::<PacketNativeFreshRestoreAllocationReceipt>(),
        string_bank(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT.len())?,
        reference_backing(PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)?,
    ])?;
    let authentication = sum(&[
        // DATA/proof and final full-report phases are summed conservatively.
        mul(2, report.requested_total()?)?,
        mul(2, MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES)?,
        size_of::<blake3::Hasher>(),
        mul(3, blake3::OUT_LEN)?,
        // Each actual Bytes formatter allocates its base64 String before the
        // serializer callback. Precount and DOM passes visit DATA5, report7
        // and query3 byte fields independently; sum both passes conservatively.
        mul(2 * (5 + 7 + 3), string_bank(43)?)?,
        size_of::<PacketNativeFreshRestoreAllocationProof>(),
        string_bank(PACKET_FRESH_RESTORE_ALLOCATION_PROOF.len())?,
        string_bank(FRESH_RESTORE_ALLOCATION_ALGORITHM.len())?,
        mul(2, byte_bank(32)?)?,
    ])?;
    let result = FreshRestoreAllocationStartupShapes {
        original,
        terminal,
        query,
        report,
        receipt,
        query_typed_requested_bytes: query_typed,
        report_typed_requested_bytes: report_typed,
        receipt_typed_requested_bytes: receipt_typed,
        report_authentication_transient_requested_bytes: authentication,
        declared_counter_scratch_bytes: fresh_restore_allocation_startup_counter_scratch_data(),
    };
    let total = sum(&[
        result.original.requested_total()?,
        result.terminal.requested_total()?,
        result.query.requested_total()?,
        result.report.requested_total()?,
        result.receipt.requested_total()?,
        query_typed,
        report_typed,
        receipt_typed,
        authentication,
        result.declared_counter_scratch_bytes,
    ])?;
    if total > maximum_requested_bytes {
        return Err(invalid());
    }
    Ok(result)
}

/// Names only declared projection/type/hash headers, excluding compiler frames.
pub(crate) const fn fresh_restore_allocation_startup_counter_scratch_data() -> usize {
    size_of::<FreshRestoreAllocationStartupShapes>()
        + 2 * size_of::<Projection>()
        + 5 * size_of::<OriginalSerializationStorageData>()
        + size_of::<ScopeFields<'static>>()
        + size_of::<blake3::Hasher>()
        + 20
        + 3 * blake3::OUT_LEN
}

struct ScopeFields<'a> {
    session: &'a Id,
    incarnation: &'a Id,
    node: &'a Id,
    owner: &'a Id,
    owner_generation: U64,
    world: &'a HashRef,
    prepared_token: &'a Id,
    admission: &'a Id,
}

fn count(
    maximum: usize,
    fields: impl FnOnce(&mut Projection) -> Result<(), ProviderError>,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    fields(&mut p)?;
    p.finish(maximum)
}

fn object(p: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    p.add_object()?;
    for field in fields {
        p.add_field(field)?;
    }
    Ok(())
}

fn decimal(p: &mut Projection) -> Result<(), ProviderError> {
    p.add_unescaped_ascii_extent(20)
}

fn digest(p: &mut Projection) -> Result<(), ProviderError> {
    p.add_unescaped_ascii_extent(43)
}

fn hash(p: &mut Projection, domain: &str) -> Result<(), ProviderError> {
    object(p, &["algorithm", "domain", "digest"])?;
    p.add_string("blake3-256")?;
    p.add_string(domain)?;
    p.add_unescaped_ascii_extent(64)
}

fn reference(p: &mut Projection, media: &str) -> Result<(), ProviderError> {
    object(p, &["hash", "length", "media_type"])?;
    hash(p, "cnp.blob.v1")?;
    decimal(p)?;
    p.add_string(media)
}

fn envelope(
    p: &mut Projection,
    scope: &ScopeFields<'_>,
    response: bool,
) -> Result<(), ProviderError> {
    object(
        p,
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "operation_id",
            "request_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ],
    )?;
    p.add_string("CNP/1")?;
    p.add_value(&if response {
        crate::envelope::MessageKind::Response
    } else {
        crate::envelope::MessageKind::Request
    })?;
    for id in [scope.session, scope.incarnation, scope.node, scope.owner] {
        p.add_value(id)?;
    }
    p.add_value(&())?; // Capture owner remains absent on the fresh query.
    p.add_value(&())?; // No operation is begun to obtain this report.
    p.add_unescaped_ascii_extent(128)?;
    decimal(p)?;
    p.add_value(&crate::envelope::Method::Observe)
}

fn query(p: &mut Projection) -> Result<(), ProviderError> {
    object(
        p,
        &[
            "schema",
            "nonce",
            "completed_admit_request",
            "completed_admit_response",
        ],
    )?;
    p.add_string(PACKET_FRESH_RESTORE_ALLOCATION_QUERY)?;
    for _ in 0..3 {
        digest(p)?;
    }
    Ok(())
}

fn original(p: &mut Projection, scope: &ScopeFields<'_>) -> Result<(), ProviderError> {
    envelope(p, scope, false)?;
    object(
        p,
        &[
            "binding_hash",
            "owner_generation",
            "after_observation_sequence",
            "maximum_items",
            "extensions",
        ],
    )?;
    hash(p, "cnp.owner-binding.v1")?;
    p.add_value(&scope.owner_generation)?;
    p.add_value(&U64::new(0))?;
    p.add_value(&U64::new(1))?;
    p.add_object()?;
    object(p, &[PACKET_FRESH_RESTORE_ALLOCATION_QUERY])?;
    query(p)
}

fn receipt(p: &mut Projection) -> Result<(), ProviderError> {
    object(p, &["schema", "allocation"])?;
    p.add_string(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT)?;
    reference(p, PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)
}

fn terminal(
    p: &mut Projection,
    scope: &ScopeFields<'_>,
    program: Option<&PacketConnectedSourceProgram>,
) -> Result<(), ProviderError> {
    envelope(p, scope, true)?;
    object(p, &["status", "operation_state", "result", "extensions"])?;
    p.add_string("completed")?;
    p.add_value(&crate::bodies::OperationState::Completed)?;
    object(
        p,
        &[
            "observations",
            "next_sequence",
            "complete",
            "inventory_hash",
        ],
    )?;
    p.add_value(&(&[] as &[crucible_node_format::ObservationBatch]))?;
    p.add_value(&U64::new(0))?;
    p.add_value(&true)?;
    hash(
        p,
        match program {
            Some(PacketConnectedSourceProgram::Producer { .. }) => {
                "source-owned.packet-inventory.v1"
            }
            Some(PacketConnectedSourceProgram::Reactive { .. }) | None => {
                "source-owned.packet-connected-inventory/4"
            }
        },
    )?;
    object(p, &[PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT])?;
    receipt(p)?;
    p.add_object() // Envelope extensions are empty; receipt lives in body.
}

fn report(p: &mut Projection, scope: &ScopeFields<'_>) -> Result<(), ProviderError> {
    object(p, &["schema", "data", "proof"])?;
    p.add_string(PACKET_FRESH_RESTORE_ALLOCATION_REPORT)?;
    object(p, &["scope", "storage"])?;
    object(
        p,
        &[
            "native_pid",
            "session",
            "incarnation",
            "node",
            "owner",
            "owner_generation",
            "owner_binding",
            "world",
            "prepared_token",
            "admission",
            "closed_gate_receipt",
            "nonce",
            "assigned_query",
            "completed_admit_request",
            "completed_admit_response",
            "ack_context",
        ],
    )?;
    decimal(p)?;
    for id in [scope.session, scope.incarnation, scope.node, scope.owner] {
        p.add_value(id)?;
    }
    p.add_value(&scope.owner_generation)?;
    hash(p, "cnp.owner-binding.v1")?;
    p.add_value(scope.world)?;
    p.add_value(scope.prepared_token)?;
    p.add_value(scope.admission)?;
    // Realize's genuine cached closed-gate evidence is application/json.
    reference(p, "application/json")?;
    for _ in 0..5 {
        digest(p)?;
    }
    object(
        p,
        &[
            "current_retained_bytes",
            "query_retained_growth_bytes",
            "prepare_retained_growth_bytes",
            "query_transient_bytes",
            "prepare_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    for _ in 0..6 {
        decimal(p)?;
    }
    object(p, &["schema", "algorithm", "context_digest", "mac"])?;
    p.add_string(PACKET_FRESH_RESTORE_ALLOCATION_PROOF)?;
    p.add_string(FRESH_RESTORE_ALLOCATION_ALGORITHM)?;
    digest(p)?;
    digest(p)
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(invalid)
}
fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(invalid)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |n, v| add(n, *v))
}
fn string_bank(bytes: usize) -> Result<usize, ProviderError> {
    add(mul(2, bytes)?, 4)
}
fn byte_bank(bytes: usize) -> Result<usize, ProviderError> {
    add(mul(2, bytes)?, 4)
}
fn hash_extent_backing(domain: &str, digest: usize) -> Result<usize, ProviderError> {
    sum(&[
        string_bank("blake3-256".len())?,
        string_bank(domain.len())?,
        string_bank(digest)?,
    ])
}
fn hash_backing(hash: &HashRef) -> Result<usize, ProviderError> {
    sum(&[
        string_bank(hash.algorithm.len())?,
        string_bank(hash.domain.len())?,
        string_bank(hash.digest.len())?,
    ])
}
fn reference_backing(media: &str) -> Result<usize, ProviderError> {
    add(
        hash_extent_backing("cnp.blob.v1", 64)?,
        string_bank(media.len())?,
    )
}

#[cfg(test)]
pub(super) fn report_shape_for_test(
    actual: &PacketNativeFreshRestoreAllocationScope,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let scope = ScopeFields {
        session: &actual.session,
        incarnation: &actual.incarnation,
        node: &actual.node,
        owner: &actual.owner,
        owner_generation: actual.owner_generation,
        world: &actual.world,
        prepared_token: &actual.prepared_token,
        admission: &actual.admission,
    };
    byte_formatter_storage(count(maximum, |p| report(p, &scope))?, 7, maximum)
}

fn byte_formatter_storage(
    mut data: OriginalSerializationStorageData,
    banks: usize,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    // Match the actual closed serializer's all-vector-capacity temporary
    // accounting, using each prospective digest bank's own admitted capacity.
    let padded = mul(banks, add(byte_bank(32)?, 2)?)?;
    data.serializer_temporary_requested_bytes = add(mul(padded / 3, 4)?, 20)?;
    if data.requested_total()? > maximum {
        return Err(invalid());
    }
    Ok(data)
}
