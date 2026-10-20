//! Aggregates Create U byte ceilings from the same actual component suppliers.
//!
//! The prefix remains explicitly incomplete. The final helper adds the owned
//! continuation formats, concrete Root tail, actual Controller pair engine,
//! real profile-row recipe and bank-history progression. Both are passive DATA:
//! neither creates an account, proves original custody or admits native work.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    request_capture::AuthenticatedBrokerMethodRequestCaptureV1,
    outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1,
};
use aos_sandbox_protocol::domain_ledger::resource_bank::{ACCOUNT_HEAD_BYTES_V1,
    CLAIM_BYTES_V1, CREATE_STORAGE_USE_BINDING_BYTES_V1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HEAD_BYTES,
    KEY_BYTES, transport::FRAME_HEADER_BYTES,
    use_reserved::{ROOT_VALIDATED_RECORD_BYTES_V1, USE_RESERVED_RECORD_BYTES_V1,
        USE_RESERVED_RECEIPT_BYTES_V1, USE_CURRENT_PROOFS_BYTES_V1}};

/// Describes actual private compiled Security owners without granting a loan.
///
/// Both real peers obtain the same value from the installed Security supplier.
/// Rust field/control storage is bytes; these values are not namespace entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCreateUseSecurityShapeDataV1 {
    /// The actual retained private flight's compiled inline width.
    pub actual_flight_bytes: usize,
    /// Actual construction/disposal overlap beyond its resident destination.
    pub actual_construction_bytes: usize,
    /// Additional retained native/replay error and temporary backing bytes.
    pub actual_failure_bytes: usize,
    /// Actual native endpoint destinations retained by the three private capsules.
    pub actual_endpoint_open_files: usize,
}

/// Prices the current concrete use prefix without completing the U ceiling.
///
/// Session/Controller prefixes come from the genuine held owners; the five
/// Cache extents come from the same completed held/current receipt supplier.
/// Request width is the common normalized nonissuing Prepare shape. The real
/// issuer independently compares originals and the FINAL complete requirement
/// before any purpose15 reservation. This passive function admits no work.
///
/// # Errors
/// Rejects invalid actual prefixes/widths or checked representation overflow.
pub fn storage_create_use_prefix_receiving_demand_v1(
    session_extent: &ProtectedJournalPreopenReplayExtentV1,
    request_shape_bytes: usize,
    controller_extent: &ProtectedJournalPreopenReplayExtentV1,
    cache_extents: &[ProtectedJournalPreopenReplayExtentV1; 5],
    private: StorageCreateUseSecurityShapeDataV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if private.actual_flight_bytes == 0 { return Err(invalid()); }
    let request = storage_create_prepare_client_request_demand_v1(session_extent, request_shape_bytes)?;
    let outcome = storage_create_prepare_client_positive_outcome_demand_v1(session_extent, request_shape_bytes)?;
    let growth = add(request.get(D::StorageBytes), outcome.get(D::StorageBytes))?;
    let future = super::super::protected_journal_preopen_replay_extent_for_prefix_v1(
        session_extent.limits, add(checked_prefix(session_extent)?, growth)?,
    ).map_err(|_| invalid())?;
    let p = usize::try_from(checked_prefix(&future)?).map_err(|_| invalid())?;
    let one_replay = storage_retained_current_replay_demand_v1(&future)?
        .checked_add(storage_retained_traffic_reconstruction_demand_v1(&future)?)
        .map_err(|_| invalid())?
        .checked_add(AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(p)
            .ok_or_else(invalid)?).map_err(|_| invalid())?;
    let terminal_readback = schema_demand(&future)?;
    let method = AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(p)
        .ok_or_else(invalid)?;
    let mut complete = request.checked_add(outcome).map_err(|_| invalid())?;
    // Before signing, before send and after authenticated terminal each retain
    // their complete canonical predecessor. This uses the forecast actual
    // positive successor width, never an absent maximum-size native history.
    for _ in 0..3 { complete = complete.checked_add(one_replay).map_err(|_| invalid())?; }
    complete = complete.checked_add(method).map_err(|_| invalid())?;
    complete = complete.checked_add(terminal_readback).map_err(|_| invalid())?;
    let names = crate::journal::create_storage_name_peak_demand_v1().map_err(|_| invalid())?;
    complete = complete.checked_add(names).map_err(|_| invalid())?.checked_add(names).map_err(|_| invalid())?;

    complete = complete.checked_add(storage_create_use_signing_receiving_demand_v1(
        request_shape_bytes, private,
    )?).map_err(|_| invalid())?;
    complete = complete.checked_add(crate::controller_resource_reservation::
        create_storage_preparation_io_receiving_demand_v1().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;

    complete = complete.checked_add(crate::controller_resource_reservation::
        create_storage_cache_current_fixed_receiving_demand_v1().map_err(|_| invalid())?)
        .map_err(|_| invalid())?.checked_add(crate::controller_resource_reservation::
        create_storage_cache_current_dynamic_receiving_demand_v1(cache_extents).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;

    let (wire, logs) = crate::normal_root::ProductionControllerNormalRootProfileV1::
        create_storage_producer_traffic_bound_v1(7).ok_or_else(invalid)?;
    complete = complete.checked_add(ResourceVector::ZERO
        .with(D::NetworkBytes, wire).with(D::LogBytes, logs)).map_err(|_| invalid())?;

    let pair = |record| encoded_transaction_append_bytes([
        RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(record) },
        RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
    ].into_iter()).map_err(|_| invalid());
    let reserve = encoded_transaction_append_bytes([
        RecordShape { key_bytes: 17, value_bytes: Some(ACCOUNT_HEAD_BYTES_V1) },
        RecordShape { key_bytes: 17, value_bytes: Some(CLAIM_BYTES_V1) },
        RecordShape { key_bytes: 17, value_bytes: Some(CREATE_STORAGE_USE_BINDING_BYTES_V1) },
    ].into_iter()).map_err(|_| invalid())?;
    let commit = encoded_transaction_append_bytes([
        RecordShape { key_bytes: 17, value_bytes: Some(ACCOUNT_HEAD_BYTES_V1) },
        RecordShape { key_bytes: 17, value_bytes: Some(CLAIM_BYTES_V1) },
    ].into_iter()).map_err(|_| invalid())?;
    // Controller extent denotes the actual InputsReady cut on BOTH peers.
    // RootValidated is an exact typed forecast here, actual returned position
    // at C; later Signed/terminal rows must be added by their format providers.
    let controller_growth = sum(&[pair(ROOT_VALIDATED_RECORD_BYTES_V1)?, reserve,
        pair(USE_RESERVED_RECORD_BYTES_V1)?, commit])?;
    let controller = super::super::protected_journal_preopen_replay_extent_for_prefix_v1(
        controller_extent.limits, add(controller_extent.native_bytes, controller_growth)?,
    ).map_err(|_| invalid())?;
    let replay = controller.dominant_native_receiving_demand_v1().map_err(|_| invalid())?
        .checked_add(controller.dominant_semantic_receiving_demand_v1().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    // Independent reserve and final positive-commit readbacks coexist. Map and
    // parser overhead use the common dominant recipe, not symbolic Result fees.
    complete = complete.checked_add(replay).map_err(|_| invalid())?
        .checked_add(replay).map_err(|_| invalid())?;
    let frames = USE_RESERVED_RECEIPT_BYTES_V1.checked_add(USE_CURRENT_PROOFS_BYTES_V1)
        .and_then(|n| n.checked_add(2 * FRAME_HEADER_BYTES)).ok_or_else(invalid)?;
    let packet = response_packet_bytes(as_u64(aos_sandbox_protocol::semantics::storage_prepare::
        storage_catalog_preparation_response_body_bound_v1())?)?;
    complete.checked_add(ResourceVector::ZERO
        .with(D::StorageBytes, add(reserve, add(pair(USE_RESERVED_RECORD_BYTES_V1)?, commit)?)?)
        .with(D::MetadataEntries, 3)
        .with(D::NetworkBytes, sum(&[as_u64(frames)?, as_u64(request_shape_bytes)?, packet])?)
        .with(D::OutputBytes, add(as_u64(frames)?, as_u64(request_shape_bytes)?)?))
        .map_err(|_| invalid())
}

/// Prices the complete owned Create U continuation without issuing authority.
///
/// Both real peers independently supply the same held Session and InputsReady
/// extents, normalized full request width, five actual Cache extents and actual
/// compiled Security layout. The genuine issuer must still match every original
/// and compare this whole amount before reserve. Root's own independent reads,
/// compiler and signer-side F are separately funded; this prices the Controller
/// continuation through its positive U commit and complete terminal transport.
///
/// Clean selected-C Producer scopes retain their own real C admission and
/// dispose positive scratch before reuse. Their cumulative traffic is included
/// by the concrete tail supplier; no per-byte intake archive is fabricated.
/// The conservative full fragmentation traffic is intentional. An insufficient
/// configured bank refuses; this helper does not shrink traffic or raise caps.
///
/// # Errors
/// Rejects invalid actual prefixes, zero or overflowing request shape, native
/// record/prefix bounds, unavailable compiled suppliers or checked arithmetic.
pub fn storage_create_use_receiving_demand_v1(
    session_extent: &ProtectedJournalPreopenReplayExtentV1,
    request_shape_bytes: usize,
    controller_extent: &ProtectedJournalPreopenReplayExtentV1,
    source_extent: &ProtectedJournalPreopenReplayExtentV1,
    cache_extents: &[ProtectedJournalPreopenReplayExtentV1; 5],
    private: StorageCreateUseSecurityShapeDataV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        RECORD_OVERHEAD_BYTES,
        continuation::SIGNED_PREPARATION_PREFIX_BYTES_V1,
        controller_use::{SIGNED_BODY_PREFIX_BYTES_V1, DISPATCH_BOUND_BODY_BYTES_V1,
            SESSION_RESERVED_BODY_BYTES_V1},
        outcome::{CONTROLLER_OUTCOME_RECORD_BYTES_V1, HANDOFF_RETAINED_RECORD_BYTES_V1},
    };
    use aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory;
    use crate::controller_resource_reservation as receiving;

    if request_shape_bytes == 0 { return Err(invalid()); }
    let mut complete = storage_create_use_prefix_receiving_demand_v1(
        session_extent, request_shape_bytes, controller_extent, cache_extents, private,
    )?;
    complete = complete.checked_add(receiving::create_storage_preparation_originals_receiving_demand_v1()
        .map_err(|_| invalid())?).map_err(|_| invalid())?;
    let tail = receiving::create_storage_root_use_tail_shape_v1(request_shape_bytes)
        .map_err(|_| invalid())?;

    // The prefix already counted frames6/7. The concrete tail now owns their
    // entire stream grammar, including both invitations and every later frame.
    let repeated_frames = USE_RESERVED_RECEIPT_BYTES_V1.checked_add(USE_CURRENT_PROOFS_BYTES_V1)
        .and_then(|bytes| bytes.checked_add(2 * FRAME_HEADER_BYTES)).ok_or_else(invalid)?;
    complete = complete.checked_sub(ResourceVector::ZERO
        .with(D::NetworkBytes, as_u64(repeated_frames)?)).map_err(|_| invalid())?;
    complete = complete.checked_add(tail.receiving).map_err(|_| invalid())?;

    let signed = request_shape_bytes.checked_mul(3)
        .and_then(|bytes| bytes.checked_add(SIGNED_PREPARATION_PREFIX_BYTES_V1))
        .and_then(|bytes| bytes.checked_add(SIGNED_BODY_PREFIX_BYTES_V1))
        .and_then(|bytes| bytes.checked_add(RECORD_OVERHEAD_BYTES)).ok_or_else(invalid)?;
    let records = [USE_RESERVED_RECORD_BYTES_V1, signed,
        RECORD_OVERHEAD_BYTES.checked_add(DISPATCH_BOUND_BODY_BYTES_V1).ok_or_else(invalid)?,
        RECORD_OVERHEAD_BYTES.checked_add(SESSION_RESERVED_BODY_BYTES_V1).ok_or_else(invalid)?,
        CONTROLLER_OUTCOME_RECORD_BYTES_V1, HANDOFF_RETAINED_RECORD_BYTES_V1];
    let pair = |record| encoded_transaction_append_bytes([
        RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(record) },
        RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
    ].into_iter()).map_err(|_| invalid());
    let bank_pair = |binding| {
        if binding {
            encoded_transaction_append_bytes([
                RecordShape { key_bytes: 17, value_bytes: Some(ACCOUNT_HEAD_BYTES_V1) },
                RecordShape { key_bytes: 17, value_bytes: Some(CLAIM_BYTES_V1) },
                RecordShape { key_bytes: 17, value_bytes: Some(CREATE_STORAGE_USE_BINDING_BYTES_V1) },
            ].into_iter()).map_err(|_| invalid())
        } else {
            encoded_transaction_append_bytes([
                RecordShape { key_bytes: 17, value_bytes: Some(ACCOUNT_HEAD_BYTES_V1) },
                RecordShape { key_bytes: 17, value_bytes: Some(CLAIM_BYTES_V1) },
            ].into_iter()).map_err(|_| invalid())
        }
    };
    let reserve = bank_pair(true)?;
    let commit = bank_pair(false)?;
    let mut controller_growth = sum(&[pair(ROOT_VALIDATED_RECORD_BYTES_V1)?, reserve, commit])?;
    for record in records { controller_growth = add(controller_growth, pair(record)?)?; }
    let future = super::super::protected_journal_preopen_replay_extent_for_prefix_v1(
        controller_extent.limits, add(checked_prefix(controller_extent)?, controller_growth)?,
    ).map_err(|_| invalid())?;
    let semantic = future.dominant_semantic_receiving_demand_v1().map_err(|_| invalid())?;

    // Actual UseReserved immediately uses this same fixed/pair/semantic recipe.
    // Each subsequent once-only pair retains its own record and owed posts.
    // Compiled controls are bytes; real semantic-map/index cardinalities and
    // the six new historical rows retain their separate namespace budgets.
    let old_pair = pair(USE_RESERVED_RECORD_BYTES_V1)?;
    complete = complete.checked_sub(ResourceVector::ZERO
        .with(D::StorageBytes, old_pair).with(D::MetadataEntries, 1))
        .map_err(|_| invalid())?;
    for record in records {
        complete = complete.checked_add(receiving::
            create_storage_use_history_pair_receiving_demand_v1(record, &semantic)
                .map_err(|_| invalid())?).map_err(|_| invalid())?;
    }
    // Three profile comparisons per pair, each using two actual retained rows.
    // This is the real intake archive route, distinct from clean operation
    // Producer scopes. Its buffer recipe is shared with actual grow admission.
    let rows = records.len().checked_mul(6).ok_or_else(invalid)?;
    complete = complete.checked_add(receiving::
        create_storage_use_profile_rows_receiving_demand_v1(rows).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;

    // Extend both bank readback ceilings to the complete actual Controller tail.
    // The prefix's earlier forecast already paid reserve/commit representation;
    // only the checked increment is added, avoiding unrelated spare credit.
    let old_growth = sum(&[pair(ROOT_VALIDATED_RECORD_BYTES_V1)?, reserve,
        pair(USE_RESERVED_RECORD_BYTES_V1)?, commit])?;
    let old = super::super::protected_journal_preopen_replay_extent_for_prefix_v1(
        controller_extent.limits, add(checked_prefix(controller_extent)?, old_growth)?,
    ).map_err(|_| invalid())?;
    let replay = |extent: &ProtectedJournalPreopenReplayExtentV1| {
        extent.dominant_native_receiving_demand_v1().map_err(|_| invalid())?
            .checked_add(extent.dominant_semantic_receiving_demand_v1().map_err(|_| invalid())?)
            .map_err(|_| invalid())
    };
    let increment = replay(&future)?.checked_sub(replay(&old)?).map_err(|_| invalid())?;
    complete = complete.checked_add(increment).map_err(|_| invalid())?
        .checked_add(increment).map_err(|_| invalid())?;

    // Each existing canonical binding occupies at least168 native value bytes.
    // The new reservation adds one. Native still admits its actual-state helper
    // before observing real physical progress; this forecast creates no entry.
    let count = usize::try_from(checked_prefix(controller_extent)? /
        as_u64(CREATE_STORAGE_USE_BINDING_BYTES_V1)?).map_err(|_| invalid())?
        .checked_add(1).ok_or_else(invalid)?;
    let progress = PhysicalHistory::additional_use_receiving_demand_for_count_v1(count)
        .map_err(|_| invalid())?;
    complete = complete.checked_add(progress).map_err(|_| invalid())?
        .checked_add(progress).map_err(|_| invalid())?;
    complete = complete.checked_add(receiving::create_storage_use_commit_receiving_demand_v1()
        .map_err(|_| invalid())?).map_err(|_| invalid())?;
    complete = complete.checked_add(receiving::create_storage_held_release_receiving_demand_v1(
        source_extent, cache_extents).map_err(|_| invalid())?).map_err(|_| invalid())?;

    // Six C rows and the U claim/binding were counted at their actual append
    // suppliers. Keep every additional resident map/index/catalog/pathname
    // cardinality from the complete lower recipes; these are not Rust fields.
    Ok(complete)
}

/// Prices the actual once-only Controller signing phase without granting it.
///
/// The same final U recipe and genuine Root8 signing admission delegate here.
/// The concrete Security shape comes from the installed no-argument supplier;
/// model/key/message construction begins only after the same U accepts this
/// whole bound. Root peer scratch stays in the existing genuine resident peak;
/// its additional before/after traffic belongs to the concrete tail supplier.
///
/// # Errors
/// Rejects zero compiled flight/request width or checked representation errors.
pub fn storage_create_use_signing_receiving_demand_v1(
    request_shape_bytes: usize,
    private: StorageCreateUseSecurityShapeDataV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if request_shape_bytes == 0 || private.actual_flight_bytes == 0 {
        return Err(invalid());
    }
    // These dominant canonical plan/statement/message/signature/body/envelope
    // planes retain the existing full normalized request bound. Private policy
    // planes use the already-existing immutable decoder ceiling, not a new cap.
    let policy = aos_sandbox_protocol::authorization_artifact::SigningAuthority::
        maximum_canonical_policy_bytes_v1();
    let bytes = request_shape_bytes.checked_mul(16)
        .and_then(|bytes| bytes.checked_add(policy.checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(private.actual_flight_bytes.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(private.actual_construction_bytes))
        .and_then(|bytes| bytes.checked_add(private.actual_failure_bytes))
        .ok_or_else(invalid)?;
    ResourceVector::ZERO.with(D::MemoryBytes, as_u64(bytes)?)
        .with(D::OpenFiles, as_u64(private.actual_endpoint_open_files)?)
        .checked_add(crate::controller_resource_reservation::
            create_storage_signing_originals_receiving_demand_v1().map_err(|_| invalid())?)
        .map_err(|_| invalid())
}
