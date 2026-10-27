//! Shares the sole saved Source hold/V8/Q04 custody-row fold.
//!
//! These checks decode historical map DATA only. They open no file, perform no
//! currentness observation, create no role or permit, and authorize no mutation.
//! Native owners keep their independent same-file/path/health/financial gates.

use std::collections::BTreeMap;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::{ProtectedHistoryDataErrorV1,
    source_policy_hold::{SourceDomainPolicyHoldV1, SourceDomainPolicyV8PendingSettlementV1}};
#[cfg(target_os = "linux")]
use aos_sandbox_protocol::domain_ledger::create_q04_history::{Q04PendingOwnerV1, Q04PendingRecordV1};

/// Names the existing saved held/released Source custody row.
pub const KEY: &[u8] = b"\0aos-source-domain-policy-hold-v1\0";
/// Names the existing saved V8 pending-settlement row.
pub const V8_PENDING_KEY: &[u8] = b"\0aos-source-domain-policy-v8-pending-settlement-v1\0";
/// Names the fixed Delete fence whose value is the complete canonical batch.
///
/// The batch is saved DATA, not acceptance or a destruction grant. Ordinary
/// Source mutation remains fenced until the same D-only owner settles it.
pub const DELETE_PENDING_KEY: &[u8] = b"\0aos-source-domain-delete-pending-v1\0";

/// Names the existing saved Q04 Source pending row.
pub use aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::SOURCE_PENDING_KEY;

/// Decodes the same current custody row without establishing a native owner.
///
/// # Errors
/// Refuses malformed, mixed, orphaned or contradictory saved rows.
pub fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<SourceDomainPolicyHoldV1>, ProtectedHistoryDataErrorV1> {
    let readback = current_state(state)?;
    if readback.delete_pending.is_some() {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    Ok(readback.hold)
}

/// Decodes the same V8 pair while refusing a Q04-only pending marker.
///
/// # Errors
/// Refuses the original parser failures and any Q04 pending row.
pub fn current_with_v8_pending(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<
    (
        Option<SourceDomainPolicyHoldV1>,
        Option<SourceDomainPolicyV8PendingSettlementV1>,
    ),
    ProtectedHistoryDataErrorV1,
> {
    let readback = current_state(state)?;
    if readback.delete_pending.is_some() {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    #[cfg(target_os = "linux")]
    if readback.q04_pending.is_some() {
        // A Q04 marker is never interpreted as a legacy/V8 release proof.
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    Ok((readback.hold, readback.v8_pending))
}

/// Contains the exact decoded held/released and pending comparison rows.
pub struct SourceDomainPolicyHoldStateV1 {
    /// Actual held or released custody row.
    pub hold: Option<SourceDomainPolicyHoldV1>,
    /// Actual V8 pending-settlement row.
    pub v8_pending: Option<SourceDomainPolicyV8PendingSettlementV1>,
    /// Commits the exact canonical pending Delete batch, without cloning it.
    pub delete_pending: Option<aos_sandbox_model::ObjectDigest>,
    #[cfg(target_os = "linux")]
    /// Actual Q04 held or released-pending row.
    pub q04_pending: Option<Q04PendingRecordV1>,
}

/// Folds the actual saved custody namespace through its sole canonical parser.
///
/// # Errors
/// Refuses unknown keys, malformed values or mismatched hold/marker bindings.
pub fn current_state(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<SourceDomainPolicyHoldStateV1, ProtectedHistoryDataErrorV1> {
    let mut records = state
        .range((RecordNamespace::SourceDomainPolicyHold, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::SourceDomainPolicyHold);
    let mut hold = None;
    let mut pending = None;
    let mut delete_pending = None;
    #[cfg(target_os = "linux")]
    let mut q04_pending = None;
    for ((_, key), value) in &mut records {
        match key.as_slice() {
            KEY if hold.is_none() => hold = Some(SourceDomainPolicyHoldV1::decode(value)?),
            V8_PENDING_KEY if pending.is_none() => {
                pending = Some(SourceDomainPolicyV8PendingSettlementV1::decode(value)?)
            }
            DELETE_PENDING_KEY if delete_pending.is_none() => {
                // The sole canonical batch decoder checks every row, graph,
                // count and checksum. No private prefix parser is introduced.
                let batch = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::decode(value)
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?;
                delete_pending = Some(aos_sandbox_model::ObjectDigest::from_bytes(
                    aos_sandbox_protocol::domain_ledger::delete_batch::native_value_digest(batch.bytes()),
                ));
            }
            #[cfg(target_os = "linux")]
            SOURCE_PENDING_KEY if q04_pending.is_none() => {
                q04_pending = Some(Q04PendingRecordV1::decode(Q04PendingOwnerV1::Source, value)?);
            }
            _ => return Err(ProtectedHistoryDataErrorV1::Malformed),
        }
    }
    if delete_pending.is_some()
        && (hold.is_some_and(SourceDomainPolicyHoldV1::is_held) || pending.is_some())
    {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    #[cfg(target_os = "linux")]
    if delete_pending.is_some() && q04_pending.is_some() {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    if let Some(marker) = pending {
        match hold {
            Some(released) if marker.matches_released(released)? => {}
            _ => return Err(ProtectedHistoryDataErrorV1::Malformed),
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(marker) = &q04_pending {
        let row = hold.ok_or(ProtectedHistoryDataErrorV1::Malformed)?;
        if pending.is_some() {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        require_q04_marker_row(marker, row)?;
    }
    Ok(SourceDomainPolicyHoldStateV1 {
        hold,
        v8_pending: pending,
        delete_pending,
        #[cfg(target_os = "linux")]
        q04_pending,
    })
}

#[cfg(target_os = "linux")]
fn require_q04_marker_row(
    marker: &Q04PendingRecordV1,
    row: SourceDomainPolicyHoldV1,
) -> Result<(), ProtectedHistoryDataErrorV1> {
    let held = (row).held_data();
    let released = (row).released_data();
    if marker.is_held() != row.is_held()
        || marker.bytes()[64..96] != *row.binding().as_bytes()
        || marker.bytes()[96..104] != row.epoch().to_be_bytes()
        || marker.bytes()[104..136] != *held.record_digest()?.as_bytes()
        || marker.bytes()[136..168] != *released.record_digest()?.as_bytes()
    {
        return Err(ProtectedHistoryDataErrorV1::Malformed);
    }
    Ok(())
}
