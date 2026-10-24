//! Derives cleanup phase from actual captured C, Host and complete Root78 history.
//!
//! The enclosing original pays all models before entry and retains the same
//! native readers, Root writers and current Recover authorization. Every value
//! returned here is comparison DATA; no phase alone can produce a signature.

use super::*;
use aos_sandbox_ledger_replay::replay::execution_no_apply_history as history;
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyFloorKeyDataV2;
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordV2,
    closed_controller::ClosedCreateFailurePrepareDataV2,
    recovery_acquisition::{RootNoApplyRecoveryHistoryDataV2, RootNoApplyRecoveryPhaseV2},
};

pub(super) struct Classified {
    pub(super) history: history::HistoryDataV2,
    pub(super) plan: aos_sandbox_protocol::domain_ledger::create_failure::ClosedCreateFailurePlanDataV2,
    pub(super) phase: RootNoApplyRecoveryPhaseV2,
    pub(super) recovery: Option<RootNoApplyRecoveryHistoryDataV2>,
}

pub(super) fn classify(
    authority: &Journal,
    controller: crate::journal::historical_observation::HistoricalObservationV1<'_>,
    authorization: &Authorization,
    host: &HostHistoryOriginalV2,
    selection: &RootNoApplyAcquisitionSelectionDataV2,
    sample: RawPairedClockSample,
) -> Result<Classified, Cause> {
    let operation = authorization.target_v1()?;
    if operation.as_bytes() != &selection.accepted_source.fields().create_operation
        || selection.marker.fields().source != selection.accepted_source
        || selection
            .historical_availability
            .fields()
            .bound_source_digest
            != *selection.accepted_source.digest().as_bytes()
    {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let (sealed, acknowledged) =
        host.require_recovery_lineage_v2(selection, sample.host_boot_id())?;
    let history =
        history::inspect_history_data_v2(authority.historical_read_view_v1(), *operation.as_bytes())?;
    let prepare = controller
        .get(
            crate::RecordNamespace::ControllerCreateFailurePrepare,
            operation.as_bytes(),
        )
        .map(|bytes| {
            ClosedCreateFailurePrepareDataV2::decode_canonical(operation.as_bytes(), bytes)
        })
        .transpose()?;
    let wall = prepare
        .map(|prepared| prepared.wall_seconds)
        .or_else(|| {
            history
                .selected_data_v2()
                .map(|floor| floor.fields().terminal_wall_seconds)
        })
        .unwrap_or(sample.wall_seconds());
    let plan = crate::reconciler::plan_closed_create_failure_rows_from_observation_v2(controller,
        selection.marker,
        aos_sandbox_model::ObjectDigest::from_bytes(selection.terminal_archive),
        aos_sandbox_model::ObjectDigest::from_bytes(selection.signed_terminal),
        wall,
    )?;
    if plan.operation_data_v2() != operation || plan.prepared_data_v2() != prepare {
        return Err(JournalError::ProtectedBoundary.into());
    }
    if let Some(floor) = history.selected_data_v2() {
        let fields = floor.fields();
        let (before, after) = plan.row_digests_data_v2();
        if fields.host_lease.fields().accepted_source != selection.accepted_source
            || fields.host_lease.fields().marker
                != HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(selection.marker)
            || fields.host_lease.fields().terminal_archive_head != selection.terminal_archive
            || fields.host_lease.fields().signed_terminal_outcome != selection.signed_terminal
            || fields.predecessor_rows != before
            || fields.successor_rows != after
            || fields.terminal_wall_seconds != wall
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
    }
    if let Some(prepare) = prepare {
        let current = history.selected_data_v2().ok_or(JournalError::ProtectedBoundary)?;
        let referenced = history::record_data_v2(
            authority.historical_read_view_v1(),
            RootExecutionNoApplyFloorKeyDataV2::new(*operation.as_bytes(), prepare.root_sequence)?,
        )?;
        if referenced.digest() != *prepare.root_floor.as_bytes()
            || referenced.fields().revision > current.fields().revision
            || ClosedCreateFailurePrepareDataV2::from_root_floor_data_v2(referenced)? != prepare
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
    }
    // Successful historical42 is not adopted as an ephemeral live owner. Its
    // exact immutable Root reference must nevertheless exist in this complete
    // native namespace78 and agree with the same terminal and row relation.
    for outcome in host.terminal_outcomes_v2() {
        use aos_sandbox_protocol::host_execution_no_apply::{
            held_settlement_transport::HostNoApplyHeldCommandV2,
            root_attestation::RootExecutionNoApplyAttestationDataV2,
        };
        let Some(request) = outcome.request().host_held_no_apply_settlement_data_v2() else {
            continue;
        };
        match request.command_v2() {
            HostNoApplyHeldCommandV2::FloorSeal {
                comparison,
                canonical_root_attestation,
                controller_prepare,
            } if comparison.fields().accepted_source == selection.accepted_source => {
                let artifact = RootExecutionNoApplyAttestationDataV2::decode_canonical(
                    canonical_root_attestation,
                )?;
                let record = artifact.floor_data_v2();
                let actual = history::record_data_v2(authority.historical_read_view_v1(), record.key())?;
                if record != actual
                    || artifact.prepare_data_v2() != *controller_prepare
                    || ClosedCreateFailurePrepareDataV2::from_root_floor_data_v2(actual)?
                        != *controller_prepare
                    || actual.fields().host_lease != *comparison
                    || actual.fields().host_lease.fields().marker
                        != HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(selection.marker)
                {
                    return Err(JournalError::ProtectedBoundary.into());
                }
            }
            HostNoApplyHeldCommandV2::Acknowledge { comparison, ack }
                if comparison.fields().accepted_source == selection.accepted_source =>
            {
                let actual = history::record_data_v2(
                    authority.historical_read_view_v1(),
                    RootExecutionNoApplyFloorKeyDataV2::new(
                        *operation.as_bytes(),
                        ack.root_sequence,
                    )?,
                )?;
                let intended = ClosedCreateFailurePrepareDataV2::from_root_floor_data_v2(actual)?;
                if ack.operation != operation
                    || ack.root_floor.as_bytes() != &actual.digest()
                    || ack.controller_prepare != intended.digest()
                    || ack.settled_cas != intended.settled_cas_digest()
                    || actual.fields().host_lease != *comparison
                {
                    return Err(JournalError::ProtectedBoundary.into());
                }
            }
            _ => {}
        }
    }
    let phase = match (
        history.selected_data_v2(),
        prepare,
        plan.settled_data_v2(),
        sealed,
        acknowledged,
    ) {
        (None, None, false, false, false) => RootNoApplyRecoveryPhaseV2::BeforeFloor,
        (Some(_), None, false, false, false) => RootNoApplyRecoveryPhaseV2::FloorAnchored,
        (Some(_), Some(_), false, _, false) => RootNoApplyRecoveryPhaseV2::Prepared,
        (Some(_), Some(_), true, _, _) => RootNoApplyRecoveryPhaseV2::Settled,
        _ => return Err(JournalError::ProtectedBoundary.into()),
    };
    let recovery = match history.selected_data_v2() {
        Some(floor) => Some(RootNoApplyRecoveryHistoryDataV2 {
            // Only FloorAnchored derives intended DATA here. Prepared and
            // Settled retain the actual canonical C prepare validated above.
            prepare: match prepare {
                Some(prepare) => prepare,
                None => ClosedCreateFailurePrepareDataV2::from_root_floor_data_v2(floor)?,
            },
            current_floor: floor.digest(),
            current_revision: floor.fields().revision,
        }),
        None => None,
    };
    Ok(Classified {
        history,
        plan,
        phase,
        recovery,
    })
}

/// Prices the actual historical Controller classifier interface before entry.
///
/// The existing closed-failure supplier retains the complete dynamic plan and
/// diagnostic-model quote. This adds no native owner, budget or phase grant.
pub(super) fn observation_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;

    size_of::<(
        &Journal,
        crate::journal::historical_observation::HistoricalObservationV1<'_>,
        &Authorization, &HostHistoryOriginalV2, &RootNoApplyAcquisitionSelectionDataV2,
        RawPairedClockSample,
    )>().checked_mul(3)?
        .checked_add(size_of::<Result<Classified, Cause>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
