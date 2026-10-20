//! Exact kind5 Attempt-selected local profile1 admission and cold rejoin.
//!
//! Current Abandoned T selects its successor S and actual predecessor S. The
//! full graph and fixed physical writer supply currentness; no old Head inverse
//! or caller-nominated reference map is reconstructed here.

use aos_sandbox_protocol::domain_ledger::capacity_family::ordinary::OrdinaryCapacityRecordV4;

use aos_sandbox_protocol::mount_source_acquisition_state::{
    DeadProviderExecutionProjectionV2, ProviderIntentV2, RecordRefV2, prepare_dead_replacement_v2,
};

use super::*;

pub(super) fn installed(
    state: &State,
    table: &MountSourceAcquisitionStateV2,
    primary: [u8; 32],
) -> Result<LocalPostimageBindings, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::dead_replacement::installed(
        state,
        table,
        primary,
    )
        .map_err(JournalError::from)
}

pub(super) fn prepare(
    state: &State,
    successor: SourceProviderSessionV2,
    death: DeadProviderExecutionProjectionV2,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::dead_replacement::prepare(
        state,
        successor,
        death,
    )
        .map_err(JournalError::from)
}

pub(super) fn validate_admission(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::dead_replacement::validate_admission(
        state,
        transaction,
    )
        .map_err(JournalError::from)
}
