//! Adapts the actual Controller writer to canonical saved genesis DATA.
//!
//! This private module retains the real Journal borrow. Fixed codecs, saved
//! rows and mutation comparisons have their single owner in Source::replay.

use aos_sandbox_model::ProjectId;
use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1;
use aos_sandbox_ledger_replay::replay::controller_source_genesis::{
    ControllerSourceGenesisRowsV1, all_rows,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use super::{Journal, JournalError};

pub(crate) fn rows(
    journal: &Journal,
    project: ProjectId,
) -> Result<Option<ControllerSourceGenesisRowsV1>, SourceGenesisErrorV1> {
    let validated = all_rows(journal.native.state()).map_err(JournalError::from).map_err(SourceGenesisErrorV1::from)?;
    Ok(validated.get(&project).cloned())
}

pub(crate) fn pending(
    journal: &Journal,
) -> Result<Option<ControllerSourceGenesisAcceptanceRecordV1>, SourceGenesisErrorV1> {
    let validated = all_rows(journal.native.state()).map_err(JournalError::from)?;
    Ok(validated
        .into_values()
        .find(|row| row.complete.is_none())
        .map(|row| row.acceptance))
}
