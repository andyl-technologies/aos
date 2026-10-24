//! Shared pure `AOSMSA02` whole-graph validation.

use super::SourceAcquisitionTableV2;
use crate::Result;

pub(super) fn validate_recovered_table(table: &SourceAcquisitionTableV2) -> Result<()> {
    aos_sandbox_protocol::mount_source_acquisition_state::validate_recovered_table(&table.state())?;
    Ok(())
}
