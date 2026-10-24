//! Lends the actual signed Host/native17 cache without issuing new rights.

use super::*;
use crate::node_state::CompleteRestoredSettledNativeRestorationData;

impl CompleteOriginalHostTicket {
    /// Reports the actual retained Host family without converting either record.
    ///
    /// # Errors
    /// Refuses another process or thread.
    pub fn is_restored_settled_data(&self) -> Result<bool, RuntimeError> {
        self.source.authenticate_birth()?;
        Ok(matches!(
            self.source.host,
            CompleteHostArchiveRecord::Settled17(_)
        ))
    }
}

impl CompleteOriginalRestorationSource {
    pub(crate) fn restored_host_record_data(
        &self,
    ) -> Result<&crate::node_contract::HostSchedulingRestoredContinuationRecord17, RuntimeError>
    {
        self.inner.authenticate_birth()?;
        self.inner.host.restored_data()
    }
}

impl CompleteOriginalSource {
    pub(in crate::node_state::native) fn restored_native_import_construction_data(
        &self,
        index: usize,
    ) -> Result<&CompleteRestoredSettledNativeRestorationData, RuntimeError> {
        self.authenticate_birth()?;
        self.settled_restoration_data
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::UnsupportedFacet)
    }
}
