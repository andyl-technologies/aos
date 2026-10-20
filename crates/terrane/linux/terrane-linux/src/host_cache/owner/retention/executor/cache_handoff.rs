//! Releases original transferred admissions after the handoff snapshot completes.

use super::NativeOwnerExecutor;
use crate::host_cache::owner::admission::TransferredFunding;
use std::io;

impl NativeOwnerExecutor {
    /// Releases acknowledged closed sources after their synchronized funding removal.
    ///
    /// # Errors
    /// Refuses another worker, stale snapshot, remaining funding or changed
    /// original native resources. Registry removal follows actual resource release.
    pub(in crate::host_cache::owner) fn release_transferred_admissions(
        &mut self,
        sources: &[TransferredFunding],
    ) -> io::Result<()> {
        self.check_physical_worker()?;
        for source in sources {
            source.release(self)?;
        }
        self.admission_jobs
            .retain(|job| !sources.iter().any(|source| source.belongs_to(job)));
        Ok(())
    }
}
