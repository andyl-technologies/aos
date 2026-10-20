//! Removes original encoded registry entries only after acknowledged closure.

use super::NativeOwnerExecutor;
use crate::{
    host_cache::owner::admission::AdmissionJob,
    publisher_local::client::{EncodedCacheCompletion, EncodedCacheReceipt},
};
use std::{
    io,
    sync::{Arc, Mutex},
};

impl NativeOwnerExecutor {
    /// Relinquishes the exact removed admissions after their native resources close.
    ///
    /// # Errors
    /// Refuses another worker, peer, acknowledgment, incomplete closure or missing
    /// original registry slot. All checks precede registry mutation.
    pub(in crate::host_cache::owner) fn unregister_retired_admissions(
        &mut self,
        members: &[Arc<Mutex<AdmissionJob>>],
        receipt: &Arc<EncodedCacheReceipt>,
        completion: &Arc<EncodedCacheCompletion>,
    ) -> io::Result<()> {
        self.check_physical_worker()?;
        let session = self
            .custody()
            .lock()
            .map_err(|_| io::Error::other("encoded registry custody poisoned"))?
            .preparation
            .publisher_session();
        for member in members {
            if !self
                .admission_jobs
                .iter()
                .any(|registered| Arc::ptr_eq(member, registered))
            {
                return Err(io::Error::other(
                    "removed encoded admission lost original registry",
                ));
            }
            member
                .lock()
                .map_err(|_| io::Error::other("removed encoded admission poisoned"))?
                .check_cache_removed(&session, receipt, completion)?;
        }
        self.admission_jobs
            .retain(|registered| !members.iter().any(|member| Arc::ptr_eq(member, registered)));
        Ok(())
    }
}
