//! Shares read bookkeeping only through the original physical owner's bodies.

use super::NativeOwnerExecutor;
use crate::{
    host_cache::owner::{
        publication::eviction::{ReadActivities, ReadActivity},
        retention::{Custody, RetainedManifest},
    },
    publisher_local::client::PeerPublishedObject,
};
use std::{io, sync::Arc};
use terrane_sdk::host::cache::HostDomainLocation;

impl NativeOwnerExecutor {
    /// Retains bounded activity for an actual verified body in this owner's root.
    ///
    /// # Errors
    /// Refuses another worker or root, exhausted activity storage or native errors.
    pub(in crate::host_cache::owner) fn body_read_activity(
        &self,
        owner: &Custody,
        body: &Arc<PeerPublishedObject<HostDomainLocation>>,
    ) -> io::Result<Arc<ReadActivity>> {
        self.check_physical_worker()?;
        if !Arc::ptr_eq(body.layout(), owner.preparation.layout()) {
            return Err(io::Error::other(
                "read activity belongs to another native root",
            ));
        }
        self.cache
            .activities
            .lock()
            .map_err(|_| io::Error::other("read activity registry poisoned"))?
            .for_body(body, owner.preparation.config.state.records)
    }

    /// Shares activity only after binding the actual encoded admission source.
    ///
    /// # Errors
    /// Refuses another worker/root, exhausted registry storage or native errors.
    pub(in crate::host_cache::owner) fn admission_read_activity(
        &self,
        source: &crate::host_cache::owner::admission::reads::AdmittedRead,
    ) -> io::Result<ReadActivities> {
        self.check_physical_worker()?;
        let owner = self
            .custody()
            .lock()
            .map_err(|_| io::Error::other("admitted activity custody poisoned"))?;
        source.check_protected(&owner)?;
        self.cache
            .activities
            .lock()
            .map_err(|_| io::Error::other("read activity registry poisoned"))?
            .for_admission(source, owner.preparation.config.state.records)
    }

    /// Shares activity only after binding the actual metadata pair source.
    ///
    /// # Errors
    /// Refuses another worker/root, exhausted registry storage or native errors.
    pub(in crate::host_cache::owner) fn metadata_read_activity(
        &self,
        source: &crate::host_cache::owner::admission::pack_reads::AdmittedPackRead,
    ) -> io::Result<ReadActivities> {
        self.check_physical_worker()?;
        let owner = self
            .custody()
            .lock()
            .map_err(|_| io::Error::other("admitted activity custody poisoned"))?;
        source.check_protected(&owner)?;
        self.cache
            .activities
            .lock()
            .map_err(|_| io::Error::other("read activity registry poisoned"))?
            .for_metadata(source, owner.preparation.config.state.records)
    }

    /// Shares activity for a completed metadata source's original owned admission.
    ///
    /// # Errors
    /// Refuses another physical worker/root, changed retention, exhausted finite
    /// activity storage or native metadata errors.
    pub(in crate::host_cache::owner) fn manifest_read_activity(
        &self,
        retained: &RetainedManifest,
    ) -> io::Result<Option<Arc<ReadActivity>>> {
        self.check_physical_worker()?;
        let owner = self
            .custody()
            .lock()
            .map_err(|_| io::Error::other("metadata activity custody poisoned"))?;
        if !Arc::ptr_eq(&retained.custody, self.custody())
            || !Arc::ptr_eq(retained.source.layout(), owner.preparation.layout())
        {
            return Err(io::Error::other(
                "metadata activity belongs to another root",
            ));
        }
        retained.check_registration(&owner)?;
        let Some(order) = crate::host_cache::owner::admission::reads::metadata_activity_order(
            self,
            &owner,
            &retained.source,
        )?
        else {
            return Ok(None);
        };
        self.cache
            .activities
            .lock()
            .map_err(|_| io::Error::other("read activity registry poisoned"))?
            .for_manifest(
                &retained.source,
                order,
                owner.preparation.config.state.records,
            )
            .map(Some)
    }
}
