//! Shares read bookkeeping only through the original physical owner's bodies.

use super::NativeOwnerExecutor;
use crate::{
    host_cache::owner::{publication::eviction::ReadActivity, retention::Custody},
    publisher_local::client::PeerPublishedObject,
};
use std::{io, sync::Arc};
use terrane::host::cache::HostDomainLocation;

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
}
