//! Holds physical exclusion throughout each original cached-body namespace RPC.

use super::NativeOwnerExecutor;
use crate::{
    host_cache::owner::publication::eviction::CachePermit,
    publisher_local::{
        client::{PeerPublishedObject, PendingCacheBody, PublisherRunningContext},
        wire::Operation,
    },
};
use std::{io, sync::Arc};
use terrane_sdk::host::cache::HostDomainLocation;

/// Borrows the actual worker and its original validated cache-transition permit.
pub(crate) struct PublisherCacheRetirementTurn<'turn> {
    executor: &'turn mut NativeOwnerExecutor,
    permit: &'turn CachePermit<'turn>,
}

impl NativeOwnerExecutor {
    /// Removes original publication registry slots after final native removal.
    ///
    /// # Errors
    /// Refuses another worker, missing original slots or an unrelated final reply.
    pub(in crate::host_cache::owner) fn unregister_retired_publications(
        &mut self,
        members: &[Arc<std::sync::Mutex<crate::host_cache::owner::publication::PublicationJob>>],
        pending: &Arc<PendingCacheBody>,
        completion: &Arc<crate::publisher_local::client::CacheBodyCompletion>,
    ) -> io::Result<()> {
        self.check_physical_worker()?;
        completion.check_removed(pending)?;
        if members.iter().any(|member| {
            !self
                .publications
                .iter()
                .any(|registered| Arc::ptr_eq(registered, member))
        }) {
            return Err(io::Error::other("retired cache lost its original registry"));
        }
        self.publications
            .retain(|job| !members.iter().any(|member| Arc::ptr_eq(member, job)));
        Ok(())
    }

    /// Excludes every other physical command for the complete namespace RPC.
    ///
    /// # Errors
    /// Refuses another physical worker.
    pub(in crate::host_cache::owner) fn cache_retirement_turn<'turn>(
        &'turn mut self,
        permit: &'turn CachePermit<'turn>,
    ) -> io::Result<PublisherCacheRetirementTurn<'turn>> {
        self.check_physical_worker()?;
        Ok(PublisherCacheRetirementTurn {
            executor: self,
            permit,
        })
    }
}

impl PublisherCacheRetirementTurn<'_> {
    /// Borrows only the original cache body's native publication for Retire.
    ///
    /// # Errors
    /// Refuses another context, physical phase or permit.
    pub(crate) fn retiring_body(
        &self,
        context: &PublisherRunningContext,
    ) -> io::Result<Arc<PeerPublishedObject<HostDomainLocation>>> {
        self.permit
            .body(self.executor, context, None, Operation::Retire)
    }

    /// Borrows original pending custody for its exact restoration or final removal.
    ///
    /// # Errors
    /// Refuses another context, receipt, operation or physical phase.
    pub(crate) fn pending_body(
        &self,
        context: &PublisherRunningContext,
        pending: &Arc<PendingCacheBody>,
        operation: Operation,
    ) -> io::Result<Arc<PeerPublishedObject<HostDomainLocation>>> {
        self.permit
            .body(self.executor, context, Some(pending), operation)
    }
}
