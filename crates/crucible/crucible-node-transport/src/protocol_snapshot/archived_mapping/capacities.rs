//! Observes actual archived-mapping custody independently of live registration.
//!
//! Capacity DATA preserves revoked or failed owners. It neither reconstructs an
//! archived mapping nor authenticates its source, target, deadline or nonce.

use super::*;
use crate::retained_metadata::MetadataObserver;
use std::mem::size_of;

impl PreparedArchivedProtocolMapping {
    /// Checks original process/thread custody without testing registration.
    pub(crate) fn check_capacity_creator_data(&self) -> Result<(), ProviderError> {
        self.controller_owner.ensure_current()?;
        self.connection_owner.ensure_current()
    }

    /// Visits the defining mapping roster without locking or renewing its lease.
    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.check_capacity_creator_data()?;
        let Self {
            identity,
            class,
            archive_protocol,
            native_protocol,
            nonce,
            fresh,
            controller_owner,
            connection_owner,
            codec,
            cut,
        } = self;
        super::super::capacities::inline(class);
        super::super::capacities::inline(nonce);
        super::super::capacities::inline(cut);

        observer.shared_value(identity.as_ref())?;
        observer.observe(archive_protocol)?;
        observer.observe(native_protocol)?;
        fresh.observe_retained_metadata(observer)?;
        observer.shared_value(controller_owner.as_ref())?;
        observer.shared_value(connection_owner.as_ref())?;
        observer.shared_value(codec.as_ref())?;
        codec.observe_retained_metadata(observer)?;
        self.check_capacity_creator_data()
    }

    /// Names concrete borrowed mapping and authority traversal controls.
    pub(crate) fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Rc<ArchivedProtocolMappingIdentity>,
                &RestorationMappingClass,
                &ContentRef,
                &ContentRef,
                &[u8; 32],
                &ConnectionAuthority,
                &Rc<ProtocolCaptureOwner>,
                &Rc<ProtocolCaptureOwner>,
                &Rc<crate::connection::Native5CodecOwner>,
                &crate::operational_time::OperationalDeadline,
            )>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
            + ConnectionAuthority::retained_capacity_counter_scratch_data()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
