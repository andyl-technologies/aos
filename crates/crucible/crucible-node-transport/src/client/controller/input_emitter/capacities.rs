//! Observes the original emitter's retained allocations independently of liveness.
//!
//! Repeated controller, connection, registrar and codec views keep independent
//! shared rows. The existing emitter authentication remains the dispatch gate.

use super::*;
use crate::retained_metadata::MetadataObserver;
use std::mem::size_of;

impl OriginalCanonicalRestoreInputEmitter {
    /// Checks the original controller and connection creator process/thread.
    ///
    /// # Errors
    /// Refuses custody created by another process or thread.
    pub(crate) fn check_capacity_creator_data(&self) -> Result<(), ProviderError> {
        self.controller.ensure_current()?;
        self.connection.ensure_current()
    }

    /// Records the original emitter roster without locking or renewing custody.
    ///
    /// # Errors
    /// Refuses foreign creators, exhausted rows or checked traversal/layout bounds.
    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.check_capacity_creator_data()?;
        let Self {
            controller,
            connection,
            registration,
            codec,
        } = self;
        observer.shared_value(controller.as_ref())?;
        observer.shared_value(connection.as_ref())?;
        registration.observe_retained_metadata_data(observer)?;
        observer.shared_value(codec.as_ref())?;
        codec.observe_retained_metadata(observer)?;
        self.check_capacity_creator_data()
    }

    /// Names compiled borrowed controls for this emitter component's census.
    ///
    /// Dynamic banks and whole-Source traversal work are charged separately.
    pub(crate) fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Rc<ProtocolCaptureOwner>,
                &Rc<ProtocolCaptureOwner>,
                &RegistrationRead,
                &Rc<Native5CodecOwner>,
            )>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
            + RegistrationRead::settled_history_counter_scratch_data()
    }
}
