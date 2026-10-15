//! Counts independent backing allocated by cloning the actual current lease.
//!
//! Existing Arc payloads are shared by derived Clone. Their new handle slots
//! live in the caller's already counted authority header; no payload or Arc
//! allocation occurs. Ordinary retained-owner and wire observers are unchanged.

use super::*;
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};

impl ConnectionAuthority {
    /// Counts actual backing independently copied by this lease's derived Clone.
    ///
    /// The enclosing authority/owner header and counter scratch are separate.
    /// This authenticates currentness, not permission to construct another owner.
    ///
    /// # Errors
    /// Refuses a revoked lease, bounded traversal failure or requested overflow.
    pub(crate) fn independent_clone_backing_storage_data(&self) -> Result<usize, ProviderError> {
        self.ensure_live()?;
        let Self {
            shared_epoch,
            registration_gate,
            epoch,
            connection,
            session,
            incarnation,
            limits,
            features,
            envelope_extensions,
            extensions,
        } = self;
        // All three derived Clone implementations retain their existing Arc
        // allocation. No backing is copied for these actual shared edges.
        let _shared_edges = (shared_epoch, registration_gate, extensions);
        let mut observer = MetadataObserver::new();
        observer.observe(epoch)?;
        observer.observe(connection)?;
        observer.observe(session)?;
        observer.observe(incarnation)?;
        observer.observe(limits)?;
        observer.observe(features)?;
        observer.observe(envelope_extensions)?;
        let facts = observer.finish();
        let bytes =
            crate::retained_metadata::requested_storage::requested_metadata_backing_storage_data(
                &facts,
            )?;
        self.ensure_live()?;
        Ok(bytes)
    }

    /// Names explicit borrowed walk/result headers, excluding compiler frames.
    pub(crate) const fn independent_clone_counter_scratch_data() -> usize {
        std::mem::size_of::<MetadataObserver<'static>>()
            + std::mem::size_of::<RetainedProtocolMetadataFacts>()
            + 3 * std::mem::size_of::<&ConnectionAuthority>()
            + 3 * std::mem::size_of::<usize>()
            + std::mem::size_of::<[usize; 6]>()
            + std::mem::size_of::<std::alloc::Layout>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::coordinator::original_canonical_ack_controller_scope;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_clone_has_independent_ids_and_rosters_with_same_shared_roots() -> TestResult {
        let (handshake, mut authority, _, _) = original_canonical_ack_controller_scope();
        authority.features.try_reserve_exact(37)?;
        let requested = authority.independent_clone_backing_storage_data()?;
        let cloned = authority.clone();
        assert!(cloned.independent_clone_backing_storage_data()? <= requested);
        assert!(requested > 0);
        assert!(Arc::ptr_eq(&authority.shared_epoch, &cloned.shared_epoch));
        assert!(Arc::ptr_eq(
            &authority.registration_gate,
            &cloned.registration_gate
        ));
        assert_ne!(
            authority.session.as_str().as_ptr(),
            cloned.session.as_str().as_ptr()
        );
        assert_ne!(authority.features.as_ptr(), cloned.features.as_ptr());
        assert_eq!(authority.features, cloned.features);

        drop(handshake);
        assert!(authority.independent_clone_backing_storage_data().is_err());
        assert!(cloned.independent_clone_backing_storage_data().is_err());
        Ok(())
    }
}
