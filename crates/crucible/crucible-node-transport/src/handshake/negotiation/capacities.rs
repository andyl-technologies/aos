//! Names borrowed controls for the actual original authority capacity roster.
//!
//! The defining observer visits retained gate/epoch/extension allocations without
//! locking registration, sampling currentness or replacing revoked custody.

use super::*;
use std::mem::size_of;

impl ConnectionAuthority {
    pub(crate) fn retained_capacity_counter_scratch_data() -> usize {
        // This exhaustive view tracks the real observer's defining field loans.
        fn fields<T>(_: impl FnOnce(&'static ConnectionAuthority) -> T) -> usize {
            size_of::<T>()
        }
        fields(|authority| {
            let ConnectionAuthority {
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
            } = authority;
            (
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
            )
        }) + size_of::<&Self>()
            + size_of::<&Arc<[ExtensionSelection]>>()
            + size_of::<std::slice::Iter<'_, ExtensionSelection>>()
            + size_of::<&ExtensionSelection>()
            + size_of::<&mut crate::retained_metadata::MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
    }
}
