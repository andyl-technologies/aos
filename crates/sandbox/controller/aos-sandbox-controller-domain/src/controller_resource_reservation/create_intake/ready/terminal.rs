//! Seals only the actual completed same-original Create terminal.
//!
//! J was committed at capture entry. This final crossing checks the positive U,
//! both original releases, C10, Root6 and the native Cache/control close; it
//! never performs a second settlement or publishes from a pending prefix.

use super::*;

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Finishes the original joined scope after C10, Root6 and all final posts.
    ///
    /// The borrowed scope remains resident on error so its actual first cause
    /// can be diagnosed before the installed caller fences. Success alone lets
    /// the caller drop the original Cache clock/writer guards and then require
    /// the same intake's operation-specific terminal proof.
    ///
    /// # Errors
    /// Refuses incomplete or failed original stages, reentry, a native final
    /// Cache/currentness post, or the final retained association crossing.
    #[doc(hidden)]
    pub fn finish_original_create_terminal_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.original.owner.ready_after.is_some() {
            return self.original.finish_association_once().map_err(|_| CreateStorageReadyClosedV1);
        }
        if self.failure().is_some() { return Err(CreateStorageReadyClosedV1); }
        self.finish_original_storage_cache_after_root_once()?;
        self.original.finish_association_once().map_err(|_| CreateStorageReadyClosedV1)
    }
}
