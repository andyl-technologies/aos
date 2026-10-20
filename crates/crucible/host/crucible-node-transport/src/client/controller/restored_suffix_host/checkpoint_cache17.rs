//! Lends one immutable completed suffix pair without rebuilding policy schemas.
//!
//! Native/source proof validation remains with the actual Source completed
//! owner. This guard authenticates only its same SDK actor, immutable installed
//! emitter/codec, exact ClientCustody pair and saved completion frontier.

use super::*;

impl OriginalRestoredSuffixHostAttempt {
    /// Borrows this actual completed pair at its unchanged saved SDK cut.
    ///
    /// The loan neither decodes another artifact nor reserializes an original.
    /// Its historical mode still requires the same live Controller and immutable
    /// registration; inert archive data cannot construct this SDK owner.
    ///
    /// # Errors
    /// Refuses a foreign process/thread/Controller/emitter, revoked or replaced
    /// codec, partial attempt, missing/changed custody pair or saved frontier,
    /// future cut, or subsequent SDK traffic when `current` is true.
    pub fn authenticate_completed_checkpoint17_cache_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        expected_frontier: U64,
        current: bool,
    ) -> Result<(&Envelope, &Envelope, &ResponseBody), ProviderError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.controller, controller)
        {
            return Err(refused());
        }
        emitter.authenticate_original(controller)?;
        controller.authenticate_native5_source_codec()?;
        let (original, terminal, typed) = self.completed_pair_data()?;
        let saved = self.completed_frontier.ok_or_else(refused)?;
        let actual_frontier = controller.session.fresh_restore_query_sequence()?;
        if saved <= original.sequence
            || saved != expected_frontier
            || saved > actual_frontier
            || (current && saved != actual_frontier)
        {
            return Err(refused());
        }
        let actual = controller.original(&self.request_id).ok_or_else(refused)?;
        if &actual.request != original || actual.response.as_ref() != Some(terminal) {
            return Err(refused());
        }
        Ok((original, terminal, typed))
    }

    /// Names this borrowed completed-pair validator's actual fixed headers.
    pub const fn completed_checkpoint17_cache_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&CnpController>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
            + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
            + size_of::<Option<U64>>()
            + size_of::<[U64; 3]>()
            + size_of::<&ClientOriginal>()
            + size_of::<Option<&ClientOriginal>>()
            + size_of::<bool>()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl OriginalRestoredSuffixHostAttempt {
    /// Borrows its exact retained SDK pair without asserting currentness.
    ///
    /// A separately authenticated current Source bridge may borrow this frozen
    /// pair while retaining its own final cut. The full original suffix guard
    /// remains required, and the saved actual cut is checked against the SDK
    /// journal before returning any historical references.
    ///
    /// # Errors
    /// Refuses another process/thread/controller/emitter or immutable codec,
    /// incomplete private custody, changed actual request/terminal membership,
    /// an absent saved frontier or a frontier beyond the actual Session.
    pub fn authenticate_retained_pair_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(&Envelope, &Envelope, &ResponseBody), ProviderError> {
        controller.authenticate_original_installed_restored_suffix_data(emitter)?;
        let frontier = self.completed_frontier_data().ok_or_else(refused)?;
        self.authenticate_completed_checkpoint17_cache_data(controller, emitter, frontier, false)
    }
}
