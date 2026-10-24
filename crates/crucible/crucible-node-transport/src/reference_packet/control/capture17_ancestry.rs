//! Rejoins a Capture request's immutable first checkpoint to actual custody.
//!
//! The native first-owner loan supplies the original and terminal. This check
//! creates no current-model, Capture-ticket, row or output authority.

use super::*;

impl PacketControl {
    /// Matches the actual immutable first pair without allocating or decoding.
    ///
    /// # Errors
    /// Refuses foreign/fenced Control, absent original/terminal/content custody
    /// or a different first restored proof. Currency is checked independently.
    pub(crate) fn authenticate_capture17_first_checkpoint_data(
        &self,
        original: &Envelope,
        terminal: &Envelope,
        first_observation: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.authenticate_observation17_checkpoint_cache_data(original, terminal)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let (_, reply) = self.originals.get(id).ok_or_else(refused)?;
        let [_, restored] = reply.evidence.as_slice() else {
            return Err(refused());
        };
        if &restored.0 != first_observation {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("Capture17 immutable first checkpoint differs")
}
