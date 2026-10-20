//! Borrows immutable completed SDK custody without regenerating schemas.
//!
//! This loan authenticates only transport ownership and the saved completion
//! cut. The Source separately owns its verified, append-only model cache and
//! actual read fence. Inert historical data cannot manufacture a live SDK slot.

use super::*;

impl CompletedOriginalInstalledRestorationObservation<'_> {
    /// Borrows the immutable typed first-observation request in this same slot.
    pub fn request_data(&self) -> &PacketRestorationObservationRequest {
        self.request
    }

    /// Borrows the immutable ordinary Observe body in this same completed slot.
    pub fn body_data(&self) -> &ObserveRequest {
        self.body
    }
}

fn authenticate_frontier_data(
    original: U64,
    saved: U64,
    actual: U64,
    expected: U64,
    current: bool,
) -> Result<(), ProviderError> {
    if saved <= original || saved != expected || saved > actual || (current && saved != actual) {
        return Err(refused());
    }
    Ok(())
}

impl CnpController {
    /// Borrows the actual first SDK checkpoint under its current immutable actor.
    ///
    /// The private Complete slot retains its original typed request/body and
    /// exact original/terminal pair after every promised proof was drained.
    /// This borrower checks that same actual ClientCustody pair and saved cut;
    /// it performs no schema construction, DTO decode or canonical serialization.
    /// Historical ancestry remains DATA when `current` is false. Neither mode
    /// grants a native effect or establishes a Source model's verified state.
    ///
    /// # Errors
    /// Refuses a foreign emitter, fenced/revoked/replaced codec, incomplete first
    /// slot, missing or changed actual custody, a different saved frontier, a
    /// saved cut beyond this Session or later traffic in current mode.
    pub fn original_completed_restoration_checkpoint17_cache_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        expected_frontier: U64,
        current: bool,
    ) -> Result<CompletedOriginalInstalledRestorationObservation<'_>, ProviderError> {
        emitter.authenticate_original(self)?;
        self.authenticate_native5_source_codec()?;
        let completed = self.original_completed_installed_restoration_observation(emitter)?;
        authenticate_frontier_data(
            completed.original().sequence,
            completed.completed_frontier_data(),
            self.session.fresh_restore_query_sequence()?,
            expected_frontier,
            current,
        )?;
        let id = completed
            .original()
            .request_id
            .0
            .as_ref()
            .ok_or_else(refused)?;
        let actual = self.original(id).ok_or_else(refused)?;
        if &actual.request != completed.original()
            || actual.response.as_ref() != Some(completed.response())
        {
            return Err(refused());
        }
        Ok(completed)
    }

    /// Names the fixed headers used by the borrowed completed-cache validator.
    pub const fn original_completed_restoration_checkpoint17_cache_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<CompletedOriginalInstalledRestorationObservation<'static>>()
            + size_of::<
                Result<CompletedOriginalInstalledRestorationObservation<'static>, ProviderError>,
            >()
            + size_of::<&Self>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&AssignedOriginalInstalledRestorationObservation>()
            + size_of::<&Envelope>() * 2
            + size_of::<&ResponseBody>()
            + size_of::<&ClientOriginal>()
            + size_of::<Option<&ClientOriginal>>()
            + size_of::<&Id>()
            + size_of::<[U64; 4]>()
            + size_of::<bool>()
            + size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_sdk_cut_is_exact_and_never_inferred_from_terminal_sequence() {
        let valid = |original, saved, actual, expected, current| {
            authenticate_frontier_data(
                U64::new(original),
                U64::new(saved),
                U64::new(actual),
                U64::new(expected),
                current,
            )
        };
        // There may be many real Blob originals after the terminal. Only the
        // separately retained completed cut is authoritative in this DATA check.
        assert!(valid(7, 23, 23, 23, true).is_ok());
        assert!(valid(7, 23, 40, 23, false).is_ok());
        assert!(valid(7, 23, 40, 23, true).is_err());
        assert!(valid(7, 23, 23, 8, true).is_err());
        assert!(valid(7, 23, 22, 23, false).is_err());
        assert!(valid(7, 7, 7, 7, true).is_err());
        assert!(valid(7, 0, 23, 0, false).is_err());
    }
}

impl CnpController {
    /// Borrows hash-verified JSON proof bytes through the same immutable SDK.
    ///
    /// This performs a stack BLAKE3 comparison against the actual stored full
    /// reference. It does not construct HashRef strings, a model DTO or a Source
    /// permission. The genuine completed Source cache separately owns the exact
    /// model/measurement association and its current native read.
    ///
    /// # Errors
    /// Refuses a foreign emitter/actor, revoked or replaced immutable codec,
    /// non-JSON, empty or oversized proof, missing content, changed full stored
    /// reference, length or hash. No custody or deadline is changed.
    pub fn original_completed_checkpoint17_content_cache_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        reference: &ContentRef,
    ) -> Result<&[u8], ProviderError> {
        emitter.authenticate_original(self)?;
        self.authenticate_native5_source_codec()?;
        if reference.media_type != "application/json"
            || reference.length.get() == 0
            || reference.length.get() > 65_536
        {
            return Err(refused());
        }
        self.custody
            .content()
            .original_capture_allocation_body_data(reference)
    }

    /// Names the actual borrowed content/hash comparison's fixed headers.
    pub const fn original_completed_checkpoint17_content_cache_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&ContentRef>() * 2
            + size_of::<&[u8]>()
            + size_of::<Result<&[u8], ProviderError>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 4]>()
            + size_of::<[u8; 8]>()
            + size_of::<std::slice::Iter<'static, [u8; 2]>>()
            + size_of::<std::slice::Iter<'static, u8>>()
            + size_of::<
                std::iter::Zip<std::slice::Iter<'static, [u8; 2]>, std::slice::Iter<'static, u8>>,
            >()
            + size_of::<[u8; 3]>()
            + size_of::<Result<(), ProviderError>>()
    }
}
