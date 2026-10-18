//! Retains an admitted original Control decode for prospective native visitors.
//!
//! The actual existing Core Control quote and Provider decoder are reused.
//! This is immutable historical DATA, with no restored Program, socket or grant.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::{
    archive_native_input::{NativeInputData, NativeInputSelection},
    archive_owner::ArchivedContentData,
};
use crate::node_contract::NodeRuntime;
use crucible_node_provider::{
    ProviderError,
    reference_packet::control::{
        PacketDecodedCaptureFutureControlData,
        decode_packet_control_snapshot_for_capture_future_data,
    },
};
use std::cell::Cell;

/// Retains independently admitted original parser and byte-owner axes.
#[derive(Clone, Copy)]
pub(crate) struct OriginalInitial15FutureControlConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
    maximum_control: usize,
    source: *const PacketCompleteSemanticSource,
    identity: [u8; 32],
    control: *const ContentRef,
}

impl OriginalInitial15FutureControlConstructionData {
    /// Returns independent new retained, simultaneous transient and fixed axes.
    pub(crate) fn requested_storage_data(self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }
}

/// Retains parsed model DATA, original bytes and every installed failed partial.
pub(crate) struct OriginalInitial15FutureControlAttempt {
    source: *const PacketCompleteSemanticSource,
    process: u32,
    thread: ThreadId,
    reference: Option<ContentRef>,
    raw: Vec<u8>,
    decoded: Option<PacketDecodedCaptureFutureControlData>,
    verified: bool,
    failed: bool,
}

impl OriginalInitial15FutureControlAttempt {
    /// Names the existing actual quote/decode and direct owning controls.
    pub(crate) fn counter_scratch_data() -> usize {
        NativeInputData::semantic_validation_construction_counter_scratch_data()
            + PacketDecodedCaptureFutureControlData::retained_metadata_counter_scratch_data()
            + PacketDecodedCaptureFutureControlData::provenance_counter_scratch_data()
            + OriginalRestorationColdGroup::original_initial15_future_control_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<OriginalInitial15FutureControlConstructionData>()
            + size_of::<Result<OriginalInitial15FutureControlConstructionData, RuntimeError>>()
            + size_of::<Result<PacketDecodedCaptureFutureControlData, ProviderError>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<&OriginalInitial15FutureControlLoan<'static>>()
    }

    /// Counts actual retained backing instead of substituting the constructor row.
    ///
    /// # Errors
    /// Refuses foreign actor, defining census failure or checked ceiling excess.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut total = size_of::<Self>();
        sum(&mut total, self.raw.capacity(), maximum)?;
        if let Some(reference) = &self.reference {
            sum(
                &mut total,
                NodeRuntime::capture_reference_storage(reference)?,
                maximum,
            )?;
        }
        if let Some(decoded) = &self.decoded {
            let backing = decoded
                .retained_requested_storage_data(maximum)
                .map_err(|_| RuntimeError::ResourceLimit)?
                .checked_sub(PacketDecodedCaptureFutureControlData::header_requested_bytes_data())
                .ok_or(RuntimeError::ResourceLimit)?;
            sum(&mut total, backing, maximum)?;
        }
        Ok(total)
    }

    /// Lends the same actual decoded Control to an independently funded visitor.
    ///
    /// Callback allocation/formatting has its own row admitted before entry.
    /// No whole-owner observation or borrowing of live Source/native custody may
    /// occur inside this callback. It returns immutable prospective facts only.
    ///
    /// # Errors
    /// Refuses incomplete/failed or foreign actual Source/body custody, callback
    /// failure, or changed completed origin after the visitor.
    pub(crate) fn with_model_data<T>(
        &mut self,
        original: &OriginalInitial15FutureControlLoan<'_>,
        visitor: impl FnOnce(&PacketDecodedCaptureFutureControlData) -> Result<T, ProviderError>,
    ) -> Result<T, RuntimeError> {
        if !self.verified
            || self.failed
            || self.source != original.owner.source as *const _
            || self.reference.as_ref() != Some(original.control)
            || self.raw.as_slice() != original.control_bytes
            || self.process != std::process::id()
            || self.thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // A failed future projection cannot silently reuse an earlier success.
        self.failed = true;
        original.authenticate_source_data()?;
        let decoded = self
            .decoded
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        decoded
            .authenticate_body_data(original.control, original.control_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let result = visitor(decoded);
        original.authenticate_source_data()?;
        let result = result.map_err(|_| RuntimeError::ResourceLimit)?;
        self.failed = false;
        Ok(result)
    }
}

impl OriginalRestorationColdGroup {
    /// Quotes the existing defining Control parser before any decoded owner exists.
    ///
    /// The caller independently funds the original native-validation quote
    /// floor and fixed controls returned below. All preexisting Source, archive,
    /// old decoder and other phase owners remain separate enclosing census terms.
    ///
    /// # Errors
    /// Refuses actual original custody/selection, absent or malformed Control,
    /// defining parser geometry failure, overflow or unchanged policy excess.
    pub(crate) fn original_initial15_future_control_construction_data(
        &self,
        index: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        prior_retained_bytes: usize,
        maximum: usize,
    ) -> Result<OriginalInitial15FutureControlConstructionData, RuntimeError> {
        let original = self.original_initial15_future_control_data(index, source, ticket)?;
        let data = self.future_control_quote_inputs(&original, prior_retained_bytes, maximum)?;
        let (raw, demand, maximum_control) = data
            .control_construction_requested_data(original.control)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut retained = size_of::<OriginalInitial15FutureControlAttempt>();
        for term in [
            raw.len(),
            NodeRuntime::capture_reference_storage(original.control)?,
            demand,
        ] {
            sum(&mut retained, term, maximum)?;
        }
        let transient = demand
            .checked_add("blake3-256".len() + "cnp.blob.v1".len() + 64)
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = OriginalInitial15FutureControlAttempt::counter_scratch_data();
        if prior_retained_bytes
            .checked_add(retained)
            .and_then(|n| n.checked_add(transient))
            .and_then(|n| n.checked_add(scratch))
            .is_none_or(|n| n > maximum)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        self.origin()?;
        Ok(OriginalInitial15FutureControlConstructionData {
            retained,
            transient,
            scratch,
            maximum_control,
            source: original.owner.source,
            identity: *blake3::hash(raw).as_bytes(),
            control: original.control,
        })
    }

    /// Declares the same original parser quote floor before quoting it.
    pub(crate) fn original_initial15_future_control_prewalk_data() -> (usize, usize) {
        (
            NativeInputData::semantic_validation_quote_transient_data(),
            OriginalInitial15FutureControlAttempt::counter_scratch_data(),
        )
    }

    /// Retains an actual spent decoder slot before any parse or reference clone.
    ///
    /// The caller admits full independent R/T/S first, then marks its observation
    /// dirty and releases all actual original Ref guards before reobserving.
    ///
    /// # Errors
    /// Refuses reused output, changed actual origin/bytes/row, decode/census
    /// failure, exhausted policy or a model from another administrative cut.
    pub(crate) fn original_initial15_future_control_into(
        &self,
        index: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        row: &OriginalInitial15FutureControlConstructionData,
        output: &mut Option<OriginalInitial15FutureControlAttempt>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        *output = Some(OriginalInitial15FutureControlAttempt {
            source: source.as_ref(),
            process: std::process::id(),
            thread: std::thread::current().id(),
            reference: None,
            raw: Vec::new(),
            decoded: None,
            verified: false,
            failed: true,
        });
        let attempt = output.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        let original = self.original_initial15_future_control_data(index, source, ticket)?;
        if row.source != original.owner.source as *const _
            || row.control != original.control as *const _
            || blake3::hash(original.control_bytes).as_bytes() != &row.identity
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        attempt.reference = Some(original.control.clone());
        attempt
            .raw
            .try_reserve_exact(original.control_bytes.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        attempt.raw.extend_from_slice(original.control_bytes);
        attempt.decoded = Some(
            decode_packet_control_snapshot_for_capture_future_data(
                &attempt.raw,
                attempt
                    .reference
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                row.maximum_control,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        let decoded = attempt
            .decoded
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if decoded.control_data().administrative_cut() != original.owner.journal.cut {
            return Err(RuntimeError::InvalidReceipt);
        }
        attempt.retained_requested_storage_data(row.retained)?;
        original.authenticate_source_data()?;
        attempt.verified = true;
        attempt.failed = false;
        Ok(())
    }

    fn future_control_quote_inputs<'a>(
        &'a self,
        original: &'a OriginalInitial15FutureControlLoan<'a>,
        prior_retained_bytes: usize,
        maximum: usize,
    ) -> Result<NativeInputData<'a>, RuntimeError> {
        Ok(NativeInputData {
            selection: NativeInputSelection::Live(original.owner.source),
            host: original
                .owner
                .host
                .historical()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            native: original
                .owner
                .native_after
                .historical()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            content: ArchivedContentData::Verified(self.archive.content()),
            retained: prior_retained_bytes,
            maximum,
            scratch: Cell::new(0),
            construction: None,
        })
    }
}

fn sum(total: &mut usize, term: usize, maximum: usize) -> Result<(), RuntimeError> {
    *total = total
        .checked_add(term)
        .filter(|total| *total <= maximum)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_partial_control_retains_actual_raw_and_reference_backing() {
        let raw = b"retained failed Control bytes".to_vec();
        let reference =
            crucible_node_contract::canonical::content_ref(&raw, "application/json").unwrap();
        let attempt = OriginalInitial15FutureControlAttempt {
            source: std::ptr::null(),
            process: std::process::id(),
            thread: std::thread::current().id(),
            reference: Some(reference),
            raw,
            decoded: None,
            verified: false,
            failed: true,
        };

        let expected = size_of::<OriginalInitial15FutureControlAttempt>()
            + attempt.raw.capacity()
            + NodeRuntime::capture_reference_storage(attempt.reference.as_ref().unwrap()).unwrap();
        assert_eq!(
            attempt.retained_requested_storage_data(expected).unwrap(),
            expected
        );
        assert!(
            attempt
                .retained_requested_storage_data(expected - 1)
                .is_err()
        );
        assert!(attempt.failed);
        assert!(!attempt.verified);
        assert!(!attempt.raw.is_empty());
    }

    #[test]
    fn foreign_partial_cannot_supply_a_census() {
        let attempt = OriginalInitial15FutureControlAttempt {
            source: std::ptr::null(),
            process: 0,
            thread: std::thread::current().id(),
            reference: None,
            raw: Vec::new(),
            decoded: None,
            verified: false,
            failed: true,
        };

        assert!(attempt.retained_requested_storage_data(usize::MAX).is_err());
        assert!(attempt.failed);
    }
}
