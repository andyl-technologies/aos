//! Moves distinct Native18 frames through their original Session and literal slots.
//!
//! The caller retains its Prepare occurrence before entry. The raw Envelope and
//! whole typed receive are stored in that owner before later receipt inspection.
//! This supplier never issues Commit or assumes a public Held18 prefix format.

use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18Phase;

impl ClientSession {
    /// Borrows the same actual Connection's fully selected host contract DATA.
    ///
    /// # Errors
    /// Refuses another endpoint/codec, changed full contract or expired authority.
    pub(in crate::client) fn native_import18_selection_data(
        &self,
    ) -> Result<&PacketControlSelection, ProviderError> {
        self.connection.native_import18_selection_data()
    }

    /// Reserves one original new-family literal without publishing it.
    ///
    /// # Errors
    /// Refuses changed scope/phase, a reused slot/ID or exhausted frame capacity.
    pub(in crate::client) fn reserve_native_import18_data(
        &mut self,
        original: &Envelope,
        phase: PacketNativeImport18Phase,
        maximum: usize,
        output: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        self.connection
            .reserve_native_import18_data(original, phase, maximum, output)
    }

    /// Publishes once and retains a strict raw frame without Envelope decoding.
    ///
    /// # Errors
    /// Refuses a changed cut, used output, selection/correlation or transport loss.
    pub(in crate::client) fn publish_native_import18_prepare_raw_into_data(
        &mut self,
        _custody: &mut ClientCustody,
        publication: OriginalAssignedPublicationData<'_>,
        raw: &mut Option<crate::transport::RetainedFrame>,
        profile: &mut crate::retained_metadata::NativeImport18JsonMetadataProfileData,
    ) -> Result<(), ProviderError> {
        let OriginalAssignedPublicationData {
            original,
            bytes,
            slot,
            cut,
        } = publication;

        self.authenticate_original_ack_admit_cut(original.sequence, cut)?;
        if raw.is_some() {
            return Err(invalid());
        }
        self.connection.publish_native_import18_data(
            original,
            PacketNativeImport18Phase::Prepare,
            bytes,
            slot,
        )?;
        self.sequence = self.sequence.checked_add(U64::new(1))?;
        self.connection
            .receive_native_import18_raw_into_data(original, raw, profile)
    }

    /// Checks the same pending original and exact raw literal without a new cut.
    ///
    /// # Errors
    /// Refuses expiration, different sequence, loss, selection or changed raw bytes.
    pub(in crate::client) fn authenticate_native_import18_raw_data(
        &self,
        original: &Envelope,
        cut: crate::operational_time::OperationalDeadline,
        raw: &crate::transport::RetainedFrame,
    ) -> Result<(), ProviderError> {
        if self.deadline.original_cut() != cut
            || cut.remaining().is_none()
            || self.original_response_loss.is_some()
            || self.sequence != original.sequence.checked_add(U64::new(1))?
        {
            return Err(invalid());
        }
        self.connection
            .authenticate_native_import18_raw_data(original, raw)
    }

    /// Decodes this exact retained raw input only after caller-admitted geometry.
    ///
    /// # Errors
    /// Retains raw/Envelope/typed partials on syntax, correlation or receipt refusal.
    pub(in crate::client) fn decode_native_import18_prepare_into_data(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        cut: crate::operational_time::OperationalDeadline,
        raw: &crate::transport::RetainedFrame,
        response: &mut Option<Envelope>,
        received: &mut Option<crate::connection::ReceivedFrame>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native_import18_raw_data(original, cut, raw)?;
        self.connection
            .decode_native_import18_raw_into_data(original, raw, response, received)?;
        let terminal = response.as_ref().ok_or_else(invalid)?;
        let frame = received.as_ref().ok_or_else(invalid)?;
        let ReceivedBody::Response(_) = &frame.body else {
            return Err(invalid());
        };
        if terminal.extensions.len() != 1
            || !terminal
                .extensions
                .contains_key(PacketNativeImport18Phase::Prepare.receipt_extension())
        {
            return Err(invalid());
        }
        custody.retain_journal_bytes(envelope_bytes(terminal)?)?;
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        custody.controller.get_mut(id).ok_or_else(invalid)?.response = Some(terminal.clone());
        Ok(())
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("distinct Native18 Session Prepare changed")
}

impl ClientSession {
    /// Checks this actual reserved original without advancing its frontier.
    ///
    /// # Errors
    /// Refuses an absent/changed slot, foreign pending original or attempted send.
    pub(in crate::client) fn authenticate_pending_native_import18_data(
        &self,
        original: &Envelope,
        bytes: &[u8],
        slot: Option<usize>,
        sealed: bool,
    ) -> Result<(), ProviderError> {
        self.connection
            .authenticate_pending_native_import18_data(original, bytes, slot, sealed)
    }
}

#[path = "native_import18_upload.rs"]
mod input_upload;

impl ClientCustody {
    /// Observes actual custody rows with only the same capsule's paid profiles.
    ///
    /// # Errors
    /// Refuses foreign literals, bounded traversal or checked backing overflow.
    pub(in crate::client) fn observe_native_import18_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
        capsule: &crate::client::OriginalNativeImport18Assignment,
    ) -> Result<(), ProviderError> {
        let Self {
            maximum_requests,
            maximum_bytes,
            retained_bytes,
            controller,
            provider,
            content,
        } = self;
        observer.observe(maximum_requests)?;
        observer.observe(maximum_bytes)?;
        observer.observe(retained_bytes)?;
        observer.tree::<Id, super::ClientOriginal>(controller.len())?;
        for (id, original) in controller {
            if let Some(profile) = capsule.metadata_profile_for_envelope_data(&original.request)? {
                observer.with_native_import18_json_profile_data(profile, |observer| {
                    observer.observe(id)?;
                    observer.observe(original)
                })?;
            } else {
                observer.observe(id)?;
                observer.observe(original)?;
            }
        }
        // Provider rows and all unrelated original families remain ordinary.
        observer.observe(provider)?;
        content.observe_owned_metadata(observer)
    }
}

#[path = "native_import18_access.rs"]
mod custody_access;
