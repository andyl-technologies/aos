//! Retains an original controller behind a read-only legacy journal boundary.
//!
//! Runtime calls reuse its actual session, actor, route, budget and content.
//! Only new compact originals can grow. This SDK ownership boundary does not
//! perform the independently funded Source18 action or select a native profile.

use super::*;
use crate::client::session::CompactClientJournal;
use crate::envelope::RequestOrigin;

mod identity;
mod storage;

/// Owns compact runtime exchanges alongside the complete original controller.
///
/// The legacy controller has no mutable accessor, extractor or deref conversion.
/// Its original maps remain read-only; its same session and content store serve
/// runtime traffic. Existing quotas and consumption are preserved across both
/// journal representations. Construction allocates no replacement content store.
///
/// Callers separately fund this header, the legacy owner, future compact and
/// content growth, connection/codec work and failure custody. Before moving the
/// controller, the actual Source must also authenticate its completed Initial
/// action and the absence or retirement of address-bound future claims. This
/// SDK type establishes none of those Source or native permissions.
pub struct CompactRuntimeController {
    original: CnpController,
    journal: CompactClientJournal,
}

impl CompactRuntimeController {
    /// Retains the whole original controller with empty compact suffix journals.
    ///
    /// Every fallible check precedes the move. Refusal preserves both slots;
    /// success installs the same complete owner without a later allocation,
    /// callback or fallible step. The new journal receives exactly the original
    /// unconsumed byte allowance and unchanged request ceiling. Each namespace
    /// continues to count its legacy originals toward that lifetime ceiling.
    ///
    /// This operation consumes SDK ownership only. Source admission, outstanding
    /// claims and the complete future R/T/S row remain caller responsibilities.
    ///
    /// # Errors
    /// Refuses missing input, occupied output, revoked or fenced ownership,
    /// unresolved transport or journal originals, response-loss callbacks,
    /// retained future operation assignments, or unsupported remaining credit.
    pub fn retain_into(
        original: &mut Option<CnpController>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(changed());
        }
        let runtime = Self::retain_original(original)?;
        *output = Some(runtime);
        Ok(())
    }

    // Both public ownership surfaces use this same pre-move validation. A
    // successful result is a concrete owner, ready for an infallible slot move.
    pub(super) fn retain_original(
        original: &mut Option<CnpController>,
    ) -> Result<Self, ProviderError> {
        let controller = original.as_ref().ok_or_else(changed)?;
        let journal = controller.prepare_compact_runtime_handoff_data()?;

        let controller = original.take().ok_or_else(changed)?;
        Ok(Self {
            original: controller,
            journal,
        })
    }

    /// Borrows the same original transport authority without granting effects.
    pub fn authority(&self) -> &crate::handshake::ConnectionAuthority {
        self.original.authority()
    }

    /// Borrows the original routing labels without authenticating their meaning.
    pub fn route(&self) -> &ControllerRoute {
        self.original.route()
    }

    /// Borrows a complete original from the read-only legacy namespace.
    pub fn legacy_originals(&self, origin: RequestOrigin) -> impl Iterator<Item = &ClientOriginal> {
        self.original.custody.originals_by_origin(origin)
    }

    /// Borrows complete new compact originals from their explicit namespace.
    pub fn compact_originals(
        &self,
        origin: RequestOrigin,
    ) -> impl Iterator<Item = &super::super::CompactClientOriginal> {
        self.journal.runtime_originals(origin)
    }

    /// Reports `[original ceiling, legacy debit, compact debit]` without renewal.
    pub fn journal_byte_reservations_data(&self) -> [usize; 3] {
        let [maximum, retained] = self.original.custody.runtime_journal_bytes_data();
        [maximum, retained, self.journal.runtime_retained_bytes()]
    }

    /// Borrows hash-verified original content without native receipt authority.
    ///
    /// # Errors
    /// Refuses missing bytes or metadata inconsistent with the retained object.
    pub fn content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        self.original.content(reference)
    }

    /// Borrows a received envelope retained after a failed compact operation.
    pub fn pending_envelope(&self) -> Option<(RequestOrigin, &Envelope)> {
        self.journal.runtime_pending_envelope()
    }

    /// Borrows unsupported complete traffic retained when this stream was fenced.
    pub fn unexpected_frame(&self) -> Option<&crate::connection::ReceivedFrame> {
        self.journal.runtime_unexpected_frame()
    }

    /// Exchanges one complete caller-owned envelope through the original stream.
    ///
    /// Only its sequence can change. Cached legacy replies preserve the caller's
    /// sequence and the original deadline. Every failure fences the stream and
    /// preserves surviving legacy, compact and received originals. The caller
    /// separately authenticates routing, Source action and future allocations.
    ///
    /// # Errors
    /// Refuses changed originals, exhausted combined lifetime credit, revoked
    /// ownership, invalid traffic, pending quarantine or uncertain transport.
    pub fn exchange(&mut self, request: &mut Envelope) -> Result<Envelope, ProviderError> {
        let result = self.ensure_live().and_then(|()| {
            self.original.session.exchange_compact_runtime(
                &mut self.original.custody,
                &mut self.journal,
                request,
                self.original.budget,
            )
        });
        if result.is_err() {
            self.fence();
        }
        result
    }

    /// Receives promised evidence into the same original content store.
    ///
    /// Blob ACK replay and new provider originals use their combined namespace
    /// and unchanged byte allowance. Hash verification supplies no Source or
    /// native receipt authority. Failure retains the received original and
    /// fences the stream; the operational deadline is tightened, never renewed.
    ///
    /// # Errors
    /// Refuses excessive roots, invalid or unavailable content, exhausted credit,
    /// unsupported traffic, unresolved correlation or the original deadline.
    pub fn receive_content(&mut self, roots: &[ContentRef]) -> Result<(), ProviderError> {
        let result = self.ensure_live().and_then(|()| {
            self.original.session.receive_compact_runtime_content(
                &mut self.original.custody,
                &mut self.journal,
                roots,
                self.original.budget,
            )
        });
        if result.is_err() {
            self.fence();
        }
        result
    }

    /// Sends a scoped baseline call and retains its promised content.
    ///
    /// The defining borrowed sizing pass precedes JSON construction. Requests,
    /// typed responses, reference traversal and content work require the caller's
    /// independently admitted windows; decoding confers no semantic authority.
    ///
    /// # Errors
    /// Refuses invalid or oversized bodies, exhausted credit, changed originals,
    /// unnegotiated scope, failed decoding, missing content or uncertain traffic.
    pub fn call(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        method: Method,
        owner_scoped: bool,
        body: impl Serialize,
    ) -> Result<ResponseBody, ProviderError> {
        self.call_scoped(
            request_id,
            CallScope {
                operation_id,
                method,
                owner_scoped,
                capture_owner: None,
            },
            body,
            Extensions::new(),
        )
    }

    pub(super) fn call_scoped(
        &mut self,
        request_id: Id,
        scope: CallScope,
        body: impl Serialize,
        extensions: Extensions,
    ) -> Result<ResponseBody, ProviderError> {
        self.call_with_extensions(
            request_id,
            scope,
            body,
            request::RequestExtensions::Owned(extensions),
        )
    }

    pub(super) fn call_packet(
        &mut self,
        request_id: Id,
        scope: CallScope,
        body: PacketRuntimeRequest<'_>,
        extensions: &Extensions,
    ) -> Result<ResponseBody, ProviderError> {
        self.call_with_extensions(
            request_id,
            scope,
            body,
            request::RequestExtensions::Borrowed(extensions),
        )
    }

    fn call_with_extensions(
        &mut self,
        request_id: Id,
        scope: CallScope,
        body: impl Serialize,
        extensions: request::RequestExtensions<'_>,
    ) -> Result<ResponseBody, ProviderError> {
        let result = self.call_inner(request_id, scope, body, extensions);
        if result.is_err() {
            self.fence();
        }
        result
    }

    fn call_inner(
        &mut self,
        request_id: Id,
        scope: CallScope,
        body: impl Serialize,
        extensions: request::RequestExtensions<'_>,
    ) -> Result<ResponseBody, ProviderError> {
        self.ensure_live()?;
        let (original, mut request) = self
            .original
            .prepare_scoped_request_with_extensions(request_id, scope, body, extensions)?;
        let reply = self.exchange(&mut request)?;
        let response = decode_response(&original, &reply.body)?;
        if matches!(response.shape, ResponseShape::Completed { .. }) {
            let mut roots = Vec::new();
            references(&Value::Object(reply.body), &mut roots)?;
            self.receive_content(&roots)?;
        }
        Ok(response)
    }

    /// Observes the whole original owner, compact suffix and actual supervisor.
    ///
    /// The allocation-free census counts original content, both journal
    /// representations, literal and correlation state, codec backing and
    /// pending failure owners. Shared views are charged independently. Enclosing
    /// inline headers, future growth and physical stack remain separate terms.
    /// The caller admits [`Self::retained_metadata_counter_scratch_data`] before
    /// this walk. Fencing and registration revocation retain the same owning
    /// allocations; observing them does not renew live registration or effects.
    /// Reading facts supplies no Source admission.
    ///
    /// # Errors
    /// Refuses a foreign creator, changed registration or codec/supervisor backing,
    /// conflicting loans, metadata exhaustion or checked observation overflow.
    pub fn retained_metadata_facts_with_retained_supervisor(
        &self,
        owner: &crate::connection::OriginalRetainedSupervisor,
        witness: Option<&crate::connection::OriginalProtocolSupervisor>,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_retained_runtime_metadata_data(owner, witness, &mut observer)?;
        Ok(observer.finish())
    }

    /// Walks the original owners under the caller's private observer profile.
    pub(super) fn observe_retained_runtime_metadata_data(
        &self,
        owner: &crate::connection::OriginalRetainedSupervisor,
        witness: Option<&crate::connection::OriginalProtocolSupervisor>,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_retained_runtime_metadata_owners_data(owner, witness)?;
        self.original
            .observe_compact_runtime_legacy_metadata(observer)?;
        self.journal.observe_runtime_metadata(observer)?;
        self.original
            .session
            .observe_original_restoration_metadata_extras(observer)?;
        owner.observe_retained_metadata(observer)?;
        if let Some(witness) = witness {
            witness.observe_original_header(observer)?;
            witness.observe_original_actor(observer)?;
        }
        self.original
            .session
            .authenticate_original_retained_supervisor_data(owner)?;
        self.original.protocol_owner.ensure_current()?;
        Ok(())
    }

    /// Checks the original owners before a recording observer clears its bank.
    pub(super) fn authenticate_retained_runtime_metadata_owners_data(
        &self,
        owner: &crate::connection::OriginalRetainedSupervisor,
        witness: Option<&crate::connection::OriginalProtocolSupervisor>,
    ) -> Result<(), ProviderError> {
        self.original.protocol_owner.ensure_current()?;
        self.original
            .session
            .authenticate_original_retained_supervisor_data(owner)?;
        if let Some(witness) = witness {
            self.original
                .session
                .authenticate_original_protocol_supervisor_data(witness)?;
        }
        Ok(())
    }

    /// Names the original observer and new borrowed journal/result controls.
    ///
    /// These declared layouts precede the metadata walk. They provide no
    /// physical stack bound, allocation admission or future growth allowance.
    pub fn retained_metadata_counter_scratch_data() -> usize {
        use std::mem::size_of;

        CnpController::original_restoration_host_metadata_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CnpController>()
            + size_of::<&CompactClientJournal>()
            + size_of::<&crate::connection::OriginalRetainedSupervisor>()
            + size_of::<Option<&crate::connection::OriginalProtocolSupervisor>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<
                Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError>,
            >()
    }

    fn ensure_live(&self) -> Result<(), ProviderError> {
        self.original.protocol_owner.ensure_current()?;
        if self.original.fenced {
            return Err(changed());
        }
        self.original.authority().ensure_live()
    }

    /// Fences the same original stream while retaining all journal and content owners.
    pub fn fence(&mut self) {
        self.original.fence();
    }
}

impl CnpController {
    /// Checks the original handoff boundary without effects or ownership moves.
    ///
    /// The later move uses this same predicate. Empty suffix construction owns
    /// only inline headers; it changes no debit, ID namespace or content owner.
    /// Funding can therefore inspect the complete boundary before admitting
    /// incident allocation or consuming a Source action.
    ///
    /// # Errors
    /// Refuses foreign, fenced, revoked or unresolved ownership, outstanding
    /// future assignments, response-loss callbacks or unsupported journal credit.
    pub(super) fn prepare_compact_runtime_handoff_data(
        &self,
    ) -> Result<CompactClientJournal, ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced
            || self.original_complete_restore.is_some()
            || self.original_complete_restore_prepare.is_some()
            || self.original_complete_restore_commit.is_some()
            || self.installed_complete_restore.is_some()
            || self
                .original_installed_restoration_activation
                .iter()
                .any(Option::is_some)
            || self
                .original_installed_restoration_upload
                .iter()
                .any(Option::is_some)
            || self.original_installed_restoration_observation.is_some()
            || self.original_restored_settled_capture.is_some()
        {
            return Err(changed());
        }
        if let Some(assigned) = &self.original_ack_admit {
            assigned.validate_owned_snapshot()?;
        }
        self.session.prepare_compact_runtime_journal(&self.custody)
    }
}

fn changed() -> ProviderError {
    ProviderError::Conflict("compact runtime original ownership changed")
}

#[cfg(all(test, unix))]
mod tests;
