//! Retains original journal and quarantine ownership without a content store.
//!
//! The live exchange borrows this journal and its actual content owner
//! independently. Construction creates empty maps and preserves the declared
//! unrecycled quotas; it supplies no Source admission or history migration.

use super::*;

impl CompactClientJournal {
    /// Constructs empty journals without allocating or replacing a content store.
    ///
    /// # Errors
    /// Refuses unsupported request, byte or compact-bank ceilings.
    pub(in crate::client) fn new(
        maximum_requests: usize,
        maximum_bytes: usize,
        maximum_envelope_bank_bytes: usize,
    ) -> Result<Self, ProviderError> {
        validate_journal_limits(maximum_requests, maximum_bytes, maximum_envelope_bank_bytes)?;
        Ok(Self {
            maximum_requests,
            maximum_bytes,
            retained_bytes: 0,
            maximum_envelope_bank_bytes,
            controller: BTreeMap::new(),
            provider: BTreeMap::new(),
            pending: None,
            unexpected: None,
        })
    }

    pub(super) fn observe_originals_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.maximum_requests)?;
        observer.observe(&self.maximum_bytes)?;
        observer.observe(&self.retained_bytes)?;
        observer.observe(&self.maximum_envelope_bank_bytes)?;
        observer.observe(&self.controller)?;
        observer.observe(&self.provider)
    }

    pub(super) fn observe_pending_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(PendingEnvelope {
            origin: _,
            envelope,
        }) = &self.pending
        {
            observer.observe(envelope)?;
        }
        if let Some(frame) = &self.unexpected {
            observe_unexpected_frame(frame, observer)?;
        }
        Ok(())
    }

    pub(super) fn namespace(&self, origin: RequestOrigin) -> &BTreeMap<Id, CompactClientOriginal> {
        match origin {
            RequestOrigin::Controller => &self.controller,
            RequestOrigin::Provider => &self.provider,
        }
    }

    pub(super) fn namespace_mut(
        &mut self,
        origin: RequestOrigin,
    ) -> &mut BTreeMap<Id, CompactClientOriginal> {
        match origin {
            RequestOrigin::Controller => &mut self.controller,
            RequestOrigin::Provider => &mut self.provider,
        }
    }

    pub(super) fn ensure_room(&self, additional: usize) -> Result<(), ProviderError> {
        self.retained_bytes
            .checked_add(additional)
            .filter(|&bytes| bytes <= self.maximum_bytes)
            .map(|_| ())
            .ok_or_else(credit)
    }

    pub(super) fn retain_bytes(&mut self, additional: usize) -> Result<(), ProviderError> {
        self.ensure_room(additional)?;
        self.retained_bytes += additional;
        Ok(())
    }

    pub(super) fn retain_request(
        &mut self,
        origin: RequestOrigin,
        request: &Envelope,
        response_room: usize,
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        let id = request.request_id.0.as_ref().ok_or_else(changed)?;
        let retry = self.namespace(origin).contains_key(id);
        let bytes = self.preflight_envelope_with_limit(request, retry, maximum_frame_bytes)?;
        let identity = identity::request_hash(request, origin, bytes)?;
        if let Some(original) = self.namespace(origin).get(id) {
            if original.identity != identity {
                return Err(changed());
            }
            if !original.has_response() {
                self.ensure_room(response_room)?;
            }
            return Ok(());
        }
        if self.namespace(origin).len() >= self.maximum_requests {
            return Err(credit());
        }
        self.ensure_room(bytes.checked_add(response_room).ok_or_else(credit)?)?;
        let bank = CompactJson::from_envelope(request, self.maximum_envelope_bank_bytes)?;
        self.retain_bytes(bytes)?;
        self.namespace_mut(origin).insert(
            id.clone(),
            CompactClientOriginal {
                request: bank,
                identity,
                response: None,
            },
        );
        Ok(())
    }

    pub(super) fn hold(
        &mut self,
        origin: RequestOrigin,
        envelope: Envelope,
    ) -> Result<(), ProviderError> {
        if self.pending.is_some() {
            return Err(changed());
        }
        self.pending = Some(PendingEnvelope { origin, envelope });
        Ok(())
    }

    pub(super) fn complete_response(&mut self, id: &Id) -> Result<Envelope, ProviderError> {
        let pending = self.pending.as_ref().ok_or_else(changed)?;
        let bytes = self.preflight_envelope(&pending.envelope, false)?;
        self.ensure_room(bytes)?;
        let bank = CompactJson::from_envelope(&pending.envelope, self.maximum_envelope_bank_bytes)?;
        let origin = pending.origin;
        // The exclusive borrow keeps this checked entry present throughout the
        // scalar charge and response installation.
        if !self.namespace(origin).contains_key(id) {
            return Err(changed());
        }
        self.retain_bytes(bytes)?;
        self.namespace_mut(origin)
            .get_mut(id)
            .ok_or_else(changed)?
            .response = Some(bank);
        self.pending
            .take()
            .map(|pending| pending.envelope)
            .ok_or_else(changed)
    }

    pub(super) fn preflight_envelope(
        &self,
        envelope: &Envelope,
        retry: bool,
    ) -> Result<usize, ProviderError> {
        self.preflight_envelope_with_limit(envelope, retry, self.maximum_bytes)
    }

    pub(super) fn preflight_envelope_with_limit(
        &self,
        envelope: &Envelope,
        retry: bool,
        maximum_canonical_bytes: usize,
    ) -> Result<usize, ProviderError> {
        // Only sequence is mutable on a same-identity retry. Its decimal U64
        // string can grow to twenty bytes after the original was journaled.
        // This slack bounds preflight work only: no new bank or byte credit is
        // granted, and changed retry bodies still fail the defining hash check.
        let sequence_slack = if retry { 20 } else { 0 };
        let bank = self
            .maximum_envelope_bank_bytes
            .checked_add(sequence_slack)
            .ok_or_else(credit)?;
        let canonical = self
            .maximum_bytes
            .min(maximum_canonical_bytes)
            .checked_add(sequence_slack)
            .ok_or_else(credit)?;
        CompactJson::envelope_extents(envelope, bank, canonical).map(|(_, bytes)| bytes)
    }
}
