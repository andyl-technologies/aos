//! Checks unchanged journal credit across a retained legacy prefix and suffix.
//!
//! The prefix lends only settled original maps. Content is borrowed separately
//! from its actual owner, so runtime transfers neither copy nor replace it.
//! These SDK mechanics supply no Source action or allocation admission.

use super::*;
use crate::client::ClientOriginal;

/// Borrows original journal history without a mutable prefix or content handle.
pub(super) struct CompactJournalPrefix<'a> {
    pub(super) maximum_requests: usize,
    pub(super) remaining_bytes: usize,
    pub(super) controller: &'a BTreeMap<Id, ClientOriginal>,
    pub(super) provider: &'a BTreeMap<Id, ClientOriginal>,
}

impl CompactJournalPrefix<'_> {
    pub(super) fn authenticate(&self, suffix: &CompactClientJournal) -> Result<(), ProviderError> {
        if suffix.maximum_requests != self.maximum_requests
            || suffix.maximum_bytes != self.remaining_bytes
        {
            return Err(changed());
        }
        for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
            let prefix = self.namespace(origin);
            let current = suffix.namespace(origin);
            if prefix
                .len()
                .checked_add(current.len())
                .is_none_or(|total| total > self.maximum_requests)
            {
                return Err(credit());
            }
            if prefix.values().any(|original| original.response.is_none())
                || current.keys().any(|id| prefix.contains_key(id))
            {
                return Err(changed());
            }
        }
        Ok(())
    }

    pub(super) fn ensure_new_original(
        &self,
        suffix: &CompactClientJournal,
        origin: RequestOrigin,
        request: &Envelope,
    ) -> Result<(), ProviderError> {
        let id = request.request_id.0.as_ref().ok_or_else(changed)?;
        let prefix = self.namespace(origin);
        let current = suffix.namespace(origin);
        if prefix.contains_key(id) {
            return Err(changed());
        }
        let additional = usize::from(!current.contains_key(id));
        if prefix
            .len()
            .checked_add(current.len())
            .and_then(|count| count.checked_add(additional))
            .is_none_or(|total| total > self.maximum_requests)
        {
            return Err(credit());
        }
        Ok(())
    }

    pub(super) fn cached_response(
        &self,
        origin: RequestOrigin,
        request: &Envelope,
        frame: usize,
    ) -> Result<Option<Envelope>, ProviderError> {
        let id = request.request_id.0.as_ref().ok_or_else(changed)?;
        let Some(original) = self.namespace(origin).get(id) else {
            return Ok(None);
        };

        // Replaying a prefix original consumes no new suffix bank or byte
        // credit. Bound identity work by the connection's canonical expansion,
        // even when the suffix has less than one frame of remaining credit.
        let maximum = crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(frame)?
            .maximum_canonical_encoded_bytes;
        let bank = CompactJson::maximum_storage_bytes(maximum, usize::MAX)?;
        let (_, bytes) = CompactJson::envelope_extents(request, bank, maximum)?;
        if identity::request_hash(request, origin, bytes)? != original.identity {
            return Err(changed());
        }
        original.response.clone().map(Some).ok_or_else(changed)
    }

    fn namespace(&self, origin: RequestOrigin) -> &BTreeMap<Id, ClientOriginal> {
        match origin {
            RequestOrigin::Controller => self.controller,
            RequestOrigin::Provider => self.provider,
        }
    }
}
