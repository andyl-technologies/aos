//! Per-group paid presence scratch with a fresh arena reader for every key.
//!
//! Only storage is retained. Source authentication, path reopening, arena length
//! checks and complete page authentication remain in the existing caller order.

use super::*;
use crate::content_store::batch;

#[cfg(test)]
mod tests;

// Body storage and its loan close before the concrete control's credit.
pub(in crate::content_store::packed) struct PresenceScratch<'s, 'o> {
    snapshot: &'s IndexSnapshot,
    original: &'o DecodeBudget,
    page: Bytes,
    _control: DecodeScratch,
}

impl IndexSnapshot {
    /// Reuses one group's paid storage while freshly authenticating each key.
    ///
    /// # Errors
    /// Returns the existing path, integrity, original or quota refusal. A
    /// retained scratch owner for another snapshot or original is refused.
    pub(in crate::content_store::packed) fn find_for_group<'s, 'o>(
        &'s self,
        backend: &PackedBlobBackend,
        id: ContentId,
        original: &'o DecodeBudget,
        scratch: &mut Option<PresenceScratch<'s, 'o>>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Option<IndexEntry>, StoreError> {
        let mut operation = Operation {
            original: Some(original),
            boundary,
        };
        // Fresh path/open/length refusals retain their priority over the page
        // admission cut. The descriptor is never stored in group scratch.
        let reader = self.reader(backend, &mut operation)?;
        if let Some(retained) = scratch.as_ref()
            && (!std::ptr::eq(retained.snapshot, self)
                || !std::ptr::eq(retained.original, original))
        {
            return Err(StoreError::Incompatible);
        }
        if reader.arena.is_none() {
            return reader
                .find(Key::object(id), &mut operation)?
                .map(Value::entry)
                .transpose();
        }
        if scratch.is_some() {
            // Reuse removes allocation, not the prior live-owner admission cut.
            original
                .verify_live()
                .map_err(|error| batch::admission_under(original, error))?;
        } else {
            let control = original
                .reserve_scratch_array::<PresenceScratch<'_, '_>>(1)
                .map_err(|error| batch::admission_under(original, error))?;
            let page = operation.buffer(wire::PAGE_BYTES)?;
            *scratch = Some(PresenceScratch {
                snapshot: self,
                original,
                page,
                _control: control,
            });
        }
        let retained = scratch.as_mut().ok_or(StoreError::Incompatible)?;
        reader
            .find_into(Key::object(id), &mut retained.page, &mut operation)?
            .map(Value::entry)
            .transpose()
    }
}
