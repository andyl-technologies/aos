//! Checked cache lookup and best-effort promotion under the same caller.
//!
//! Only clean lookup absence selects another child. Cache placement failure may
//! leave source availability unchanged, but refusal of the current callback
//! stops promotion and retains the concrete publisher's complete failure.

use super::*;
use crate::owned_decode::DecodeBudget;

pub(super) fn read_through(
    store: &ReadThroughStore,
    original: &DecodeBudget,
    id: ContentId,
    range: Option<ByteRange>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    let blob = match store.cache.read_with_boundary(original, id, None, boundary) {
        Ok(blob) => blob,
        Err(error) if error.confirmed_absence(id) => {
            let blob = store
                .source
                .read_with_boundary(original, id, None, boundary)?;
            promote(store.cache.as_ref(), original, id, &blob, boundary)?;
            blob
        }
        Err(error) => return Err(error),
    };
    super::super::checked_reader::slice_handle(blob, range, original, boundary)
}

pub(super) fn tiered(
    store: &TieredStore,
    original: &DecodeBudget,
    id: ContentId,
    range: Option<ByteRange>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    for (index, tier) in store.tiers.iter().enumerate() {
        if !tier.readable {
            continue;
        }
        let blob = match tier
            .backend
            .read_with_boundary(original, id, None, boundary)
        {
            Ok(blob) => blob,
            Err(error) if error.confirmed_absence(id) => continue,
            Err(error) => return Err(error),
        };
        for cache in store.tiers[..index]
            .iter()
            .filter(|tier| tier.promote_reads)
        {
            promote(cache.backend.as_ref(), original, id, &blob, boundary)?;
        }
        return super::super::checked_reader::slice_handle(blob, range, original, boundary);
    }
    Err(StoreError::NotFound { id })
}

fn promote(
    cache: &dyn ImmutableBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
    blob: &BlobHandle,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut refused = false;
    let mut check = || {
        if refused {
            return Err(StoreError::Unsupported {
                capability: "refused-cache-promotion-boundary",
            });
        }
        let result = boundary();
        refused = result.is_err();
        result
    };
    let objects = [(id, blob.clone())];
    let result = cache
        .put_many_if_absent_with_boundary(original, &objects, &mut check)
        .and_then(|receipt| {
            receipt.check(|receipts| {
                if receipts.len() != 1
                    || receipts[0].id != id
                    || receipts[0]
                        .placements
                        .iter()
                        .any(|placement| placement.logical_length != blob.logical_length())
                {
                    return Err(StoreError::Corrupt { id });
                }
                Ok(())
            })
        })
        .and_then(|receipt| receipt.accept_with_boundary(&mut check));
    match result {
        Ok(_) => Ok(()),
        Err(error) if refused || original.verify_live().is_err() => Err(error),
        // A publisher can observe an original-owner refusal after an effect
        // even when the callback returned success. Keep that concrete outcome;
        // a fresh admission error cannot replace its publication evidence.
        // Cache writes are optional. Every returned source still retains its
        // actual original owner and must authenticate its complete read.
        Err(_) => Ok(()),
    }
}
