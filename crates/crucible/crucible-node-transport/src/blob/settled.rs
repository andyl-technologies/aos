//! Borrows actual quarantined Blob state without reviving a receiver or pin.
//!
//! ```text
//! ["source-private.blob-quarantine-history/17", session, incarnation,
//!  [reserved,object,chunk,transfers,tombstones,chunks,pins], complete_ledger]
//! ```
//!
//! The complete ledger component is the existing defining logical state view;
//! using that child does not invoke an old whole11 reader or construct a live
//! receiver. Current native17 supplies the actual supervisor/alias relation.

use super::*;
use crate::retained_metadata::MetadataObserver;
use serde::{Serialize, Serializer};

pub(crate) struct BlobQuarantineHistory<'a> {
    owner: &'a BlobQuarantine,
    state: super::owned11::BlobStateOwned11View<'a>,
}

impl BlobQuarantine {
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<BlobQuarantineHistory<'_>, ProviderError> {
        Ok(BlobQuarantineHistory {
            owner: self,
            state: super::owned11::borrow_state(&self.state)?,
        })
    }

    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            session,
            incarnation,
            limits: _,
            state,
        } = self;
        observer.observe(session)?;
        observer.observe(incarnation)?;
        super::owned11::borrow_state(state)?.observe_owned11_metadata(observer)
    }

    pub(crate) const fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<BlobQuarantineHistory<'static>>()
            + size_of::<super::owned11::BlobStateOwned11View<'static>>()
            + size_of::<Result<BlobQuarantineHistory<'static>, ProviderError>>()
            + size_of::<[usize; 7]>()
            + size_of::<(
                &str,
                &Id,
                &Id,
                [usize; 7],
                &super::owned11::BlobStateOwned11View<'static>,
            )>()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl Serialize for BlobQuarantineHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let BlobQuarantine {
            session,
            incarnation,
            limits,
            state: _,
        } = self.owner;
        let BlobLimits {
            reserved_bytes,
            content_bytes,
            chunk_bytes,
            transfers_per_origin,
            tombstones_per_origin,
            chunks_per_transfer,
            operation_pins,
        } = *limits;
        (
            "source-private.blob-quarantine-history/17",
            session,
            incarnation,
            [
                reserved_bytes,
                content_bytes,
                chunk_bytes,
                transfers_per_origin,
                tombstones_per_origin,
                chunks_per_transfer,
                operation_pins,
            ],
            &self.state,
        )
            .serialize(serializer)
    }
}
