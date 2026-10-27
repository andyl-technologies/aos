//! Counts complete ordinary suffix DTOs without assignment or eligibility gates.
//!
//! These borrowed bodies carry no Controller or native claim. Independent raw
//! request envelopes and decoded suffix replies are counted by their own owners.

use super::*;
use crate::reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerTypedOwnerData;
use crate::retained_metadata::MetadataObserver;
use crucible_node_format::{Bytes, Event, Extensions, HashRef, Id, U64};

impl OriginalRestoredSuffixBody<'_> {
    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Begin(value) => {
                PacketRestoredProducerTypedOwnerData::Begin(value).observe_capacity_data(observer)
            }
            Self::Input(value) => observer.observe(*value),
            Self::Poll(value) => {
                PacketRestoredProducerTypedOwnerData::Poll(value).observe_capacity_data(observer)
            }
            Self::Retire(value) => {
                PacketRestoredProducerTypedOwnerData::Retire(value).observe_capacity_data(observer)
            }
            Self::Observe(value) => {
                PacketRestoredProducerTypedOwnerData::Observe(value).observe_capacity_data(observer)
            }
            Self::BlobBegin(value) => {
                let BlobBeginRequest {
                    transfer_id,
                    content,
                    extensions,
                } = value;
                observer.observe(transfer_id)?;
                observer.observe(content)?;
                observer.observe(extensions)
            }
            Self::BlobChunk(value) => {
                let BlobChunkRequest {
                    transfer_id,
                    offset,
                    bytes,
                    extensions,
                } = value;
                observer.observe(transfer_id)?;
                observer.observe(offset)?;
                observer.observe(bytes)?;
                observer.observe(extensions)
            }
            Self::BlobFinish(value) => {
                let BlobFinishRequest {
                    transfer_id,
                    extensions,
                } = value;
                observer.observe(transfer_id)?;
                observer.observe(extensions)
            }
        }
    }

    pub(crate) fn capacity_counter_scratch_data() -> usize {
        PacketRestoredProducerTypedOwnerData::capacity_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<(
                &HashRef,
                &U64,
                &Id,
                &U64,
                &Id,
                &Vec<Event>,
                &HashRef,
                &Extensions,
            )>()
            + size_of::<&InputRequest>()
            + size_of::<&BlobBeginRequest>()
            + size_of::<&BlobChunkRequest>()
            + size_of::<&BlobFinishRequest>()
            + size_of::<(&Id, &ContentRef, &Extensions)>()
            + size_of::<(&Id, &U64, &Bytes, &Extensions)>()
            + size_of::<(&Id, &Extensions)>()
    }
}

#[cfg(test)]
#[path = "body_capacities/tests.rs"]
mod tests;
