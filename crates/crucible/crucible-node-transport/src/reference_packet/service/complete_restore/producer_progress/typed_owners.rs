//! Counts separately retained typed arguments and lifecycle request partials.

use super::*;
use crate::bodies::{BeginRequest, ObserveRequest, PollRequest, RetireRequest};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};

mod capacities;

/// Borrows one real typed owner, including an incomplete or rejected partial.
///
/// The Source retains each owner before any fallible validation or assignment.
/// Walking it never copies a wire body or creates an execution permission.
#[derive(serde::Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum PacketRestoredProducerTypedOwnerData<'a> {
    /// Borrows separately retained exact arguments and their actual capacities.
    Arguments(&'a ExactRunArguments),
    /// Borrows the complete typed Begin, including its independent arguments DOM.
    Begin(&'a BeginRequest),
    /// Borrows a typed Poll retained before SDK assignment.
    Poll(&'a PollRequest),
    /// Borrows a typed Retire and its actual request/operation vectors.
    Retire(&'a RetireRequest),
    /// Borrows a typed Observe with its full owner binding.
    Observe(&'a ObserveRequest),
}

impl PacketRestoredProducerTypedOwnerData<'_> {
    /// Counts actual retained capacities independently of encoded byte extent.
    ///
    /// # Errors
    /// Refuses an overflowing count or an unsupported nested metadata shape.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }
}

/// Names borrowed owner, observer and result layouts before a fallible census.
pub fn original_restored_producer_typed_owner_counter_scratch_data() -> usize {
    use std::mem::size_of;
    crate::retained_metadata::historical_serialization_counter_scratch_data()
        + size_of::<PacketRestoredProducerTypedOwnerData<'static>>()
        + size_of::<&PacketRestoredProducerTypedOwnerData<'static>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&mut crate::retained_metadata::records::MetadataRecordBank>()
        + size_of::<&mut crate::retained_metadata::aliases::MetadataAliasBank>()
}

impl PacketRestoredProducerTypedOwnerData<'_> {
    fn observe_historical_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Arguments(value) => {
                let ExactRunArguments {
                    grant_id,
                    participant_ids,
                    realization_id,
                    activation_id,
                    world_generation: _,
                    owner_generation: _,
                    input_epoch,
                    mode: _,
                    ordering_profile,
                    start: _,
                    limit: _,
                    boundary_policy: _,
                    input_authorization,
                    input_watermark: _,
                } = value;
                observer.observe(grant_id)?;
                observer.observe(participant_ids)?;
                observer.observe(realization_id)?;
                observer.observe(activation_id)?;
                observer.observe(input_epoch)?;
                observer.observe(ordering_profile)?;
                observer.observe(input_authorization)?;
            }
            Self::Begin(value) => observer.observe(*value)?,
            Self::Poll(value) => {
                let PollRequest {
                    after_observation_sequence: _,
                    extensions,
                } = value;
                observer.observe(extensions)?;
            }
            Self::Retire(value) => {
                let RetireRequest {
                    request_ids,
                    operation_ids,
                    disposition: _,
                    custody_receipt,
                    extensions,
                } = value;
                observer.observe(request_ids)?;
                observer.observe(operation_ids)?;
                observer.observe(custody_receipt)?;
                observer.observe(extensions)?;
            }
            Self::Observe(value) => {
                let ObserveRequest {
                    binding_hash,
                    owner_generation: _,
                    after_observation_sequence: _,
                    maximum_items: _,
                    extensions,
                } = value;
                observer.observe(binding_hash)?;
                observer.observe(extensions)?;
            }
        }
        Ok(())
    }

    /// Records exact child capacities into this owner's independent finite banks.
    ///
    /// Clears only the supplied banks before walking. No reservation or growth
    /// occurs; callers separately retain and price every bank through failure.
    ///
    /// # Errors
    /// Refuses unsupported children, traversal/overflow or finite bank exhaustion.
    /// Recorded rows are inert allocation data and create no live owner.
    pub fn record_historical_metadata_data(
        &self,
        records: &mut crate::retained_metadata::records::MetadataRecordBank,
        aliases: &mut crate::retained_metadata::aliases::MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }
}

impl PacketRestoredProducerTypedOwnerData<'_> {
    /// Bounds actual Bytes base64 encoding work separately from output storage.
    ///
    /// Each encoding temporary is dropped after its serialize_str call. This
    /// bound covers the largest one using the exhaustive actual capacity walk;
    /// callers independently admit serializer output, DOM and canonical banks.
    ///
    /// # Errors
    /// Refuses the metadata walk's finite bound or base64 extent overflow.
    pub fn historical_serialization_transient_bytes_data(&self) -> Result<usize, ProviderError> {
        crate::retained_metadata::historical_serialization_transient_data(
            self.retained_metadata_data()?,
        )
    }
}
