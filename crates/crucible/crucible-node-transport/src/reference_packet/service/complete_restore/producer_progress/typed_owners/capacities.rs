//! Lends Producer typed owners to physical capacity rows without serialization.
//!
//! The existing defining walk owns every dynamic field. Copy witnesses keep its
//! intentionally omitted fixed fields inline if these public schemas evolve.

use super::*;
use crate::bodies::{BoundaryPolicy, RetirementDisposition};
use crate::envelope::Nullable;
use crucible_node_format::{HashRef, IdSet, OperatingMode, U64};
use std::mem::size_of;

impl PacketRestoredProducerTypedOwnerData<'_> {
    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Arguments(value) => {
                let ExactRunArguments {
                    grant_id: _,
                    participant_ids: _,
                    realization_id: _,
                    activation_id: _,
                    world_generation,
                    owner_generation,
                    input_epoch: _,
                    mode,
                    ordering_profile: _,
                    start,
                    limit,
                    boundary_policy,
                    input_authorization: _,
                    input_watermark,
                } = value;
                inline(world_generation);
                inline(owner_generation);
                inline(mode);
                inline(start);
                inline(limit);
                inline(boundary_policy);
                inline(input_watermark);
            }
            Self::Begin(_) => {}
            Self::Poll(value) => {
                let PollRequest {
                    after_observation_sequence,
                    extensions: _,
                } = value;
                inline(after_observation_sequence);
            }
            Self::Retire(value) => {
                let RetireRequest {
                    request_ids: _,
                    operation_ids: _,
                    disposition,
                    custody_receipt: _,
                    extensions: _,
                } = value;
                inline(disposition);
            }
            Self::Observe(value) => {
                let ObserveRequest {
                    binding_hash: _,
                    owner_generation,
                    after_observation_sequence,
                    maximum_items,
                    extensions: _,
                } = value;
                inline(owner_generation);
                inline(after_observation_sequence);
                inline(maximum_items);
            }
        }
        self.observe_historical_metadata_data(observer)
    }

    pub(crate) fn capacity_counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<(&Id, &IdSet, &Id, &Id, &Id, &String, &ContentRef)>()
            + size_of::<(
                &U64,
                &U64,
                &OperatingMode,
                &Position,
                &Position,
                &BoundaryPolicy,
                &U64,
            )>()
            + size_of::<(
                &BeginKind,
                &HashRef,
                &U64,
                &Nullable<Id>,
                &U64,
                &serde_json::Map<String, serde_json::Value>,
                &crucible_node_format::Extensions,
            )>()
            + size_of::<&BeginRequest>()
            + size_of::<&PollRequest>()
            + size_of::<&RetireRequest>()
            + size_of::<&ObserveRequest>()
            + size_of::<&ExactRunArguments>()
            + size_of::<&crucible_node_format::Extensions>()
            + size_of::<&U64>()
            + size_of::<(
                &IdSet,
                &IdSet,
                &Nullable<ContentRef>,
                &crucible_node_format::Extensions,
            )>()
            + size_of::<&RetirementDisposition>()
            + size_of::<(&HashRef, &crucible_node_format::Extensions)>()
            + size_of::<(&U64, &U64, &U64)>()
    }
}

const fn inline<T: Copy>(_value: &T) {}

#[cfg(test)]
mod tests;
