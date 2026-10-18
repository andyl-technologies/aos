//! Prices the actual closed Node17 decoder before its first retained allocation.
//!
//! The selected JSON scanner charges every array slot at the largest defining
//! closed DTO layout. This conservative bound handles even failed variants;
//! allocator geometry and compiler frames remain separate physical terms.

use super::{CnpRestoredNode17DecodeAttempt, CnpRestoredSettledValidatedNode17, record::*};
use crate::node_contract::{NodeRoute, NodeRuntime, RuntimeError};
use crate::node_scheduling::{InputPayload, NativeSchedulingObservation};
use crucible_node_contract::{ContentRef, Id, PreparedOwner};
use std::mem::size_of;

/// Separates requested retained decoder products and fixed traversal scratch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CnpRestoredNode17DecodeConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl CnpRestoredNode17DecodeConstructionData {
    pub(crate) const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }
    pub(crate) const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }
    pub(crate) const fn declared_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Quotes both retained DOMs, typed histories, canonical bytes and cloned keys.
    ///
    /// This data-only scanner allocates no bank and authorizes no Source action.
    /// The complete caller admits this row together with the raw bytes and all
    /// other independently owned constructor products before invoking the reader.
    ///
    /// # Errors
    /// Refuses malformed JSON, bounded scanner exhaustion, typed layout overflow
    /// or the independent requested-byte ceiling.
    pub(crate) fn quote(
        reference: &ContentRef,
        bytes: &[u8],
        route: &NodeRoute,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        let typed_slot = [
            size_of::<NodeRecord17>(),
            size_of::<RestoredFamilies17>(),
            size_of::<BaseRecord17>(),
            size_of::<OriginalOperation17>(),
            size_of::<OriginalInput17>(),
            size_of::<InputCommitment17>(),
            size_of::<AdmissionRecord17>(),
            size_of::<BatchRecord17>(),
            size_of::<OriginalBatch17>(),
            size_of::<WorldRecord17>(),
            size_of::<WorldPublication17>(),
            size_of::<NodePreparation17>(),
            size_of::<Readiness17>(),
            size_of::<ProducerAttempt17>(),
            size_of::<CurrentObservation17>(),
            size_of::<ActivationOwnerWrapper17>(),
            size_of::<ResponseWrapper17>(),
            size_of::<MethodResult17>(),
            size_of::<NativeSchedulingObservation>(),
            size_of::<crate::node_scheduling::NativePublication>(),
            size_of::<crate::node_scheduling::NativeExternalInput>(),
            size_of::<crate::node_scheduling::event::Delivery>(),
            size_of::<PreparedOwner>(),
            size_of::<InputPayload>(),
            size_of::<CommonCapacity17>(),
            size_of::<ProviderCapacity17>(),
            size_of::<ProviderAlias17>(),
            size_of::<serde_json::Value>(),
        ]
        .into_iter()
        .max()
        .ok_or(RuntimeError::ResourceLimit)?;
        let typed_map_node = [
            NodeRuntime::capture_map_node_storage::<Id, OriginalOperation17>(),
            NodeRuntime::capture_map_node_storage::<Id, OriginalInput17>(),
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
            NodeRuntime::capture_map_node_storage::<Id, HistoricalAdmission17>(),
            NodeRuntime::capture_map_node_storage::<Id, HistoricalBatch17>(),
        ]
        .into_iter()
        .max()
        .ok_or(RuntimeError::ResourceLimit)?;
        let (typed, dom, canonical_temporaries) =
            NodeRuntime::capture_selected_json_decode_axes_data(
                bytes,
                typed_slot,
                typed_map_node,
                maximum,
            )?;
        // The exact canonical byte bank remains in the one-shot owner. The
        // canonicalizer's independent sorting/UTF-16 and Bytes serializer work
        // remains a maximum-phase term, even while that bank is retained.
        let canonical_bank = bytes
            .len()
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(8))
            .ok_or(RuntimeError::ResourceLimit)?;
        let transient = canonical_temporaries;
        let mut retained = typed
            .checked_add(dom)
            .and_then(|total| total.checked_add(dom))
            .and_then(|total| total.checked_add(canonical_bank))
            .ok_or(RuntimeError::ResourceLimit)?;
        let terms = [
            size_of::<Option<CnpRestoredNode17DecodeAttempt>>(),
            size_of::<Option<CnpRestoredSettledValidatedNode17>>(),
            NodeRuntime::capture_route_storage_data(route, maximum)?,
            reference.hash.algorithm.capacity(),
            reference.hash.domain.capacity(),
            reference.hash.digest.capacity(),
            reference.media_type.capacity(),
        ];
        for term in terms {
            retained = retained
                .checked_add(term)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let scratch = NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            .checked_add(size_of::<[usize; 32]>())
            .and_then(|total| total.checked_add(size_of::<Self>()))
            .and_then(|total| total.checked_add(size_of::<Result<Self, RuntimeError>>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        retained
            .checked_add(transient)
            .and_then(|total| total.checked_add(scratch))
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(Self {
            retained,
            transient,
            scratch,
        })
    }
}
