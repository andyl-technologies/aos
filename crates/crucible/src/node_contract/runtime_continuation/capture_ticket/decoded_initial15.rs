//! Lends actual defining Core heap walks to the inert initial15 decoder.
//!
//! Inline output slots and the caller's separate fixed counters are excluded.
//! These methods observe capacities only and create no runtime or Source grant.

use super::OwnedStorage;
use crate::node_contract::{NodeRuntime, RuntimeError};

macro_rules! observed {
    ($name:ident, $ty:ty) => {
        impl NodeRuntime {
            /// Counts this actual typed DATA owner's nested requested capacities.
            ///
            /// # Errors
            /// Refuses checked overflow, unsupported layout or the supplied bound.
            pub(crate) fn $name(value: &$ty, maximum: usize) -> Result<usize, RuntimeError> {
                let bytes = value.owned_storage()?;
                if bytes > maximum {
                    return Err(RuntimeError::ResourceLimit);
                }
                Ok(bytes)
            }
        }
    };
}

observed!(capture_initial15_json_storage_data, serde_json::Value);
observed!(
    capture_initial15_owner_storage_data,
    crate::node_contract::OwnerIdentity
);
observed!(
    capture_initial15_activation_storage_data,
    crate::node_contract::SavedRuntimeActivation
);
observed!(
    capture_initial15_prepared_storage_data,
    crucible_node_contract::PreparedOwner
);
observed!(
    capture_initial15_route_storage_data,
    crate::node_contract::NodeRoute
);
observed!(
    capture_initial15_request_storage_data,
    crate::node_contract::OperationRequest
);
observed!(
    capture_initial15_outcome_storage_data,
    crate::node_contract::OperationOutcome
);
observed!(
    capture_initial15_failure_storage_data,
    crate::node_contract::OperationFailure
);
observed!(
    capture_initial15_payload_storage_data,
    crate::node_scheduling::InputPayload
);
observed!(
    capture_initial15_ack_storage_data,
    crate::node_scheduling::NativeInputAcknowledgement
);
observed!(
    capture_initial15_observation_storage_data,
    crate::node_scheduling::NativeSchedulingObservation
);
observed!(
    capture_initial15_event_storage_data,
    crucible_node_contract::Event
);
observed!(
    capture_initial15_scope_storage_data,
    crate::node_contract::SavedOriginalInputScope
);
observed!(
    capture_initial15_origin_storage_data,
    crate::node_contract::OriginalPublicationOrigin
);
observed!(
    capture_initial15_lineage_storage_data,
    crate::node_contract::OriginalLineageRow
);
observed!(
    capture_initial15_delivery_storage_data,
    crate::node_scheduling::event::Delivery
);
