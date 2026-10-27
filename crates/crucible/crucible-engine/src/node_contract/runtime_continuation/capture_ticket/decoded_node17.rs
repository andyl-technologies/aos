//! Lends existing typed Core heap walks to the inert Node17 decoder census.
//!
//! These helpers observe actual independently owned capacities only. No visitor
//! creates runtime tokens, currentness, Source provenance or a live admission.

use super::OwnedStorage;
use crate::node_contract::{NodeRuntime, RuntimeError};

macro_rules! observed {
    ($name:ident,$ty:ty) => {
        impl NodeRuntime {
            /// Counts the actual decoded common value's independently owned heaps.
            ///
            /// The enclosing Node census separately charges its actual inline
            /// slot. Existing defining Core visitors count nested capacities.
            ///
            /// # Errors
            /// Refuses unsupported layouts, arithmetic overflow or the maximum.
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

observed!(
    capture_decoded_node17_saved_activation_storage_data,
    crate::node_contract::SavedRuntimeActivation
);
observed!(
    capture_decoded_node17_owner_identity_storage_data,
    crate::node_contract::OwnerIdentity
);
observed!(
    capture_decoded_node17_operation_request_storage_data,
    crate::node_contract::OperationRequest
);
observed!(
    capture_decoded_node17_delivery_storage_data,
    crate::node_scheduling::event::Delivery
);
