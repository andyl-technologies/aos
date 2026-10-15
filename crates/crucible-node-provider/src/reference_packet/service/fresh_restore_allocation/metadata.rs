//! Walks the closed fresh13 typed data's actual independently owned backing.

use super::*;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};

macro_rules! fields {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl ObserveMetadata for $ty {
            fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
                let Self { $($field,)+ } = self;
                $(observer.observe($field)?;)+
                Ok(())
            }
        }
    };
}

fields!(
    PacketNativeFreshRestoreAllocationQuery,
    schema,
    nonce,
    completed_admit_request,
    completed_admit_response
);
fields!(
    PacketNativeFreshRestoreAllocationScope,
    native_pid,
    session,
    incarnation,
    node,
    owner,
    owner_generation,
    owner_binding,
    world,
    prepared_token,
    admission,
    closed_gate_receipt,
    nonce,
    assigned_query,
    completed_admit_request,
    completed_admit_response,
    ack_context
);
fields!(
    PacketNativeFreshRestoreAllocationStorage,
    current_retained_bytes,
    query_retained_growth_bytes,
    prepare_retained_growth_bytes,
    query_transient_bytes,
    prepare_transient_bytes,
    declared_counter_scratch_bytes
);
fields!(PacketNativeFreshRestoreAllocationData, scope, storage);
fields!(
    PacketNativeFreshRestoreAllocationProof,
    schema,
    algorithm,
    context_digest,
    mac
);
fields!(
    PacketNativeFreshRestoreAllocationReport,
    schema,
    data,
    proof
);
fields!(
    PacketNativeFreshRestoreAllocationReceipt,
    schema,
    allocation
);
fields!(
    PacketNativeFreshRestoreAllocationPrepareBinding,
    schema,
    assigned_query,
    completed_query_response,
    allocation
);

impl ObserveMetadata for PacketNative5FreshRestoreAllocationSelection {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::CompletedAdmit13 => Ok(()),
        }
    }
}
