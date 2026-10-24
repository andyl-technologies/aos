//! Reexports portable receiving arithmetic for private original owners.
//!
//! The Core engine is nonauthorizing DATA. Native keeps each real receiving
//! original and borrows its same ledger only inside the closed paid entry.

pub(crate) use aos_sandbox_model::component_receiving::{
    ComponentServiceReceivingLedgerV1, complete_bound_delta_v1,
};

pub(crate) use aos_sandbox_broker::receiving::{
    ComponentReceivingOperationClosedV1, ComponentReceivingOperationLoanV1,
    ComponentReceivingOperationV1, ComponentReceivingOwnedOperationV1,
};
