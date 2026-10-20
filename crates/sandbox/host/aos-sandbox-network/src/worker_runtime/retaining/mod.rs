//! Shares the existing worker quiescence reducer with retained native owners.

mod preparation;
mod quiescence;
mod parent_transport_v2;
mod parent_mutation_v2;

pub(crate) use parent_mutation_v2::{NetworkParentMutationInputV2, NetworkParentMutationOriginalV2};

pub(crate) use parent_transport_v2::NetworkParentTransportOriginalV2;
pub(crate) use quiescence::WorkerQuiescenceOriginalV4;

pub(super) use quiescence::{LocalQuiescenceV4, quiesce_engine_v4, wait_engine_v4};
