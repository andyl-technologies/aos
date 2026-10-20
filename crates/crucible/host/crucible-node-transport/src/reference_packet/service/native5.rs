//! Adapts shared private-launch DATA to original upper storage accounting.

#[cfg(test)]
use super::PacketConnectedSourceProgram;
#[cfg(test)]
use crate::{ProviderError, handshake::Limits};
#[cfg(test)]
use crucible_node_format::*;

#[path = "native5/credit_failure.rs"]
mod credit_failure;
pub use credit_failure::{
    PacketNative5SerializedCreditFailureStorage,
    original_import18_serialized_credit_failure_counter_scratch_data,
};

mod profile;
#[cfg(test)]
#[path = "native5/validation.rs"]
mod validation;
pub use crucible_source_birth_data::profile::reference_packet::service::{
    PacketNative5CaptureProfile, PacketNative5LaunchValidationFields,
    PacketNative5LaunchValidationProjection, PacketNative5PathSerializationData,
    PacketNative5SourceLaunch, PacketNative5StorageLimits,
};

#[cfg(test)]
mod storage_geometry_tests;

#[cfg(test)]
pub(crate) use validation::PacketNative5LaunchValidationOracle;
