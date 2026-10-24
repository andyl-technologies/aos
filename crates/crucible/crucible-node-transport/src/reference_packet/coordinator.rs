//! Reexports the shared static grammar while preserving original live test owners.

pub use crucible_source_birth_data::profile::reference_packet::coordinator::{
    PACKET_CONNECTED_COORDINATOR_BYTES, PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES,
    PacketConnectedCoordinatorInstallation, PacketConnectedHostSelection,
    PacketCoordinatorInstallation, PacketNative5CoordinatorInstallation,
    PacketWorldCoordinatorInstallation,
    packet_native5_coordinator_installation_counter_scratch_data,
};

#[cfg(test)]
use crucible_source_birth_data::profile::reference_packet::coordinator::{
    FIELDS, LIMIT, refused, verify_static_content,
};
#[cfg(test)]
mod continuation;
#[cfg(test)]
pub(crate) use continuation::original_canonical_ack_controller_scope;
#[cfg(test)]
pub(crate) use continuation::original_canonical_ack_controller_scope_with_identity_suffix;
#[cfg(test)]
pub(crate) use continuation::original_native5_controller_scope;
