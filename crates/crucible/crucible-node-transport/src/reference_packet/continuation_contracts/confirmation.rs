//! Builds confirmation declarations before native binding and template construction.
//!
//! The returned manifest and content are declaration data. They install no codec,
//! capture mechanism, factory, source association or restoration permission.

pub use crucible_source_birth_data::profile::reference_packet::continuation_contracts::{
    PacketNative5ConfirmationDeclaration, complete_packet_confirmation_declaration,
};
