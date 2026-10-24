//! Preserves actual original handshake fixtures above the portable grammar.

use super::*;
use crate::reference_packet::continuation_contracts as contracts;
use crate::reference_packet::control::PacketControlSelection;
use crate::{ProviderError, bodies::ActivateRequest};
use crucible_node_format::*;
use crucible_source_birth_data::profile::reference_packet::coordinator::{
    host_configuration, validate_host, validate_native,
};
use serde::Serialize;
use serde_json::{Value, json};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn original_native5_controller_scope() -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    tests::original_native5_controller_scope()
}

#[cfg(test)]
pub(crate) fn original_canonical_ack_controller_scope() -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    tests::original_canonical_ack_controller_scope()
}

#[cfg(test)]
pub(crate) fn original_canonical_ack_controller_scope_with_identity_suffix(
    suffix: Option<&str>,
) -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    tests::original_canonical_ack_controller_scope_with_identity_suffix(suffix)
}
