//! Serializes unchanged SourceBirth and planned registration data from inert fields.
//!
//! These borrowed views share the exact serializer used by the ordinary staged
//! Source constructor. They validate no launch or original-world association and
//! issue no accepted bank, Birth, Initial, Recipe or native permission. A worker
//! can lend its own decoded nonsecret fields without constructing a private
//! launch, admission token or effects path.

use crate::profile::reference_packet::{
    coordinator::PacketNative5CoordinatorInstallation, service::PacketNative5LaunchValidationFields,
};
use crucible_node_format::Id;
use serde::{Serialize, ser::SerializeMap};

/// Borrows nonsecret SourceBirth fields and the independently decoded coordinator.
///
/// Serialization preserves the existing schema selection and map-entry order.
/// The fields are unauthenticated DATA; successful serialization grants nothing.
pub struct SourceBirthView<'a> {
    /// Retains only the Transport adapter's explicit nonsecret operands.
    pub fields: PacketNative5LaunchValidationFields<'a>,
    /// Borrows the actual coordinator selected by the enclosing computation.
    pub coordinator: &'a PacketNative5CoordinatorInstallation,
}

impl Serialize for SourceBirthView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let launch = &self.fields;
        let capture = launch.capture_allocation_selection.is_some();
        let native = launch.native_codec_metadata_extent.is_some() || capture;
        let metadata = launch.protocol_metadata_limits.is_some() || capture;
        let restore = launch.complete_restore_selection.is_some() || capture;
        let input = launch.restore_input_emitter_selection.is_some() || capture;
        let schema = if capture {
            "source-owned.packet-canonical-ack-source-binding/12"
        } else if input {
            "source-owned.packet-canonical-ack-source-binding/11"
        } else if launch.complete_restore_selection == Some(
            crate::profile::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
        ) {
            "source-owned.packet-canonical-ack-source-binding/10"
        } else if restore {
            "source-owned.packet-canonical-ack-source-binding/9"
        } else if metadata {
            "source-owned.packet-canonical-ack-source-binding/8"
        } else if native {
            "source-owned.packet-canonical-ack-source-binding/7"
        } else {
            "source-owned.packet-canonical-ack-source-binding/6"
        };
        let fields = 10
            + usize::from(native)
            + usize::from(metadata)
            + usize::from(restore)
            + usize::from(input)
            + usize::from(capture);
        let mut map = serializer.serialize_map(Some(fields))?;
        map.serialize_entry("schema", schema)?;
        map.serialize_entry("selection", launch.selection)?;
        map.serialize_entry("program", launch.program)?;
        map.serialize_entry("coordinator", self.coordinator)?;
        map.serialize_entry("limits", launch.limits)?;
        map.serialize_entry("storage", launch.storage)?;
        map.serialize_entry("capture_profile", launch.capture_profile)?;
        map.serialize_entry("confirmation_selection", &launch.confirmation_selection)?;
        map.serialize_entry("ack_emitter_selection", &launch.ack_emitter_selection)?;
        map.serialize_entry(
            "codec_metadata_extent",
            &crate::profile::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
        )?;
        if native {
            map.serialize_entry(
                "native_codec_metadata_extent",
                &launch.native_codec_metadata_extent,
            )?;
        }
        if metadata {
            map.serialize_entry("protocol_metadata_limits", &launch.protocol_metadata_limits)?;
        }
        if restore {
            map.serialize_entry(
                "complete_restore_selection",
                &launch.complete_restore_selection,
            )?;
        }
        if input {
            map.serialize_entry(
                "restore_input_emitter_selection",
                &launch.restore_input_emitter_selection,
            )?;
        }
        if capture {
            map.serialize_entry(
                "capture_allocation_selection",
                &launch.capture_allocation_selection,
            )?;
        }
        map.end()
    }
}

/// Borrows the unchanged nine-field planned registration wire view.
///
/// The ordinary caller supplies its fixed schema/role and actual binding IDs.
/// Other callers can serialize ordinary data here but cannot create a live
/// registration authority, accepted bank or Source association.
#[derive(Serialize)]
pub struct RegistrationView<'a> {
    /// Names the planned registration schema.
    pub schema: &'static str,
    /// Names the planned endpoint role.
    pub role: &'static str,
    /// Borrows the actual planned physical connection.
    pub connection_id: &'a Id,
    /// Borrows the actual selected session.
    pub session_id: &'a Id,
    /// Borrows the actual selected incarnation.
    pub incarnation_id: &'a Id,
    /// Borrows the original protocol limits.
    pub limits: &'a crate::profile::handshake::Limits,
    /// Borrows the exact ordered feature roster.
    pub features: &'a crucible_node_format::IdSet,
    /// Borrows the exact typed extension selection.
    pub extensions: &'a [crucible_node_format::ExtensionSelection],
    /// Borrows the exact ordered envelope-key roster.
    pub envelope_extensions: &'a [String],
}
