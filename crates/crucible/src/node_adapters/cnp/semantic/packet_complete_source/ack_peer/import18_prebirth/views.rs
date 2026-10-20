//! Serializes the unchanged pre-report SourceBirth and planned controller9.
//!
//! These views borrow real constructor operands. No startup/report allocation,
//! Initial budget, recipe, handshake authority or SDK witness is manufactured.

use super::*;
use serde::{Serialize, ser::SerializeMap};

pub(super) struct SourceBirthView<'a> {
    pub(super) launch: &'a PacketNative5SourceLaunch,
    pub(super) coordinator: &'a PacketNative5CoordinatorInstallation,
}

impl Serialize for SourceBirthView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let launch = self.launch;
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
            crucible_node_provider::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
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
        map.serialize_entry("selection", &launch.selection)?;
        map.serialize_entry("program", &launch.program)?;
        map.serialize_entry("coordinator", self.coordinator)?;
        map.serialize_entry("limits", &launch.limits)?;
        map.serialize_entry("storage", &launch.storage)?;
        map.serialize_entry("capture_profile", &launch.capture_profile)?;
        map.serialize_entry("confirmation_selection", &launch.confirmation_selection)?;
        map.serialize_entry("ack_emitter_selection", &launch.ack_emitter_selection)?;
        map.serialize_entry(
            "codec_metadata_extent",
            &crucible_node_provider::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
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

#[derive(Serialize)]
pub(super) struct RegistrationView<'a> {
    pub(super) schema: &'static str,
    pub(super) role: &'static str,
    pub(super) connection_id: &'a Id,
    pub(super) session_id: &'a Id,
    pub(super) incarnation_id: &'a Id,
    pub(super) limits: &'a crucible_node_provider::handshake::Limits,
    pub(super) features: &'a crucible_node_contract::IdSet,
    pub(super) extensions: &'a [crucible_node_contract::ExtensionSelection],
    pub(super) envelope_extensions: &'a [String],
}
