//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(HistoricalNativePolicy => HistoricalNativePolicyCurrent17, "source-private.current-import-historical-native-policy/17", {
    selection: PacketControlSelection,
    coordinator_reference: ContentRef,
    coordinator_bytes: Vec<u8>,
    definition: ContentRef,
    connected: PacketNative5CoordinatorInstallation,
    capture_profile: PacketNative5CaptureProfile,
    confirmation_selection: Option<PacketNative5ConfirmationSelection>,
    confirmation_definition: Option<ContentRef>,
    ack_emitter_selection: Option<PacketNative5AckEmitterSelection>,
    ack_emitter_definition: Option<ContentRef>,
    native_codec_metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    complete_restore_selection: Option< crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection, >,
    complete_restore_definitions: Option<[ContentRef; 3]>,
    complete_restore_transfer_definitions: Option<[ContentRef; 7]>,
    restore_input_emitter_selection: Option<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    restore_input_emitter_definition: Option<ContentRef>,
    capture_allocation_selection: Option<crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>,
    capture_allocation_definitions: Option<[ContentRef; 2]>,
    fresh_restore_allocation_selection: Option<crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>,
    fresh_restore_allocation_definitions: Option<[ContentRef; 5]>,
    protocol_metadata_limits: Option<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>,
});

impl SharedImport17 for HistoricalNativePolicy {
    const KIND: MetadataSharedKind = MetadataSharedKind::HistoricalImportPolicy;
}

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativePolicy>()
        + std::mem::size_of::<HistoricalNativePolicyCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativePolicy>>()
        + std::mem::size_of::<Result<Option<HistoricalNativePolicyCurrent17>, crate::ProviderError>>(
        )
}
