//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(HistoricalNativeBootData => HistoricalNativeBootDataCurrent17, "source-private.current-import-historical-native-boot-data/17", {
    schema: String,
    private_key: Bytes,
    birth_id: Bytes,
    source_birth: Value,
    expected_host_registration: Value,
    private_launch: Id,
    host_executable: ContentRef,
});

import_fields17!(HistoricalNativeBoot => HistoricalNativeBootCurrent17, "source-private.current-import-historical-native-boot/17", {
    creator: u32,
    data: HistoricalNativeBootData,
    launch_body: Vec<u8>,
    policy: Rc<HistoricalNativePolicy>,
    source_body: Vec<u8>,
    host_body: Vec<u8>,
    normalized: [Value; 5],
    banks: [Vec<u8>; 5],
    context: PacketCanonicalAckAdmissionContext,
    proof: PacketCanonicalAckAdmissionProof,
    original: Envelope,
    startup: Option<super::super::startup::HistoricalNativeStartupBoot>,
    invocation: Option<super::super::invocation::HistoricalNativeInvocationPhase>,
});

impl SharedImport17 for HistoricalNativeBoot {
    const KIND: MetadataSharedKind = MetadataSharedKind::HistoricalImportBoot;
}

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeBootData>()
        + std::mem::size_of::<HistoricalNativeBootDataCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeBootData>>()
        + std::mem::size_of::<Result<Option<HistoricalNativeBootDataCurrent17>, crate::ProviderError>>(
        )
        + std::mem::size_of::<HistoricalNativeBoot>()
        + std::mem::size_of::<HistoricalNativeBootCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeBoot>>()
        + std::mem::size_of::<Result<Option<HistoricalNativeBootCurrent17>, crate::ProviderError>>()
}
