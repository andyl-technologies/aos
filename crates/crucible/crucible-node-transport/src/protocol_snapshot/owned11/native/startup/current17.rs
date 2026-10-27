//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, import_fields17,
};

import_fields17!(HistoricalNativeStartupBoot => HistoricalNativeStartupBootCurrent17, "source-private.current-import-historical-native-startup-boot/17", {
    allocation: PacketNativeStartupAllocation,
    source_digest: [u8; 32],
    launch_digest: [u8; 32],
    birth_id: [u8; 32],
    native_birth_issued: bool,
    baseline_complete: bool,
    prepare_startup_issued: bool,
});

import_fields17!(HistoricalNativeStartupBootstrap => HistoricalNativeStartupBootstrapCurrent17, "source-private.current-import-historical-native-startup-bootstrap/17", {
    creator: u32,
    preamble: [u8; 336],
    private_bootstrap: PacketNativeStartupAllocationRow,
    native_birth: PacketNativeStartupAllocationRow,
    restore_prepare: Option<PacketNativeStartupAllocationRow>,
    expected_controller_pid: u64,
    expected_controller_uid: u64,
    maximum_launch_bytes: usize,
    maximum_boot_bytes: usize,
    native_issued: bool,
    failed: bool,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeStartupBoot>()
        + std::mem::size_of::<HistoricalNativeStartupBootCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeStartupBoot>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeStartupBootCurrent17>, crate::ProviderError>,
        >()
        + std::mem::size_of::<HistoricalNativeStartupBootstrap>()
        + std::mem::size_of::<HistoricalNativeStartupBootstrapCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeStartupBootstrap>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeStartupBootstrapCurrent17>, crate::ProviderError>,
        >()
}
