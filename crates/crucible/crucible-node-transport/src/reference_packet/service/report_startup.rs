//! Describes closed publication allowances in an original private Source birth.
//!
//! ```text
//! {"schema":"source-private.native-report-startup-allocation/13",
//!  "original_observe12":{"raw_report_capacity":"16384",
//!   "retained_growth_bytes":"...","maximum_simultaneous_transient_bytes":"...",
//!   "declared_counter_scratch_bytes":"..."},"fresh_completed_admit13":null}
//! ```
//!
//! These values are process-protocol data. Core's original installed scenario
//! policy admits the actual pre-Child owners before Source finalizes this part
//! of the same private birth. Native code must independently authenticate that
//! actual boot/ACK association and the selected purpose before obtaining any
//! internal construction right. Deserialization and arithmetic issue no permit.

use crate::ProviderError;

pub(crate) use crucible_source_birth_data::profile::reference_packet::service::report_startup::original_invocation_report_startup_allocation_counter_scratch_data;
pub use crucible_source_birth_data::profile::reference_packet::service::report_startup::{
    PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA, PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
    PacketNativeReportStartupAllocation, PacketNativeReportStartupAllocationRow,
    PacketNativeReportStartupPurpose, original_invocation_report_startup_allocation_peak_data,
};

mod storage;
pub use storage::{
    PacketNativeReportStartupStorageData, original_initial_report_startup_storage_data,
    original_report_startup_counter_scratch_data, original_report_startup_storage_data,
};

pub(crate) use storage::original_fresh_schema_generation_storage_data;

pub use storage::{
    original_invocation_report_startup_counter_scratch_data,
    original_invocation_report_startup_storage_data,
};
