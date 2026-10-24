//! Defines the unchanged closed fresh restore allocation selector data.

use serde::{Deserialize, Serialize};

/// Selects a readonly producer on the same fresh target after its once-only Admit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNative5FreshRestoreAllocationSelection {
    /// Measures the admitted inactive target without activation or Prepare.
    CompletedAdmit13,
}

/// Names the independently selected fresh-target allocation family.
pub const PACKET_FRESH_RESTORE_ALLOCATION_FEATURE: &str =
    "source-owned.packet-fresh-restore-allocation/13";

/// Names the startup Observe request's sole envelope extension.
pub const PACKET_FRESH_RESTORE_ALLOCATION_QUERY: &str =
    "source-owned.packet-fresh-restore-allocation-query/13";

/// Names the immutable fresh-target report.
pub const PACKET_FRESH_RESTORE_ALLOCATION_REPORT: &str =
    "source-owned.packet-fresh-restore-allocation-report/13";

/// Names the domain-separated proof over the complete report data.
pub const PACKET_FRESH_RESTORE_ALLOCATION_PROOF: &str =
    "source-owned.packet-fresh-restore-allocation-proof/13";

/// Names the completed startup Observe response's report reference.
pub const PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT: &str =
    "source-owned.packet-fresh-restore-allocation-receipt/13";

/// Names the exact completed startup exchange bound into a later Prepare.
pub const PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING: &str =
    "source-owned.packet-fresh-restore-allocation-prepare-binding/13";

/// Names the report's exact content media type.
pub const PACKET_FRESH_RESTORE_ALLOCATION_MEDIA: &str =
    "application/vnd.source-owned.packet-fresh-restore-allocation.v13+json";

/// Bounds the closed report encoding independently of its allocation arithmetic.
pub const MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES: usize = 16 * 1024;

/// Bounds a closed startup query independently of the negotiated whole frame.
pub const MAXIMUM_FRESH_RESTORE_ALLOCATION_QUERY_BYTES: usize = 1024;

/// Names the keyed canonical report authentication algorithm.
pub const FRESH_RESTORE_ALLOCATION_ALGORITHM: &str = "blake3-keyed-canonical/1";

mod contract;
pub use contract::{
    PacketNativeFreshRestoreAllocationSchema, fresh_restore_allocation_contract,
    fresh_restore_allocation_schema,
};

/// Validates immutable schema content without negotiation or native authority.
pub mod policy;
