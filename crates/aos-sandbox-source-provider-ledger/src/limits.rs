//! Hard canonical AOSSPL01 allocation and retention ceilings.

/// Maximum retained holder sessions.
pub const MAXIMUM_HOLDERS: usize = 256;
/// Maximum active acquisitions per holder.
pub const MAXIMUM_ACTIVE_ACQUISITIONS_PER_HOLDER: usize = 1_024;
/// Maximum inventory entries per holder.
pub const MAXIMUM_INVENTORY_ENTRIES_PER_HOLDER: usize = 2_048;
/// Maximum retained durable identities.
pub const MAXIMUM_RETAINED_IDENTITIES: usize = 262_144;
/// Maximum backend evidence payload bytes.
pub const MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES: usize = 65_536;
/// Maximum retained signed hello bytes.
pub const MAXIMUM_SIGNED_HELLO_BYTES: usize = 4_096;
/// Maximum retained signed request or response bytes.
pub const MAXIMUM_SIGNED_REQUEST_OR_RESPONSE_BYTES: usize = 1_048_576;
/// Maximum retained signed lease bytes.
pub const MAXIMUM_SIGNED_LEASE_BYTES: usize = 262_144;
/// Maximum retained signed release receipt bytes.
pub const MAXIMUM_SIGNED_RELEASE_RECEIPT_BYTES: usize = 65_536;
/// Maximum prospective apply template bytes.
pub const MAXIMUM_APPLY_TEMPLATE_BYTES: usize = 2_048;
/// Maximum logical binding bytes.
pub const MAXIMUM_LOGICAL_BINDING_BYTES: usize = 65_536;
/// Maximum records in one transaction.
pub const MAXIMUM_TRANSACTION_RECORDS: usize = 6;
/// Maximum aggregate transaction bytes, including deleted keys.
pub const MAXIMUM_TRANSACTION_BYTES: usize = 8 * 1024 * 1024;
/// Maximum aggregate encoded bytes inspected in one recovered ledger graph.
///
/// The bound is checked before cloning any record into the validator. It is
/// intentionally larger than a transaction while remaining a finite recovery
/// allocation ceiling.
pub const MAXIMUM_LEDGER_GRAPH_BYTES: usize = 512 * 1024 * 1024;
/// Maximum canonical records inspected in one recovered ledger graph.
///
/// One retained identity budget covers attempts/acquisitions/releases, a
/// second covers immutable session history, and the remainder admits catalog
/// history plus the singleton authority head.
pub const MAXIMUM_LEDGER_RECORDS: usize =
    MAXIMUM_RETAINED_IDENTITIES * 2 + MAXIMUM_RETAINED_CATALOG_HEADS + 1;
/// Maximum retained released inventory entries per holder.
pub const MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER: usize = 1_024;
/// Maximum retained catalog heads.
pub const MAXIMUM_RETAINED_CATALOG_HEADS: usize = 4_096;
/// Maximum predecessor leases retained per acquisition.
pub const MAXIMUM_LEASE_HISTORY_PER_ACQUISITION: usize = 1_024;
