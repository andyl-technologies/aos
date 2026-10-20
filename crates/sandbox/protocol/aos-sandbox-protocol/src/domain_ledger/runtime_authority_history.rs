//! Owns sole canonical Runtime pending/binding/head record DATA and codecs.
//!
//! These values and decoded histories authenticate no Journal, current holder,
//! publication, Native original, process or effect. Native accepted wrappers
//! remain private to the real currentness/writer owner. All widths, versioned
//! bytes, constraints and digest domains are the established formats.

/// Shares historical operation/gate/effect comparisons without Native acceptance.
pub mod crosslinks;
/// Shares complete historical namespace/continuity checks over actual borrowed objects.
pub mod ledger_read;
mod receiving;
pub use receiving::namespace_scan_map_receiving_demand_v2;

mod model;
mod format;

pub use model::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityHeadV1, RuntimeAuthorityIntentV1,
    RuntimeAuthorityLimits, RuntimeAuthorityPendingV1, RuntimeAuthorityStateV1,
};
pub use format::{
    binding_digest, decode_binding, decode_head, decode_pending,
    encode_binding, encode_head, encode_pending,
    runtime_pending_encoded_bytes_v1, runtime_binding_encoded_bytes_v1,
    runtime_head_encoded_bytes_v1,
};

/// Canonical key prefix for immutable pending intents.
pub const PENDING_PREFIX: &[u8] = b"pending/";
/// Canonical key prefix for immutable Runtime bindings.
pub const BINDING_PREFIX: &[u8] = b"binding/";
/// Canonical key prefix for current-head DATA.
pub const CURRENT_PREFIX: &[u8] = b"current/";
/// Exact pending-intent key width.
pub const PENDING_KEY_BYTES: usize = PENDING_PREFIX.len() + 16;
/// Exact sandbox-and-revision binding key width.
pub const BINDING_KEY_BYTES: usize = BINDING_PREFIX.len() + 16 + 8;
/// Exact sandbox current-head key width.
pub const CURRENT_KEY_BYTES: usize = CURRENT_PREFIX.len() + 16;

/// Established pending-intent record magic.
pub const PENDING_MAGIC: &[u8; 8] = b"AOSRAP01";
/// Established immutable-binding record magic.
pub const BINDING_MAGIC: &[u8; 8] = b"AOSRAB01";
/// Established current-head record magic.
pub const HEAD_MAGIC: &[u8; 8] = b"AOSRAH01";
/// Established pending-intent record version.
pub const PENDING_VERSION: u16 = 1;
/// Established immutable-binding record version.
pub const BINDING_VERSION: u16 = 1;
/// Established current-head record version.
pub const HEAD_VERSION: u16 = 1;
/// Domain separator for canonical binding-record commitments.
pub const BINDING_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.runtime-authority-binding.v1\0";
/// Domain separator for nonauthorizing intent commitments.
pub const INTENT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.runtime-authority-intent.v1\0";

/// Unchanged hard Runtime namespace record-count ceiling.
pub const MAXIMUM_RECORDS: usize = 1_000_000;
/// Existing native record header width used by the schema ceiling.
pub const JOURNAL_RECORD_HEADER_BYTES: usize = 7;
/// Unchanged hard Runtime record-byte ceiling.
pub const MAXIMUM_RECORD_BYTES: usize =
    16 * 1024 * 1024 - JOURNAL_RECORD_HEADER_BYTES - BINDING_KEY_BYTES;
/// Unchanged hard Runtime namespace aggregate-byte ceiling.
pub const MAXIMUM_MATERIALIZED_BYTES: usize = 512 * 1024 * 1024;

/// Reports invalid portable Runtime-authority record DATA without Native custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeAuthorityDataErrorV1 {
    /// A proposed intent has a reserved holder or revision.
    #[error("runtime-authority intent is invalid")]
    InvalidIntent,
    /// A configured DATA bound exceeds the unchanged schema ceilings.
    #[error("runtime-authority limits are invalid")]
    InvalidLimits,
    /// A record exceeds its fixed byte/count representation bound.
    #[error("runtime-authority {0} limit exceeded")]
    LimitExceeded(&'static str),
    /// A record violates its canonical schema or checksum/cross-links.
    #[error("protected runtime-authority state is corrupt")]
    CorruptState,
}
