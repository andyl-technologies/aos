//! Portable closed direct multipart models and canonical binary commitments.
//!
//! This module has no Hub database, provider credential or Connect runtime.
//! Hub, Worker and clients share exact geometry and manifest commitments.
//!
//! ```json
//! {"sessionId":"retained-session","logicalFingerprint":"<64 lowercase hex>"}
//! ```
//!
//! Counters are canonical decimal strings. Public protobuf JSON uses camelCase;
//! closed tagged variants use snake_case kind values. The illustration is one
//! session reference, not a complete admission or provider capability.

mod batch;
mod capabilities;
mod control;
mod grant;
mod integer;
mod model;
mod protobuf;
mod validation;

pub use batch::*;
pub use capabilities::*;
pub use control::*;
pub use integer::WireInteger;
pub use model::*;
pub use validation::*;

/// Maximum encoded bytes of a delegated provider URL.
pub const MAX_DIRECT_GRANT_URL_BYTES: usize = 8192;

/// Capability negotiated before any direct-required upload begins.
pub const DIRECT_UPLOAD_CAPABILITY: &str = "aos.direct.multipart.v1";
/// Maximum encoded bytes of an entire control request or response.
pub const MAX_DIRECT_CONTROL_BYTES: usize = 256 * 1024;
/// Maximum objects admitted, queried or completed by one batch.
pub const MAX_DIRECT_BATCH_ITEMS: usize = 64;
/// Maximum aggregate part descriptors in one grant/report/status batch.
pub const MAX_DIRECT_BATCH_PARTS: usize = 64;
/// Maximum required storage destinations of one immutable admission.
pub const MAX_DIRECT_PLACEMENTS: usize = 16;
/// Maximum multipart part count supported by S3 and R2.
pub const MAX_DIRECT_PARTS: u32 = 10_000;
/// Maximum object size supported by existing bounded storage work.
pub const MAX_DIRECT_OBJECT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Minimum geometry for every part except a final, possibly smaller part.
pub const MIN_DIRECT_PART_BYTES: u64 = 5 * 1024 * 1024;
/// Maximum part geometry exposed to bounded direct-upload clients.
pub const MAX_DIRECT_PART_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(test)]
mod tests;
