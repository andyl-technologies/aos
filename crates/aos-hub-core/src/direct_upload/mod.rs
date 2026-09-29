//! Closed direct multipart upload controls shared by Hub, Worker and clients.
//!
//! Clients receive only exact UploadPart grants for private staging. Logical
//! admission and independently verified promotion remain server operations.
//! Reports and expiry never establish provider settlement or erase fences.
//!
//! ```text
//! BeginBatch -> bounded grants/reports + sparse status -> compact CompleteBatch
//! client bytes -> provider private staging -> storage verification -> promotion
//! ```

mod actor;
mod admission;
mod admission_validation;
mod batch;
mod evidence;
mod external_capabilities;
mod capabilities_wire;
mod logical;
mod managed_profile;
mod wire;

pub use actor::*;
pub use admission::*;
pub use admission_validation::direct_staging_key;
pub use aos_proto_types::direct_upload::*;
pub use batch::*;
pub use capabilities_wire::*;
pub use external_capabilities::*;
pub use logical::*;
pub use managed_profile::*;
pub use wire::*;

#[cfg(test)]
mod tests;
