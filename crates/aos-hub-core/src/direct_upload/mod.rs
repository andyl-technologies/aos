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
mod authority_lookup;
mod baseline;
mod batch;
mod capabilities_wire;
mod evidence;
mod external_capabilities;
mod final_guard;
mod foreground;
mod logical;
mod logical_refs;
mod managed_profile;
mod protected_profile;
mod runtime_qualification;
mod selected_complete;
mod service;
mod wire;
mod worker_deployment;
mod worker_installation;
mod worker_qualification;

pub use actor::*;
pub use admission::*;
pub use admission_validation::direct_staging_key;
pub use aos_proto_types::direct_upload::*;
pub use authority_lookup::*;
pub use baseline::*;
pub use batch::*;
pub use capabilities_wire::*;
pub use external_capabilities::*;
pub use final_guard::*;
pub use foreground::*;
pub use logical::*;
pub use logical_refs::*;
pub use managed_profile::*;
pub use protected_profile::*;
pub use runtime_qualification::*;
pub use selected_complete::*;
pub use service::*;
pub use wire::*;
pub use worker_deployment::*;
pub use worker_installation::*;
pub use worker_qualification::*;

#[cfg(feature = "test-fixtures")]
pub use worker_qualification::fixtures::direct_worker_qualification_fixture;

#[cfg(test)]
mod tests;
