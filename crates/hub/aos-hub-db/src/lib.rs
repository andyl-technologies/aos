//! Portable Hub persistence and SQL backends.
//!
//! The `db` module owns migrations and capability queries; `backend` provides
//! atomic SQL operations, native SQLx drivers, and the Worker backend port.
//! Domain policies come from `aos-hub-model`; application services depend on
//! this crate, while persistence never depends on service orchestration.

pub mod backend;
pub mod db;
pub mod dialect;
pub mod value;

pub mod application_body_observation;
pub mod direct_upload;
pub mod hybrid_ingress;
pub mod hybrid_upload;
pub mod mirror_acceptance;
pub mod mirror_batch;
pub mod mirror_candidate;
pub mod mirror_guard;
pub mod mirror_inspection;
pub mod mirror_membership;
pub mod mirror_tree_inventory;
pub mod mirror_work;
pub mod oci_cleanup;
pub mod oci_projection;
pub mod oci_sdk_emulation;
pub mod snapshot;
pub mod storage_authority;
pub mod storage_work;
pub mod tree_projection;
