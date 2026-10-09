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
