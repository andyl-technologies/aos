//! Optional coordinator placement and ordered-watch implementation.
//!
//! [`placement`] ranks validated node observations without reserving capacity
//! or granting ownership. [`watch_service`] produces and consumes bounded,
//! ordered history from protected bootstraps. On Linux, `lease_projection`
//! projects an existing committed local lease without issuing or renewing it.
//!
//! Selecting this crate enables the Domain's `multi-node` contracts. The local
//! Domain has no dependency on this implementation. Protected transport and
//! store orchestration remain Domain-owned; this crate starts no service.

#[cfg(target_os = "linux")]
pub mod lease_projection;
pub mod placement;
pub mod watch_service;
