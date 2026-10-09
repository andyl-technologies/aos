//! Shared durable package assessment orchestration for Local, Native and Worker.
//!
//! [`scan`] defines bounded requests, operation transitions and lease fences.
//! [`alerts`] reduces durable attention episodes without granting release authority.
//! [`attention`] derives exact issue scopes and resolution proofs from reproduced
//! results. [`events`] defines replayable admission and attention events, while
//! [`status`] computes conservative profile freshness deadlines.
//! [`provider`] defines separately authenticated, typed provider work with fixed
//! source/result limits. [`ports`] separates durable coordination, transport,
//! evidence custody and explicit time from the shared orchestration.
//!
//! Hybrid hosts logical coordination in Native and runs scoped provider effects
//! on Workers. Placement never changes assessment policy or evidence schemas.

#![forbid(unsafe_code)]

pub mod alerts;
pub mod attention;
pub mod events;
pub mod ports;
pub mod provider;
pub mod scan;
pub mod status;
mod validation;
