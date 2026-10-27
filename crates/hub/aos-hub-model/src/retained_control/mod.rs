//! Retained Hub control-plane domain contracts.
//!
//! This module is deliberately independent of SQL, Connect, and HTTP. It
//! models the invariants that every retained control-plane resource must carry
//! through those adapters: stable identity, immutable revisions, compare-and-
//! swap heads, attributable actors, reviewed plan seals, idempotency, and an
//! atomic audit/outbox intent.
//!
//! Authoritative aggregates are intentionally `Serialize`-only. Adapters must
//! decode transport-specific DTOs and enter this model through validating
//! constructors or gates; untrusted bytes cannot deserialize an invalid domain
//! value and then obtain a fresh canonical digest. The one retained aggregate
//! decoded directly, [`plan::SealedPlan`], has a custom deserializer that
//! reconstructs and revalidates its complete seal.
//!
//! The module remains isolated until the shared API and storage cutover lands.
//! Its integration test includes it by path so the contracts are executable
//! without registering a second mutation path in the Hub runtime.

pub mod canonical;
pub mod change_request;
pub mod channel;
pub mod classifier;
pub mod iam;
pub mod instance;
pub mod plan;
pub mod primitives;
pub mod signing;
