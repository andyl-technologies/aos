//! Optional fleet placement, reconciliation and remote workflow implementation.
//!
//! [`placement`] ranks validated observations without granting ownership.
//! [`reconciliation`] folds remote assignment observations. [`transport`] owns
//! canonical packet exchanges over genuine native channel loans; [`draining`],
//! [`transfer`] and [`watch_requests`] select and assemble the existing remote
//! workflows. [`watch_service`] produces and consumes bounded ordered history.
//!
//! Selecting this crate enables the Domain's `multi-node` native contracts.
//! The Domain has no dependency on this implementation. Fixed local openers,
//! authenticated proof issuers, protected artifacts, publication and recovery
//! retain their genuine native owners. This crate starts no service or worker.

pub mod draining;
pub mod placement;
pub mod reconciliation;
pub mod transfer;
pub mod transport;
pub mod watch_requests;
pub mod watch_service;
