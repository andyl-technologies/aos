//! Actor-side concurrent native dispatch with deterministic round publication.
//!
//! [`DispatchRound`] starts only disjoint admitted owner groups. Native engines
//! can execute concurrently while this owning actor polls their original tokens;
//! no `Send` or `Sync` requirement is imposed on model objects. Completion order
//! never selects publication order, and every unresolved token remains retained
//! in the node runtime if this coordinator-side handle is dropped.

mod round;

pub use round::*;
