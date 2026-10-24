//! Defines distinct versioned Root provisioning exchanges as passive DATA.
//!
//! Native Controller and Root owners independently fund and authenticate every
//! flight. No codec constructs an admission, payer, peer or temporal loan.

/// Frames the separate Storage workspace Apply continuation.
pub mod storage_apply;

mod opening;

/// Frames the separate accepted Start and Host resource/launch continuation.
pub mod host_launch;

/// Frames the distinct current Maintenance Storage31 Root purpose.
pub mod maintenance_storage;

/// Binds a new authorized observation without restoring interrupted Apply.
pub mod finality_recover;

/// Frames read-only current signed inputs before fresh Start assignment compilation.
pub mod start_assignment_inputs;

/// Frames the retained Execution no-Apply floor-to-ACK exchange.
pub mod execution_no_apply;

/// Frames the held fresh Stop cleanup and its ordinary Controller signature.
pub mod stop_cleanup;
