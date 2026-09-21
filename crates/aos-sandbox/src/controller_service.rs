//! Journal validation and public projections shared by controller services.
//!
//! Production process ownership lives in the broker-session-security crate,
//! above both the controller core and the authenticated broker transports.

pub mod journal;
pub mod public_observation;
