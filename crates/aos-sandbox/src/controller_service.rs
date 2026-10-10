//! Journal validation and public projections shared by controller services.
//!
//! HTTP application assembly lives in the sandbox-services crate; protected
//! runtime integration remains in the broker-session-security crate,
//! above both the controller core and the authenticated broker transports.

pub mod public_observation;
pub mod public_projection;
