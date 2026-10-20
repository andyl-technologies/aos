//! Exposes the shared ordinary attachment mechanism without role admission.
//!
//! Genuine Publisher receiving owns the lower flight directly inside its real
//! C/profile/operation parent. The sealed startup Host producer is separate.

pub(super) use aos_sandbox_broker::fixed_service_identity::ServiceIdentityRefusalV1;
pub use aos_sandbox_broker::fixed_service_identity::ControllerAttachmentStartupV1;
