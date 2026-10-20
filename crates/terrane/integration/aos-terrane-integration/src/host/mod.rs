//! Owns host-supplied Terrane provisioning and privileged quota-query wiring.
//!
//! Implementation belongs to the T2 native quota task. Declaring this boundary
//! does not implement a service or satisfy HOST-23.

/// Consumes genuine fresh-bucket evidence for first administrative enrollment.
pub mod initial_enrollment;
