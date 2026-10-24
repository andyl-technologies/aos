//! Reuses the SAME fixed process-bus readback owned by Native Domain.
//!
//! Initial selected startup and each genuine recurring operation retain their
//! own real observations; this facade duplicates no parser or environment engine.

pub(super) use aos_sandbox_controller_domain::ControllerPublisherBusEnvironmentV1 as PublisherBusEnvironmentV1;
