//! Crucible session dispatch and authenticated HTTP/2 server integration.
//!
//! Spec index: RFC-0010 files 21.
//!
//! Module map: lifecycle owns actor registries and in-process client adapters;
//! streaming owns actor streams; server and transport_security own HTTP/2 and
//! TLS. Debug modules manage authorization, leases, and the standalone gateway.
//! Production QEMU lifecycle composition belongs to crucible-daemon.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod control_responsive;
pub mod debug_access;
pub mod debug_gateway;
mod debug_holders;
pub mod debug_relay;
pub mod event_log_stream;
pub mod in_process;
pub mod lifecycle;
pub mod server;
pub mod streaming;
pub mod transport_security;
pub use control_responsive::ControlResponsiveSessionProbe;
use crucible_control_api::*;
use crucible_control_client::{ControlClientError, InProcessLifecycleControlStream};
pub use debug_access::{DebugAuthorizationPolicy, DebugAuthorizationPolicyError};
pub use debug_gateway::{
    DEBUG_GATEWAY_STARTUP_TIMEOUT, DEBUG_GATEWAY_V1_CAPABILITY, DebugGatewayClientError,
    DebugGatewayControlClient, DebugGatewayProcess,
};
pub use event_log_stream::ControlPlaneEventLog;
pub use in_process::InProcessControlClient;
pub use lifecycle::{
    DebugRepositionDispatch, GuestIntrospectionDispatch, InProcessLifecycleClient,
    LifecycleControlPlane, LifecycleLoopFactory, QuiescentLifecycleLoop,
    ResumeObservationCancellation, ResumeObservationCancellationRegistration,
    ResumeObservationLoopFactory, ResumeObservationPreparationContext,
    ResumeReplayClosureValidationError, ResumeReplayClosureValidator, SessionLifetimeRetention,
};
pub use server::{
    LifecycleServerMode, serve_lifecycle_http2,
    serve_lifecycle_http2_mtls_with_mode_until_shutdown,
    serve_lifecycle_http2_with_debug_policy_until_shutdown, serve_lifecycle_http2_with_mode,
    serve_lifecycle_http2_with_mode_until_shutdown,
    serve_shared_lifecycle_http2_mtls_with_mode_until_shutdown,
    serve_shared_lifecycle_http2_with_debug_policy_until_shutdown,
};
pub use streaming::{ControlStream, InProcessStreamingSession, WatchStream};
pub use transport_security::{
    DebugTransportIdentity, MutualTlsServerConfigError, mutual_tls_acceptor_from_pem,
};
