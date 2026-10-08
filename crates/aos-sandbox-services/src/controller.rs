//! Assembles the installed Controller's authenticated HTTP surfaces.
//!
//! Journal ownership, independent admission, reconciliation, original startup
//! custody, and readiness remain in the protected runtime. This module supplies
//! the fixed public/diagnostic listener recipe and concrete service registration.

use std::sync::Arc;

use aos_proto::aos::sandbox::v1::{
    CacheServiceExt, CapabilityServiceExt, DiscoveryServiceExt, ExecutionServiceExt,
    FilesystemViewServiceExt, OperationServiceExt, OperatorServiceExt, SandboxServiceExt,
    SnapshotServiceExt,
};
use aos_sandbox_controller_runtime::controller_service::{
    CapabilityService, ControllerRuntimeError,
    assembly::{ControllerServerAssembly, ControllerServerTerminal},
};

mod diagnostic;
mod public_api;

use diagnostic::bind_controller_socket;

/// Runs the fixed Controller runtime with its installed HTTP assembly.
///
/// # Errors
/// Returns the existing process, configuration, startup, reconciliation, or
/// server error. Selected original-custody failures terminate in the runtime.
pub fn run_from_environment() -> Result<(), ControllerRuntimeError> {
    aos_sandbox_controller_runtime::controller_service::run_from_environment::<
        ControllerAssembly,
    >()
}

struct ControllerAssembly;

impl ControllerServerAssembly for ControllerAssembly {
    type DiagnosticListener = diagnostic::AuthenticatedDiagnosticListener;
    type PublicListener = public_api::PublicListener;
    type PublicStartup = public_api::PublicListenerStartupV1;
    type Application = axum::Router;

    fn public_startup() -> Self::PublicStartup {
        public_api::PublicListenerStartupV1::new()
    }

    fn bind_socket(
        path: &std::path::Path,
        uid: u32,
        mode: u32,
    ) -> Result<std::os::unix::net::UnixListener, ControllerRuntimeError> {
        bind_controller_socket(path, uid, mode)
    }

    async fn diagnostic_listener(
        listener: std::os::unix::net::UnixListener,
    ) -> Result<Self::DiagnosticListener, ControllerRuntimeError> {
        diagnostic::into_async_diagnostic_listener(listener).await
    }

    fn register_diagnostic(
        attempt: &mut tokio::net::UnixListenerRegistrationAttempt,
        destination: &mut Option<Self::DiagnosticListener>,
        terminal: &dyn ControllerServerTerminal,
    ) {
        diagnostic::register_retained_diagnostic(attempt, destination, terminal);
    }

    async fn public_listener(uid: u32) -> Result<Self::PublicListener, ControllerRuntimeError> {
        public_api::bind(uid).await
    }

    fn bind_public_retained(
        uid: u32,
        partial: &mut Self::PublicStartup,
        destination: &mut Option<Option<Self::PublicListener>>,
        terminal: &dyn ControllerServerTerminal,
    ) {
        public_api::bind_retained(uid, partial, destination, terminal);
    }

    fn git_read_acceptor(
        listener: &Self::PublicListener,
    ) -> Arc<aos_sandbox::public_api_session::PublicApiSessionAcceptor> {
        listener.git_read_acceptor()
    }

    fn applications(
        public: Arc<CapabilityService>,
        diagnostic: Arc<CapabilityService>,
    ) -> (Self::Application, Self::Application) {
        controller_applications(public, diagnostic)
    }

    async fn serve_public(
        listener: Option<Self::PublicListener>,
        application: Self::Application,
    ) -> Result<(), ControllerRuntimeError> {
        public_api::serve(listener, application).await
    }

    async fn serve_diagnostic(
        listener: Self::DiagnosticListener,
        application: Self::Application,
    ) -> Result<(), ControllerRuntimeError> {
        axum::serve(listener, application)
            .await
            .map_err(ControllerRuntimeError::DiagnosticServer)
    }
}

// Keeps the complete fixed public-first/diagnostic-second owning recipe together.
fn controller_applications(
    public_service: Arc<CapabilityService>,
    diagnostic_service: Arc<CapabilityService>,
) -> (axum::Router, axum::Router) {
    let public_connect =
        DiscoveryServiceExt::register(Arc::clone(&public_service), connectrpc::Router::new());
    let public_connect = SandboxServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect = ExecutionServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect =
        FilesystemViewServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect = SnapshotServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect =
        CapabilityServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect = CacheServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect = OperatorServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect =
        OperationServiceExt::register(public_service, public_connect).into_axum_service();
    let public_application = axum::Router::new().fallback_service(public_connect);
    let connect =
        DiscoveryServiceExt::register(Arc::clone(&diagnostic_service), connectrpc::Router::new());
    let connect = OperationServiceExt::register(diagnostic_service, connect).into_axum_service();
    let application = axum::Router::new().fallback_service(connect);

    (public_application, application)
}
