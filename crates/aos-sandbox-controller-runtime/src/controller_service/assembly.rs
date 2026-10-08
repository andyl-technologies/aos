//! Non-authorizing application assembly port for the installed Controller.
//!
//! The runtime retains its journal, startup originals, readiness checks, and
//! terminal ordering. The application supplies only listener custody and HTTP
//! registration. Handler fields and authority constructors remain private.

use std::path::Path;
use std::sync::Arc;

use aos_sandbox::public_api_session::PublicApiSessionAcceptor;

use super::{CapabilityService, ControllerRuntimeError};

/// Terminates application startup with the runtime's original custody resident.
///
/// This negative-only loan cannot complete a startup stage or open readiness.
pub trait ControllerServerTerminal {
    /// Parks an actual returned runtime cause before terminating the process.
    fn runtime(&self, cause: ControllerRuntimeError) -> !;

    /// Records an incomplete application startup before terminating the process.
    fn closed(&self, cause: &'static str) -> !;
}

/// Supplies transport and registration for the installed Controller runtime.
///
/// The port accepts only opaque, already constructed handlers. Implementations
/// cannot replace their admission checks or obtain the journal, signer, worker,
/// or readiness owner. Each listener stays in the runtime's original parent
/// until the existing serving/terminal handoff; startup failure must call the
/// supplied negative-only terminal before returning or dropping partial state.
/// This is a trusted application contract, not a type-enforced authentication
/// proof. The installed service crate supplies its private fixed assembly.
#[allow(async_fn_in_trait)]
pub trait ControllerServerAssembly {
    /// Owns the registered root-only diagnostic listener.
    type DiagnosticListener;

    /// Owns the registered mutual-TLS public listener.
    type PublicListener;

    /// Retains partial public-listener startup returns in the original parent.
    type PublicStartup;

    /// Holds concrete registered HTTP service routes without domain authority.
    type Application;

    /// Allocates empty public-listener startup slots without performing I/O.
    fn public_startup() -> Self::PublicStartup;

    /// Binds a socket under the fixed Controller ownership and permission rules.
    ///
    /// # Errors
    /// Rejects unsafe parent/stale-entry custody or filesystem/socket failures.
    fn bind_socket(
        path: &Path,
        uid: u32,
        mode: u32,
    ) -> Result<std::os::unix::net::UnixListener, ControllerRuntimeError>;

    /// Registers the existing diagnostic socket with UID 0 acceptance policy.
    ///
    /// # Errors
    /// Reports asynchronous runtime registration failure.
    async fn diagnostic_listener(
        listener: std::os::unix::net::UnixListener,
    ) -> Result<Self::DiagnosticListener, ControllerRuntimeError>;

    /// Parks diagnostic registration in the original parent's destination.
    ///
    /// Registration failure terminates through the borrowed runtime terminal.
    fn register_diagnostic(
        attempt: &mut tokio::net::UnixListenerRegistrationAttempt,
        destination: &mut Option<Self::DiagnosticListener>,
        terminal: &dyn ControllerServerTerminal,
    );

    /// Loads the fixed protected TLS acceptor and binds the public endpoint.
    ///
    /// # Errors
    /// Rejects credential, socket-custody, or runtime registration failures.
    async fn public_listener(uid: u32) -> Result<Self::PublicListener, ControllerRuntimeError>;

    /// Parks every reached public-startup return before the runtime continues.
    ///
    /// A failure terminates before partial listener custody can be released.
    fn bind_public_retained(
        uid: u32,
        partial: &mut Self::PublicStartup,
        destination: &mut Option<Option<Self::PublicListener>>,
        terminal: &dyn ControllerServerTerminal,
    );

    /// Borrows the same acceptor for the independently checked Git read ingress.
    fn git_read_acceptor(listener: &Self::PublicListener) -> Arc<PublicApiSessionAcceptor>;

    /// Registers the fixed public-first and diagnostic-second handler surfaces.
    fn applications(
        public: Arc<CapabilityService>,
        diagnostic: Arc<CapabilityService>,
    ) -> (Self::Application, Self::Application);

    /// Serves public HTTP requests or remains pending when explicitly disabled.
    ///
    /// # Errors
    /// Reports termination of the public HTTP server.
    async fn serve_public(
        listener: Option<Self::PublicListener>,
        application: Self::Application,
    ) -> Result<(), ControllerRuntimeError>;

    /// Serves root-only diagnostic HTTP requests with the registered handler.
    ///
    /// # Errors
    /// Reports termination of the diagnostic HTTP server.
    async fn serve_diagnostic(
        listener: Self::DiagnosticListener,
        application: Self::Application,
    ) -> Result<(), ControllerRuntimeError>;
}
