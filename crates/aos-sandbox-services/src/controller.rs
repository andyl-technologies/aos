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
mod ingress;
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

    fn public_receiving_credential_geometry() -> Option<
        aos_sandbox::public_api_session::ControllerStartupCredentialGeometryV1,
    > {
        aos_sandbox::public_api_session::PublicApiSessionStartupV1::credential_geometry()
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
        credentials: Option<&mut aos_sandbox::ControllerPublicTlsReceivingV1>,
        partial: &mut Self::PublicStartup,
        destination: &mut Option<Option<Self::PublicListener>>,
        terminal: &dyn ControllerServerTerminal,
    ) {
        public_api::bind_retained(uid, credentials, partial, destination, terminal);
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
    let public_connect = OperationServiceExt::register(public_service, public_connect);
    let public_application = ingress::application(
        public_connect,
        aos_sandbox::public_api_session::MAXIMUM_PUBLIC_RPC_REQUESTS,
    );
    let connect =
        DiscoveryServiceExt::register(Arc::clone(&diagnostic_service), connectrpc::Router::new());
    let connect = OperationServiceExt::register(diagnostic_service, connect);
    let application = ingress::application(
        connect,
        aos_sandbox::public_api_session::MAXIMUM_DIAGNOSTIC_RPC_REQUESTS,
    );

    (public_application, application)
}

#[cfg(test)]
mod runtime_fit_tests {
    use super::ControllerAssembly;
    use aos_sandbox_controller_runtime::controller_service::assembly::installed_startup_shapes_v1;

    #[test]
    fn installed_assembly_reports_every_startup_flag_combination() {
        for public_api in [false, true] {
            for cache_bundle in [false, true] {
                for publisher in [false, true] {
                    let (fixed, credentials) = installed_startup_shapes_v1::<ControllerAssembly>(
                        public_api, cache_bundle, publisher,
                    );
                    let parent_bytes = fixed.parent_bytes;
                    let worker_bytes = fixed.worker_bytes;
                    let public_startup_bytes = std::mem::size_of::<<ControllerAssembly as
                        aos_sandbox_controller_runtime::controller_service::assembly::
                        ControllerServerAssembly>::PublicStartup>();
                    let fixed = fixed.requested_counts_v1().expect("actual fixed shape arithmetic");
                    let credentials = credentials.requested_counts_v1()
                        .expect("actual credential suppliers and arithmetic");
                    let memory = fixed.memory_bytes.checked_add(credentials.memory_bytes).unwrap();
                    let files = fixed.open_files.checked_add(credentials.open_files).unwrap();
                    let metadata = fixed.metadata_entries.checked_add(credentials.metadata_entries).unwrap();
                    // Main and one serial property observer are existing
                    // original/scope tasks, outside this fixed additional row.
                    let role_tasks = fixed.pids.checked_add(2).unwrap();
                    println!(
                        "RFC21_RUNTIME_FIT public={} bundle={} publisher={} parent={} worker={} public_startup={} fixed_memory={} credential_memory={} total_memory={} fixed_files={} credential_files={} total_files={} role_tasks={} fixed_metadata={} credential_metadata={} total_metadata={} fits_no_nix_hard={} fits_online_nix_hard={}",
                        public_api, cache_bundle, publisher, parent_bytes, worker_bytes,
                        public_startup_bytes, fixed.memory_bytes, credentials.memory_bytes, memory,
                        fixed.open_files, credentials.open_files, files, role_tasks,
                        fixed.metadata_entries, credentials.metadata_entries, metadata,
                        memory <= 512 * 1024 * 1024 && files <= 128 && role_tasks <= 8,
                        memory <= 4 * 1024 * 1024 * 1024 && files <= 16384 && role_tasks <= 8,
                    );
                    // These are comparison shapes, not installed profile receipts.
                    // An actual artifact's measured runtime-file count can be
                    // supplied explicitly; otherwise print named schema probes.
                    let measured_files = std::env::var("AOS_RFC21_PROFILE_RUNTIME_FILES")
                        .ok().map(|value| value.parse::<usize>().expect("measured profile runtime-file count"));
                    let file_counts: Vec<usize> = measured_files.map_or_else(
                        || vec![0, 32, 512], |count| vec![count],
                    );
                    for runtime_files in file_counts {
                        let (actual_fixed, actual_credentials) = installed_startup_shapes_v1::<ControllerAssembly>(
                            public_api, cache_bundle, publisher,
                        );
                        let envelope = aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1::
                            startup_envelope_requested_counts_for_runtime_files_v1(
                                runtime_files, actual_fixed, actual_credentials,
                            ).expect("actual closed startup envelope arithmetic");
                        println!(
                            "RFC21_STARTUP_ENVELOPE public={} bundle={} publisher={} measured_count={} runtime_files={} memory={} files={} metadata={} tasks={} subset_no_nix_fit={} other_B_owners_included=false",
                            public_api, cache_bundle, publisher, measured_files.is_some(), runtime_files,
                            envelope.memory_bytes, envelope.open_files, envelope.metadata_entries,
                            envelope.pids, envelope.memory_bytes <= 512 * 1024 * 1024
                                && envelope.open_files <= 128 && envelope.pids <= 8,
                        );

                    }
                    if publisher {
                        let operation = aos_sandbox::ControllerPublisherReceivingV1::
                            operation_requested_counts_v1().expect("actual Publisher operation arithmetic");
                        let with_operation_memory = memory.checked_add(operation.memory_bytes).unwrap();
                        let with_operation_files = files.checked_add(operation.open_files).unwrap();
                        println!(
                            "RFC21_PUBLISHER_OPERATION public={} bundle={} memory={} files={} metadata={} network={} log={} output={} concurrent={} runtime_plus_operation_memory={} runtime_plus_operation_files={} fits_no_nix_subset={}",
                            public_api, cache_bundle, operation.memory_bytes, operation.open_files,
                            operation.metadata_entries, operation.network_bytes, operation.log_bytes,
                            operation.output_bytes, operation.concurrent_operations,
                            with_operation_memory, with_operation_files,
                            with_operation_memory <= 512 * 1024 * 1024 && with_operation_files <= 128,
                        );
                    }
                    // This checks only the actual Runtime cohort's arithmetic.
                    // Other B owners/resident P/I/Q/J/native providers must be
                    // added using their real policy receipt before whole fit.
                    assert_ne!(memory, 0);
                    assert_ne!(files, 0);
                }
            }
        }
    }
}
