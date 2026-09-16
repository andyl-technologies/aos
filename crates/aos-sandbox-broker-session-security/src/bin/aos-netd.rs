//! Runs the authenticated, systemd-activated Network broker.
//!
//! Startup claims the fixed listener before opening protected policy or state.
//! Each accepted connection completes one authenticated, durable, bounded
//! request cycle against the authoritative namespace inventory.

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use aos_sandbox_broker_session_security::{
    ProductionBrokerDeadlineErrorV1, ProductionBrokerServiceErrorV1,
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    production_deadline_after,
};
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_sandbox_network::{
    MAXIMUM_RETAINED_NETWORK_NAMESPACES, NetworkBrokerSessionRuntimeErrorV1,
    NetworkBrokerSessionRuntimeV1, NetworkNamespaceStoreError, NetworkPolicyCatalogV1,
    ProtectedNetworkPolicyErrorV1, claim_network_activation,
};

const STATE_ROOT: &str = "/var/lib/aos/sandbox-network/broker-state";
const MINIMUM_POLICY_GENERATION: u64 = 1;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
enum NetworkDaemonErrorV1 {
    #[error("usage: aos-netd MAXIMUM_RETAINED_NAMESPACES")]
    Arguments,
    #[error("Network broker must start with real and effective UID zero")]
    Identity,
    #[error("systemd authority credential directory is absent")]
    CredentialDirectory,
    #[error("Network activation failed: {0}")]
    Activation(#[from] ProductionBrokerSessionActivationErrorV1),
    #[error("Network policy failed: {0}")]
    Policy(#[from] ProtectedNetworkPolicyErrorV1),
    #[error("Network runtime failed: {0}")]
    Runtime(#[from] NetworkBrokerSessionRuntimeErrorV1),
    #[error("Network descriptor custody failed: {0}")]
    NamespaceStore(#[from] NetworkNamespaceStoreError),
    #[error("Network namespace inspection failed")]
    Namespace,
    #[error("Network deadline failed: {0}")]
    Deadline(#[from] ProductionBrokerDeadlineErrorV1),
    #[error("Network request failed: {0}")]
    Request(#[from] ProductionBrokerServiceErrorV1),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-netd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), NetworkDaemonErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(NetworkDaemonErrorV1::Identity);
    }

    let maximum_retained_namespaces = parse_capacity()?;

    // SAFETY: this is the single-threaded entrypoint before any descriptor is
    // opened. PID 1 exclusively transfers the listener and complete FD-store tail.
    let pending_activation = unsafe { claim_network_activation() }?;
    let host_namespace =
        NamespaceFd::current_network().map_err(|_| NetworkDaemonErrorV1::Namespace)?;
    let mut retained =
        pending_activation.classify(maximum_retained_namespaces, host_namespace.identity())?;
    let listener = retained.take_listener()?;
    let mut activation = ProductionBrokerSessionActivationV1::adopt_network_listener(listener)?;
    let authority_directory =
        env::var_os("CREDENTIALS_DIRECTORY").ok_or(NetworkDaemonErrorV1::CredentialDirectory)?;
    let policy = NetworkPolicyCatalogV1::load_protected_publication(
        Path::new(&authority_directory),
        MINIMUM_POLICY_GENERATION,
    )?;
    let mut network = NetworkBrokerSessionRuntimeV1::open_root_owned(
        Path::new(&authority_directory),
        Path::new(STATE_ROOT),
        policy,
        MINIMUM_POLICY_GENERATION,
        retained,
        host_namespace,
    )?;

    loop {
        let accept_deadline = production_deadline_after(ACCEPT_TIMEOUT)?;
        let session = match activation.accept_authenticated(accept_deadline) {
            Ok(session) => session,
            Err(ProductionBrokerSessionActivationErrorV1::Deadline) => continue,
            Err(error) => return Err(error.into()),
        };
        let request_deadline = production_deadline_after(REQUEST_TIMEOUT)?;
        let (mut callsite, catalog) = network.callsite_and_catalog();
        if let Err(error) =
            session.serve_production_network_request(&mut callsite, catalog, request_deadline)
        {
            // Request completion consumes session custody even on failure.
            // Reconnect and exact replay are the only continuation mechanism.
            eprintln!("aos-netd: authenticated request failed: {error}");
        }
    }
}

fn parse_capacity() -> Result<usize, NetworkDaemonErrorV1> {
    let mut arguments = env::args_os();
    let _program = arguments.next().ok_or(NetworkDaemonErrorV1::Arguments)?;
    let value = arguments.next().ok_or(NetworkDaemonErrorV1::Arguments)?;
    if arguments.next().is_some() {
        return Err(NetworkDaemonErrorV1::Arguments);
    }
    let value = value
        .to_str()
        .ok_or(NetworkDaemonErrorV1::Arguments)?
        .parse::<usize>()
        .map_err(|_| NetworkDaemonErrorV1::Arguments)?;
    if value == 0 || value > MAXIMUM_RETAINED_NETWORK_NAMESPACES {
        return Err(NetworkDaemonErrorV1::Arguments);
    }

    Ok(value)
}
