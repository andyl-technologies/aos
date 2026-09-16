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
use aos_sandbox_network::{
    NetworkBrokerSessionRuntimeErrorV1, NetworkBrokerSessionRuntimeV1, NetworkPolicyCatalogV1,
    ProtectedNetworkPolicyErrorV1,
};

const STATE_ROOT: &str = "/var/lib/aos/sandbox-network/broker-state";
const MINIMUM_POLICY_GENERATION: u64 = 1;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
enum NetworkDaemonErrorV1 {
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

    // SAFETY: this is the single-threaded entrypoint before any descriptor is
    // opened. PID 1 exclusively transfers the sole fixed Network listener.
    let mut activation = unsafe { ProductionBrokerSessionActivationV1::adopt_network() }?;
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
