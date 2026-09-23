//! Runs the fixed, systemd-activated sandbox ownership authority.
//!
//! The service owns the protected lease journal and issuer inbox. It accepts
//! only the node controller's configured local identity and authenticates
//! every post-negotiation record with a separate systemd credential.

use std::process::ExitCode;

fn main() -> ExitCode {
    match aos_sandbox_broker_session_security::ownership_authority_runtime::run_from_environment() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-ownershipd: {error}");
            ExitCode::FAILURE
        }
    }
}
