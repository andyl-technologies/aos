//! Runs the explicitly selected, independently provisioned online Resolve50 owner.
//!
//! The fixed service captures its complete original launch table before any
//! protected I/O. It does not initialize NV, import/build outputs or substitute
//! method46/offline approval for the distinct ONLINE058/059 purpose.

fn main() {
    if let Err(cause) = aos_sandbox_broker_session_security::nix_service::run_from_environment() {
        eprintln!("aos-sandbox-nixd: {cause}");
        std::process::exit(1);
    }
}
