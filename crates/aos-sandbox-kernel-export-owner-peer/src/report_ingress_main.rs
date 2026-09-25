//! One-shot, closed PREPARED map report ingress.
//!
//! The fixed socket and reporter cgroup are checked before one packet is
//! compared to a protected AOSKGH01 tuple. The accepted observation is dropped.
//! There is no Stage, ACTIVE, descriptor-release, or Apply operation here.

use std::error::Error;

use aos_sandbox_kernel_export_owner_peer::protected_report_ingress::ProtectedPreparedReportIngress;
use aos_sandbox_kernel_export_owner_peer::report_ingress_deployment::handoff_from_systemd_credential;

fn main() {
    if let Err(error) = run() {
        eprintln!("kernel-export report ingress stopped closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    // Claim the sole activation FD before opening the credential file.
    let mut ingress = ProtectedPreparedReportIngress::from_systemd_activation()?;
    let handoff = handoff_from_systemd_credential()?;
    let _closed_observation = ingress.receive_once(&handoff)?;
    Ok(())
}
