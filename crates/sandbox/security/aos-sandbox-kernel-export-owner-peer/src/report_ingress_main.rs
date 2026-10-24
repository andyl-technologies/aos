//! One-shot, closed PREPARED map report ingress.
//!
//! The fixed socket and reporter cgroup are checked before one packet is
//! compared to a protected AOSKGH01 tuple. The accepted observation is dropped.
//! There is no Stage, ACTIVE, descriptor-release, or Apply operation here.

use std::error::Error;

use aos_sandbox_kernel_export_owner_peer::protected_report_ingress::ProtectedPreparedReportIngress;
use aos_sandbox_kernel_export_owner_peer::report_ingress_deployment::handoff_from_systemd_credential;
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;

fn main() {
    if let Err(error) = run() {
        eprintln!("kernel-export report ingress stopped closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args();
    let policy_path = match (args.next(), args.next(), args.next()) {
        (Some(_), Some(path), None) => path,
        _ => return Err("exact deployed SELinux policy path is required".into()),
    };

    // Claim the sole activation FD before opening the credential file.
    let mut ingress = ProtectedPreparedReportIngress::from_systemd_activation()?;
    let mac = VerifiedLiveSelinuxPolicy::verify(&policy_path)?;
    let handoff = handoff_from_systemd_credential()?;
    let _closed_observation = ingress.receive_once(&handoff)?;
    mac.revalidate(&policy_path)?;
    Ok(())
}
