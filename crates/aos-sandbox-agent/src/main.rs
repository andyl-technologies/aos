//! Dormant independently packaged AOS sandbox guest-agent entry point.
//!
//! The executable accepts no caller-selected transport or path. Until a
//! protected launcher supplies the fixed inherited transport and provisioning
//! contract, it fails closed without opening a listener or reporting readiness.

use std::fmt;

use aos_sandbox_agent::{DormantGuestAgentServiceV1, dormant_guest_agent_main_v1};

struct ProtectedLauncherRequired;

impl DormantGuestAgentServiceV1 for ProtectedLauncherRequired {
    type Error = ProtectedLauncherRequiredError;

    fn run(&mut self) -> Result<(), Self::Error> {
        Err(ProtectedLauncherRequiredError)
    }
}

#[derive(Debug)]
struct ProtectedLauncherRequiredError;

impl fmt::Display for ProtectedLauncherRequiredError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("protected inherited guest-agent transport is absent")
    }
}

impl std::error::Error for ProtectedLauncherRequiredError {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut service = ProtectedLauncherRequired;
    dormant_guest_agent_main_v1(std::env::args_os(), &mut service)?;
    Ok(())
}
