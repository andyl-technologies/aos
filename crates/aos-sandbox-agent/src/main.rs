//! Independently packaged AOS sandbox guest-agent entry point.
//!
//! The executable accepts no caller-selected transport or path. It claims only
//! the protected launcher's fixed inherited channel and sealed provisioning.

#[cfg(not(target_os = "linux"))]
use aos_sandbox_agent::DormantGuestAgentServiceV1;
use aos_sandbox_agent::dormant_guest_agent_main_v1;

#[cfg(target_os = "linux")]
use aos_sandbox_agent::protected_entry::{ProtectedGuestAgentV1, RejectingGuestEffectsV1};

#[cfg(not(target_os = "linux"))]
struct UnsupportedPlatform;

#[cfg(not(target_os = "linux"))]
impl DormantGuestAgentServiceV1 for UnsupportedPlatform {
    type Error = std::io::Error;

    fn run(&mut self) -> Result<(), Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "protected guest-agent entry requires Linux",
        ))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    let mut service = ProtectedGuestAgentV1::new(RejectingGuestEffectsV1::default());
    #[cfg(not(target_os = "linux"))]
    let mut service = UnsupportedPlatform;

    dormant_guest_agent_main_v1(std::env::args_os(), &mut service)?;
    Ok(())
}
