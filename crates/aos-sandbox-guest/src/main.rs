//! Protected guest-agent executable with concrete local process effects.

use aos_sandbox_agent::dormant_guest_agent_main_v1;
use aos_sandbox_agent::protected_entry::ProtectedGuestAgentV1;
use aos_sandbox_guest::GuestProcessEffectsV1;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut selected_arguments = std::env::args_os().skip(1);
    if selected_arguments.next().as_deref() == Some(std::ffi::OsStr::new("--host-canary-readiness-v1")) {
        if selected_arguments.next().is_some() {
            return Err("selected Host canary Agent accepts only its fixed switch".into());
        }
        return aos_sandbox_agent::protected_entry::run_host_canary_readiness_v1();
    }

    let effects = GuestProcessEffectsV1::open()?;
    let mut service = ProtectedGuestAgentV1::new(effects);
    dormant_guest_agent_main_v1(std::env::args_os(), &mut service)?;
    Ok(())
}
