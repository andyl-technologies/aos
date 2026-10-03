//! Protected guest-agent executable with concrete local process effects.

use aos_sandbox_agent::dormant_guest_agent_main_v1;
use aos_sandbox_agent::protected_entry::ProtectedGuestAgentV1;
use aos_sandbox_guest::GuestProcessEffectsV1;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let effects = GuestProcessEffectsV1::open()?;
    let mut service = ProtectedGuestAgentV1::new(effects);
    dormant_guest_agent_main_v1(std::env::args_os(), &mut service)?;
    Ok(())
}
