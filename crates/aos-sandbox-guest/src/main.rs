//! Protected guest-agent executable with concrete local process effects.

use aos_sandbox_guest::dormant_guest_agent_main_v1;
use aos_sandbox_guest::protected_entry::ProtectedGuestAgentV1;
use aos_sandbox_guest::GuestProcessEffectsV1;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut selected_arguments = std::env::args_os().skip(1);
    if selected_arguments.next().as_deref() == Some(std::ffi::OsStr::new("--host-canary-readiness-v1")) {
        if selected_arguments.next().is_some() {
            return Err("selected Host canary Agent accepts only its fixed switch".into());
        }
        return aos_sandbox_guest::protected_entry::run_host_canary_readiness_v1();
    }

    let effects = match GuestProcessEffectsV1::open() {
        Ok(effects) => effects,
        Err(error) if error.requires_original_guardian_hold_v1() => {
            eprintln!("guest-agent startup remains occupied: {error}");
            // The same pre-thread main retains the entire failed owner. Only
            // the original Host startup Guardian may dispose of this Guest.
            let _original = error;
            loop { std::thread::park(); }
        }
        Err(error) => return Err(error),
    };
    let mut service = ProtectedGuestAgentV1::with_original_process_owner_v1(effects);
    if let Err(error) = dormant_guest_agent_main_v1(std::env::args_os(), &mut service) {
        if let Some(cause) = service.capture_failure() {
            // Keep actual received/failed process owners resident while the
            // installed diagnostic borrows their chronological native cause.
            eprintln!("guest-agent Capture failed: {cause}");
            std::process::exit(1);
        }
        return Err(error.into());
    }
    Ok(())
}
