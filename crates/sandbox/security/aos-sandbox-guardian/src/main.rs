//! Runs one capability-less per-assignment ownership guardian.

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next();
    let extra = arguments.next();
    let result = match (mode.as_deref(), extra) {
        (None, None) => aos_sandbox_guardian::run_from_environment(),
        (Some(mode), None) if mode == aos_sandbox_guardian::PINNED_ACTIVATION_ARGUMENT => {
            aos_sandbox_guardian::exec_pinned_activation()
        }
        _ => Err(aos_sandbox_guardian::GuardianRuntimeError::InvalidActivation),
    };

    if let Err(error) = result {
        eprintln!("aos-sandbox-lease-guard failed: {error}");
        std::process::exit(1);
    }
}
