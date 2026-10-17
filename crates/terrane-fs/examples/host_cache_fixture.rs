//! Runs bounded component witnesses over the real native cache owner in a guest.
//!
//! Each role starts in a fresh process with no capabilities or inherited cache
//! descriptors. Confinement precedes every executor and owner thread. Successful
//! empty recovery is not Resume, serving readiness, admission or BKT-15 proof.

#[path = "host_cache_fixture/actor.rs"]
mod actor;
#[path = "host_cache_fixture/config.rs"]
mod config;

fn main() -> std::process::ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "--list" {
        for selector in [
            "prepare",
            "empty",
            "refuse",
            "cancel",
            "edquot",
            "hold",
            "start-refuse",
        ] {
            println!("host-cache:{selector}");
        }
        return std::process::ExitCode::SUCCESS;
    }
    match actor::run(&mode) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host-cache component proof: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
