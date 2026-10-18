//! Runs bounded component witnesses over the real native cache owner in a guest.
//!
//! Each role starts in a fresh process with no capabilities or inherited cache
//! descriptors. Confinement precedes every executor and owner thread. Successful
//! empty recovery is not Resume, serving readiness, admission or BKT-15 proof.

#[path = "host_cache_fixture/actor.rs"]
mod actor;
#[path = "host_cache_fixture/admission.rs"]
mod admission;
#[path = "host_cache_fixture/config.rs"]
mod config;
#[path = "host_cache_fixture/recovery.rs"]
mod recovery;

fn main() -> std::process::ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "--list" {
        for selector in [
            "prepare",
            "empty",
            "refuse",
            "late-refuse",
            "cancel",
            "edquot",
            "hold",
            "start-refuse",
            "admit-chunk",
            "admit-metadata",
            "admit-cancel",
            "seed-manifest",
            "seed-bad-manifest",
            "recover-manifest",
            "refuse-manifest",
        ] {
            println!("host-cache:{selector}");
        }
        return std::process::ExitCode::SUCCESS;
    }
    let result = if matches!(mode.as_str(), "seed-manifest" | "seed-bad-manifest") {
        recovery::seed(&mode)
    } else {
        actor::run(&mode)
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host-cache component proof: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
