//! Runs the closed private actor under its consumed authentic original issuer.

fn main() {
    if let Err(error) = crucible_daemon::private_measurement_runtime::run_original_actor() {
        eprintln!("measurement original actor refused: {error}");
        std::process::exit(1);
    }
}
