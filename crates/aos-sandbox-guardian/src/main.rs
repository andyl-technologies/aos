//! Runs one capability-less per-assignment ownership guardian.

fn main() {
    if let Err(error) = aos_sandbox_guardian::run_from_environment() {
        eprintln!("aos-sandbox-lease-guard failed: {error}");
        std::process::exit(1);
    }
}
