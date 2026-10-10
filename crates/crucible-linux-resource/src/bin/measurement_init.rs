//! Runs the one original private measurement issuer as the disposable root PID1.

fn main() {
    if let Err(error) = crucible_linux_resource::measurement_origin::run_original_pid1() {
        eprintln!("measurement original issuer refused: {error}");
        // Exiting real PID1 terminates this disposable kernel and all children.
        // The enclosing VM owner must still join and retire its physical domain.
        std::process::exit(1);
    }
}
