//! Read-only qualification observer for configuration materialization.

fn main() {
    if let Err(error) = aos_configuration_provider::run_observer_from_process() {
        eprintln!("aos-configuration-observer: {error}");
        std::process::exit(1);
    }
}
