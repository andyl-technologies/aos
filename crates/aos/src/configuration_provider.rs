//! Native entry point for configuration materialization abilities.

fn main() {
    if let Err(error) = aos_configuration_provider::run_from_process() {
        eprintln!("aos-configuration-provider: {error}");
        std::process::exit(1);
    }
}
