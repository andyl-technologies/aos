//! Runs the retained AOS boot measurement operation.

fn main() {
    if let Err(error) = aos_boot_runtime::commands::run_boot_measurements() {
        eprintln!("aos-systemd-boot-measurements: {error:#}");
        std::process::exit(1);
    }
}
