//! Runs the retained AOS boot platform operation.

fn main() {
    if let Err(error) = aos_boot_runtime::commands::run_boot_platform() {
        eprintln!("aos-systemd-boot-platform: {error:#}");
        std::process::exit(1);
    }
}
