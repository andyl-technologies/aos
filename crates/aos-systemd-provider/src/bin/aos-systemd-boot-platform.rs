//! Runs directly selected boot platform operations using exact retained tools.

#[path = "../boot_platform.rs"]
mod boot_platform;

fn main() {
    if let Err(error) = boot_platform::run_from_process() {
        eprintln!("aos-systemd-boot-platform: {error:#}");
        std::process::exit(1);
    }
}
