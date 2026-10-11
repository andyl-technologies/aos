//! Runs directly selected boot platform operations using exact retained tools.

#[path = "../boot_platform.rs"]
mod boot_platform;
#[path = "../boot_storage.rs"]
mod boot_storage;
#[path = "../image_profile.rs"]
mod image_profile;
#[path = "../recovery.rs"]
mod recovery;

fn main() {
    if let Err(error) = boot_platform::run_from_process() {
        eprintln!("aos-systemd-boot-platform: {error:#}");
        std::process::exit(1);
    }
}
