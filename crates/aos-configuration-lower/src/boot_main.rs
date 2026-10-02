//! Mounts one native generation result during verified-image boot preparation.

use anyhow::{Result, ensure};
use aos_configuration_lower::{boot, lower::Tools};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-configuration-boot: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        arguments.len() == 3,
        "usage: aos-configuration-boot ROOT GENERATION DESTINATION"
    );
    let root = Path::new(&arguments[0]);
    ensure!(
        root == Path::new("/sysroot"),
        "configuration boot reader requires the verified sysroot"
    );
    let profile = root.join("var/lib/profiles/system");
    let binding = root.join("usr/lib/aos/configuration-lower-effect");
    let tools = Tools {
        mkfs: PathBuf::from(env!("AOS_MKFS_EROFS")),
        fsck: PathBuf::from(env!("AOS_FSCK_EROFS")),
    };
    boot::mount_generation(
        root,
        &profile,
        arguments[1].parse()?,
        &binding,
        Path::new(&arguments[2]),
        Path::new(env!("AOS_PACKAGE_RUNTIME")),
        Path::new(env!("AOS_MOUNT")),
        &tools,
    )
}
