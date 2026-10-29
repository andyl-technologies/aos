//! UEFI boot-entry handoff from installer media to the installed disk.
//!
//! After the image is written, the installer registers the target's ESP
//! fallback loader as a firmware boot entry, places it first in `BootOrder`,
//! and sets `BootNext`. The next reset therefore starts the installed system
//! even though the installer media is still attached for first-boot
//! provisioning. systemd-boot's own one-shot variables cannot do this: they
//! select an entry inside the boot manager that is already running, which is
//! the one on the installer media.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};

const EFIVARS: &str = "/sys/firmware/efi/efivars";
const ENTRY_LABEL: &str = "AOS";

/// Returns the removable-media fallback loader path for this architecture.
///
/// # Errors
///
/// Returns an error on an architecture AOS does not install.
pub fn fallback_loader() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(r"\EFI\BOOT\BOOTX64.EFI"),
        "aarch64" => Ok(r"\EFI\BOOT\BOOTAA64.EFI"),
        other => bail!("no UEFI fallback loader is defined for {other}"),
    }
}

/// Creates a first-priority boot entry for `disk` and selects it for the next boot.
///
/// `esp_partition` is the ESP's partition number on `disk`.
///
/// # Errors
///
/// Returns an error when the firmware exposes no EFI variables or
/// `efibootmgr` cannot create and select the entry.
pub fn boot_next(efibootmgr: &Path, mount: &Path, disk: &Path, esp_partition: u32) -> Result<String> {
    ensure_efivars(mount)?;
    let before = entries(efibootmgr)?;

    let output = Command::new(efibootmgr)
        .arg("--create")
        .arg("--disk")
        .arg(disk)
        .arg("--part")
        .arg(esp_partition.to_string())
        .args(["--label", ENTRY_LABEL, "--loader", fallback_loader()?])
        .output()
        .context("running efibootmgr --create")?;
    ensure!(
        output.status.success(),
        "efibootmgr could not create the boot entry: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );

    let after = entries(efibootmgr)?;
    let created = after
        .difference(&before)
        .next()
        .cloned()
        .context("efibootmgr reported no new boot entry")?;
    let status = Command::new(efibootmgr)
        .args(["--bootnext", &created])
        .output()
        .context("running efibootmgr --bootnext")?;
    ensure!(
        status.status.success(),
        "efibootmgr could not set BootNext: {}",
        String::from_utf8_lossy(&status.stderr).trim()
    );
    Ok(created)
}

fn ensure_efivars(mount: &Path) -> Result<()> {
    ensure!(
        Path::new("/sys/firmware/efi").is_dir(),
        "the machine did not boot through UEFI"
    );
    if fs::read_dir(EFIVARS).is_ok_and(|mut entries| entries.next().is_some()) {
        return Ok(());
    }
    let status = Command::new(mount)
        .args(["-t", "efivarfs", "efivarfs", EFIVARS])
        .status()
        .context("mounting efivarfs")?;
    ensure!(status.success(), "efivarfs could not be mounted");
    Ok(())
}

/// Lists the four-digit hexadecimal identities of every `BootXXXX` entry.
fn entries(efibootmgr: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new(efibootmgr)
        .output()
        .context("running efibootmgr")?;
    ensure!(
        output.status.success(),
        "efibootmgr could not list boot entries: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(parse_entries(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_entries(listing: &str) -> BTreeSet<String> {
    listing
        .lines()
        .filter_map(|line| line.strip_prefix("Boot"))
        .filter_map(|rest| rest.get(..4).map(|id| (id, &rest[4..])))
        .filter(|(id, rest)| {
            id.bytes().all(|byte| byte.is_ascii_hexdigit())
                && (rest.starts_with('*') || rest.starts_with(' '))
        })
        .map(|(id, _)| id.to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_entries;

    #[test]
    fn only_numbered_boot_entries_are_listed() {
        let listing = "BootCurrent: 0001\nTimeout: 0 seconds\nBootOrder: 0003,0001\n\
                       Boot0001* UEFI QEMU HARDDISK\tPciRoot(0x0)\nBoot0003  AOS\tHD(1)\n";
        let entries = parse_entries(listing);
        assert_eq!(
            entries.into_iter().collect::<Vec<_>>(),
            vec!["0001".to_owned(), "0003".to_owned()]
        );
    }
}
