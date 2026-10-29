//! Unattended installation of a signed AOS release image from boot media.
//!
//! An AOS installer stick boots a signed installer UKI whose initrd runs the
//! same detect, acquire, authorize, and evaluate operations as a normal first
//! boot, against the `host.nix` on the stick's `AOS-META` partition. Instead
//! of provisioning storage, it hands the evaluated plans to this handler,
//! which:
//!
//! 1. requires `aos.provisioning.install.mode = "unattended"`;
//! 2. verifies the db-signed release payload on the `aos-payload` partition;
//! 3. checks the target disk ([`target`]) and every secondary storage device;
//! 4. counts down on the console, then streams the decompressed image onto
//!    the target and verifies it by reading it back;
//! 5. relocates the backup GPT header to the end of the target; and
//! 6. makes the installed disk the next firmware boot target ([`firmware`]).
//!
//! The installer never partitions or formats storage. The installed system's
//! own first boot does that from the same `host.nix`, which it reads from the
//! still-attached stick.
//!
//! # Modules
//!
//! - [`payload`] verifies the signed release payload.
//! - [`target`] resolves and checks the disk that is erased.
//! - [`firmware`] creates the boot entry and sets `BootNext`.
//! - [`console`] reports progress to the operator.

#![forbid(unsafe_code)]

pub mod console;
pub mod firmware;
pub mod payload;
pub mod target;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail, ensure};
use aos_activation::activation::{Action, Invocation};
use aos_boot_media::trust::DbTrust;
use aos_boot_media::{Tools, block, device};
use aos_storage_layout::CanonicalProvisioningPlan;
use aos_storage_layout::install::{InstallPlan, validate_install_intent};
use serde::Deserialize;
use serde_json::json;

/// GPT label of the installer media's release payload partition.
pub const PAYLOAD_LABEL: &str = "aos-payload";

const WORK_DIR: &str = "/run/aos-installer";
const PAYLOAD_MOUNT: &str = "/run/aos-installer/payload";

/// Exact helper executables, supplied as store paths by the installer module.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallerTools {
    blkid: PathBuf,
    mount: PathBuf,
    umount: PathBuf,
    openssl: PathBuf,
    zstd: PathBuf,
    sgdisk: PathBuf,
    udevadm: PathBuf,
    efibootmgr: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    install_plan: InstallPlan,
    provisioning_plan: CanonicalProvisioningPlan,
    trust_bundle: PathBuf,
    countdown_seconds: u64,
    tools: InstallerTools,
}

/// Executes one native invocation of the installation operation.
///
/// `action` is the controller's dispatch verb. `observe` reports whether the
/// target can safely receive a replayed installation; `apply` installs.
///
/// # Errors
///
/// Returns an error for a malformed invocation, a disabled or invalid install
/// plan, an unverifiable payload, an unsafe target, or any failed write.
pub fn handle(action: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let invocation: Invocation = serde_json::from_slice(bytes)?;
    ensure!(
        matches!(action, "apply" | "observe")
            && (action == "observe" || invocation.action == Action::Apply),
        "installation supports only apply and observe"
    );
    let input: Input = serde_json::from_value(invocation.input.clone())?;

    if action == "observe" {
        // A target that already carries AOS partitions may hold a partial
        // write from an interrupted attempt; never replay onto it.
        let status = match input.install_plan.target_device.as_deref() {
            Some(target) if target_is_untouched(target) => "retry-safe",
            _ => "indeterminate",
        };
        return Ok(serde_json::to_vec(&json!({"status": status}))?);
    }

    let outputs = install(&input, &invocation.id).inspect_err(|error| {
        console::say(&format!("installation failed: {error:#}"));
        console::say("no reboot will occur; the target disk may need to be wiped before retrying");
    })?;
    Ok(serde_json::to_vec(&outputs)?)
}

fn install(input: &Input, resource: &str) -> Result<serde_json::Value> {
    // The evaluator validated this record; installation re-checks the exact
    // value it is about to act on.
    let Some(target_path) = validate_install_intent(&input.install_plan)? else {
        bail!(
            "host.nix on the AOS-META partition does not enable unattended installation; \
             set aos.provisioning.install.mode = \"unattended\" and targetDevice"
        );
    };

    let tools = Tools {
        blkid: input.tools.blkid.clone(),
        openssl: input.tools.openssl.clone(),
        // Payload verification checks a detached signature only.
        sbverify: PathBuf::new(),
    };
    let trust = DbTrust {
        bundle: input.trust_bundle.clone(),
        work_dir: PathBuf::from(WORK_DIR).join("trust"),
    };

    console::say("verifying the signed release payload");
    let payload_partition = device::unique_device(&tools.blkid, "PARTLABEL", PAYLOAD_LABEL)?;
    let mut media_disks = vec![device::disk_of(&payload_partition)?];
    for metadata in device::matching_devices(&tools.blkid, "LABEL", "AOS-META")? {
        media_disks.push(device::disk_of(&metadata)?);
    }
    mount_read_only(&input.tools.mount, &payload_partition, Path::new(PAYLOAD_MOUNT))?;
    let result = install_from_payload(input, &tools, &trust, target_path, &media_disks, resource);
    let unmounted = Command::new(&input.tools.umount).arg(PAYLOAD_MOUNT).status();
    let outputs = result?;
    ensure!(
        unmounted.is_ok_and(|status| status.success()),
        "the payload partition could not be unmounted"
    );
    Ok(outputs)
}

fn install_from_payload(
    input: &Input,
    tools: &Tools,
    trust: &DbTrust,
    target_path: &str,
    media_disks: &[PathBuf],
    resource: &str,
) -> Result<serde_json::Value> {
    // Release platforms are named `<architecture>-linux`, as in Nix.
    let platform = format!("{}-linux", std::env::consts::ARCH);
    let payload = payload::verify(tools, trust, Path::new(PAYLOAD_MOUNT), &platform)?;
    target::require_secondary_devices(&input.provisioning_plan)?;
    let required = target::required_bytes(payload.disk_byte_size, &input.provisioning_plan)?;
    let target = target::resolve(target_path, media_disks, required)?;

    console::say(&format!(
        "release {} will be installed to {} ({}, {} bytes)",
        payload.release,
        target.stable_path,
        if target.model.is_empty() { "unknown model" } else { &target.model },
        target.capacity,
    ));
    console::say("every partition and file on that disk will be destroyed");
    console::countdown(input.countdown_seconds, "erasing the target disk");

    console::say("writing the release image");
    let mut decompressor = Command::new(&input.tools.zstd)
        .arg("-dc")
        .arg(&payload.disk_image)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting zstd")?;
    let stream = decompressor
        .stdout
        .take()
        .context("zstd stdout was not created")?;
    let mut stream = console::Progress::new(stream, payload.disk_byte_size);
    let written = block::write_verified(
        tools,
        &mut stream,
        &target.device,
        payload.disk_byte_size,
        &payload.disk_sha256,
    );
    drop(stream);
    let decompressed = decompressor.wait_with_output()?;
    written?;
    ensure!(
        decompressed.status.success(),
        "zstd failed: {}",
        String::from_utf8_lossy(&decompressed.stderr).trim()
    );
    console::say("image written and verified by read-back");

    relocate_backup_gpt(&input.tools, &target.device)?;
    let esp = esp_partition_number(&target.sysfs)?;
    match firmware::boot_next(&input.tools.efibootmgr, &input.tools.mount, &target.device, esp) {
        Ok(entry) => console::say(&format!("firmware entry Boot{entry} selected for the next boot")),
        // The installed disk is complete. Without a firmware entry the media
        // boots again, finds the AOS layout, and refuses to reinstall.
        Err(error) => console::say(&format!(
            "could not select the installed disk in firmware ({error:#}); \
             choose it in the firmware boot menu"
        )),
    }
    console::say("installation complete; first boot reads host.nix from this media");

    Ok(json!({
        "resource": resource,
        "release": payload.release,
        "target": target.stable_path,
    }))
}

fn mount_read_only(mount: &Path, device: &Path, mountpoint: &Path) -> Result<()> {
    fs::create_dir_all(mountpoint)?;
    let output = Command::new(mount)
        .args(["-o", "ro,nodev,nosuid,noexec"])
        .arg(device)
        .arg(mountpoint)
        .output()
        .context("mounting the payload partition")?;
    ensure!(
        output.status.success(),
        "the payload partition could not be mounted: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn relocate_backup_gpt(tools: &InstallerTools, disk: &Path) -> Result<()> {
    let output = Command::new(&tools.sgdisk)
        .arg("-e")
        .arg(disk)
        .output()
        .context("running sgdisk -e")?;
    ensure!(
        output.status.success(),
        "sgdisk could not relocate the backup GPT header: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let settled = Command::new(&tools.udevadm)
        .args(["settle", "--timeout=30"])
        .status()
        .context("running udevadm settle")?;
    ensure!(settled.success(), "udev did not settle after repartitioning");
    Ok(())
}

fn esp_partition_number(disk: &Path) -> Result<u32> {
    for partition in device::partitions(disk)? {
        let uevent = fs::read_to_string(partition.join("uevent"))?;
        if uevent.lines().any(|line| line == "PARTNAME=ESP") {
            return Ok(fs::read_to_string(partition.join("partition"))?
                .trim()
                .parse()?);
        }
    }
    bail!("the written image has no ESP partition")
}

fn target_is_untouched(stable_path: &str) -> bool {
    let Ok(device) = fs::canonicalize(stable_path) else {
        return false;
    };
    let Ok(disk) = device::disk_of(&device) else {
        return false;
    };
    device::partitions(&disk).is_ok_and(|partitions| {
        partitions.iter().all(|partition| {
            fs::read_to_string(partition.join("uevent")).is_ok_and(|uevent| {
                !uevent.lines().any(|line| {
                    line.strip_prefix("PARTNAME=")
                        .is_some_and(|label| device::INSTALLED_PARTITION_LABELS.contains(&label))
                })
            })
        })
    })
}
