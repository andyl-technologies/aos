//! Local QEMU lifecycle for downloaded AOS UEFI disk images.
//!
//! The runner preserves the downloaded image as an immutable input. It creates
//! a sparse raw working disk, extends its GPT to the requested capacity, keeps
//! one writable OVMF variable store per VM, and optionally delivers literal
//! `host.nix` through QEMU's native fw_cfg metadata channel.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::cli::{VmAcceleration, VmCommand, VmRunArgs};

const GIB: u64 = 1024 * 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Deserialize, Serialize)]
struct VmStateManifest {
    schema_version: u32,
    base_image: PathBuf,
    base_sha256: String,
    disk_size_bytes: u64,
}

/// Runs an `aos vm` command.
///
/// # Errors
///
/// Returns an error when an input is unsafe, a required host tool or firmware
/// image is unavailable, VM state cannot be prepared, or QEMU exits
/// unsuccessfully.
pub fn run(command: &VmCommand, printer: &Printer) -> Result<()> {
    match command {
        VmCommand::Run(args) => run_image(args, printer),
    }
}

fn run_image(args: &VmRunArgs, printer: &Printer) -> Result<()> {
    validate_args(args)?;
    let image = canonical_regular_file(&args.image, "image")?;
    let host_config = args
        .host_config
        .as_deref()
        .map(|path| canonical_regular_file(path, "host configuration"))
        .transpose()?;
    let host_config_signature = args
        .host_config_signature
        .as_deref()
        .map(|path| canonical_regular_file(path, "host configuration signature"))
        .transpose()?;
    let name = resolve_name(args, &image)?;
    let state_dir = resolve_state_dir(args, &name)?;
    let acceleration = resolve_acceleration(args.accel, printer)?;
    let qemu = find_executable("qemu-system-x86_64")?;
    let qemu_img = find_executable("qemu-img")?;
    let sgdisk = find_executable("sgdisk")?;
    let firmware_code = resolve_firmware(
        args.firmware_code.as_deref(),
        "AOS_OVMF_CODE",
        &[
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/edk2/x64/OVMF_CODE.fd",
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        ],
    )?;
    let firmware_vars_template = resolve_firmware(
        args.firmware_vars.as_deref(),
        "AOS_OVMF_VARS",
        &[
            "/usr/share/OVMF/OVMF_VARS.fd",
            "/usr/share/edk2/x64/OVMF_VARS.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ],
    )?;
    let disk = state_dir.join("disk.img");
    let partial_disk = state_dir.join(".disk.img.aos-part");
    let firmware_vars = state_dir.join("OVMF_VARS.fd");
    let manifest_path = state_dir.join("vm-state.json");
    let disk_bytes = args
        .disk_size_gib
        .checked_mul(GIB)
        .context("virtual disk size overflow")?;

    print_plan(
        args,
        &image,
        &state_dir,
        &disk,
        &firmware_code,
        &firmware_vars,
        host_config.as_deref(),
        host_config_signature.as_deref(),
        acceleration,
        printer,
    );
    if args.dry_run {
        return Ok(());
    }

    fs::create_dir_all(&state_dir)
        .with_context(|| format!("creating VM state directory {}", state_dir.display()))?;
    let base_sha256 = hash_file(&image, printer)?;
    if !disk.exists() {
        if manifest_path.exists() {
            bail!(
                "VM state {} has metadata but no disk; remove that state directory or choose another --name",
                state_dir.display()
            );
        }
        let activity = printer.activity("Converting the verified image to a writable disk...");
        run_checked(
            Command::new(&qemu_img)
                .arg("convert")
                .arg("-O")
                .arg("raw")
                .arg(&image)
                .arg(&partial_disk),
            "converting the downloaded image",
        )?;
        fs::OpenOptions::new()
            .write(true)
            .open(&partial_disk)
            .with_context(|| format!("opening {}", partial_disk.display()))?
            .set_len(disk_bytes)
            .with_context(|| format!("extending {}", partial_disk.display()))?;
        run_checked(
            Command::new(&sgdisk).arg("-e").arg(&partial_disk),
            "relocating the backup GPT",
        )?;
        fs::rename(&partial_disk, &disk).with_context(|| {
            format!(
                "installing prepared disk {} as {}",
                partial_disk.display(),
                disk.display()
            )
        })?;
        write_manifest(
            &manifest_path,
            &VmStateManifest {
                schema_version: 1,
                base_image: image.clone(),
                base_sha256,
                disk_size_bytes: disk_bytes,
            },
        )?;
        activity.finish();
        printer.success("Prepared writable VM disk");
    } else {
        validate_existing_state(&manifest_path, &image, &base_sha256, disk_bytes)?;
        printer.info(&format!("Reusing writable disk {}", disk.display()));
    }
    if !firmware_vars.exists() {
        fs::copy(&firmware_vars_template, &firmware_vars).with_context(|| {
            format!(
                "copying {} to {}",
                firmware_vars_template.display(),
                firmware_vars.display()
            )
        })?;
    }

    printer.success(&format!(
        "Starting {name}; SSH forwards from 127.0.0.1:{}",
        args.ssh_port
    ));
    let mut command = qemu_command(
        args,
        &qemu,
        &disk,
        &firmware_code,
        &firmware_vars,
        host_config.as_deref(),
        host_config_signature.as_deref(),
        acceleration,
    );
    let status = command.status().context("starting QEMU")?;
    if !status.success() {
        bail!("QEMU exited with {}", display_status(status));
    }
    Ok(())
}

fn validate_args(args: &VmRunArgs) -> Result<()> {
    if args.disk_size_gib < 8 {
        bail!("--disk-size-gib must be at least 8 for AOS first-boot state");
    }
    if args.memory_mib < 512 {
        bail!("--memory-mib must be at least 512");
    }
    if args.cpus == 0 {
        bail!("--cpus must be greater than zero");
    }
    Ok(())
}

fn resolve_name(args: &VmRunArgs, image: &Path) -> Result<String> {
    let candidate = args.name.as_deref().unwrap_or_else(|| {
        image
            .file_stem()
            .and_then(OsStr::to_str)
            .unwrap_or("aos-vm")
    });
    if candidate.is_empty()
        || candidate.len() > 64
        || !candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("VM name must contain only ASCII letters, digits, '-' or '_'");
    }
    Ok(candidate.to_string())
}

fn resolve_state_dir(args: &VmRunArgs, name: &str) -> Result<PathBuf> {
    if let Some(path) = &args.state_dir {
        return absolute_path(path);
    }
    let base = if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(path)
    } else {
        let home = std::env::var_os("HOME").context(
            "HOME is unset; provide --state-dir or set XDG_STATE_HOME for persistent VM state",
        )?;
        PathBuf::from(home).join(".local/state")
    };
    Ok(base.join("aos/vms").join(name))
}

fn resolve_acceleration(requested: VmAcceleration, printer: &Printer) -> Result<&'static str> {
    let kvm_available = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    match requested {
        VmAcceleration::Auto | VmAcceleration::Kvm if kvm_available => Ok("kvm"),
        VmAcceleration::Tcg => Ok("tcg"),
        VmAcceleration::Auto => {
            printer.warning(
                "KVM is unavailable because /dev/kvm is inaccessible; using slower TCG emulation",
            );
            Ok("tcg")
        }
        VmAcceleration::Kvm => bail!("--accel kvm requires an accessible /dev/kvm"),
    }
}

fn resolve_firmware(
    explicit: Option<&Path>,
    variable: &str,
    candidates: &[&str],
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return canonical_regular_file(path, "firmware");
    }
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.is_file() {
            return canonical_regular_file(path, "firmware");
        }
    }
    bail!(
        "could not find OVMF firmware; set {variable} or pass the corresponding --firmware option"
    )
}

#[allow(clippy::too_many_arguments)]
fn print_plan(
    args: &VmRunArgs,
    image: &Path,
    state_dir: &Path,
    disk: &Path,
    firmware_code: &Path,
    firmware_vars: &Path,
    host_config: Option<&Path>,
    host_config_signature: Option<&Path>,
    acceleration: &str,
    printer: &Printer,
) {
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "image": image,
            "state_dir": state_dir,
            "disk": disk,
            "disk_size_gib": args.disk_size_gib,
            "cpus": args.cpus,
            "memory_mib": args.memory_mib,
            "acceleration": acceleration,
            "firmware_code": firmware_code,
            "firmware_vars": firmware_vars,
            "ssh": { "host": "127.0.0.1", "host_port": args.ssh_port, "guest_port": 22 },
            "host_config": host_config,
            "host_config_signature": host_config_signature,
            "dry_run": args.dry_run,
        }));
        return;
    }
    printer.header("AOS virtual machine");
    printer.kv("Image", &image.display().to_string());
    printer.kv("State", &state_dir.display().to_string());
    printer.kv(
        "Disk",
        &format!("{} ({} GiB)", disk.display(), args.disk_size_gib),
    );
    printer.kv("CPUs", &args.cpus.to_string());
    printer.kv("Memory", &format!("{} MiB", args.memory_mib));
    printer.kv("Acceleration", acceleration);
    printer.kv("Firmware code", &firmware_code.display().to_string());
    printer.kv("Firmware state", &firmware_vars.display().to_string());
    printer.kv("SSH", &format!("127.0.0.1:{} -> guest:22", args.ssh_port));
    if let Some(host_config) = host_config {
        printer.kv("Configuration", &host_config.display().to_string());
    }
    if let Some(signature) = host_config_signature {
        printer.kv("Configuration signature", &signature.display().to_string());
    }
}

#[allow(clippy::too_many_arguments)]
fn qemu_command(
    args: &VmRunArgs,
    qemu: &Path,
    disk: &Path,
    firmware_code: &Path,
    firmware_vars: &Path,
    host_config: Option<&Path>,
    host_config_signature: Option<&Path>,
    acceleration: &str,
) -> Command {
    let mut command = Command::new(qemu);
    command
        .arg("-machine")
        .arg(format!("q35,smm=on,accel={acceleration}"))
        .arg("-cpu")
        .arg(if acceleration == "kvm" { "host" } else { "max" })
        .arg("-m")
        .arg(args.memory_mib.to_string())
        .arg("-smp")
        .arg(args.cpus.to_string())
        .arg("-nographic")
        .arg("-global")
        .arg("driver=cfi.pflash01,property=secure,value=on")
        .arg("-global")
        .arg("ICH9-LPC.disable_s3=1")
        .arg("-drive")
        .arg(format!(
            "if=pflash,unit=0,format=raw,readonly=on,file={}",
            firmware_code.display()
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,unit=1,format=raw,file={}",
            firmware_vars.display()
        ))
        .arg("-drive")
        .arg(format!("file={},format=raw,if=virtio", disk.display()))
        .arg("-nic")
        .arg(format!(
            "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{}-:22",
            args.ssh_port
        ))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(host_config) = host_config {
        command.arg("-fw_cfg").arg(format!(
            "name=opt/org.andyl/host-nix,file={}",
            host_config.display()
        ));
    }
    if let Some(signature) = host_config_signature {
        command.arg("-fw_cfg").arg(format!(
            "name=opt/org.andyl/host-nix.sig,file={}",
            signature.display()
        ));
    }
    command
}

fn hash_file(path: &Path, printer: &Printer) -> Result<String> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let total = file
        .metadata()
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .len();
    let progress = printer.transfer("Checking base image identity", total);
    let mut reader = BufReader::with_capacity(COPY_BUFFER_SIZE, file);
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    let mut hasher = Sha256::new();
    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        progress.inc(count as u64);
    }
    progress.finish();
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_manifest(path: &Path, manifest: &VmStateManifest) -> Result<()> {
    let temporary = path.with_extension("json.aos-part");
    let encoded = serde_json::to_vec_pretty(manifest).context("encoding VM state metadata")?;
    fs::write(&temporary, encoded).with_context(|| format!("writing {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("installing VM state metadata {}", path.display()))
}

fn validate_existing_state(
    manifest_path: &Path,
    image: &Path,
    image_sha256: &str,
    disk_size_bytes: u64,
) -> Result<()> {
    let encoded = fs::read(manifest_path).with_context(|| {
        format!(
            "reading {}; existing VM disks without identity metadata are not reused",
            manifest_path.display()
        )
    })?;
    let manifest: VmStateManifest = serde_json::from_slice(&encoded)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    if manifest.schema_version != 1 {
        bail!(
            "VM state {} uses unsupported metadata schema {}",
            manifest_path.display(),
            manifest.schema_version
        );
    }
    if manifest.base_sha256 != image_sha256 {
        bail!(
            "VM state is bound to a different base image (recorded {}, selected {}); choose another --name or --state-dir",
            manifest.base_image.display(),
            image.display()
        );
    }
    if manifest.disk_size_bytes != disk_size_bytes {
        bail!(
            "VM state disk size is {} bytes, but {} bytes was requested; keep the original size or choose another --name",
            manifest.disk_size_bytes,
            disk_size_bytes
        );
    }
    Ok(())
}

fn find_executable(name: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("PATH is unset")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("required host tool '{name}' was not found on PATH")
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolving {label} {}", path.display()))?;
    if !canonical.is_file() {
        bail!("{label} {} is not a regular file", canonical.display());
    }
    Ok(canonical)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("resolving current directory")?
            .join(path))
    }
}

fn run_checked(command: &mut Command, operation: &str) -> Result<()> {
    let status = command.status().with_context(|| operation.to_string())?;
    if !status.success() {
        bail!("{operation} failed with {}", display_status(status));
    }
    Ok(())
}

fn display_status(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| format!("exit code {code}"))
        .unwrap_or_else(|| "a signal".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_name_rejects_path_syntax() {
        let image = Path::new("/tmp/aos.qcow2");
        let mut args = test_args(image);
        args.name = Some("../escape".into());
        assert!(resolve_name(&args, image).is_err());
        args.name = Some("aos-test_1".into());
        assert_eq!(resolve_name(&args, image).unwrap(), "aos-test_1");
    }

    #[test]
    fn qemu_command_uses_uefi_disk_boot_without_kernel_arguments() {
        let args = test_args(Path::new("base.qcow2"));
        let command = qemu_command(
            &args,
            Path::new("qemu-system-x86_64"),
            Path::new("disk.img"),
            Path::new("OVMF_CODE.fd"),
            Path::new("OVMF_VARS.fd"),
            Some(Path::new("host.nix")),
            Some(Path::new("host.nix.sig")),
            "kvm",
        );
        let arguments = command
            .get_args()
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>();
        assert!(!arguments.iter().any(|argument| argument == "-kernel"));
        assert!(!arguments.iter().any(|argument| argument == "-initrd"));
        assert!(
            arguments
                .iter()
                .any(|argument| argument.contains("accel=kvm"))
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument.contains("opt/org.andyl/host-nix"))
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument.contains("opt/org.andyl/host-nix.sig"))
        );
    }

    #[test]
    fn existing_vm_state_is_bound_to_the_base_image_and_disk_size() {
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("base.qcow2");
        fs::write(&image, b"base image").unwrap();
        let manifest_path = directory.path().join("vm-state.json");
        write_manifest(
            &manifest_path,
            &VmStateManifest {
                schema_version: 1,
                base_image: image.clone(),
                base_sha256: "abc123".to_string(),
                disk_size_bytes: 16 * GIB,
            },
        )
        .unwrap();

        assert!(validate_existing_state(&manifest_path, &image, "abc123", 16 * GIB).is_ok());
        assert!(validate_existing_state(&manifest_path, &image, "different", 16 * GIB).is_err());
        assert!(validate_existing_state(&manifest_path, &image, "abc123", 32 * GIB).is_err());
    }

    fn test_args(image: &Path) -> VmRunArgs {
        VmRunArgs {
            image: image.to_path_buf(),
            name: None,
            host_config: None,
            host_config_signature: None,
            disk_size_gib: 16,
            memory_mib: 4096,
            cpus: 2,
            ssh_port: 2222,
            accel: VmAcceleration::Kvm,
            state_dir: None,
            firmware_code: None,
            firmware_vars: None,
            dry_run: false,
        }
    }
}
