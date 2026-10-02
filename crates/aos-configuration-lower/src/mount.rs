//! Atomically publishes a new OS configuration overlay after lower verification.

use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, ensure};

use crate::lower::{Tools, validate};
use crate::model::Lower;

fn paths(lower: &Lower) -> (PathBuf, PathBuf, PathBuf) {
    let key = lower.image_sha256.trim_start_matches("sha256:");
    (
        PathBuf::from(format!("/run/etc/native-config-{key}/etc")),
        PathBuf::from(format!("/run/etc/native-upper-{key}")),
        PathBuf::from(format!("/run/etc/native-activation-{key}")),
    )
}

/// Determines whether the exact requested overlay is currently mounted at `/etc`.
///
/// # Errors
/// Returns an error when mount topology cannot be inspected.
pub fn current(lower: &Lower) -> Result<bool> {
    let (configuration, _, _) = paths(lower);
    mounted_at(
        Path::new("/etc"),
        "overlay",
        &configuration.to_string_lossy(),
    )
}

fn mounted_at(path: &Path, filesystem: &str, marker: &str) -> Result<bool> {
    let stat = rustix::fs::statx(
        rustix::fs::CWD,
        path,
        rustix::fs::AtFlags::NO_AUTOMOUNT,
        rustix::fs::StatxFlags::MNT_ID,
    )?;
    ensure!(
        stat.stx_mask & rustix::fs::StatxFlags::MNT_ID.bits() != 0,
        "kernel did not report mount identity"
    );
    let topology = fs::read_to_string("/proc/self/mountinfo")?;
    Ok(topology.lines().any(|line| {
        let Some((fields, mounted)) = line.split_once(" - ") else {
            return false;
        };
        fields
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            == Some(stat.stx_mnt_id)
            && fields.split_whitespace().nth(4) == path.to_str()
            && mounted.split_whitespace().next() == Some(filesystem)
            && mounted.contains(marker)
    }))
}

// PID 1 makes mounts shared again at switch-root. Only the dedicated staging
// tmpfs may change propagation; a foreign directory must never affect /run.
fn prepare_staging_mount(mount: &Path) -> Result<()> {
    let staging = Path::new("/run/etc");
    ensure!(
        fs::symlink_metadata(staging)
            .context("inspecting /run/etc staging root")?
            .is_dir(),
        "OS configuration staging root is not a real directory"
    );
    ensure!(
        mounted_at(staging, "tmpfs", "").context("checking /run/etc staging mount identity")?,
        "OS configuration staging root is not an exact mounted tmpfs"
    );

    let status = Command::new(mount)
        .env_clear()
        .args(["--make-private", "/run/etc"])
        .status()
        .context("isolating /run/etc staging mount")?;
    ensure!(
        status.success(),
        "isolating OS configuration staging mount failed: {status}"
    );
    Ok(())
}

/// Stages and switches the exact native overlay while retaining prior mounts.
///
/// The lower is immutable. A fresh upper/work pair is staged before the mount
/// moves over `/etc`, so uncertain dispatch can be observed through mountinfo.
/// Prior overlays remain covered for recovery and explicit retained rollback.
///
/// # Errors
/// Returns an error for inconsistent lower evidence, missing bootstrap layers,
/// failed mount commands, or inability to establish the requested topology.
pub fn apply(lower: &Lower, mount: &Path, tools: &Tools) -> Result<()> {
    validate(lower, &lower.receipt_effect, tools)?;
    if current(lower)? {
        publish_upper_link(&paths(lower).1)?;
        return Ok(());
    }
    ensure!(
        Path::new("/run/etc/system/metadata").is_dir()
            && Path::new("/run/etc/system/content").is_dir(),
        "image configuration layers are not mounted"
    );
    prepare_staging_mount(mount)?;
    let (configuration, upper, activation) = paths(lower);
    for path in [
        &configuration,
        &upper.join("dir"),
        &upper.join("work"),
        &activation,
    ] {
        fs::create_dir_all(path)?;
        ensure!(
            fs::symlink_metadata(path)?.is_dir(),
            "configuration staging path is not a real directory"
        );
    }
    if !mounted_at(&configuration, "erofs", &lower.image)? {
        let status = Command::new(mount)
            .env_clear()
            .args(["-t", "erofs", "-o", "ro,nodev,nosuid"])
            .arg(&lower.image)
            .arg(&configuration)
            .status()?;
        ensure!(status.success(), "mounting staged lower failed: {status}");
    }
    let options = format!(
        "nodev,nosuid,metacopy=on,redirect_dir=on,lowerdir+=/var/etc,lowerdir+={},lowerdir+=/run/etc/system/metadata,datadir+=/run/etc/system/content,upperdir={},workdir={}",
        configuration.display(),
        upper.join("dir").display(),
        upper.join("work").display()
    );
    if !mounted_at(&activation, "overlay", &configuration.to_string_lossy())? {
        preserve_user_upper(lower, &upper.join("dir"))?;
        let status = Command::new(mount)
            .env_clear()
            .args(["-t", "overlay", "overlay", "-o", &options])
            .arg(&activation)
            .status()?;
        ensure!(
            status.success(),
            "staging native /etc overlay failed: {status}"
        );
    }
    let status = Command::new(mount)
        .env_clear()
        .arg("--move")
        .arg(&activation)
        .arg("/etc")
        .status()?;
    ensure!(
        status.success(),
        "switching native /etc overlay failed: {status}"
    );
    publish_upper_link(&upper)?;
    ensure!(
        current(lower)?,
        "native /etc overlay was not observed after publication"
    );
    Ok(())
}

/// Retires the active overlay and reveals the retained prior configuration.
///
/// # Errors
/// Returns an error when unmount fails or the desired overlay remains active.
pub fn remove(lower: &Lower, umount: &Path) -> Result<()> {
    if !current(lower)? {
        return Ok(());
    }
    let status = Command::new(umount).env_clear().arg("/etc").status()?;
    ensure!(
        status.success(),
        "retiring native /etc overlay failed: {status}"
    );
    ensure!(
        !current(lower)?,
        "retired native /etc overlay is still current"
    );
    publish_upper_link(&visible_upper_root()?)?;
    Ok(())
}

fn visible_upper_root() -> Result<PathBuf> {
    let stat = rustix::fs::statx(
        rustix::fs::CWD,
        "/etc",
        rustix::fs::AtFlags::NO_AUTOMOUNT,
        rustix::fs::StatxFlags::MNT_ID,
    )?;
    let topology = fs::read_to_string("/proc/self/mountinfo")?;
    for line in topology.lines() {
        let Some((fields, mounted)) = line.split_once(" - ") else {
            continue;
        };
        if fields
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            != Some(stat.stx_mnt_id)
        {
            continue;
        }
        ensure!(
            mounted.split_whitespace().next() == Some("overlay"),
            "restored OS configuration is not an overlay"
        );
        let upper = mounted
            .split_whitespace()
            .nth(2)
            .and_then(|options| {
                options
                    .split(',')
                    .find_map(|option| option.strip_prefix("upperdir="))
            })
            .ok_or_else(|| anyhow::anyhow!("restored overlay has no upper directory"))?;
        let root = Path::new(upper)
            .parent()
            .ok_or_else(|| anyhow::anyhow!("restored upper has no root"))?;
        ensure!(
            root.starts_with("/run/etc"),
            "restored upper is outside the OS runtime namespace"
        );
        return Ok(root.to_owned());
    }
    anyhow::bail!("restored OS configuration mount is unavailable")
}

fn publish_upper_link(upper: &Path) -> Result<()> {
    let temporary = Path::new("/run/etc/upper.next");
    match fs::remove_file(temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::os::unix::fs::symlink(upper, temporary)?;
    fs::rename(temporary, "/run/etc/upper")?;
    Ok(())
}

fn preserve_user_upper(lower: &Lower, destination: &Path) -> Result<()> {
    let source = Path::new("/run/etc/upper/dir");
    ensure!(
        source.is_dir(),
        "previous OS configuration upper is unavailable"
    );
    let managed = crate::lower::managed_paths(lower)?;
    copy_user_entries(source, Path::new(""), destination, &managed)
}

fn copy_user_entries(
    source: &Path,
    relative: &Path,
    destination: &Path,
    managed: &[String],
) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let relative = relative.join(entry.file_name());
        let name = relative
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("configuration upper name is not UTF-8"))?;
        if managed
            .iter()
            .any(|path| name == path || name.starts_with(&format!("{path}/")))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        let target = destination.join(&relative);
        if metadata.is_dir() {
            fs::create_dir_all(&target)?;
            copy_user_entries(&entry.path(), &relative, destination, managed)?;
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(metadata.mode() & 0o7777),
            )?;
            std::os::unix::fs::chown(&target, Some(metadata.uid()), Some(metadata.gid()))?;
        } else {
            if fs::symlink_metadata(&target).is_ok() {
                fs::remove_file(&target)?;
            }
            if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &target,
                    rustix::fs::FileType::CharacterDevice,
                    rustix::fs::Mode::empty(),
                    0,
                )?;
            } else if metadata.file_type().is_symlink() {
                std::os::unix::fs::symlink(fs::read_link(entry.path())?, &target)?;
            } else {
                ensure!(metadata.is_file(), "unsupported configuration upper entry");
                // Reading the visible file resolves overlay metacopy data from
                // its old lower rather than copying an empty metadata inode.
                fs::copy(Path::new("/etc").join(&relative), &target)?;
                fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(metadata.mode() & 0o7777),
                )?;
                std::os::unix::fs::chown(&target, Some(metadata.uid()), Some(metadata.gid()))?;
            }
        }
    }
    Ok(())
}
