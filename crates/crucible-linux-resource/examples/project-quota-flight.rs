//! Exercises real ext4 quota enforcement inside a disposable privileged VM.
//!
//! The parent installs quotas through the production API. Children run as an
//! unprivileged user and must encounter EDQUOT for both bytes and inodes. The
//! fixture also proves failed release retains authority and cleared project
//! IDs can be reused. Invoke only against a dedicated empty quota filesystem:
//!
//! ```text
//! project-quota-flight /tmp/quota-root
//! ```

#![forbid(unsafe_code)]
// crucible-lint: allow clippy-disallowed-method -- the disposable VM probe intentionally launches unprivileged subprocesses.
#![allow(clippy::disallowed_methods)]

use std::error::Error;
use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};

use crucible_linux_resource::{
    LinuxProjectQuotaError, LinuxProjectQuotaLimits, LinuxProjectQuotaReservation,
    validate_project_quota_root,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("project-quota-flight: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [root] => parent(Path::new(root)),
        [mode, directory] if mode == "--write-bytes" => exhaust_bytes(Path::new(directory)),
        [mode, directory] if mode == "--write-inodes" => exhaust_inodes(Path::new(directory)),
        _ => Err("expected one dedicated ext4 quota root".into()),
    }
}

fn parent(root: &Path) -> Result<(), Box<dyn Error>> {
    let filesystem: OwnedFd = File::open(root)?.into();
    validate_project_quota_root(&filesystem, root)?;
    for (mode, name, project, inodes) in [
        ("--write-bytes", "bytes", 10001, 32),
        ("--write-inodes", "inodes", 10002, 4),
    ] {
        let directory = root.join(name);
        fs::create_dir(&directory)?;
        let limits = LinuxProjectQuotaLimits::new(64 * 1024, inodes)?;
        let reservation = LinuxProjectQuotaReservation::install(
            filesystem.try_clone()?,
            File::open(&directory)?.into(),
            &directory,
            project,
            limits,
        )?;
        fs::set_permissions(&directory, Permissions::from_mode(0o777))?;
        let output = Command::new(std::env::current_exe()?)
            .args([Path::new(mode), &directory])
            .uid(65534)
            .gid(65534)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "{name} child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        reservation.verify_usage()?;

        // Failure must preserve the same live quota, not clear it while an
        // entry still charges this project's accounting.
        let reservation = match reservation.release() {
            Ok(()) => return Err("nonempty quota directory was released".into()),
            Err(error)
                if matches!(
                    error.source_error(),
                    LinuxProjectQuotaError::DirectoryNotEmpty { .. }
                ) =>
            {
                error.into_reservation()
            }
            Err(error) => return Err(error.into()),
        };
        reservation.verify_usage()?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err("unexpected non-file in isolated quota fixture".into());
            }
            fs::remove_file(entry.path())?;
        }
        reservation.release()?;

        let reused = LinuxProjectQuotaReservation::install(
            filesystem.try_clone()?,
            File::open(&directory)?.into(),
            &directory,
            project,
            limits,
        )?;
        reused.verify_usage()?;
        reused.release()?;
        println!("{name}_quota_enforced=true");
    }
    println!("nonempty_release_retains_authority=true");
    println!("cleared_project_ids_reusable=true");
    println!("PASS");
    Ok(())
}

fn exhaust_bytes(directory: &Path) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(directory.join("payload"))?;
    for _ in 0..64 {
        if quota_reached(file.write_all(&[0x5a; 4096]))? || quota_reached(file.sync_all())? {
            return Ok(());
        }
    }
    Err("unprivileged writer exceeded the hard byte quota".into())
}

fn exhaust_inodes(directory: &Path) -> Result<(), Box<dyn Error>> {
    for index in 0..16 {
        if quota_reached(File::create(directory.join(format!("inode-{index}"))).map(drop))? {
            return Ok(());
        }
    }
    Err("unprivileged writer exceeded the hard inode quota".into())
}

fn quota_reached(result: io::Result<()>) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(false),
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::DQUOT.raw_os_error()) => {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}
