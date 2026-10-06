//! Exercises real ext4 quota enforcement inside a disposable privileged VM.
//!
//! The parent installs quotas through the production API. Children run as an
//! unprivileged user and must encounter EDQUOT for both bytes and inodes. The
//! fixture also proves failed release retains authority and cleared project
//! IDs can be reused. Invoke only against a dedicated empty quota filesystem:
//!
//! ```text
//! project-quota-flight /tmp/quota-root /path/to/aos-e2fsprogs/bin/chattr
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
    LinuxProjectQuotaBinding, LinuxProjectQuotaError, LinuxProjectQuotaLimits,
    LinuxProjectQuotaReservation, validate_project_quota_root,
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
        [mode, directory] if mode == "--write-bytes" => exhaust_bytes(Path::new(directory)),
        [mode, directory] if mode == "--write-inodes" => exhaust_inodes(Path::new(directory)),
        [root, chattr] => parent(Path::new(root), Path::new(chattr)),
        _ => Err("expected a dedicated ext4 quota root and the AOS chattr executable".into()),
    }
}

fn parent(root: &Path, chattr: &Path) -> Result<(), Box<dyn Error>> {
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
    audit_persistent_namespace(root, &filesystem, chattr)?;
    println!("PASS");
    Ok(())
}

fn audit_persistent_namespace(
    root: &Path,
    filesystem: &OwnedFd,
    chattr: &Path,
) -> Result<(), Box<dyn Error>> {
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationSupervisor,
    };

    let path = root.join("persistent");
    fs::create_dir(&path)?;
    let limits = LinuxProjectQuotaLimits::new(1024 * 1024, 256)?;
    let reservation = LinuxProjectQuotaReservation::install(
        filesystem.try_clone()?,
        File::open(&path)?.into(),
        &path,
        10003,
        limits,
    )?;
    fs::create_dir(path.join("existing"))?;
    fs::write(
        path.join("existing/page"),
        b"preexisting authenticated bytes",
    )?;
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let bind = || {
        LinuxProjectQuotaBinding::bind_existing_supervised(
            &path,
            10003,
            1024 * 1024,
            256,
            supervisor.clone(),
        )
    };

    let binding = bind()?;
    if bind().is_ok() {
        return Err("second persistent namespace owner acquired the same lease".into());
    }
    binding.prepare_descendant_directory(&path.join("new/catalog"))?;
    fs::write(path.join("new/catalog/page"), b"inherited bytes")?;
    binding.verify()?;
    drop(binding);

    // The operator deliberately changes attributes while no namespace lease
    // is held. Root-only checks would miss each preexisting descendant defect.
    change_attributes(chattr, &["-p", "0"], &path.join("existing/page"))?;
    if bind().is_ok() {
        return Err("foreign-project preexisting file escaped quota audit".into());
    }
    change_attributes(chattr, &["-p", "10003"], &path.join("existing/page"))?;
    change_attributes(chattr, &["-P"], &path.join("existing"))?;
    if bind().is_ok() {
        return Err("noninheriting preexisting directory escaped quota audit".into());
    }
    change_attributes(chattr, &["+P"], &path.join("existing"))?;

    fs::hard_link(path.join("existing/page"), path.join("alias"))?;
    if bind().is_ok() {
        return Err("hard-linked existing quota inode was admitted".into());
    }
    fs::remove_file(path.join("alias"))?;
    std::os::unix::fs::symlink(root, path.join("escape"))?;
    if bind().is_ok() {
        return Err("symlink descendant escaped persistent quota audit".into());
    }
    fs::remove_file(path.join("escape"))?;
    bind()?.verify()?;

    for name in ["existing", "new"] {
        fs::remove_dir_all(path.join(name))?;
    }
    fs::remove_file(path.join(".crucible-physical-quota.lock"))?;
    reservation.release()?;
    println!("persistent_descendant_audit_and_lease_enforced=true");
    Ok(())
}

fn change_attributes(tool: &Path, arguments: &[&str], path: &Path) -> Result<(), Box<dyn Error>> {
    if !Command::new(tool)
        .args(arguments)
        .arg(path)
        .status()?
        .success()
    {
        return Err("operator fixture could not change project attributes".into());
    }
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
