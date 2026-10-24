//! Exercises persistent quota namespace authentication in a disposable ext4 VM.
//!
//! ```text
//! persistent-quota-flight /tmp/quota-root /path/to/aos-e2fsprogs/bin/chattr
//! ```

#![forbid(unsafe_code)]
// crucible-lint: allow clippy-disallowed-method -- the disposable VM probe invokes the operator attribute tool.
#![allow(clippy::disallowed_methods)]

use std::error::Error;
use std::fs::{self, File};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Command, ExitCode};

use aos_linux_project_quota::{
    LinuxProjectQuotaLimits, LinuxProjectQuotaReservation, validate_project_quota_root,
};
use crucible_host_resources::SupervisedProjectQuotaBinding;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("persistent-quota-flight: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [root, chattr] = arguments.as_slice() else {
        return Err("expected a dedicated ext4 quota root and the AOS chattr executable".into());
    };
    let root = Path::new(root);
    let filesystem: OwnedFd = File::open(root)?.into();
    validate_project_quota_root(&filesystem, root)?;
    audit_persistent_namespace(root, &filesystem, Path::new(chattr))
}

fn audit_persistent_namespace(
    root: &Path,
    filesystem: &OwnedFd,
    chattr: &Path,
) -> Result<(), Box<dyn Error>> {
    use crucible_host_resources::host_supervision::{
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
        SupervisedProjectQuotaBinding::bind_existing_supervised(
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
