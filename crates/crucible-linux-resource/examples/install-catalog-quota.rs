//! Installs a persistent RAM-catalog quota inside a disposable privileged VM.
//!
//! This operator setup fixture uses the actual kernel quota transaction, then
//! independently authenticates the installed namespace after dropping its
//! installation reservation. It deliberately leaves the kernel limits in
//! place for the separately launched production provider. The caller owns the
//! dedicated filesystem, unique project ID, and outer process deadline.
//!
//! ```text
//! install-catalog-quota /tmp/attempts /tmp/attempts/ram-catalogs 40000 2147483648 262144
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, File};
use std::path::Path;
use std::process::ExitCode;

use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_linux_resource::{
    LinuxProjectQuotaBinding, LinuxProjectQuotaLimits, LinuxProjectQuotaReservation,
    validate_project_quota_root,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("install-catalog-quota: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [filesystem, catalog, project, bytes, inodes] = arguments.as_slice() else {
        return Err(
            "expected dedicated filesystem, catalog root, project ID, bytes, and inodes".into(),
        );
    };
    let filesystem = Path::new(filesystem);
    let catalog = Path::new(catalog);
    if !filesystem.is_absolute() || catalog.parent() != Some(filesystem) {
        return Err(
            "catalog must be a direct child of the dedicated absolute filesystem root".into(),
        );
    }
    let project = project.parse::<u32>()?;
    let bytes = bytes.parse::<u64>()?;
    let inodes = inodes.parse::<u64>()?;
    let limits = LinuxProjectQuotaLimits::new(bytes, inodes)?;
    let filesystem = File::open(filesystem)?.into();
    validate_project_quota_root(&filesystem, catalog.parent().ok_or("missing parent")?)?;
    fs::create_dir(catalog)?;

    let reservation = LinuxProjectQuotaReservation::install(
        filesystem,
        File::open(catalog)?.into(),
        catalog,
        project,
        limits,
    )?;
    reservation.verify_usage()?;
    drop(reservation);

    // Closing installer authority must never implicitly clear persistent
    // quotas. The independent provider performs the same authentication again.
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let binding = LinuxProjectQuotaBinding::bind_existing_supervised(
        catalog, project, bytes, inodes, supervisor,
    )?;
    binding.verify()?;
    println!("catalog_quota_survives_installer_drop=true");
    println!("catalog_project={project}");
    println!("catalog_backing_bytes={bytes}");
    println!("catalog_maximum_inodes={inodes}");
    Ok(())
}
