//! Provisions fixed non-production guest projects before confined actors start.
//!
//! These administrative observations are fixture evidence, never native cache
//! admission, durable manifest retention or recovery-completion receipts.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rustix::process::{Gid, Uid};
use terrane_linux::host_quota::{
    DomainProvisioningGuard, NativeProject, NativeQuota, provision_project, require_unused_project,
};

const BASE: &str = "/mnt/terrane-publication";
const LEDGERS: &str = "/var/lib/terrane-publication";
const LIMIT: u64 = 32 * 1024 * 1024;
const ROOTS: &[&str] = &[
    "worker-cancellation",
    "worker-startup-failure",
    "worker-pending-restart",
    "worker-pack-partial-rename",
    "worker-pack-partial-unlink",
    "worker-prepared-roots",
    "worker-staged-root-retention",
    "worker-binding-path-failure",
    "kernel-sequence",
];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check_project(file: &File, project: u32, device: u64) -> io::Result<()> {
    let metadata = file.metadata()?;
    let actual = NativeProject::inspect(file)?;
    if (!metadata.is_dir() && !metadata.is_file())
        || actual.device != device
        || actual.project_id != project
        || (metadata.is_dir() && !actual.inherit)
    {
        return Err(invalid("fixture inode lacks genuine project custody"));
    }
    Ok(())
}

fn verify_tree(path: &Path, project: u32, device: u64, budget: &mut usize) -> io::Result<()> {
    *budget = budget
        .checked_sub(1)
        .ok_or_else(|| invalid("fixture verification entry budget exceeded"))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(invalid("unexpected fixture inode type"));
    }
    let file = File::open(path)?;
    check_project(&file, project, device)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            verify_tree(&entry?.path(), project, device, budget)?;
        }
    }
    file.sync_all()
}

fn ledger_record(name: &str, metadata: &fs::Metadata, project: u32) -> String {
    format!(
        "fixture={name} owner_uid=841 content_uid=840 gid=845 device={} inode={} project={project} limit={LIMIT}\n",
        metadata.dev(),
        metadata.ino(),
    )
}

/// Runs only the fixed external root supervisor's project preparation/check.
///
/// # Errors
/// Returns errors for non-VM/root invocation, unsafe administrative custody,
/// existing roots/ledgers, unavailable quotas or mismatched actual projects.
pub(super) fn run(verify: bool) -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0
        || std::env::var("TERRANE_PUBLISH_VM").as_deref() != Ok("1")
        || std::env::var_os("TERRANE_PUBLISH_VM_ROOT").as_deref()
            != Some(std::ffi::OsStr::new(BASE))
    {
        return Err(invalid(
            "project supervisor requires its fixed root VM environment",
        ));
    }
    let administrative = File::open(LEDGERS)?;
    let metadata = administrative.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(invalid("fixture project ledger directory is not protected"));
    }
    let base = File::open(BASE)?;
    let device = base.metadata()?.dev();
    let mut budget = 4096;
    for (index, name) in ROOTS.iter().enumerate() {
        let project = 64101 + u32::try_from(index).map_err(io::Error::other)?;
        let path = Path::new(BASE).join(name);
        if verify {
            let root = File::open(&path)?;
            let _guard = DomainProvisioningGuard::shared(&root)?;
            let metadata = root.metadata()?;
            let mut ledger = File::from(rustix::fs::open(
                Path::new(LEDGERS).join(format!("fixture-project-{project}")),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?);
            let custody = ledger.metadata()?;
            if !custody.is_file()
                || custody.uid() != 0
                || custody.mode() & 0o077 != 0
                || custody.len() > 1024
            {
                return Err(invalid("fixture project ledger custody changed"));
            }
            let mut record = String::new();
            Read::by_ref(&mut ledger)
                .take(1025)
                .read_to_string(&mut record)?;
            if record != ledger_record(name, &metadata, project) {
                return Err(invalid("fixture project root differs from durable binding"));
            }
            if NativeQuota::query(&root, project)?.hard_limit_bytes != LIMIT {
                return Err(invalid("fixture project quota is not finite and exact"));
            }
            verify_tree(&path, project, device, &mut budget)?;
            continue;
        }

        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let root = File::open(&path)?;
        let _guard = DomainProvisioningGuard::exclusive(&root)?;
        if let Some(entry) = fs::read_dir(&path)?.next() {
            let _entry = entry?;
            return Err(invalid("project provisioning requires an empty root"));
        }
        if NativeProject::inspect(&root)?.project_id != 0 {
            return Err(invalid("project provisioning requires an unassigned root"));
        }
        require_unused_project(&root, project)?;
        let metadata = root.metadata()?;
        let mut ledger = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(Path::new(LEDGERS).join(format!("fixture-project-{project}")))?;
        ledger.write_all(ledger_record(name, &metadata, project).as_bytes())?;
        ledger.sync_all()?;
        administrative.sync_all()?;
        root.sync_all()?;
        base.sync_all()?;
        provision_project(&root, project, LIMIT)?;
        check_project(&root, project, device)?;
        if NativeQuota::query(&root, project)?.hard_limit_bytes != LIMIT {
            return Err(invalid("fixture finite quota provisioning failed"));
        }
        rustix::fs::chown(&path, Some(Uid::from_raw(841)), Some(Gid::from_raw(845)))?;
        root.sync_all()?;
        base.sync_all()?;
    }
    Ok(())
}
