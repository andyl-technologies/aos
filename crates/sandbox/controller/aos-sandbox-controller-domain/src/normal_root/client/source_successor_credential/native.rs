//! Retains the issue recipe's actual directory, label, ACL and name prefixes.
//!
//! The enclosing genuine issue owner prepays these fixed reservoirs. Successful
//! leaf probes dispose only after their complete held/name/label comparison;
//! failed probes and original credential descriptions remain owned separately.

use std::error::Error;
use std::fs::File;
use std::os::fd::BorrowedFd;

use aos_sandbox_linux::inventory::{MountId, ReadOnlyDirectorySnapshot, ReadOnlyDirectorySnapshotOriginalV1};
use aos_sandbox_linux::protected_file::open_nofollow_child;
use rustix::fs::OFlags;

use super::{CONTEXT, Identity, SourceSuccessorCredentialErrorV2 as Refusal};

const IDENTITIES: usize = 11;
const LABELS: usize = 5;
const DESCRIPTIONS: usize = 4;
const SNAPSHOTS: usize = 2;
const OPENS: usize = 6;

pub(super) struct CredentialNativePassV1 {
    pub(super) identities: Vec<IdentityOriginalV1>,
    pub(super) labels: Vec<LabelOriginalV1>,
    pub(super) descriptions: Vec<DescriptionOriginalV1>,
    pub(super) snapshots: Vec<ReadOnlyDirectorySnapshotOriginalV1>,
    pub(super) opens: Vec<Result<(), Refusal>>,
    pub(super) named_directory: Option<File>,
    pub(super) named_leaf: Option<File>,
}

impl CredentialNativePassV1 {
    pub(super) fn new() -> Self {
        Self {
            identities: Vec::with_capacity(IDENTITIES), labels: Vec::with_capacity(LABELS),
            descriptions: Vec::with_capacity(DESCRIPTIONS), snapshots: Vec::with_capacity(SNAPSHOTS),
            opens: Vec::with_capacity(OPENS), named_directory: None, named_leaf: None,
        }
    }

    pub(super) fn receiving_footprint_v1() -> Option<(usize, usize)> {
        let (snapshot, boot_files) = ReadOnlyDirectorySnapshotOriginalV1::receiving_footprint_v1()?;
        let backing = IDENTITIES.checked_mul(std::mem::size_of::<IdentityOriginalV1>())?
            .checked_add(LABELS.checked_mul(std::mem::size_of::<LabelOriginalV1>())?)?
            .checked_add(DESCRIPTIONS.checked_mul(std::mem::size_of::<DescriptionOriginalV1>())?)?
            .checked_add(SNAPSHOTS.checked_mul(snapshot)?)?
            .checked_add(OPENS.checked_mul(std::mem::size_of::<Result<(), Refusal>>())?)?;
        // The parent separately pays two compiled copies of this inline owner.
        // Construction/push temporaries and fixed native diagnostics coexist
        // with the actual capped backing; no native-field metadata is charged.
        let bytes = backing.checked_mul(2)?.checked_add(16 * 4096)?;
        Some((bytes, 2usize.checked_add(boot_files)?))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.opens.iter().find_map(|result| result.as_ref().err().map(|cause| cause as &dyn Error))
            .or_else(|| self.identities.iter().find_map(IdentityOriginalV1::failure))
            .or_else(|| self.snapshots.iter().find_map(ReadOnlyDirectorySnapshotOriginalV1::failure))
            .or_else(|| self.descriptions.iter().find_map(DescriptionOriginalV1::failure))
            .or_else(|| self.labels.iter().find_map(LabelOriginalV1::failure))
    }
}

pub(super) struct IdentityOriginalV1 {
    stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    length: Option<Result<u64, std::num::TryFromIntError>>,
    mount: Option<aos_linux_descriptors::Result<MountId>>,
}

impl IdentityOriginalV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.stat).or_else(|| error(&self.length)).or_else(|| error(&self.mount))
    }
}

pub(super) fn identity(file: BorrowedFd<'_>, originals: &mut Vec<IdentityOriginalV1>) -> Result<Identity, Refusal> {
    if originals.len() >= IDENTITIES { return Err(Refusal::Rejected); }
    originals.push(IdentityOriginalV1 { stat: None, length: None, mount: None });
    let original = originals.last_mut().ok_or(Refusal::Rejected)?;
    original.stat = Some(rustix::fs::fstat(file));
    let metadata = original.stat.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Refusal::Rejected)?;
    original.length = Some(u64::try_from(metadata.st_size));
    let bytes = original.length.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(Refusal::Rejected)?;
    original.mount = Some(MountId::from_fd(file));
    let mount = original.mount.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(Refusal::Rejected)?;
    Ok(Identity {
        device: metadata.st_dev, inode: metadata.st_ino, mode: metadata.st_mode,
        uid: metadata.st_uid, gid: metadata.st_gid, links: u64::from(metadata.st_nlink), bytes,
        mtime: (i64::from(metadata.st_mtime), u64::from(metadata.st_mtime_nsec)),
        ctime: (i64::from(metadata.st_ctime), u64::from(metadata.st_ctime_nsec)), mount,
    })
}

pub(super) fn snapshot(
    file: BorrowedFd<'_>, originals: &mut Vec<ReadOnlyDirectorySnapshotOriginalV1>,
) -> Result<ReadOnlyDirectorySnapshot, Refusal> {
    if originals.len() >= SNAPSHOTS { return Err(Refusal::Rejected); }
    originals.push(ReadOnlyDirectorySnapshotOriginalV1::new());
    let original = originals.last_mut().ok_or(Refusal::Rejected)?;
    ReadOnlyDirectorySnapshot::capture_retaining_once_v1(file, original).map_err(|_| Refusal::Rejected)
}

pub(super) fn open_directory(path_only: bool, originals: &mut Vec<Result<(), Refusal>>) -> Result<File, Refusal> {
    if originals.len() >= OPENS { return Err(Refusal::Rejected); }
    park_open(super::open_directory(path_only), originals)
}

pub(super) fn open_child(
    directory: &File, name: &'static str, originals: &mut Vec<Result<(), Refusal>>,
) -> Result<File, Refusal> {
    if originals.len() >= OPENS { return Err(Refusal::Rejected); }
    park_open(open_nofollow_child(directory, name).map(File::from).map_err(Refusal::from), originals)
}

fn park_open(result: Result<File, Refusal>, originals: &mut Vec<Result<(), Refusal>>) -> Result<File, Refusal> {
    match result {
        Ok(file) => {
            originals.push(Ok(()));
            // The caller's next operation parks this same File in the resident
            // original/named slot before any further fallible native action.
            Ok(file)
        }
        Err(cause) => {
            originals.push(Err(cause));
            Err(Refusal::Rejected)
        }
    }
}

pub(super) struct DescriptionOriginalV1 {
    status: Option<rustix::io::Result<OFlags>>,
    descriptor: Option<rustix::io::Result<rustix::io::FdFlags>>,
    binding: Option<Result<(), Refusal>>,
}

impl DescriptionOriginalV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.status).or_else(|| error(&self.descriptor)).or_else(|| error(&self.binding))
    }
}

pub(super) fn read_description(file: BorrowedFd<'_>, originals: &mut Vec<DescriptionOriginalV1>) -> Result<(), Refusal> {
    if originals.len() >= DESCRIPTIONS { return Err(Refusal::Rejected); }
    originals.push(DescriptionOriginalV1 { status: None, descriptor: None, binding: None });
    let original = originals.last_mut().ok_or(Refusal::Rejected)?;
    original.status = Some(rustix::fs::fcntl_getfl(file));
    let flags = original.status.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(Refusal::Rejected)?;
    // Preserve the old lazy condition: invalid access never performs getfd.
    if flags.contains(OFlags::PATH) || flags & OFlags::ACCMODE != OFlags::RDONLY {
        original.binding = Some(Err(Refusal::Rejected));
        return Err(Refusal::Rejected);
    }
    original.descriptor = Some(rustix::io::fcntl_getfd(file));
    let flags = original.descriptor.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(Refusal::Rejected)?;
    original.binding = Some(if flags.contains(rustix::io::FdFlags::CLOEXEC) { Ok(()) } else { Err(Refusal::Rejected) });
    if matches!(original.binding, Some(Ok(()))) { Ok(()) } else { Err(Refusal::Rejected) }
}

pub(super) struct LabelOriginalV1 {
    context: [u8; 256],
    context_result: Option<rustix::io::Result<usize>>,
    context_binding: Option<Result<(), Refusal>>,
    acl: [[u8; 4096]; 2],
    acl_results: [Option<rustix::io::Result<usize>>; 2],
    acl_bindings: [Option<Result<(), Refusal>>; 2],
}

impl LabelOriginalV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(cause) = error(&self.context_result).or_else(|| error(&self.context_binding)) {
            return Some(cause);
        }
        for index in 0..2 {
            if let Some(Err(cause)) = &self.acl_results[index] {
                if *cause != rustix::io::Errno::NODATA { return Some(cause); }
            }
            if let Some(cause) = error(&self.acl_bindings[index]) { return Some(cause); }
        }
        None
    }
}

pub(super) fn label_and_acl(file: BorrowedFd<'_>, originals: &mut Vec<LabelOriginalV1>) -> Result<(), Refusal> {
    if originals.len() >= LABELS { return Err(Refusal::Rejected); }
    originals.push(LabelOriginalV1 {
        context: [0; 256], context_result: None, context_binding: None,
        acl: [[0; 4096]; 2], acl_results: [None, None], acl_bindings: [None, None],
    });
    let original = originals.last_mut().ok_or(Refusal::Rejected)?;
    original.context_result = Some(rustix::fs::fgetxattr(file, "security.selinux", &mut original.context));
    let length = original.context_result.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(Refusal::Rejected)?;
    let context = original.context[..length].strip_suffix(&[0]).unwrap_or(&original.context[..length]);
    original.context_binding = Some(if context == CONTEXT { Ok(()) } else { Err(Refusal::Rejected) });
    if !matches!(original.context_binding, Some(Ok(()))) { return Err(Refusal::Rejected); }
    for (index, name) in ["system.posix_acl_access", "system.posix_acl_default"].into_iter().enumerate() {
        original.acl_results[index] = Some(rustix::fs::fgetxattr(file, name, &mut original.acl[index]));
        original.acl_bindings[index] = Some(match &original.acl_results[index] {
            Some(Err(error)) if *error == rustix::io::Errno::NODATA => Ok(()),
            _ => Err(Refusal::Rejected),
        });
        if !matches!(original.acl_bindings[index], Some(Ok(()))) { return Err(Refusal::Rejected); }
    }
    Ok(())
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;
    use super::*;

    #[test]
    fn failed_fixed_child_open_keeps_the_actual_error_without_retry() {
        let directory = tempfile::tempdir().unwrap();
        let parent = File::open(directory.path()).unwrap();
        let mut original = CredentialNativePassV1::new();

        assert!(open_child(&parent, "missing", &mut original.opens).is_err());
        let first = std::ptr::from_ref(original.failure().unwrap());

        assert_eq!(original.opens.len(), 1);
        assert!(original.identities.is_empty());
        assert!(original.snapshots.is_empty());
        assert!(std::ptr::eq(std::ptr::from_ref(original.failure().unwrap()), first));
    }

    #[test]
    fn refused_description_keeps_the_actual_named_file_and_lazy_order() {
        let directory = tempfile::tempdir().unwrap();
        let mut original = CredentialNativePassV1::new();
        original.named_leaf = Some(File::create(directory.path().join("writable")).unwrap());

        assert!(read_description(original.named_leaf.as_ref().unwrap().as_fd(), &mut original.descriptions).is_err());

        assert!(original.named_leaf.as_ref().unwrap().metadata().is_ok());
        assert!(matches!(original.descriptions[0].status, Some(Ok(_))));
        assert!(original.descriptions[0].descriptor.is_none());
        assert!(original.failure().is_some());
    }
}
