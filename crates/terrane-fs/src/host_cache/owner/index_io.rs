//! Performs fixed native missing-index writes under the physical owner's hold.
//!
//! This module supplies only the filesystem sequence. The command owner must
//! durably reserve capacity and pin the actual source before calling it, retain
//! returned failure resources, and reconcile actual charge before acknowledgment.
//! Existing mismatching indexes are never overwritten. No serving, retention or
//! completed-recovery authority is created by this physical result alone.

use crate::{
    host_cache::recovery_inspection::{DerivedIndexRepair, DetachedIndexStatus},
    host_quota::{NativeProject, synchronized_allocated_bytes},
};
use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, fchmod, open, openat, renameat_with, unlinkat,
};
use std::{
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, IntoRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
};

/// Retains the successfully synchronized actual canonical index descriptor.
pub(super) struct IndexWriteCompletion {
    /// Actual read-only descriptor of the verified canonical index inode.
    pub(super) index: File,
    /// Synchronized allocated bytes for that inode, excluding quota reservations.
    pub(super) allocated_bytes: u64,
}

impl IndexWriteCompletion {
    /// Rechecks exact bytes and canonical inode after the owner's state effects.
    ///
    /// # Errors
    /// Refuses a replaced, modified or unavailable canonical detached index.
    pub(super) fn check_current(&self, source: &DerivedIndexRepair) -> io::Result<()> {
        let current = open_regular_at(source.parent_file(), &format!("{}.idx", source.pack_id()))?;
        let expected = self.index.metadata()?;
        if !same_file(&expected, &current.metadata()?) {
            return Err(invalid("completed canonical index was replaced"));
        }
        verify_bytes(&self.index, source.index_bytes())?;
        if !same_file(&expected, &self.index.metadata()?)
            || !same_file(&expected, &current.metadata()?)
        {
            return Err(invalid(
                "completed canonical index changed during verification",
            ));
        }
        Ok(())
    }
}

/// Retains physical resources whose cleanup has not been acknowledged.
pub(super) struct PendingIndexWrite {
    temporary: String,
    writer: Option<File>,
    readonly: Option<File>,
    canonical: bool,
    temporary_unlinked: bool,
    temporary_created: bool,
}

/// Returns a real error together with all still-owned temporary resources.
pub(super) struct IndexWriteFailure {
    /// Physical error, including failures after a successful namespace effect.
    pub(super) error: io::Error,
    /// Still-owned files and exact namespace progress for later reconciliation.
    pub(super) pending: PendingIndexWrite,
}

/// Writes an actual missing detached index without replacing any canonical file.
///
/// This private binding accepts only genuine inspected source evidence. The
/// caller is the serialized native owner, holding an already durable reservation
/// and source pin throughout the operation and subsequent accounting/state work.
///
/// # Errors
/// Retains actual temporary descriptors/names on all failures, including late
/// close, raced corrupt indexes and errors after successful canonical rename.
pub(super) fn write_missing_index(
    source: &DerivedIndexRepair,
) -> Result<IndexWriteCompletion, IndexWriteFailure> {
    let mut pending = PendingIndexWrite {
        temporary: String::new(),
        writer: None,
        readonly: None,
        canonical: false,
        temporary_unlinked: false,
        temporary_created: false,
    };
    write_inner(source, &mut pending).map_err(|error| IndexWriteFailure { error, pending })
}

fn write_inner(
    source: &DerivedIndexRepair,
    pending: &mut PendingIndexWrite,
) -> io::Result<IndexWriteCompletion> {
    source.check_pack_current()?;
    if source.detached_index_status() != DetachedIndexStatus::Missing {
        return Err(invalid(
            "native create-no-replace repair requires a missing index",
        ));
    }
    let parent = source.parent_file();
    let directory = parent.metadata()?;
    let project = NativeProject::inspect(parent)?;
    if !project.inherit || project.device != directory.dev() {
        return Err(invalid(
            "index repair parent lacks native project inheritance",
        ));
    }
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    pending.temporary = format!(".terrane-tmp:{}", hex(&random));
    pending.writer = Some(File::from(openat(
        parent,
        &pending.temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?));
    pending.temporary_created = true;
    let writer = pending
        .writer
        .as_mut()
        .ok_or_else(|| invalid("index writer missing"))?;
    check_custody(writer, &directory, project.project_id)?;
    writer.write_all(source.index_bytes())?;
    // The private staging mode is 0600. The publisher requires group read on
    // canonical encoded bodies while namespace custody stays on the shared dir.
    fchmod(&*writer, Mode::from_raw_mode(0o640))?;
    writer.sync_all()?;
    let staged = writer.metadata()?;
    let writer = pending
        .writer
        .take()
        .ok_or_else(|| invalid("index writer disappeared"))?;
    close_checked(writer)?;

    pending.readonly = Some(open_regular_at(parent, &pending.temporary)?);
    let readonly = pending
        .readonly
        .as_ref()
        .ok_or_else(|| invalid("readonly index missing"))?;
    if !same_file(&staged, &readonly.metadata()?) {
        return Err(invalid(
            "temporary index inode changed after writer closure",
        ));
    }
    check_canonical_mode(readonly)?;
    verify_bytes(readonly, source.index_bytes())?;
    source.check_pack_current()?;
    let name = format!("{}.idx", source.pack_id());
    let index = match renameat_with(
        parent,
        &pending.temporary,
        parent,
        &name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            pending.canonical = true;
            pending
                .readonly
                .take()
                .ok_or_else(|| invalid("published index descriptor missing"))?
        }
        Err(rustix::io::Errno::EXIST) => {
            let existing = open_regular_at(parent, &name)?;
            check_custody(&existing, &directory, project.project_id)?;
            check_canonical_mode(&existing)?;
            verify_bytes(&existing, source.index_bytes())?;
            existing.sync_all()?;
            // A raced correct immutable index wins. Only our own registered
            // temporary is removed, and its retained descriptor closes before
            // the caller's fresh charge reconciliation.
            unlinkat(parent, &pending.temporary, AtFlags::empty())?;
            pending.temporary_unlinked = true;
            close_checked(
                pending
                    .readonly
                    .take()
                    .ok_or_else(|| invalid("raced index temporary descriptor missing"))?,
            )?;
            existing
        }
        Err(error) => return Err(error.into()),
    };
    // Keep the canonical descriptor in failure custody until every required
    // durability and source-incarnation observation has completed.
    pending.readonly = Some(index);
    parent.sync_all()?;
    let objects = source
        .layout()
        .directories
        .get("objects")
        .ok_or_else(|| invalid("retained objects root missing"))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let packs = File::from(openat(objects, "pack", flags, Mode::empty())?);
    packs.sync_all()?;
    File::from(openat(objects, ".", flags, Mode::empty())?).sync_all()?;
    File::from(openat(&source.layout().root, ".", flags, Mode::empty())?).sync_all()?;
    source.check_pack_current()?;
    let index = pending
        .readonly
        .as_ref()
        .ok_or_else(|| invalid("canonical index custody lost"))?;
    verify_bytes(index, source.index_bytes())?;
    let current = open_regular_at(parent, &name)?;
    if !same_file(&index.metadata()?, &current.metadata()?) {
        return Err(invalid("canonical index pathname changed"));
    }
    let allocated_bytes = synchronized_allocated_bytes(index)?;
    let index = pending
        .readonly
        .take()
        .ok_or_else(|| invalid("completed index descriptor lost"))?;
    Ok(IndexWriteCompletion {
        index,
        allocated_bytes,
    })
}

/// Classifies without opening a FIFO/device, then reads only that retained inode.
///
/// # Errors
/// Refuses missing, nonregular, inaccessible or changing ordinary inodes.
pub(in crate::host_cache) fn open_regular_at(parent: &File, name: &str) -> io::Result<File> {
    let observation = File::from(openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = observation.metadata()?;
    if !before.is_file() {
        return Err(invalid("index candidate is not an ordinary regular inode"));
    }

    // The proc descriptor path follows the retained O_PATH inode, not a second
    // lookup of the mutable canonical name. NONBLOCK remains defense in depth;
    // a missing procfs path is an error, never a pathname-open fallback.
    let file = File::from(open(
        format!("/proc/self/fd/{}", observation.as_raw_fd()),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !same_file(&before, &file.metadata()?) || !same_file(&before, &observation.metadata()?) {
        return Err(invalid(
            "classified index inode changed during read-only reopen",
        ));
    }
    Ok(file)
}

fn check_custody(file: &File, parent: &Metadata, project_id: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.dev() != parent.dev()
        || metadata.uid() != parent.uid()
        || metadata.gid() != parent.gid()
        || metadata.mode() & 0o002 != 0
        || NativeProject::inspect(file)?.project_id != project_id
    {
        return Err(invalid("index inode differs from native parent custody"));
    }
    Ok(())
}

fn verify_bytes(file: &File, expected: &[u8]) -> io::Result<()> {
    let before = file.metadata()?;
    if before.len() != expected.len() as u64 {
        return Err(invalid("index length differs from verified derivation"));
    }
    let mut buffer = [0; 8192];
    let mut offset = 0;
    while offset < expected.len() {
        let length = buffer.len().min(expected.len() - offset);
        file.read_exact_at(&mut buffer[..length], offset as u64)?;
        if buffer[..length] != expected[offset..offset + length] {
            return Err(invalid("existing index differs from verified derivation"));
        }
        offset += length;
    }
    if !same_file(&before, &file.metadata()?) {
        return Err(invalid("index changed during positioned verification"));
    }
    Ok(())
}

fn check_canonical_mode(file: &File) -> io::Result<()> {
    if file.metadata()?.mode() & 0o040 == 0 {
        return Err(invalid(
            "canonical index is not readable by the shared publisher group",
        ));
    }
    Ok(())
}

fn close_checked(file: File) -> io::Result<()> {
    let descriptor = file.into_raw_fd();
    // SAFETY: into_raw_fd transferred unique ownership of this descriptor. Linux
    // releases it even on a late close error; retrying could close a reused FD.
    if unsafe { libc::close(descriptor) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 16];
            File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut random)
                .unwrap();
            let path = std::env::temp_dir().join(format!("terrane-index-open-{}", hex(&random)));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn classified_index_open_reads_regular_inode_and_refuses_fifo_and_symlink() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("index"), b"exact index").unwrap();
        let parent = File::open(&fixture.0).unwrap();
        rustix::fs::mkfifoat(&parent, "fifo", Mode::from_raw_mode(0o600)).unwrap();
        std::os::unix::fs::symlink("index", fixture.0.join("symlink")).unwrap();

        let mut file = open_regular_at(&parent, "index").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"exact index");
        for name in ["fifo", "symlink"] {
            assert_eq!(
                open_regular_at(&parent, name).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn classified_index_open_refuses_character_device_before_read_open() {
        let parent = File::open("/dev").unwrap();
        assert_eq!(
            open_regular_at(&parent, "null").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn invalid_index_error_preserves_typed_source() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "original failure");
        let error = invalid(source);
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
