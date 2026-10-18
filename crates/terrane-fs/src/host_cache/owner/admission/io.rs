//! Publishes only generated shared keys using retained native directory inodes.
//!
//! Private writes use BKT-14 `.terrane-tmp:<random-id>` names. No replacement or
//! pathname supplied by a request is accepted. Unfinished descriptors and names
//! stay in the operation registry; this module never claims failed cleanup.

use super::super::{open_regular_at, retention::Custody};
use crate::host_quota::NativeProject;
use rustix::fs::{self, Mode, OFlags, RenameFlags};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::IntoRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
};

/// Retains a generated directory name and any descriptor acquired after its effect.
pub(super) struct DirectoryProgress {
    /// Exact fixed class selecting the retained layout root.
    pub(super) label: &'static str,
    /// Generated relative components known before attempting mkdir.
    pub(super) parts: Vec<String>,
    /// Actual inode retained immediately after successful open.
    pub(super) retained: Option<File>,
    /// Records actual successful mkdir, never an inferred existence claim.
    pub(super) created: bool,
}

/// Retains a generated canonical directory chain, including every actual inode.
pub(super) struct Parent {
    file: File,
    label: &'static str,
    parts: Vec<String>,
    chain: Vec<File>,
}

impl Parent {
    /// Duplicates retained descriptors without reopening a caller pathname.
    ///
    /// # Errors
    /// Refuses native descriptor duplication failure.
    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            label: self.label,
            parts: self.parts.clone(),
            chain: self
                .chain
                .iter()
                .map(File::try_clone)
                .collect::<io::Result<Vec<_>>>()?,
        })
    }

    fn recheck(&self, owner: &Custody) -> io::Result<()> {
        owner.preparation.layout().recheck()?;
        let root = owner
            .preparation
            .layout()
            .directories
            .get(self.label)
            .ok_or_else(|| io::Error::other("admission class root absent"))?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut current = File::from(fs::openat(root, ".", flags, Mode::empty())?);
        for (index, expected) in self.chain.iter().enumerate() {
            if index != 0 {
                current = File::from(fs::openat(
                    &current,
                    &self.parts[index - 1],
                    flags,
                    Mode::empty(),
                )?);
            }
            same_inode(expected, &current)?;
            check(owner, &current, InodePhase::Directory)?;
        }
        same_inode(&self.file, &current)
    }

    /// Borrows every actual directory touched by this admission for measurement.
    pub(super) fn chain(&self) -> &[File] {
        &self.chain
    }
}

/// Retains actual member descriptors and namespace progress through every error.
pub(super) struct PendingFile {
    /// Actual retained canonical directory chain.
    pub(super) parent: Parent,
    /// Generated logical member name, never a caller pathname.
    pub(super) canonical: String,
    temporary: String,
    writer: Option<File>,
    /// Actual independent read-only open description retained before writer close.
    pub(super) readonly: Option<File>,
    published: bool,
    closed: Option<FileStamp>,
    canonical_stamp: Option<FileStamp>,
}

/// Retains or creates only the generated configured shared directory chain.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn parent(
    owner: &Custody,
    label: &'static str,
    parts: &[&str],
    progress: &mut Vec<DirectoryProgress>,
) -> io::Result<Parent> {
    let root = owner
        .preparation
        .layout()
        .directories
        .get(label)
        .ok_or_else(|| io::Error::other("admission class root absent"))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(fs::openat(root, ".", flags, Mode::empty())?);
    progress.push(DirectoryProgress {
        label,
        parts: Vec::new(),
        retained: Some(directory.try_clone()?),
        created: false,
    });
    check(owner, &directory, InodePhase::Directory)?;
    let mut path = Vec::new();
    let mut chain = vec![directory.try_clone()?];
    for part in parts {
        path.push((*part).to_owned());
        progress.push(DirectoryProgress {
            label,
            parts: path.clone(),
            retained: None,
            created: false,
        });
        let member = progress
            .last_mut()
            .ok_or_else(|| io::Error::other("directory progress slot absent"))?;
        let created = match fs::mkdirat(&directory, *part, Mode::from_raw_mode(0o2770)) {
            Ok(()) => true,
            Err(error) if error == rustix::io::Errno::EXIST => false,
            Err(error) => return Err(error.into()),
        };
        member.created = created;
        member.retained = Some(File::from(fs::openat(
            &directory,
            *part,
            flags,
            Mode::empty(),
        )?));
        let child = member
            .retained
            .as_ref()
            .ok_or_else(|| io::Error::other("directory descriptor absent"))?;
        if created {
            // Ordinary setgid creation inherits the provisioned group/project.
            // Reapply only the fixed shared directory mode removed by umask.
            fs::fchmod(child, Mode::from_raw_mode(0o2770))?;
        }
        check(owner, child, InodePhase::Directory)?;
        child.sync_all()?;
        directory.sync_all()?;
        directory = child.try_clone()?;
        chain.push(directory.try_clone()?);
    }
    let parent = Parent {
        file: directory,
        label,
        parts: parts.iter().map(|part| (*part).to_owned()).collect(),
        chain,
    };
    parent.recheck(owner)?;
    Ok(parent)
}

/// Allocates a random BKT-14 temporary name without creating a file.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn pending(parent: Parent, canonical: String) -> io::Result<PendingFile> {
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(PendingFile {
        parent,
        canonical,
        temporary: format!(".terrane-tmp:{}", super::state::hex(&random)),
        writer: None,
        readonly: None,
        published: false,
        closed: None,
        canonical_stamp: None,
    })
}

/// Refuses every existing canonical inode without opening its readable side.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn refuse_existing(parent: &Parent, name: &str) -> io::Result<()> {
    match fs::statat(&parent.file, name, fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "canonical admission candidate already exists",
        )),
    }
}

/// Synchronizes a private verified byte payload and checks actual writer closure.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn write(owner: &Custody, pending: &mut PendingFile, bytes: &[u8]) -> io::Result<()> {
    pending.parent.recheck(owner)?;
    pending.writer = Some(File::from(fs::openat(
        &pending.parent.file,
        &pending.temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?));
    let writer = pending
        .writer
        .as_mut()
        .ok_or_else(|| io::Error::other("admission writer absent"))?;
    check(owner, writer, InodePhase::Writer)?;
    writer.write_all(bytes)?;
    check(owner, writer, InodePhase::Writer)?;
    // Match existing index publication: owner write, shared content group read,
    // no other access. This does not substitute permission bits for verification.
    fs::fchmod(&*writer, Mode::from_raw_mode(0o640))?;
    writer.sync_all()?;
    check(owner, writer, InodePhase::Closed)?;
    let closing = FileStamp::capture(writer)?;
    let reader = open_regular_at(&pending.parent.file, &pending.temporary)?;
    same_inode(writer, &reader)?;
    pending.readonly = Some(reader);
    let writer = pending
        .writer
        .take()
        .ok_or_else(|| io::Error::other("admission writer disappeared"))?;
    let descriptor = writer.into_raw_fd();
    // SAFETY: into_raw_fd transfers unique ownership of this live descriptor.
    // Linux close consumes it even on EINTR; never retry or reuse the integer.
    if unsafe { libc::close(descriptor) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let reader = pending
        .readonly
        .as_ref()
        .ok_or_else(|| io::Error::other("admission reader absent"))?;
    check(owner, reader, InodePhase::Closed)?;
    closing.check(reader)?;
    verify_custodied_bytes(owner, reader, bytes)?;
    closing.check(reader)?;
    pending.closed = Some(closing);
    Ok(())
}

/// Publishes the exact retained inode without replacing any canonical member.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn publish(owner: &Custody, pending: &mut PendingFile, bytes: &[u8]) -> io::Result<()> {
    pending.parent.recheck(owner)?;
    let reader = pending
        .readonly
        .as_ref()
        .ok_or_else(|| io::Error::other("admission reader absent"))?;
    let closed = pending
        .closed
        .as_ref()
        .ok_or_else(|| io::Error::other("closed admission stamp absent"))?;
    closed.check(reader)?;
    verify_custodied_bytes(owner, reader, bytes)?;
    closed.check(reader)?;
    let named = open_regular_at(&pending.parent.file, &pending.temporary)?;
    same_inode(reader, &named)?;
    fs::renameat_with(
        &pending.parent.file,
        &pending.temporary,
        &pending.parent.file,
        &pending.canonical,
        RenameFlags::NOREPLACE,
    )?;
    pending.published = true;
    pending.parent.file.sync_all()?;
    let renamed = FileStamp::capture(reader)?;
    if !closed.same_content_metadata(&renamed) {
        return Err(io::Error::other("admission metadata changed during rename"));
    }
    // Rename may update ctime. Retain that specific observed transition only
    // after checking every other field against the actual post-close stamp.
    pending.canonical_stamp = Some(renamed);
    check_current(owner, pending, bytes)
}

/// Rechecks the complete canonical directory chain, member inode and bytes.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn check_current(
    owner: &Custody,
    pending: &PendingFile,
    bytes: &[u8],
) -> io::Result<()> {
    if !pending.published || pending.writer.is_some() {
        return Err(io::Error::other(
            "admission member is not closed and canonical",
        ));
    }
    pending.parent.recheck(owner)?;
    let reader = pending
        .readonly
        .as_ref()
        .ok_or_else(|| io::Error::other("admission reader absent"))?;
    let named = open_regular_at(&pending.parent.file, &pending.canonical)?;
    same_inode(reader, &named)?;
    let stamp = pending
        .canonical_stamp
        .as_ref()
        .ok_or_else(|| io::Error::other("canonical admission stamp absent"))?;
    stamp.check(reader)?;
    verify_custodied_bytes(owner, reader, bytes)?;
    let closing_name = open_regular_at(&pending.parent.file, &pending.canonical)?;
    same_inode(reader, &closing_name)?;
    stamp.check(&closing_name)?;
    pending.parent.recheck(owner)?;
    stamp.check(reader)
}

/// Checks actual configured UID, GID, project, device and inode class.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
fn check(owner: &Custody, file: &File, phase: InodePhase) -> io::Result<()> {
    let directory = matches!(phase, InodePhase::Directory);
    let value = file.metadata()?;
    let config = &owner.preparation.config;
    let project = NativeProject::inspect(file)?;
    if value.is_dir() != directory
        || (!directory && !value.is_file())
        || value.uid() != config.content_uid
        || value.gid() != config.content_gid
        || value.dev()
            != owner
                .preparation
                .layout()
                .directory_binding("layout-root")?
                .0
        || project.device != value.dev()
        || project.project_id != config.project_id
        || (directory && (!project.inherit || value.mode() & 0o7777 != 0o2770))
        || (!directory && (value.mode() & 0o7777 != phase.mode() || value.nlink() != 1))
    {
        return Err(io::Error::other(
            "admission inode differs from actual configured custody",
        ));
    }
    Ok(())
}

/// Distinguishes exact writable staging custody from closed shared custody.
#[derive(Clone, Copy)]
enum InodePhase {
    Directory,
    Writer,
    Closed,
}

impl InodePhase {
    fn mode(self) -> u32 {
        match self {
            Self::Directory => 0o2770,
            Self::Writer => 0o600,
            Self::Closed => 0o640,
        }
    }
}

/// Retains content and custody fields; atime alone may change during reads.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MetadataStamp {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<&std::fs::Metadata> for MetadataStamp {
    fn from(value: &std::fs::Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            length: value.len(),
            uid: value.uid(),
            gid: value.gid(),
            mode: value.mode(),
            links: value.nlink(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}

/// Retains actual kernel project assignment with the observed file incarnation.
struct FileStamp {
    metadata: MetadataStamp,
    project: NativeProject,
}

impl FileStamp {
    fn capture(file: &File) -> io::Result<Self> {
        let before = MetadataStamp::from(&file.metadata()?);
        let project = NativeProject::inspect(file)?;
        let after = MetadataStamp::from(&file.metadata()?);
        if before != after || project.device != before.device || project.inode != before.inode {
            return Err(io::Error::other(
                "admission custody changed during observation",
            ));
        }
        Ok(Self {
            metadata: before,
            project,
        })
    }

    fn check(&self, file: &File) -> io::Result<()> {
        let current = Self::capture(file)?;
        if self.metadata != current.metadata || self.project != current.project {
            return Err(io::Error::other("retained admission file metadata changed"));
        }
        Ok(())
    }

    fn same_content_metadata(&self, other: &Self) -> bool {
        let mut expected = self.metadata.clone();
        expected.changed = other.metadata.changed;
        expected == other.metadata && self.project == other.project
    }
}

fn verify_custodied_bytes(owner: &Custody, file: &File, bytes: &[u8]) -> io::Result<()> {
    check(owner, file, InodePhase::Closed)?;
    let before = FileStamp::capture(file)?;
    verify_bytes(file, bytes)?;
    check(owner, file, InodePhase::Closed)?;
    before.check(file)
}

fn same_inode(expected: &File, actual: &File) -> io::Result<()> {
    let left = expected.metadata()?;
    let right = actual.metadata()?;
    if MetadataStamp::from(&left) != MetadataStamp::from(&right) {
        return Err(io::Error::other("admission inode replaced or changed"));
    }
    Ok(())
}

/// Compares bounded positioned reads without changing the open description cursor.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn verify_bytes(file: &File, bytes: &[u8]) -> io::Result<()> {
    let before = file.metadata()?;
    if !before.is_file() || before.len() != bytes.len() as u64 {
        return Err(io::Error::other("admission length changed"));
    }
    let mut buffer = [0; 65536];
    for (index, expected) in bytes.chunks(buffer.len()).enumerate() {
        let offset = index
            .checked_mul(buffer.len())
            .ok_or_else(|| io::Error::other("admission offset overflow"))?;
        file.read_exact_at(
            &mut buffer[..expected.len()],
            u64::try_from(offset).map_err(io::Error::other)?,
        )?;
        if &buffer[..expected.len()] != expected {
            return Err(io::Error::other("admission bytes changed"));
        }
    }
    let after = file.metadata()?;
    if MetadataStamp::from(&before) != MetadataStamp::from(&after) {
        return Err(io::Error::other("admission inode changed during read"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    #[test]
    fn actual_admission_byte_check_is_positioned_and_rejects_modified_inode_bytes() {
        let mut random = [0; 16];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "terrane-admission-{}",
            super::super::state::hex(&random)
        ));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        // Retain the real inode while ensuring fixture cleanup on test failure.
        std::fs::remove_file(&path).unwrap();
        file.write_all(b"admission bytes").unwrap();
        file.seek(SeekFrom::Start(4)).unwrap();

        // These are observations of a real regular inode, not project or
        // admission authority. Exact phase modes and retained stamps reject
        // later permission changes even when bytes and length are unchanged.
        fs::fchmod(&file, Mode::from_raw_mode(0o600)).unwrap();
        let writer = MetadataStamp::from(&file.metadata().unwrap());
        assert_eq!(writer.mode & 0o7777, InodePhase::Writer.mode());
        fs::fchmod(&file, Mode::from_raw_mode(0o640)).unwrap();
        let closed = MetadataStamp::from(&file.metadata().unwrap());
        assert_eq!(closed.mode & 0o7777, InodePhase::Closed.mode());
        assert_ne!(writer, closed);
        fs::fchmod(&file, Mode::from_raw_mode(0o644)).unwrap();
        let changed = MetadataStamp::from(&file.metadata().unwrap());
        assert_ne!(changed.mode & 0o7777, InodePhase::Closed.mode());
        assert_ne!(closed, changed);
        fs::fchmod(&file, Mode::from_raw_mode(0o640)).unwrap();

        verify_bytes(&file, b"admission bytes").unwrap();
        assert_eq!(file.stream_position().unwrap(), 4);
        file.write_all_at(b"X", 0).unwrap();
        assert!(verify_bytes(&file, b"admission bytes").is_err());
        assert!(verify_bytes(&file, b"short").is_err());
    }
}
