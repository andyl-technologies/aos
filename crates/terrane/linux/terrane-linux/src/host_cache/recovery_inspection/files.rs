//! Retains readonly canonical shared-content inodes and rechecks their custody.

use super::{ContentCustody, NativeRecoveryInspector};
use crate::host_quota::NativeProject;
use rustix::fs::{Mode, OFlags, open, openat};
use std::{
    fs::{File, Metadata},
    io,
    os::{
        fd::AsRawFd,
        unix::{fs::FileExt, fs::MetadataExt},
    },
};
use terrane_sdk::pack::PackId;

#[derive(Clone)]
pub(super) enum CanonicalName {
    Pack { id: PackId, index: bool },
    Chunk { digest: String, codec: u32 },
}

impl CanonicalName {
    fn components(&self) -> (&'static str, Vec<String>, String) {
        match self {
            Self::Pack { id, index } => (
                "objects",
                vec!["pack".into(), format!("{:02x}", id.as_bytes()[0])],
                format!("{id}.{}", if *index { "idx" } else { "pack" }),
            ),
            Self::Chunk { digest, codec } => (
                "chunks",
                vec![digest[..2].to_owned()],
                format!("{digest}.{codec}"),
            ),
        }
    }
}

/// Private source construction accepts only generated, registered shared keys.
pub(super) struct RetainedFile {
    context: NativeRecoveryInspector,
    name: CanonicalName,
    file: File,
    metadata: Metadata,
    parents: Vec<File>,
    parent: File,
}

impl RetainedFile {
    pub(super) fn open(context: &NativeRecoveryInspector, name: CanonicalName) -> io::Result<Self> {
        context.check_current()?;
        let (label, components, leaf) = name.components();
        let root = context
            .layout
            .directories
            .get(label)
            .ok_or_else(|| invalid("missing retained shared-content directory"))?;
        let mut parent = File::from(openat(root, ".", directory_flags(), Mode::empty())?);
        check_custody(context, &parent, true)?;
        let mut parents = vec![parent.try_clone()?];
        for component in components {
            parent = File::from(openat(
                &parent,
                component,
                directory_flags(),
                Mode::empty(),
            )?);
            check_custody(context, &parent, true)?;
            parents.push(parent.try_clone()?);
        }
        // NONBLOCK prevents a replaced FIFO from waiting for a writer. Devices
        // are classified through O_PATH before any readable open is attempted.
        let path = File::from(openat(
            &parent,
            &leaf,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let expected = path.metadata()?;
        if !expected.is_file() {
            return Err(invalid("shared-content candidate is not an ordinary file"));
        }
        let file = File::from(open(
            format!("/proc/self/fd/{}", path.as_raw_fd()),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !same_file(&expected, &metadata) {
            return Err(invalid("shared-content candidate changed during open"));
        }
        check_custody(context, &file, false)?;
        let source = Self {
            context: context.clone(),
            name,
            file,
            metadata,
            parents,
            parent,
        };
        source.recheck()?;
        Ok(source)
    }

    pub(super) fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn parent(&self) -> &File {
        &self.parent
    }

    pub(super) fn context(&self) -> &NativeRecoveryInspector {
        &self.context
    }

    pub(super) fn matches(&self, file: &File) -> io::Result<()> {
        let flags = rustix::fs::fcntl_getfl(file)?;
        if flags.intersects(OFlags::PATH | OFlags::WRONLY | OFlags::RDWR)
            || !same_file(&self.metadata, &file.metadata()?)
        {
            return Err(invalid(
                "publisher candidate differs from retained canonical inode",
            ));
        }
        Ok(())
    }

    pub(super) fn read(&self, bound: usize) -> io::Result<Vec<u8>> {
        self.recheck()?;
        let bytes = read_bounded(&self.file, bound)?;
        self.recheck()?;
        Ok(bytes)
    }

    pub(super) fn check_hash(&self, expected: blake3::Hash) -> io::Result<()> {
        self.recheck()?;
        verify_read_hash(
            &self.file,
            self.context.reads.max_allocation_bytes,
            expected,
        )?;
        self.recheck()
    }

    pub(super) fn recheck(&self) -> io::Result<()> {
        self.context.check_current()?;
        if !same_file(&self.metadata, &self.file.metadata()?) {
            return Err(invalid("retained shared-content inode changed"));
        }
        let (label, components, leaf) = self.name.components();
        let root = self
            .context
            .layout
            .directories
            .get(label)
            .ok_or_else(|| invalid("missing retained shared-content directory"))?;
        let mut current = File::from(openat(root, ".", directory_flags(), Mode::empty())?);
        let mut parents = self.parents.iter();
        check_parent(parents.next(), &current)?;
        check_custody(&self.context, &current, true)?;
        for component in components {
            current = File::from(openat(
                &current,
                component,
                directory_flags(),
                Mode::empty(),
            )?);
            check_parent(parents.next(), &current)?;
            check_custody(&self.context, &current, true)?;
        }
        let path = File::from(openat(
            &current,
            leaf,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        if !same_file(&self.metadata, &path.metadata()?) {
            return Err(invalid("canonical shared-content pathname changed"));
        }
        check_custody(&self.context, &self.file, false)
    }
}

pub(super) fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
}

fn check_parent(expected: Option<&File>, actual: &File) -> io::Result<()> {
    let expected = expected
        .ok_or_else(|| invalid("missing retained canonical parent"))?
        .metadata()?;
    let actual = actual.metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(invalid("canonical shared-content parent changed"));
    }
    Ok(())
}

fn check_custody(
    context: &NativeRecoveryInspector,
    file: &File,
    directory: bool,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    context.custody.check(&metadata, directory)?;
    let project = NativeProject::inspect(file)?;
    if metadata.dev() != context.layout.directory_binding("layout-root")?.0
        || project.project_id != context.project_id
        || (directory && !project.inherit)
    {
        return Err(invalid(
            "shared-content candidate has foreign native custody",
        ));
    }
    Ok(())
}

impl ContentCustody {
    pub(super) fn check(&self, metadata: &Metadata, directory: bool) -> io::Result<()> {
        if metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.is_dir() != directory
            || (!directory && !metadata.is_file())
            || (directory && metadata.mode() & 0o7777 != self.directory_mode)
            || (!directory && metadata.mode() & 0o002 != 0)
        {
            return Err(invalid(
                "shared-content inode differs from configured custody",
            ));
        }
        Ok(())
    }
}

pub(super) fn read_bounded(file: &File, bound: usize) -> io::Result<Vec<u8>> {
    let before = file.metadata()?;
    let length = usize::try_from(before.len()).map_err(invalid)?;
    if !before.is_file() || length > bound {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "candidate exceeds encoded read budget",
        ));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(invalid)?;
    bytes.resize(length, 0);
    let mut offset = 0;
    while offset < length {
        let count = file.read_at(&mut bytes[offset..], offset as u64)?;
        if count == 0 {
            return Err(invalid("candidate shortened during positioned read"));
        }
        offset += count;
    }
    if !same_file(&before, &file.metadata()?) {
        return Err(invalid("candidate changed during positioned read"));
    }
    Ok(bytes)
}

pub(super) fn verify_read_hash(
    file: &File,
    bound: usize,
    expected: blake3::Hash,
) -> io::Result<()> {
    let encoded = read_bounded(file, bound)?;
    if blake3::hash(&encoded) != expected {
        return Err(invalid("verified encoded source bytes changed"));
    }
    Ok(())
}

pub(super) fn same_file(left: &Metadata, right: &Metadata) -> bool {
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

pub(super) fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
