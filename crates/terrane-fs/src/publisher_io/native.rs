//! Implements descriptor-relative sealed-inode publication on local filesystems.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags};
use terrane::host::publication::{
    AdoptionFailure, PublicationClaim, PublicationKernel, VerityBinding,
};
use terrane_core::properties::Domain;

use crate::verity;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "publisher directory must be an absolute path without parent traversal",
        ));
    }
    let descriptor = fs::openat2(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )?;
    let file = File::from(descriptor);
    check_directory(&file)?;
    Ok(file)
}

fn check_directory(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid(
            "publisher directory must be owned by publisher without other writers",
        ));
    }
    // Explicitly admit native filesystems supporting fs-verity. A seal ioctl
    // subsequently proves support for the particular inode and superblock.
    let stat = fs::fstatfs(file)?;
    if !matches!(stat.f_type as u64, 0xef53 | 0xf2f5_2010 | 0x9123_683e) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sealed directory requires native ext4, f2fs or btrfs",
        ));
    }
    Ok(())
}

fn child_directory(parent: &File, name: &str) -> io::Result<File> {
    match fs::mkdirat(parent, name, Mode::from_raw_mode(0o755)) {
        Ok(()) => parent.sync_all()?,
        Err(error) if error == rustix::io::Errno::EXIST => {}
        Err(error) => return Err(error.into()),
    }
    let file = File::from(fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    check_directory(&file)?;
    Ok(file)
}

fn name(claim: &PublicationClaim) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(claim.descriptor().digest().len() * 2);
    for byte in claim.descriptor().digest() {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 15)]));
    }
    name
}

/// Retains a private reader and unexported writer through verification.
pub struct StagedFile {
    reader: File,
    writer: Option<File>,
    directory: Arc<File>,
    name: String,
}

impl Read for StagedFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reader.read(bytes)
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        // Unserved scratch files are safe to clean on restart if unlink fails.
        let _result = fs::unlinkat(
            self.directory.as_ref(),
            self.name.as_str(),
            AtFlags::empty(),
        );
    }
}

/// Owns one disclosure domain's sealed, staging and pending-delete directories.
pub struct NativePublisher {
    domain: String,
    sealed: File,
    staging: Arc<File>,
    pending: File,
    quarantine: File,
    next_staging: u64,
}

impl NativePublisher {
    /// Creates and measures an empty private inode for internal capability checks.
    ///
    /// The returned read-only descriptor is a probe, not a serving handle: it
    /// has no canonical name or publication binding. Cache inspection must
    /// independently measure it and check its filesystem against retained roots.
    ///
    /// # Errors
    /// Returns private creation, writer close, genuine seal, sync or open errors.
    pub fn probe_seal(&mut self) -> io::Result<File> {
        loop {
            self.next_staging = self
                .next_staging
                .checked_add(1)
                .ok_or_else(|| io::Error::other("staging sequence exhausted"))?;
            let temporary = format!("probe-{}-{}", std::process::id(), self.next_staging);
            let descriptor = match fs::openat(
                self.staging.as_ref(),
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o400),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(error.into()),
            };
            let result = (|| {
                close_writer(File::from(descriptor))?;
                let reader = File::from(fs::openat(
                    self.staging.as_ref(),
                    temporary.as_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
                verity::enable(&reader)?;
                reader.sync_all()?;
                Ok(reader)
            })();
            let cleanup = fs::unlinkat(self.staging.as_ref(), temporary.as_str(), AtFlags::empty());
            cleanup?;
            return result;
        }
    }

    /// Opens existing publisher-owned native directories without symlinks.
    ///
    /// The caller must provision distinct filesystem roots for distinct
    /// disclosure domains. The exclusive sealed-directory lock prevents
    /// concurrent publisher processes from racing identity-checked mutations.
    ///
    /// # Errors
    /// Rejects unsafe ownership, permissions, filesystem types, cross-device
    /// paths, symlinks and an already-running publisher for this directory.
    pub fn open(domain: String, sealed: &Path, staging: &Path, pending: &Path) -> io::Result<Self> {
        Domain::parse(&domain)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let quarantine_path = sealed
            .parent()
            .ok_or_else(|| invalid("sealed root has no parent"))?
            .join("quarantine");
        let sealed = open_directory(sealed)?;
        let staging = open_directory(staging)?;
        let pending = open_directory(pending)?;
        if staging.metadata()?.mode() & 0o777 != 0o700 {
            return Err(invalid(
                "publisher staging directory must be private mode 0700",
            ));
        }
        let device = sealed.metadata()?.dev();
        let quarantine = File::from(fs::openat2(
            fs::CWD,
            &quarantine_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?);
        let quarantine_metadata = quarantine.metadata()?;
        if quarantine_metadata.mode() & 0o002 != 0 || quarantine_metadata.dev() != device {
            return Err(invalid("unsafe domain quarantine directory"));
        }
        if staging.metadata()?.dev() != device || pending.metadata()?.dev() != device {
            return Err(invalid("publisher directories must share one filesystem"));
        }
        let inodes = [
            sealed.metadata()?.ino(),
            staging.metadata()?.ino(),
            pending.metadata()?.ino(),
        ];
        if inodes[0] == inodes[1] || inodes[0] == inodes[2] || inodes[1] == inodes[2] {
            return Err(invalid("publisher directories must be distinct"));
        }
        fs::flock(&sealed, fs::FlockOperation::NonBlockingLockExclusive)?;
        fs::flock(&staging, fs::FlockOperation::NonBlockingLockExclusive)?;
        fs::flock(&pending, fs::FlockOperation::NonBlockingLockExclusive)?;
        let publisher = Self {
            domain,
            sealed,
            staging: Arc::new(staging),
            pending,
            quarantine,
            next_staging: 0,
        };
        publisher.recover_staging()?;
        Ok(publisher)
    }

    fn recover_staging(&self) -> io::Result<()> {
        let entries = fs::Dir::read_from(self.staging.as_ref())?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let metadata = fs::statat(self.staging.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW)?;
            if metadata.st_uid != rustix::process::geteuid().as_raw()
                || metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
            {
                return Err(invalid(
                    "unexpected staging owner or directory during recovery",
                ));
            }
            fs::unlinkat(self.staging.as_ref(), name, AtFlags::empty())?;
        }
        self.staging.sync_all()
    }

    fn check_claim(&self, claim: &PublicationClaim) -> io::Result<()> {
        if claim.domain() != self.domain {
            return Err(invalid("publisher disclosure domain mismatch"));
        }
        Ok(())
    }

    fn shard(&self, claim: &PublicationClaim) -> io::Result<File> {
        self.check_claim(claim)?;
        child_directory(&self.sealed, &name(claim)[..2])
    }

    /// Renames a sealed inode into bounded two-phase deletion storage.
    ///
    /// The caller must re-extract live chunk ranges and durably record the
    /// deletion deadline before releasing its exclusion over cache policy.
    ///
    /// # Errors
    /// Returns domain, missing inode, conflicting pending name or sync failures.
    pub fn retire(&mut self, claim: &PublicationClaim) -> io::Result<()> {
        let shard = self.shard(claim)?;
        let name = name(claim);
        fs::renameat_with(
            &shard,
            name.as_str(),
            &self.pending,
            name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )?;
        shard.sync_all()?;
        self.pending.sync_all()
    }

    /// Restores a pending inode without replacing any canonical entry.
    ///
    /// Restored files must pass `Publisher::adopt` before consumers receive them.
    ///
    /// # Errors
    /// Returns missing pending data, canonical conflict or synchronization errors.
    pub fn restore(&mut self, claim: &PublicationClaim) -> io::Result<()> {
        let shard = self.shard(claim)?;
        let name = name(claim);
        fs::renameat_with(
            &self.pending,
            name.as_str(),
            &shard,
            name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )?;
        self.pending.sync_all()?;
        shard.sync_all()
    }

    pub(super) fn retire_checked(
        &mut self,
        claim: &PublicationClaim,
        expected: &File,
    ) -> io::Result<()> {
        let current = self.open(claim)?;
        compare_inode(expected, &current)?;
        self.retire(claim)
    }

    pub(super) fn restore_checked(
        &mut self,
        claim: &PublicationClaim,
        expected: &File,
    ) -> io::Result<()> {
        let current = self.open_pending(claim)?;
        compare_inode(expected, &current)?;
        self.restore(claim)
    }

    pub(super) fn finish_none_checked(
        &mut self,
        claim: &PublicationClaim,
        expected: &File,
    ) -> io::Result<()> {
        let current = self.open_pending(claim)?;
        compare_inode(expected, &current)?;
        self.complete_unlink_none(claim)
    }

    fn open_pending(&self, claim: &PublicationClaim) -> io::Result<File> {
        self.check_claim(claim)?;
        let current = File::from(fs::openat(
            &self.pending,
            name(claim).as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        if !current.metadata()?.is_file() {
            return Err(invalid("pending body is not a regular inode"));
        }
        Ok(current)
    }

    /// Unlinks an expired pending inode for a domain with `wipe = none`.
    ///
    /// This operation does not implement zero, discard or volatile wiping.
    ///
    /// # Errors
    /// Returns domain, unlink or synchronization errors.
    pub fn complete_unlink_none(&mut self, claim: &PublicationClaim) -> io::Result<()> {
        self.check_claim(claim)?;
        fs::unlinkat(&self.pending, name(claim).as_str(), AtFlags::empty())?;
        self.pending.sync_all()
    }

    /// Moves an independently rejected canonical entry to scoped quarantine.
    ///
    /// The retained target directory must come from trusted configuration, not
    /// a request pathname. Cache policy retains quarantine until scrub confirms
    /// another good copy or the configured retention expires.
    ///
    /// # Errors
    /// Returns invalid target custody, cross-device, missing source, conflicting
    /// quarantine name or directory synchronization errors.
    pub fn quarantine_rejected(
        &mut self,
        claim: &PublicationClaim,
        quarantine: &File,
    ) -> io::Result<()> {
        self.check_claim(claim)?;
        let target = quarantine.metadata()?;
        if !target.is_dir()
            || target.mode() & 0o002 != 0
            || target.dev() != self.sealed.metadata()?.dev()
        {
            return Err(invalid("unsafe quarantine directory or filesystem"));
        }
        let shard = self.shard(claim)?;
        let name = name(claim);
        fs::renameat_with(
            &shard,
            name.as_str(),
            quarantine,
            name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )?;
        shard.sync_all()?;
        quarantine.sync_all()
    }
}

fn compare_inode(expected: &File, actual: &File) -> io::Result<()> {
    let expected = expected.metadata()?;
    let actual = actual.metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(invalid(
            "retained body incarnation no longer names this inode",
        ));
    }
    Ok(())
}

impl PublicationKernel for NativePublisher {
    type Source = File;
    type Staged = StagedFile;
    type Handle = File;

    fn stage(&mut self, claim: &PublicationClaim, mut source: File) -> io::Result<StagedFile> {
        self.check_claim(claim)?;
        let source_metadata = source.metadata()?;
        if !source_metadata.is_file() || source_metadata.len() != claim.plaintext_size() {
            return Err(invalid(
                "publication source must be an exact-length regular file",
            ));
        }
        let flags = fs::fcntl_getfl(&source)?;
        if flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
            return Err(invalid("publication source descriptor must be read-only"));
        }
        source.seek(SeekFrom::Start(0))?;
        loop {
            self.next_staging = self
                .next_staging
                .checked_add(1)
                .ok_or_else(|| io::Error::other("staging sequence exhausted"))?;
            let temporary = format!("{}-{}", std::process::id(), self.next_staging);
            let descriptor = match fs::openat(
                self.staging.as_ref(),
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o400),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(error.into()),
            };
            let mut writer = File::from(descriptor);
            let copied = io::copy(
                &mut source.take(claim.plaintext_size().saturating_add(1)),
                &mut writer,
            );
            if let Err(error) = copied.and_then(|copied| {
                if copied != claim.plaintext_size() {
                    Err(invalid("source length changed during copy"))
                } else {
                    Ok(())
                }
            }) {
                let _cleanup =
                    fs::unlinkat(self.staging.as_ref(), temporary.as_str(), AtFlags::empty());
                return Err(error);
            }
            let reader = File::from(fs::openat(
                self.staging.as_ref(),
                temporary.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            return Ok(StagedFile {
                reader,
                writer: Some(writer),
                directory: Arc::clone(&self.staging),
                name: temporary,
            });
        }
    }

    fn close_writers(&mut self, staged: &mut StagedFile) -> io::Result<()> {
        if let Some(writer) = staged.writer.take() {
            close_writer(writer)?;
        }
        Ok(())
    }

    fn seal(&mut self, staged: &StagedFile) -> io::Result<VerityBinding> {
        if staged.writer.is_some() {
            return Err(invalid("private inode still has a writer"));
        }
        verity::enable(&staged.reader)
    }

    fn sync_staged(&mut self, staged: &StagedFile) -> io::Result<()> {
        staged.reader.sync_all()
    }

    fn insert(&mut self, claim: &PublicationClaim, staged: &StagedFile) -> io::Result<bool> {
        let shard = self.shard(claim)?;
        match fs::linkat(
            staged.directory.as_ref(),
            staged.name.as_str(),
            &shard,
            name(claim).as_str(),
            AtFlags::empty(),
        ) {
            Ok(()) => Ok(true),
            Err(error) if error == rustix::io::Errno::EXIST => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn sync_parent(&mut self, claim: &PublicationClaim) -> io::Result<()> {
        self.shard(claim)?.sync_all()
    }

    fn rollback(&mut self, claim: &PublicationClaim, staged: &StagedFile) -> io::Result<()> {
        let current = self.open(claim)?;
        let expected = staged.reader.metadata()?;
        let actual = current.metadata()?;
        if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
            return Err(invalid("canonical inode changed before rollback"));
        }
        let shard = self.shard(claim)?;
        fs::unlinkat(&shard, name(claim).as_str(), AtFlags::empty())?;
        shard.sync_all()
    }

    fn open(&mut self, claim: &PublicationClaim) -> io::Result<File> {
        let shard = self.shard(claim)?;
        let file = File::from(fs::openat(
            &shard,
            name(claim).as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o222 != 0
            || metadata.len() != claim.plaintext_size()
        {
            return Err(invalid("unsafe canonical publisher inode"));
        }
        Ok(file)
    }

    fn measure(&mut self, handle: &File) -> io::Result<VerityBinding> {
        verity::measure(handle)
    }

    fn sync_handle(&mut self, handle: &File) -> io::Result<()> {
        handle.sync_all()
    }

    fn quarantine_adoption_failure(
        &mut self,
        claim: &PublicationClaim,
        cause: &AdoptionFailure,
    ) -> io::Result<()> {
        let corrupt = match cause {
            AdoptionFailure::RecordedBindingMismatch => true,
            AdoptionFailure::KernelSeal(error) => matches!(
                error.raw_os_error(),
                Some(libc::ENODATA | libc::EBADMSG | libc::EIO)
            ),
            AdoptionFailure::Plaintext(error) => {
                error.kind() == io::ErrorKind::InvalidData
                    || error.kind() == io::ErrorKind::UnexpectedEof
                    || error.raw_os_error() == Some(libc::EIO)
            }
            AdoptionFailure::Quarantine { .. } => false,
        };
        if !corrupt {
            return Ok(());
        }
        let quarantine = self.quarantine.try_clone()?;
        self.quarantine_rejected(claim, &quarantine)
    }
}

fn close_writer(writer: File) -> io::Result<()> {
    use std::os::fd::IntoRawFd;
    let descriptor = writer.into_raw_fd();
    // SAFETY: ownership was consumed from File, so this closes exactly once.
    // Linux releases the descriptor even on close failure; retrying could close
    // a descriptor reused by another thread and is intentionally forbidden.
    let result = unsafe { libc::close(descriptor) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
