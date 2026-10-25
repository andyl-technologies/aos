//! Implements descriptor-relative sealed-inode publication on local filesystems.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use rustix::fs::{self, AtFlags, Mode, OFlags};
#[cfg(feature = "tokio")]
use terrane_format::identity::Descriptor;
use terrane_format::properties::Domain;
use terrane_sdk::host::publication::{
    AdoptionFailure, PublicationClaim, PublicationKernel, VerityBinding,
};

use crate::verity;

#[path = "native_adoption.rs"]
mod adoption;

#[path = "native_quarantine.rs"]
mod quarantine;

#[cfg(feature = "tokio")]
pub(crate) use quarantine::quarantine_name;

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
    let file = super::path::open_directory(path)?;
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

#[cfg(feature = "tokio")]
/// Retains every checked directory and the original provisioning exclusion.
///
/// Internal adapters share these exact open descriptions. They never use their
/// directory offsets, and sharing creates no additional kernel descriptors.
pub(super) struct PreparedLayout {
    pub root: Arc<File>,
    pub chunks: Arc<File>,
    pub objects: Arc<File>,
    pub pending: Arc<File>,
    pub quarantine: Arc<File>,
    _state: Arc<File>,
    _sealed: Arc<File>,
    _staging: Arc<File>,
    _publication: Arc<File>,
    _provisioning: crate::host_quota::DomainProvisioningGuard,
}

#[cfg(feature = "tokio")]
pub(super) fn inspect_layout(config: &super::NativePublisherConfig) -> io::Result<PreparedLayout> {
    if !config.layout_root.is_absolute()
        || config
            .layout_root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(invalid(
            "publisher layout must be absolute without parent traversal",
        ));
    }
    let mut retained = Vec::new();
    let mut device = None;
    let mut inodes = Vec::new();
    let mut provisioning = None;
    for (relative, content, private) in [
        ("", false, false),
        ("state", false, false),
        ("chunks", true, false),
        ("objects", true, false),
        ("quarantine", true, false),
        ("sealed", false, true),
        ("staging", false, true),
        ("pending-delete", false, true),
        ("state/publication", false, true),
    ] {
        let path = config.layout_root.join(relative);
        let file = super::path::open_directory(&path)?;
        let metadata = file.metadata()?;
        let permissions = metadata.mode() & 0o7777;
        let valid = if content {
            metadata.uid() == config.content_uid
                && metadata.gid() == config.content_gid
                && permissions == 0o2770
        } else if private {
            metadata.uid() == rustix::process::geteuid().as_raw() && permissions == 0o700
        } else {
            (metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw())
                && permissions & 0o022 == 0
        };
        if !valid
            || device.is_some_and(|expected| expected != metadata.dev())
            || inodes.contains(&metadata.ino())
        {
            return Err(invalid(
                "publisher layout has unsafe ownership, mode, device or alias",
            ));
        }
        if relative.is_empty() {
            // The host provisioner takes the exclusive lock on this same inode.
            // Keep shared custody before any staging cleanup or other mutation.
            provisioning = Some(crate::host_quota::DomainProvisioningGuard::shared(&file)?);
        }
        device = Some(metadata.dev());
        inodes.push(metadata.ino());
        retained.push(Arc::new(file));
    }
    let [
        root,
        state,
        chunks,
        objects,
        quarantine,
        sealed,
        staging,
        pending,
        publication,
    ]: [Arc<File>; 9] = retained
        .try_into()
        .map_err(|_| invalid("publisher layout directory inventory changed"))?;
    Ok(PreparedLayout {
        root,
        chunks,
        objects,
        pending,
        quarantine,
        _state: state,
        _sealed: sealed,
        _staging: staging,
        _publication: publication,
        _provisioning: provisioning
            .ok_or_else(|| io::Error::other("publisher root guard missing"))?,
    })
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
    // A staged writer can outlive its adapter. Keep the root flock until that
    // writer and reader close, so restart cleanup cannot race the live inode.
    _staging_root: Arc<File>,
    confinement: Arc<crate::quota_confinement::Installed>,
    name: String,
}

impl Read for StagedFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.confinement.check_current()?;
        self.reader.read(bytes)
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        // An inherited child cannot exercise the parent's mutable receipt.
        if self.confinement.check_current().is_err() {
            return;
        }
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
    confinement: Arc<crate::quota_confinement::Installed>,
    domain: String,
    sealed: File,
    staging_root: Arc<File>,
    staging: Option<Arc<File>>,
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
        self.confinement.check_current()?;
        let staging = Arc::clone(self.private_staging()?);
        loop {
            self.next_staging = self
                .next_staging
                .checked_add(1)
                .ok_or_else(|| io::Error::other("staging sequence exhausted"))?;
            let temporary = format!("probe-{}-{}", std::process::id(), self.next_staging);
            let descriptor = match fs::openat(
                staging.as_ref(),
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(error.into()),
            };
            let result = (|| {
                let writer = File::from(descriptor);
                fs::fchmod(&writer, Mode::from_raw_mode(0o600))?;
                let reader = File::from(fs::openat(
                    staging.as_ref(),
                    temporary.as_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
                compare_inode(&writer, &reader)?;
                close_writer(writer)?;
                seal_private_inode(&reader)?;
                reader.sync_all()?;
                Ok(reader)
            })();
            let cleanup = fs::unlinkat(staging.as_ref(), temporary.as_str(), AtFlags::empty());
            cleanup?;
            return result;
        }
    }

    /// Opens existing publisher-owned native directories without symlinks.
    ///
    /// The caller must provision distinct filesystem roots for distinct
    /// disclosure domains. The receipt must come from actual single-threaded
    /// confinement installation before any mutable role resources are opened.
    /// It remains retained through native and staged-inode ownership. The
    /// exclusive sealed-directory lock prevents
    /// concurrent publisher processes from racing identity-checked mutations.
    ///
    /// # Errors
    /// Rejects unsafe ownership, permissions, filesystem types, cross-device
    /// paths, symlinks, changed confinement and an already-running publisher
    /// for this directory.
    pub fn open(
        confinement: Arc<crate::quota_confinement::Installed>,
        domain: String,
        sealed: &Path,
        staging: &Path,
        pending: &Path,
    ) -> io::Result<Self> {
        confinement.check_current()?;
        let mut publisher = Self::open_unrecovered(confinement, domain, sealed, staging, pending)?;
        publisher.initialize_staging()?;
        Ok(publisher)
    }

    pub(super) fn open_unrecovered(
        confinement: Arc<crate::quota_confinement::Installed>,
        domain: String,
        sealed: &Path,
        staging: &Path,
        pending: &Path,
    ) -> io::Result<Self> {
        confinement.check_current()?;
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
        let quarantine = super::path::open_directory(&quarantine_path)?;
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
        Ok(Self {
            confinement,
            domain,
            sealed,
            staging_root: Arc::new(staging),
            staging: None,
            pending,
            quarantine,
            next_staging: 0,
        })
    }

    fn private_staging(&self) -> io::Result<&Arc<File>> {
        self.confinement.check_current()?;
        self.staging
            .as_ref()
            .ok_or_else(|| io::Error::other("publisher staging is not initialized"))
    }

    pub(super) fn initialize_staging(&mut self) -> io::Result<()> {
        self.confinement.check_current()?;
        let entries = fs::Dir::read_from(self.staging_root.as_ref())?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let directory = File::from(fs::openat(
                self.staging_root.as_ref(),
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            check_directory(&directory)?;
            let directory_metadata = directory.metadata()?;
            if directory_metadata.mode() & 0o777 != 0o700
                || directory_metadata.dev() != self.staging_root.metadata()?.dev()
            {
                return Err(invalid(
                    "stale publisher staging must remain private on the retained filesystem",
                ));
            }
            for child in fs::Dir::read_from(&directory)? {
                let child = child?;
                let child_name = child.file_name();
                if child_name.to_bytes() == b"." || child_name.to_bytes() == b".." {
                    continue;
                }
                let metadata = fs::statat(&directory, child_name, AtFlags::SYMLINK_NOFOLLOW)?;
                if metadata.st_uid != rustix::process::geteuid().as_raw()
                    || metadata.st_dev != directory_metadata.dev()
                    || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
                {
                    return Err(invalid("unexpected inode in publisher-private staging"));
                }
                fs::unlinkat(&directory, child_name, AtFlags::empty())?;
            }
            directory.sync_all()?;
            fs::unlinkat(self.staging_root.as_ref(), name, AtFlags::REMOVEDIR)?;
        }
        self.staging_root.sync_all()?;

        // The registered staging/<publisher-id>/ grammar needs no new key.
        // Root exclusion prevents PID reuse from racing another live publisher.
        let publisher_id = std::process::id().to_string();
        fs::mkdirat(
            self.staging_root.as_ref(),
            publisher_id.as_str(),
            Mode::from_raw_mode(0o700),
        )?;
        self.staging_root.sync_all()?;
        let directory = File::from(fs::openat(
            self.staging_root.as_ref(),
            publisher_id.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        check_directory(&directory)?;
        if directory.metadata()?.mode() & 0o777 != 0o700 {
            return Err(invalid(
                "publisher staging subdirectory must be private mode0700",
            ));
        }
        self.staging = Some(Arc::new(directory));
        Ok(())
    }

    fn check_claim(&self, claim: &PublicationClaim) -> io::Result<()> {
        self.confinement.check_current()?;
        if claim.domain() != self.domain {
            return Err(invalid("publisher disclosure domain mismatch"));
        }
        Ok(())
    }

    fn shard(&self, claim: &PublicationClaim) -> io::Result<File> {
        self.confinement.check_current()?;
        self.check_claim(claim)?;
        child_directory(&self.sealed, &name(claim)[..2])
    }

    #[cfg(feature = "tokio")]
    pub(super) fn existing_canonical_identity(
        &self,
        claim: &PublicationClaim,
    ) -> io::Result<Option<(u64, u64)>> {
        self.check_claim(claim)?;
        let key = name(claim);
        let shard = match fs::openat(
            &self.sealed,
            &key[..2],
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(shard) => File::from(shard),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        check_directory(&shard)?;
        if shard.metadata()?.dev() != self.sealed.metadata()?.dev() {
            return Err(invalid("canonical retention shard changed filesystem"));
        }
        let file = match fs::openat(
            &shard,
            key.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.dev() != self.sealed.metadata()?.dev() {
            return Err(invalid("unsafe canonical retention preflight inode"));
        }
        Ok(Some((metadata.dev(), metadata.ino())))
    }

    /// Renames a sealed inode into bounded two-phase deletion storage.
    ///
    /// The caller must re-extract live chunk ranges and durably record the
    /// deletion deadline before releasing its exclusion over cache policy.
    ///
    /// # Errors
    /// Returns domain, missing inode, conflicting pending name or sync failures.
    pub fn retire(&mut self, claim: &PublicationClaim) -> io::Result<()> {
        self.confinement.check_current()?;
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
        self.confinement.check_current()?;
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

    #[cfg(feature = "tokio")]
    pub(super) fn retire_checked(
        &mut self,
        claim: &PublicationClaim,
        expected: &File,
    ) -> io::Result<()> {
        self.confinement.check_current()?;
        let current = self.open(claim)?;
        compare_inode(expected, &current)?;
        self.retire(claim)
    }

    // This observation intentionally does not measure verity or hash bytes.
    // A pending sealed entry may be corrupt and still need safe retirement.
    #[cfg(feature = "tokio")]
    pub(super) fn inspect_pending_sealed(&self, descriptor: &Descriptor) -> io::Result<File> {
        self.confinement.check_current()?;
        let name: String = descriptor
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let file = File::from(fs::openat(
            &self.pending,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
            || metadata.dev() != self.pending.metadata()?.dev()
        {
            return Err(invalid("unsafe pending sealed inode custody"));
        }
        // Reinforce a prior rename whose reply or parent sync may have failed.
        // This makes subsequent lifecycle acknowledgment durable in both names.
        let shard_name: String = descriptor.digest()[..1]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        match fs::openat(
            &self.sealed,
            shard_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(shard) => File::from(shard).sync_all()?,
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => return Err(error.into()),
        }
        self.pending.sync_all()?;
        Ok(file)
    }

    #[cfg(feature = "tokio")]
    /// Restores the original pending inode and rechecks its canonical name.
    ///
    /// # Errors
    /// Refuses changed inode custody, occupied canonical names, unsafe opens
    /// and failed directory synchronization before the caller can acknowledge.
    pub(super) fn restore_pending_sealed(
        &mut self,
        descriptor: &Descriptor,
        expected: &File,
    ) -> io::Result<()> {
        self.confinement.check_current()?;
        let current = self.inspect_pending_sealed(descriptor)?;
        compare_inode(expected, &current)?;
        let name: String = descriptor
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let shard = child_directory(&self.sealed, &name[..2])?;
        fs::renameat_with(
            &self.pending,
            name.as_str(),
            &shard,
            name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )?;
        self.pending.sync_all()?;
        shard.sync_all()?;
        let restored = File::from(fs::openat(
            &shard,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        compare_inode(expected, &restored)
    }

    #[cfg(feature = "tokio")]
    pub(super) fn finish_pending_sealed(
        &mut self,
        descriptor: &Descriptor,
        expected: &File,
    ) -> io::Result<()> {
        self.confinement.check_current()?;
        let current = self.inspect_pending_sealed(descriptor)?;
        compare_inode(expected, &current)?;
        let name: String = descriptor
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        fs::unlinkat(&self.pending, name.as_str(), AtFlags::empty())?;
        self.pending.sync_all()
    }

    /// Unlinks an expired pending inode for a domain with `wipe = none`.
    ///
    /// This operation does not implement zero, discard or volatile wiping.
    ///
    /// # Errors
    /// Returns domain, unlink or synchronization errors.
    pub fn complete_unlink_none(&mut self, claim: &PublicationClaim) -> io::Result<()> {
        self.confinement.check_current()?;
        self.check_claim(claim)?;
        fs::unlinkat(&self.pending, name(claim).as_str(), AtFlags::empty())?;
        self.pending.sync_all()
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

/// Enables the real seal while owner write permission remains on the inode.
///
/// Linux checks MAY_WRITE even though fs-verity must receive a read-only FD
/// with every writer closed. Private mode0600 permits that check without any
/// capability. Final mode0400 is installed on the same sealed inode before
/// durability or canonical publication; mode bits never substitute for sealing.
///
/// # Errors
/// Refuses unsafe private metadata or a writable descriptor, genuine seal or
/// measurement failure, failed final permissions and changed inode identity.
fn seal_private_inode(reader: &File) -> io::Result<VerityBinding> {
    let before = reader.metadata()?;
    let flags = fs::fcntl_getfl(reader)?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
    {
        return Err(invalid(
            "private seal requires an owned mode0600 inode and read-only descriptor",
        ));
    }
    let binding = verity::enable(reader)?;
    fs::fchmod(reader, Mode::from_raw_mode(0o400))?;
    let after = reader.metadata()?;
    if !after.is_file()
        || (
            after.dev(),
            after.ino(),
            after.uid(),
            after.gid(),
            after.len(),
            after.nlink(),
        ) != (
            before.dev(),
            before.ino(),
            before.uid(),
            before.gid(),
            before.len(),
            before.nlink(),
        )
        || after.mode() & 0o7777 != 0o400
    {
        return Err(invalid(
            "sealed private inode changed before final mode0400 custody",
        ));
    }
    Ok(binding)
}

impl PublicationKernel for NativePublisher {
    type Source = File;
    type Staged = StagedFile;
    type Handle = File;

    fn stage(&mut self, claim: &PublicationClaim, mut source: File) -> io::Result<StagedFile> {
        self.confinement.check_current()?;
        self.check_claim(claim)?;
        let staging = Arc::clone(self.private_staging()?);
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
                staging.as_ref(),
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(error.into()),
            };
            let mut writer = File::from(descriptor);
            // Keep owner MAY_WRITE for the later read-only fs-verity ioctl,
            // including when the caller's umask removed a requested owner bit.
            fs::fchmod(&writer, Mode::from_raw_mode(0o600))?;
            // Never write the lookahead byte: at an allocation boundary it
            // would consume a block outside the claimed plaintext reservation.
            let copied = io::copy(
                &mut Read::by_ref(&mut source).take(claim.plaintext_size()),
                &mut writer,
            );
            let verified_length = copied.and_then(|copied| {
                if copied != claim.plaintext_size() {
                    return Err(invalid("source length changed during copy"));
                }
                let mut extra = [0];
                if source.read(&mut extra)? != 0 {
                    return Err(invalid("source length changed during copy"));
                }
                Ok(())
            });
            if let Err(error) = verified_length {
                let _cleanup = fs::unlinkat(staging.as_ref(), temporary.as_str(), AtFlags::empty());
                return Err(error);
            }
            let reader = File::from(fs::openat(
                staging.as_ref(),
                temporary.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            compare_inode(&writer, &reader)?;
            return Ok(StagedFile {
                reader,
                writer: Some(writer),
                directory: Arc::clone(&staging),
                _staging_root: Arc::clone(&self.staging_root),
                confinement: Arc::clone(&self.confinement),
                name: temporary,
            });
        }
    }

    fn close_writers(&mut self, staged: &mut StagedFile) -> io::Result<()> {
        self.confinement.check_current()?;
        if let Some(writer) = staged.writer.take() {
            close_writer(writer)?;
        }
        Ok(())
    }

    fn seal(&mut self, staged: &StagedFile) -> io::Result<VerityBinding> {
        self.confinement.check_current()?;
        if staged.writer.is_some() {
            return Err(invalid("private inode still has a writer"));
        }
        seal_private_inode(&staged.reader)
    }

    fn sync_staged(&mut self, staged: &StagedFile) -> io::Result<()> {
        self.confinement.check_current()?;
        staged.reader.sync_all()
    }

    fn insert(&mut self, claim: &PublicationClaim, staged: &StagedFile) -> io::Result<bool> {
        self.confinement.check_current()?;
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
        self.confinement.check_current()?;
        self.shard(claim)?.sync_all()
    }

    fn rollback(&mut self, claim: &PublicationClaim, staged: &StagedFile) -> io::Result<()> {
        self.confinement.check_current()?;
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
        adoption::open_candidate(&shard, &name(claim), &self.sealed)
    }

    fn measure(&mut self, handle: &File) -> io::Result<VerityBinding> {
        self.confinement.check_current()?;
        verity::measure(handle)
    }

    fn retain_staged(&mut self, staged: &StagedFile) -> io::Result<File> {
        self.confinement.check_current()?;
        staged.reader.try_clone()
    }

    fn duplicate_handle(&mut self, handle: &File) -> io::Result<File> {
        self.confinement.check_current()?;
        handle.try_clone()
    }

    fn sync_handle(&mut self, handle: &File) -> io::Result<()> {
        self.confinement.check_current()?;
        adoption::synchronize_verified(handle, &self.sealed)
    }

    fn quarantine_adoption_failure(
        &mut self,
        claim: &PublicationClaim,
        rejected: &Self::Handle,
        cause: &AdoptionFailure,
    ) -> io::Result<()> {
        self.confinement.check_current()?;
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
            AdoptionFailure::Quarantine { .. } | AdoptionFailure::BindingRepair(_) => false,
        };
        if !corrupt {
            return Ok(());
        }
        let quarantine = self.quarantine.try_clone()?;
        self.quarantine_rejected(claim, rejected, &quarantine)
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
