//! Manual unsigned Nix key preparation and independently signed static inspection.
//!
//! The externally retained Core startup owns genuine selected launch and public
//! approval delivery. The preparation owner prepares candidates only: no TPM call, approval
//! signature, physical journal, runtime credential or current Session exists.
//! All originals and partially published files remain resident after failure.
//! Static inspection reuses these candidate and protected-file engines; it does
//! not initialize hardware, approve effects or establish session currentness.
//! The separate `initialize` coordinator borrows the hardware-selected startup,
//! verifies independent effect approval and drives the same selected supervisor
//! and private C engine. It never publishes runtime credentials or a floor.
//!
//! ```text
//! candidate-private-v3: AOSNPK03/version3/reserved + four ID16/seed32 + 4 auth32
//! candidate-public-v3:  AOSNPC03/version3 + job16/node16/commit32 + 4 ID16/public32
//! ```

use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox::normal_root::OfflineNixPrepareOriginV3;
use aos_sandbox_linux::inventory::MountId;
#[cfg(test)]
use ed25519_dalek::SigningKey;
use rustix::fs::{Mode, OFlags};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{BrokerSessionSecurityError, entropy};

mod approved_job;
mod initialize;

pub use approved_job::{NixApprovedJobInspectionAttemptV3, NixApprovedJobInspectionErrorV3};
pub use initialize::{
    NixOfflineHardwareAttemptV5, NixOfflineHardwareErrorV5, NixOfflineHardwareResourcesV5,
};

const JOB_NAME: &str = "sandbox-nix-floor-provision";
const PRIVATE_NAME: &str = "candidate-private-v3";
const PUBLIC_NAME: &str = "candidate-public-v3";
const MAXIMUM_NAMED_READBACKS: usize = 16;
#[cfg(test)]
const CANDIDATE_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.offline-candidates.v3\0";

/// Retains a redacted actual candidate preparation failure.
#[derive(Debug, thiserror::Error)]
pub enum NixPrepareKeysErrorV3 {
    /// The genuine Core startup retained its own original typed cause.
    #[error("original offline prepare startup is fenced")]
    Startup,
    /// The shared kernel entropy acquisition failed.
    #[error("offline candidate entropy failed")]
    Entropy(#[source] BrokerSessionSecurityError),
    /// An actual create, write, sync, readback or lock operation failed.
    #[error("offline candidate original I/O failed")]
    Io(#[from] io::Error),
    /// An actual original mount or descriptor observation failed.
    #[error("offline candidate kernel observation failed")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The sole positioned reader failed or observed unexpected trailing bytes.
    #[error("offline candidate exact read failed ({0:?})")]
    Read(aos_sandbox_linux::protected_file::ExactReadError),
    /// Fixed schema, separation, label or named original identity differs.
    #[error("offline candidate original custody differs")]
    Rejected,
    /// This attempt already completed, failed or was interrupted.
    #[error("offline candidate attempt is fenced")]
    Fenced,
}

impl From<rustix::io::Errno> for NixPrepareKeysErrorV3 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

type Error = NixPrepareKeysErrorV3;
type FileIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

/// Owns one fresh prepare-only attempt while borrowing the same genuine startup.
///
/// It exposes no file, seed, signer, TPM handle, raw journal or floor factory.
/// Keep it alive on error or unwind until the explicit failed process exit.
pub struct NixPrepareKeysAttemptV3<'startup> {
    origin: OfflineNixPrepareOriginV3<'startup>,
    attempted: bool,
    complete: bool,
    first_failure: Option<Error>,
    parent: Option<File>,
    parent_identity: Option<FileIdentity>,
    job_created: bool,
    directory: Option<File>,
    directory_identity: Option<FileIdentity>,
    directory_mount: Option<MountId>,
    lock: Option<File>,
    lock_identity: Option<FileIdentity>,
    files: [Option<File>; 2],
    identities: [Option<FileIdentity>; 2],
    named: Vec<File>,
    readbacks: Vec<Zeroizing<Vec<u8>>>,
    job_id: Zeroizing<Vec<u8>>,
    private: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

impl<'startup> NixPrepareKeysAttemptV3<'startup> {
    /// Parks empty attempt slots with the actual admitted startup loan.
    ///
    /// This constructor performs no protected I/O and admits no new authority.
    #[must_use]
    pub fn new(origin: OfflineNixPrepareOriginV3<'startup>) -> Self {
        Self {
            origin,
            attempted: false,
            complete: false,
            first_failure: None,
            parent: None,
            parent_identity: None,
            job_created: false,
            directory: None,
            directory_identity: None,
            directory_mount: None,
            lock: None,
            lock_identity: None,
            files: [None, None],
            identities: [None, None],
            named: Vec::new(),
            readbacks: Vec::new(),
            job_id: Zeroizing::new(Vec::new()),
            private: Zeroizing::new(Vec::new()),
            public: Vec::new(),
        }
    }

    /// Prepares and verifies the two exact unsigned candidate files once.
    ///
    /// # Errors
    /// Returns the resident first actual failure. Existing names, changed
    /// originals, bounded observation exhaustion and interrupted attempts fail
    /// closed without overwrite, deletion, retry, candidate regeneration or TPM I/O.
    pub fn prepare_keys(&mut self) -> Result<(), &Error> {
        if self.attempted {
            self.complete = false;
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.attempted = true;
        let result = self.prepare_inner();
        match result {
            Ok(()) => {
                self.complete = true;
                Ok(())
            }
            Err(error) => {
                self.first_failure.get_or_insert(error);
                self.wipe_secrets();
                Err(self.first_failure.get_or_insert(Error::Fenced))
            }
        }
    }

    /// Wipes candidate secret bytes while retaining files and failure custody.
    ///
    /// This does not delete, unlock, approve or release any published candidate.
    pub fn wipe_secrets(&mut self) {
        self.private.zeroize();
        self.job_id.zeroize();
        for bytes in &mut self.readbacks {
            bytes.zeroize();
        }
    }

    /// Borrows the first returned failure without converting it into a receipt.
    pub fn failure(&self) -> Option<&Error> {
        self.first_failure.as_ref()
    }

    fn prepare_inner(&mut self) -> Result<(), Error> {
        self.named.try_reserve_exact(MAXIMUM_NAMED_READBACKS).map_err(io::Error::other)?;
        self.readbacks.try_reserve_exact(4).map_err(io::Error::other)?;
        self.job_id.resize(16, 0);
        self.private.resize(336, 0);
        self.public.resize(268, 0);
        self.origin.recheck().map_err(|_| Error::Startup)?;
        let (node, approval) = self.origin.public_originals().map_err(|_| Error::Startup)?;
        self.create_job()?;

        // Final zeroizing buffers exist before either entropy acquisition. The
        // shared retry/partial-read policy is the only kernel entropy engine.
        entropy::fill_retained_nonzero(&mut self.job_id).map_err(Error::Entropy)?;
        entropy::fill_retained_nonzero(&mut self.private).map_err(Error::Entropy)?;
        self.private[..16].fill(0);
        self.private[..8].copy_from_slice(b"AOSNPK03");
        self.private[8..10].copy_from_slice(&3_u16.to_le_bytes());
        encode_public_candidates(&self.private, &self.job_id, &node, &approval, &mut self.public)?;

        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_job()?;
        self.publish(0, PRIVATE_NAME, 0o600)?;
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_job()?;
        self.publish(1, PUBLIC_NAME, 0o400)?;
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_job()?;
        self.require_published(0, PRIVATE_NAME, 0o600)?;
        self.require_published(1, PUBLIC_NAME, 0o400)?;
        self.origin.recheck().map_err(|_| Error::Startup)
    }

    fn create_job(&mut self) -> Result<(), Error> {
        self.parent = Some(File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            "/var/lib/aos",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?));
        let parent = self.parent.as_ref().ok_or(Error::Rejected)?;
        let identity = inspect(parent)?;
        if identity.2 != 0 || identity.3 != 0 || identity.4 & 0o022 != 0 {
            return Err(Error::Rejected);
        }
        self.parent_identity = Some(identity);
        rustix::fs::mkdirat(parent, JOB_NAME, Mode::from_raw_mode(0o700))?;
        self.job_created = true;
        self.directory = Some(File::from(rustix::fs::openat(
            parent,
            JOB_NAME,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?));
        let directory = self.directory.as_ref().ok_or(Error::Rejected)?;
        rustix::fs::fchmod(directory, Mode::from_raw_mode(0o700))?;
        self.directory_identity = Some(inspect(directory)?);
        self.directory_mount = Some(MountId::from_fd(directory.as_fd())?);
        require_label(directory)?;
        directory.sync_all()?;
        parent.sync_all()?;

        self.lock = Some(File::from(rustix::fs::openat(
            directory,
            "installation.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?));
        let lock = self.lock.as_ref().ok_or(Error::Rejected)?;
        rustix::fs::flock(lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        rustix::fs::fchmod(lock, Mode::from_raw_mode(0o600))?;
        self.lock_identity = Some(inspect(lock)?);
        require_label(lock)?;
        lock.sync_all()?;
        directory.sync_all()?;
        self.require_job()
    }

    fn require_job(&mut self) -> Result<(), Error> {
        let parent = self.parent.as_ref().ok_or(Error::Rejected)?;
        let directory = self.directory.as_ref().ok_or(Error::Rejected)?;
        let lock = self.lock.as_ref().ok_or(Error::Rejected)?;
        if !self.job_created || Some(inspect(parent)?) != self.parent_identity
            || Some(inspect(directory)?) != self.directory_identity
            || Some(MountId::from_fd(directory.as_fd())?) != self.directory_mount
            || Some(inspect(lock)?) != self.lock_identity
        {
            return Err(Error::Rejected);
        }
        require_label(directory)?;
        require_label(lock)?;
        if Some(MountId::from_fd(lock.as_fd())?) != self.directory_mount {
            return Err(Error::Rejected);
        }
        if self.named.len() == MAXIMUM_NAMED_READBACKS {
            return Err(Error::Rejected);
        }
        self.named.push(File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            "/var/lib/aos",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?));
        let named_parent = self.named.last().ok_or(Error::Rejected)?;
        if Some(inspect(named_parent)?) != self.parent_identity
            || MountId::from_fd(named_parent.as_fd())? != MountId::from_fd(parent.as_fd())?
        {
            return Err(Error::Rejected);
        }
        if self.named.len() == MAXIMUM_NAMED_READBACKS {
            return Err(Error::Rejected);
        }
        self.named.push(File::from(rustix::fs::openat(
            parent,
            JOB_NAME,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?));
        let named_directory = self.named.last().ok_or(Error::Rejected)?;
        if Some(inspect(named_directory)?) != self.directory_identity
            || Some(MountId::from_fd(named_directory.as_fd())?) != self.directory_mount
        {
            return Err(Error::Rejected);
        }
        if self.named.len() == MAXIMUM_NAMED_READBACKS {
            return Err(Error::Rejected);
        }
        self.named.push(File::from(rustix::fs::openat(
            directory,
            "installation.lock",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?));
        let named_lock = self.named.last().ok_or(Error::Rejected)?;
        if Some(inspect(named_lock)?) != self.lock_identity
            || Some(MountId::from_fd(named_lock.as_fd())?) != self.directory_mount
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn publish(&mut self, index: usize, name: &str, mode: u32) -> Result<(), Error> {
        let directory = self.directory.as_ref().ok_or(Error::Rejected)?;
        self.files[index] = Some(File::from(rustix::fs::openat(
            directory,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode),
        )?));
        let file = self.files[index].as_mut().ok_or(Error::Rejected)?;
        rustix::fs::fchmod(&*file, Mode::from_raw_mode(mode))?;
        require_label(file)?;
        let bytes = if index == 0 {
            self.private.as_slice()
        } else {
            self.public.as_slice()
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        directory.sync_all()?;
        self.identities[index] = Some(inspect(file)?);
        self.require_published(index, name, mode)
    }

    fn require_published(&mut self, index: usize, name: &str, mode: u32) -> Result<(), Error> {
        let file = self.files[index].as_ref().ok_or(Error::Rejected)?;
        let metadata = file.metadata()?;
        let expected = if index == 0 {
            self.private.as_slice()
        } else {
            self.public.as_slice()
        };
        if !metadata.is_file() || metadata.uid() != 0 || metadata.gid() != 0
            || metadata.mode() & 0o7777 != mode || metadata.nlink() != 1
            || metadata.len() != expected.len() as u64
            || Some(inspect(file)?) != self.identities[index]
            || Some(MountId::from_fd(file.as_fd())?) != self.directory_mount
        {
            return Err(Error::Rejected);
        }
        require_label(file)?;
        if self.readbacks.len() == 4 {
            return Err(Error::Rejected);
        }
        self.readbacks.push(Zeroizing::new(vec![0; expected.len()]));
        let readback = self.readbacks.last_mut().ok_or(Error::Rejected)?;
        aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
            file,
            &mut *readback,
        )
        .map_err(|failure| match failure {
            aos_sandbox_linux::protected_file::ExactReadFailure::Io(errno) => {
                Error::Io(io::Error::from_raw_os_error(errno.raw_os_error()))
            }
            failure => Error::Read(failure.legacy_classification()),
        })?;
        if readback.as_slice() != expected || Some(inspect(file)?) != self.identities[index] {
            return Err(Error::Rejected);
        }
        require_label(file)?;
        if self.named.len() == MAXIMUM_NAMED_READBACKS {
            return Err(Error::Rejected);
        }
        self.named.push(File::from(rustix::fs::openat(
            self.directory.as_ref().ok_or(Error::Rejected)?,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?));
        let named = self.named.last().ok_or(Error::Rejected)?;
        if Some(inspect(named)?) != self.identities[index]
            || Some(MountId::from_fd(named.as_fd())?) != self.directory_mount
        {
            return Err(Error::Rejected);
        }
        require_label(self.named.last().ok_or(Error::Rejected)?)?;
        Ok(())
    }
}

fn encode_public_candidates(
    private: &[u8],
    job: &[u8],
    node: &[u8; 16],
    approval: &[u8; 48],
    public: &mut [u8],
) -> Result<(), Error> {
    aos_sandbox::normal_root::derive_nix_offline_public_candidates_v3(
        private, job, node, approval, public,
    )
    .map_err(|_| Error::Rejected)
}

fn inspect(file: &File) -> io::Result<FileIdentity> {
    aos_sandbox::normal_root::inspect_nix_offline_job_identity_v5(file)
}

fn require_label(file: &File) -> Result<(), Error> {
    if !aos_sandbox::normal_root::nix_offline_job_has_original_label_v5(file)? {
        return Err(Error::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate_data() -> (Vec<u8>, [u8; 48]) {
        let mut private = vec![0; 336];
        private[..8].copy_from_slice(b"AOSNPK03");
        private[8..10].copy_from_slice(&3_u16.to_le_bytes());
        for index in 0..4 {
            private[16 + index * 48..32 + index * 48].fill(10 + index as u8);
            private[32 + index * 48..64 + index * 48].fill(20 + index as u8);
            private[208 + index * 32..240 + index * 32].fill(30 + index as u8);
        }
        let mut approval = [1; 48];
        approval[16..].copy_from_slice(&SigningKey::from_bytes(&[90; 32]).verifying_key().to_bytes());
        (private, approval)
    }

    #[test]
    fn candidate_data_has_exact_distinct_unsigned_layouts() {
        let (private, approval) = candidate_data();
        let mut public = vec![0; 268];

        encode_public_candidates(&private, &[2; 16], &[3; 16], &approval, &mut public).unwrap();
        assert_eq!(&public[..12], b"AOSNPC03\x03\0\0\0");
        assert_eq!(&public[12..28], &[2; 16]);
        assert_eq!(&public[28..44], &[3; 16]);
        assert_eq!(&public[76..92], &private[16..32]);
        assert_eq!(&public[92..124], &SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes());
        assert_eq!(CANDIDATE_DOMAIN.last(), Some(&0));
    }

    #[test]
    fn candidate_encoding_rejects_approval_and_secret_reuse() {
        let (mut private, mut approval) = candidate_data();
        let mut public = vec![0; 268];
        approval[..16].copy_from_slice(&private[16..32]);
        assert!(encode_public_candidates(&private, &[2; 16], &[3; 16], &approval, &mut public).is_err());

        let (_, approval) = candidate_data();
        private[208..240].fill(20);
        assert!(encode_public_candidates(&private, &[2; 16], &[3; 16], &approval, &mut public).is_err());
    }

    #[test]
    fn candidate_encoding_rejects_noncanonical_reserved_bytes_and_widths() {
        let (mut private, approval) = candidate_data();
        let mut public = vec![0; 268];
        private[15] = 1;
        assert!(encode_public_candidates(&private, &[2; 16], &[3; 16], &approval, &mut public).is_err());

        private[15] = 0;
        assert!(encode_public_candidates(&private[..335], &[2; 16], &[3; 16], &approval, &mut public).is_err());
        assert!(encode_public_candidates(&private, &[0; 16], &[3; 16], &approval, &mut public).is_err());
    }
}
