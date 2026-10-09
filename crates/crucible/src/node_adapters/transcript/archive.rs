//! Private source authentication for complete recorded transcripts.
//!
//! Stored files contain `CTRANS1\0`, a 32-byte domain-separated HMAC, an eight-byte
//! big-endian body length, and canonical transcript bytes. The private key and
//! archive directory are operational resources; they never affect modeled time.

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    rc::Rc,
};

use crucible_node_contract::ContentRef;
use hmac::{Hmac, Mac};
use rustix::fs::{Mode, OFlags};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    capture::CapturedTranscript,
    codec::{TranscriptError, invalid},
    types::*,
};

const MAGIC: &[u8; 8] = b"CTRANS1\0";
const DOMAIN: &[u8] = b"crucible.authenticated-boundary-transcript.v1\0";

/// Owns a persistent private signer with no arbitrary-data signing interface.
pub struct TranscriptArchive {
    directory: File,
    key: Zeroizing<[u8; 32]>,
    limits: TranscriptLimits,
}

/// Retains original source custody authenticated independently of public hashes.
///
/// This seal attests a recorded source, not a live native realization, replay
/// applicability, exact physical time or counterfactual simulated computation.
#[derive(Clone)]
pub struct AuthenticatedTranscript {
    pub(super) data: Rc<BoundaryTranscript>,
    pub(super) bytes: Rc<Vec<u8>>,
    pub(super) reference: ContentRef,
}

impl AuthenticatedTranscript {
    /// Borrows complete authenticated source interactions and origin provenance.
    pub fn transcript(&self) -> &BoundaryTranscript {
        &self.data
    }
    /// Borrows the original canonical raw body independently of source lifetimes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Borrows the body identity without granting replay or native execution.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }
}

impl TranscriptArchive {
    /// Opens private owned storage and its separate persistent authentication key.
    ///
    /// # Errors
    /// Refuses invalid limits, foreign or nonprivate directories, symlinks,
    /// hard-linked or malformed keys, incomplete key creation and I/O failures.
    pub fn open(path: impl AsRef<Path>, limits: TranscriptLimits) -> Result<Self, TranscriptError> {
        limits.validate()?;
        match fs::create_dir(path.as_ref()) {
            Ok(()) => fs::set_permissions(path.as_ref(), fs::Permissions::from_mode(0o700))
                .map_err(invalid)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(invalid(error)),
        }
        let directory = File::from(
            rustix::fs::open(
                path.as_ref(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(invalid)?,
        );
        let metadata = directory.metadata().map_err(invalid)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(TranscriptError::Unqualified(
                "transcript directory is not private and owned".into(),
            ));
        }
        let key_name = "transcript-authentication-key-v1";
        match rustix::fs::openat(
            &directory,
            key_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                let mut key = Zeroizing::new([0u8; 32]);
                File::open("/dev/urandom")
                    .map_err(invalid)?
                    .read_exact(&mut *key)
                    .map_err(invalid)?;
                let mut file = File::from(fd);
                file.write_all(&*key).map_err(invalid)?;
                file.sync_all().map_err(invalid)?;
                directory.sync_all().map_err(invalid)?;
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(invalid(error)),
        }
        let mut file = File::from(
            rustix::fs::openat(
                &directory,
                key_name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(invalid)?,
        );
        private_file(&file, 32)?;
        let mut key = Zeroizing::new([0u8; 32]);
        file.read_exact(&mut *key).map_err(invalid)?;
        Ok(Self {
            directory,
            key,
            limits,
        })
    }

    /// Persists only a completed authentic live-recording seal.
    ///
    /// # Errors
    /// Refuses incomplete capture, reservations exceeding this archive's admitted
    /// limits, changed immutable storage, nonprivate files or persistence failure.
    pub fn persist(
        &self,
        capture: CapturedTranscript,
    ) -> Result<AuthenticatedTranscript, TranscriptError> {
        self.check_limits(&capture.data)?;
        let mut mac = self.mac()?;
        mac.update(&capture.bytes);
        let authentication = mac.finalize().into_bytes();
        let name = file_name(&capture.reference)?;
        match rustix::fs::openat(
            &self.directory,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o400),
        ) {
            Ok(fd) => {
                let mut file = File::from(fd);
                file.write_all(MAGIC).map_err(invalid)?;
                file.write_all(&authentication).map_err(invalid)?;
                file.write_all(&(capture.bytes.len() as u64).to_be_bytes())
                    .map_err(invalid)?;
                file.write_all(&capture.bytes).map_err(invalid)?;
                file.sync_all().map_err(invalid)?;
                self.directory.sync_all().map_err(invalid)?;
            }
            Err(rustix::io::Errno::EXIST) => {
                if self.load(&capture.reference)?.bytes() != capture.bytes {
                    return Err(TranscriptError::Unqualified(
                        "original transcript cannot be replaced".into(),
                    ));
                }
            }
            Err(error) => return Err(invalid(error)),
        }
        Ok(AuthenticatedTranscript {
            data: Rc::new(capture.data),
            bytes: Rc::new(capture.bytes),
            reference: capture.reference,
        })
    }

    /// Authenticates complete source bytes before decoding any source claims.
    ///
    /// # Errors
    /// Refuses changed source scope or bytes, foreign signers, omitted/truncated
    /// files, unbounded allocation, unsupported formats and malformed transcripts.
    pub fn load(&self, reference: &ContentRef) -> Result<AuthenticatedTranscript, TranscriptError> {
        let name = file_name(reference)?;
        let mut file = File::from(
            rustix::fs::openat(
                &self.directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(invalid)?,
        );
        let size = reference.length.get();
        if size > self.limits.maximum_total_bytes.get() {
            return Err(TranscriptError::CaptureLimit);
        }
        private_file(
            &file,
            size.checked_add(48).ok_or(TranscriptError::CaptureLimit)?,
        )?;
        let mut header = [0u8; 48];
        file.read_exact(&mut header).map_err(invalid)?;
        let length = u64::from_be_bytes(header[40..48].try_into().map_err(invalid)?);
        if &header[..8] != MAGIC || length != size {
            return Err(TranscriptError::Invalid(
                "transcript extent or edition".into(),
            ));
        }
        let mut bytes = vec![0u8; usize::try_from(size).map_err(invalid)?];
        file.read_exact(&mut bytes).map_err(invalid)?;
        let mut excess = [0u8; 1];
        if file.read(&mut excess).map_err(invalid)? != 0 {
            return Err(TranscriptError::Invalid("transcript excess bytes".into()));
        }
        let mut mac = self.mac()?;
        mac.update(&bytes);
        mac.verify_slice(&header[8..40]).map_err(|_| {
            TranscriptError::Unqualified("original transcript authentication failed".into())
        })?;
        reference.verify(&bytes).map_err(invalid)?;
        let data = BoundaryTranscript::from_canonical_bytes(&bytes)?;
        self.check_limits(&data)?;
        Ok(AuthenticatedTranscript {
            data: Rc::new(data),
            bytes: Rc::new(bytes),
            reference: reference.clone(),
        })
    }

    fn check_limits(&self, data: &BoundaryTranscript) -> Result<(), TranscriptError> {
        if data.limits.maximum_records > self.limits.maximum_records
            || data.limits.maximum_record_bytes > self.limits.maximum_record_bytes
            || data.limits.maximum_total_bytes > self.limits.maximum_total_bytes
        {
            return Err(TranscriptError::CaptureLimit);
        }
        Ok(())
    }

    fn mac(&self) -> Result<Hmac<Sha256>, TranscriptError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_ref()).map_err(invalid)?;
        mac.update(DOMAIN);
        Ok(mac)
    }
}

fn file_name(reference: &ContentRef) -> Result<String, TranscriptError> {
    use crucible_node_contract::Validate;
    reference.validate().map_err(invalid)?;
    if reference.media_type != "application/vnd.crucible.boundary-transcript+json" {
        return Err(TranscriptError::Invalid("transcript media type".into()));
    }
    Ok(format!("transcript-{}", reference.hash.digest))
}

fn private_file(file: &File, length: u64) -> Result<(), TranscriptError> {
    let metadata = file.metadata().map_err(invalid)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() != length
    {
        return Err(TranscriptError::Unqualified(
            "transcript file is not private, owned and complete".into(),
        ));
    }
    Ok(())
}
