//! Dormant fixed-root ownership for node-local mapped structural indexes.
//!
//! The owner adopts already fs-verity-sealed index files. It validates the
//! exact authenticated descriptor and every checked structural offset through
//! [`crate::validate_index`] before atomically replacing a small current-head
//! record. Nothing in this module creates a service, listener, mount, or
//! readiness signal.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest};
use aos_sandbox_linux::immutable_file::{
    FsVerityDigest, FsVerityMapping, FsVerityPublicationRoot, ImmutableFileError,
};
use aos_sandbox_linux::path::BeneathRoot;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use crate::{IndexError, IndexExpectation, ValidatedIndex, validate_index};

const FIXED_INDEX_ROOT: &str = "/var/lib/aos/sandbox/filesystem-view/indexes";
const CURRENT_HEAD: &str = "current";
const HEAD_MAGIC: &[u8; 8] = b"AOSIXH01";
const HEAD_VERSION: u32 = 1;
const MAXIMUM_HEAD_BYTES: usize = 2_048;

/// Describes one immutable index generation eligible to become current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexPublication {
    /// Strictly increasing node-local generation.
    pub generation: u64,
    /// Ordinary relative basename of the sealed index file.
    pub file_name: String,
    /// Exact index object descriptor.
    pub index: ObjectDescriptor,
    /// Exact compiler semantic ABI.
    pub compiler_abi: [u8; 32],
    /// Exact portable source-tree descriptor.
    pub tree: ObjectDescriptor,
    /// Exact portable root-directory descriptor.
    pub root: ObjectDescriptor,
    /// Closed tree-role feature set.
    pub tree_features: u32,
    /// Independently authenticated fs-verity measurement.
    pub verity: FsVerityDigest,
}

/// Proves which exact fixed-root head was current at readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexCurrentness {
    generation: u64,
    head_digest: [u8; 32],
}

impl IndexCurrentness {
    /// Returns the current node-local generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the digest of the complete current-head bytes.
    #[must_use]
    pub const fn head_digest(self) -> [u8; 32] {
        self.head_digest
    }
}

/// Retains recovery ownership when rename or its durable readback is unknown.
#[derive(Debug)]
#[must_use = "reopen the fixed owner and recover the exact replacement"]
pub struct AmbiguousIndexReplacement {
    publication: IndexPublication,
    head_digest: [u8; 32],
    temporary_name: String,
    temporary_descriptor: Option<OwnedFd>,
    temporary_device: Option<u64>,
    temporary_inode: Option<u64>,
    predecessor: Option<IndexCurrentness>,
}

/// Retains exact index-replacement custody after any failed recovery step.
#[derive(Debug)]
pub struct IndexRecoveryFailure {
    recovery: AmbiguousIndexReplacement,
    source: IndexOwnerError,
}

impl IndexRecoveryFailure {
    /// Returns the refreshed ambiguity token and its latest failure.
    #[must_use]
    pub fn into_parts(self) -> (AmbiguousIndexReplacement, IndexOwnerError) {
        (self.recovery, self.source)
    }
}

/// Owns the dormant node-local structural-index current head.
pub struct DormantIndexOwner {
    root: OwnedFd,
    _owner_lock: OwnedFd,
    root_identity: RootIdentity,
    protected_root: FsVerityPublicationRoot,
    mapping_root: BeneathRoot,
    maximum_mapped_bytes: u64,
    maximum_validation_working_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl DormantIndexOwner {
    /// Opens the fixed protected index root without creating or activating it.
    ///
    /// # Errors
    ///
    /// Returns [`IndexOwnerError`] when the fixed root is absent, is a symlink,
    /// is not a directory, or cannot be adopted as a beneath-resolution root.
    pub(crate) fn open_fixed(
        maximum_mapped_bytes: u64,
        maximum_validation_working_bytes: u64,
    ) -> Result<Self, IndexOwnerError> {
        if maximum_mapped_bytes == 0 || maximum_validation_working_bytes == 0 {
            return Err(IndexOwnerError::InvalidPublication);
        }
        let root = rustix::fs::open(
            FIXED_INDEX_ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let root_identity = inspect_root(&root)?;
        let owner_lock = open_owner_lock(&root)?;
        let protected_root =
            FsVerityPublicationRoot::from_protected_absolute_path(Path::new(FIXED_INDEX_ROOT))?;
        if protected_root.device() != root_identity.device
            || protected_root.inode() != root_identity.inode
        {
            return Err(IndexOwnerError::RootChanged);
        }
        let mapping_root = BeneathRoot::from_owned(rustix::io::dup(&root)?)?;
        Ok(Self {
            root,
            _owner_lock: owner_lock,
            root_identity,
            protected_root,
            mapping_root,
            maximum_mapped_bytes,
            maximum_validation_working_bytes,
        })
    }

    /// Reads and validates the exact current publication head.
    ///
    /// # Errors
    ///
    /// Returns [`IndexOwnerError`] for absent, oversized, malformed, or corrupt
    /// head bytes.
    pub fn current(&self) -> Result<(IndexPublication, IndexCurrentness), IndexOwnerError> {
        self.recheck_root()?;
        let bytes = read_bounded_at(&self.root, CURRENT_HEAD, MAXIMUM_HEAD_BYTES)?;
        self.recheck_root()?;
        let publication = decode_head(&bytes)?;
        let currentness = IndexCurrentness {
            generation: publication.generation,
            head_digest: Sha256::digest(&bytes).into(),
        };
        Ok((publication, currentness))
    }

    /// Revalidates one currentness proof against fixed-root readback.
    ///
    /// # Errors
    ///
    /// Returns [`IndexOwnerError::Stale`] after any head replacement.
    pub fn validate_current(&self, currentness: IndexCurrentness) -> Result<(), IndexOwnerError> {
        let (_, observed) = self.current()?;
        if observed != currentness {
            return Err(IndexOwnerError::Stale);
        }
        Ok(())
    }

    /// Maps and structurally validates the current sealed index for one callback.
    ///
    /// Currentness is rechecked after validation and before the callback begins.
    /// The validated proof cannot escape the scoped mapping.
    ///
    /// # Errors
    ///
    /// Returns [`IndexOwnerError`] for stale head state, immutable-file proof
    /// failure, or any structural-index validation failure.
    pub fn with_current<R>(
        &self,
        use_index: impl for<'mapping> FnOnce(&ValidatedIndex<'mapping>, IndexCurrentness) -> R,
    ) -> Result<R, IndexOwnerError> {
        let (publication, currentness) = self.current()?;
        self.with_publication(&publication, Some(currentness), use_index)
    }

    /// Atomically replaces the current head after exact mapped validation.
    ///
    /// `expected` is required when a head already exists and prevents two
    /// owners from silently advancing the same generation. The sealed index
    /// file is never renamed or overwritten by this operation.
    ///
    /// # Errors
    ///
    /// Returns a before-effect error for invalid, stale, or unvalidated input.
    /// Any rename, directory-sync, or post-rename readback uncertainty returns
    /// exact recovery ownership.
    pub(crate) fn replace_current(
        &self,
        publication: IndexPublication,
        expected: Option<IndexCurrentness>,
    ) -> Result<IndexCurrentness, IndexOwnerError> {
        validate_publication(&publication)?;
        match (self.current(), expected) {
            (Ok((_, observed)), Some(expected)) if observed == expected => {
                if publication.generation
                    != observed
                        .generation
                        .checked_add(1)
                        .ok_or(IndexOwnerError::InvalidPublication)?
                {
                    return Err(IndexOwnerError::InvalidPublication);
                }
            }
            (Err(IndexOwnerError::Rustix(error)), None) if error == rustix::io::Errno::NOENT => {
                if publication.generation != 1 {
                    return Err(IndexOwnerError::InvalidPublication);
                }
            }
            (Ok(_), None) | (Ok(_), Some(_)) | (Err(_), Some(_)) => {
                return Err(IndexOwnerError::Stale);
            }
            (Err(error), None) => return Err(error),
        }

        let bytes = encode_head(&publication)?;
        let head_digest = Sha256::digest(&bytes).into();
        let currentness = IndexCurrentness {
            generation: publication.generation,
            head_digest,
        };
        self.with_publication(&publication, None, |_, _| ())?;

        let temporary_name = format!(".current-{}.tmp", publication.generation);
        self.revalidate_expected(expected)?;
        self.remove_exact_temporary_if_present(&temporary_name, &bytes)?;
        self.revalidate_expected(expected)?;
        let descriptor = rustix::fs::openat(
            &self.root,
            temporary_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let temporary_stat = match rustix::fs::fstat(&descriptor) {
            Ok(stat) => stat,
            Err(source) => {
                return Err(IndexOwnerError::Ambiguous {
                    source: source.into(),
                    recovery: AmbiguousIndexReplacement {
                        publication,
                        head_digest,
                        temporary_name,
                        temporary_descriptor: Some(descriptor),
                        temporary_device: None,
                        temporary_inode: None,
                        predecessor: expected,
                    },
                });
            }
        };
        if let Err(error) = self.revalidate_expected(expected) {
            return Err(IndexOwnerError::Ambiguous {
                source: std::io::Error::other(error.to_string()),
                recovery: AmbiguousIndexReplacement {
                    publication,
                    head_digest,
                    temporary_name,
                    temporary_descriptor: Some(descriptor),
                    temporary_device: Some(temporary_stat.st_dev),
                    temporary_inode: Some(temporary_stat.st_ino),
                    predecessor: expected,
                },
            });
        }
        let mut file = File::from(descriptor);
        if let Err(source) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            return Err(IndexOwnerError::Ambiguous {
                source,
                recovery: AmbiguousIndexReplacement {
                    publication,
                    head_digest,
                    temporary_name,
                    temporary_descriptor: None,
                    temporary_device: Some(temporary_stat.st_dev),
                    temporary_inode: Some(temporary_stat.st_ino),
                    predecessor: expected,
                },
            });
        }
        drop(file);
        if !read_bounded_at(&self.root, &temporary_name, MAXIMUM_HEAD_BYTES)
            .as_ref()
            .is_ok_and(|current| current == &bytes)
        {
            return Err(IndexOwnerError::Ambiguous {
                source: std::io::Error::other("index head temporary readback failed"),
                recovery: AmbiguousIndexReplacement {
                    publication,
                    head_digest,
                    temporary_name,
                    temporary_descriptor: None,
                    temporary_device: Some(temporary_stat.st_dev),
                    temporary_inode: Some(temporary_stat.st_ino),
                    predecessor: expected,
                },
            });
        }
        if let Err(error) = self
            .revalidate_expected(expected)
            .and_then(|()| self.recheck_root())
        {
            return Err(IndexOwnerError::Ambiguous {
                source: std::io::Error::other(error.to_string()),
                recovery: AmbiguousIndexReplacement {
                    publication,
                    head_digest,
                    temporary_name,
                    temporary_descriptor: None,
                    temporary_device: Some(temporary_stat.st_dev),
                    temporary_inode: Some(temporary_stat.st_ino),
                    predecessor: expected,
                },
            });
        }
        if let Err(error) = self.revalidate_expected(expected) {
            return Err(IndexOwnerError::Ambiguous {
                source: std::io::Error::other(error.to_string()),
                recovery: AmbiguousIndexReplacement {
                    publication,
                    head_digest,
                    temporary_name,
                    temporary_descriptor: None,
                    temporary_device: Some(temporary_stat.st_dev),
                    temporary_inode: Some(temporary_stat.st_ino),
                    predecessor: expected,
                },
            });
        }
        if let Err(source) = rustix::fs::renameat(
            &self.root,
            temporary_name.as_str(),
            &self.root,
            CURRENT_HEAD,
        ) {
            return Err(IndexOwnerError::Ambiguous {
                source: source.into(),
                recovery: AmbiguousIndexReplacement {
                    publication,
                    head_digest,
                    temporary_name,
                    temporary_descriptor: None,
                    temporary_device: Some(temporary_stat.st_dev),
                    temporary_inode: Some(temporary_stat.st_ino),
                    predecessor: expected,
                },
            });
        }
        if let Err(source) = rustix::fs::fsync(&self.root) {
            return Err(IndexOwnerError::Ambiguous {
                source: source.into(),
                recovery: AmbiguousIndexReplacement {
                    publication,
                    head_digest,
                    temporary_name,
                    temporary_descriptor: None,
                    temporary_device: Some(temporary_stat.st_dev),
                    temporary_inode: Some(temporary_stat.st_ino),
                    predecessor: expected,
                },
            });
        }
        if let Err(error) = self
            .recheck_exact_head(&publication, currentness)
            .and_then(|()| self.recheck_root())
        {
            return Err(IndexOwnerError::Ambiguous {
                source: std::io::Error::other(error.to_string()),
                recovery: AmbiguousIndexReplacement {
                    publication,
                    head_digest,
                    temporary_name,
                    temporary_descriptor: None,
                    temporary_device: Some(temporary_stat.st_dev),
                    temporary_inode: Some(temporary_stat.st_ino),
                    predecessor: expected,
                },
            });
        }
        Ok(currentness)
    }

    /// Recovers an exact replacement after post-rename durability ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`IndexRecoveryFailure`] with refreshed custody unless fixed-root
    /// readback names the exact requested generation and complete head digest.
    pub(crate) fn recover_replacement(
        &self,
        mut recovery: AmbiguousIndexReplacement,
    ) -> Result<IndexCurrentness, IndexRecoveryFailure> {
        match self.recover_replacement_inner(&mut recovery) {
            Ok(current) => Ok(current),
            Err(source) => Err(IndexRecoveryFailure { recovery, source }),
        }
    }

    fn recover_replacement_inner(
        &self,
        recovery: &mut AmbiguousIndexReplacement,
    ) -> Result<IndexCurrentness, IndexOwnerError> {
        rustix::fs::fsync(&self.root)?;
        if let Ok((observed, currentness)) = self.current()
            && observed == recovery.publication
            && currentness.head_digest == recovery.head_digest
        {
            self.recheck_exact_head(&observed, currentness)?;
            self.remove_exact_temporary_if_present(
                &recovery.temporary_name,
                &encode_head(&observed)?,
            )?;
            self.with_publication(&observed, Some(currentness), |_, _| ())?;
            return Ok(currentness);
        }
        self.revalidate_expected(recovery.predecessor)?;
        let head = encode_head(&recovery.publication)?;
        let descriptor = match recovery.temporary_descriptor.take() {
            Some(descriptor) => descriptor,
            None => rustix::fs::openat(
                &self.root,
                recovery.temporary_name.as_str(),
                OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?,
        };
        let temporary_stat = match rustix::fs::fstat(&descriptor) {
            Ok(stat) => stat,
            Err(error) => {
                recovery.temporary_descriptor = Some(descriptor);
                return Err(error.into());
            }
        };
        if recovery.temporary_device.is_none() && recovery.temporary_inode.is_none() {
            recovery.temporary_device = Some(temporary_stat.st_dev);
            recovery.temporary_inode = Some(temporary_stat.st_ino);
        }
        if FileType::from_raw_mode(temporary_stat.st_mode) != FileType::RegularFile
            || temporary_stat.st_uid != rustix::process::geteuid().as_raw()
            || temporary_stat.st_nlink != 1
            || Some(temporary_stat.st_dev) != recovery.temporary_device
            || Some(temporary_stat.st_ino) != recovery.temporary_inode
        {
            return Err(IndexOwnerError::ForeignTemporary);
        }
        if !read_bounded_at(&self.root, &recovery.temporary_name, MAXIMUM_HEAD_BYTES)
            .as_ref()
            .is_ok_and(|current| current == &head)
        {
            self.revalidate_expected(recovery.predecessor)?;
            let mut file = File::from(descriptor);
            if let Err(source) = file
                .set_len(0)
                .and_then(|()| file.write_all(&head))
                .and_then(|()| file.sync_all())
            {
                return Err(source.into());
            }
            drop(file);
            if read_bounded_at(&self.root, &recovery.temporary_name, MAXIMUM_HEAD_BYTES)? != head {
                return Err(IndexOwnerError::InvalidHead);
            }
        } else {
            drop(descriptor);
        }
        let currentness = IndexCurrentness {
            generation: recovery.publication.generation,
            head_digest: recovery.head_digest,
        };
        self.revalidate_expected(recovery.predecessor)?;
        if let Err(source) = rustix::fs::renameat(
            &self.root,
            recovery.temporary_name.as_str(),
            &self.root,
            CURRENT_HEAD,
        ) {
            return Err(source.into());
        }
        if let Err(source) = rustix::fs::fsync(&self.root) {
            return Err(source.into());
        }
        if let Err(error) = self
            .recheck_exact_head(&recovery.publication, currentness)
            .and_then(|()| {
                self.with_publication(&recovery.publication, Some(currentness), |_, _| ())
            })
        {
            return Err(std::io::Error::other(error.to_string()).into());
        }
        Ok(currentness)
    }

    fn revalidate_expected(
        &self,
        expected: Option<IndexCurrentness>,
    ) -> Result<(), IndexOwnerError> {
        match expected {
            Some(expected) => self.validate_current(expected),
            None => match self.current() {
                Err(IndexOwnerError::Rustix(error)) if error == rustix::io::Errno::NOENT => Ok(()),
                _ => Err(IndexOwnerError::Stale),
            },
        }
    }

    fn with_publication<R>(
        &self,
        publication: &IndexPublication,
        currentness: Option<IndexCurrentness>,
        use_index: impl for<'mapping> FnOnce(&ValidatedIndex<'mapping>, IndexCurrentness) -> R,
    ) -> Result<R, IndexOwnerError> {
        validate_publication(publication)?;
        let expected = IndexExpectation {
            index: &publication.index,
            compiler_abi: publication.compiler_abi,
            tree: &publication.tree,
            root: &publication.root,
            tree_features: publication.tree_features,
        };
        let result = FsVerityMapping::run_beneath(
            &self.mapping_root,
            Path::new(&publication.file_name),
            publication.verity,
            publication.index.encoded_size(),
            self.maximum_mapped_bytes,
            |bytes, _| {
                let index = validate_index(
                    bytes,
                    self.maximum_mapped_bytes,
                    self.maximum_validation_working_bytes,
                    &expected,
                )?;
                if let Some(currentness) = currentness {
                    self.validate_current(currentness)?;
                    Ok(use_index(&index, currentness))
                } else {
                    let candidate = IndexCurrentness {
                        generation: publication.generation,
                        head_digest: Sha256::digest(encode_head(publication)?).into(),
                    };
                    Ok(use_index(&index, candidate))
                }
            },
        )?;
        result
    }

    fn recheck_root(&self) -> Result<(), IndexOwnerError> {
        if inspect_root(&self.root)? != self.root_identity {
            return Err(IndexOwnerError::RootChanged);
        }
        self.protected_root.recheck_protected_path()?;
        let reopened = rustix::fs::open(
            FIXED_INDEX_ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if inspect_root(&reopened)? != self.root_identity {
            return Err(IndexOwnerError::RootChanged);
        }
        Ok(())
    }

    fn recheck_exact_head(
        &self,
        publication: &IndexPublication,
        currentness: IndexCurrentness,
    ) -> Result<(), IndexOwnerError> {
        let (observed, observed_currentness) = self.current()?;
        if &observed != publication || observed_currentness != currentness {
            return Err(IndexOwnerError::Stale);
        }
        Ok(())
    }

    fn remove_exact_temporary_if_present(
        &self,
        name: &str,
        expected: &[u8],
    ) -> Result<(), IndexOwnerError> {
        match rustix::fs::statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                    || stat.st_uid != rustix::process::geteuid().as_raw()
                    || stat.st_nlink != 1
                    || read_bounded_at(&self.root, name, MAXIMUM_HEAD_BYTES)? != expected
                {
                    return Err(IndexOwnerError::ForeignTemporary);
                }
                rustix::fs::unlinkat(&self.root, name, AtFlags::empty())?;
                rustix::fs::fsync(&self.root)?;
                Ok(())
            }
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn validate_publication(publication: &IndexPublication) -> Result<(), IndexOwnerError> {
    let name = publication.file_name.as_bytes();
    if publication.generation == 0
        || name.is_empty()
        || name.len() > 255
        || name == b"."
        || name == b".."
        || name.contains(&b'/')
        || name.contains(&0)
        || publication.index.encoded_size() == 0
    {
        return Err(IndexOwnerError::InvalidPublication);
    }
    Ok(())
}

fn encode_head(publication: &IndexPublication) -> Result<Vec<u8>, IndexOwnerError> {
    validate_publication(publication)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(HEAD_MAGIC);
    bytes.extend_from_slice(&HEAD_VERSION.to_be_bytes());
    bytes.extend_from_slice(&publication.generation.to_be_bytes());
    put_string(&mut bytes, &publication.file_name)?;
    bytes.extend_from_slice(&publication.compiler_abi);
    bytes.extend_from_slice(&publication.tree_features.to_be_bytes());
    match publication.verity {
        FsVerityDigest::Sha256(digest) => {
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&32_u16.to_be_bytes());
            bytes.extend_from_slice(&digest);
        }
        FsVerityDigest::Sha512(digest) => {
            bytes.extend_from_slice(&2_u16.to_be_bytes());
            bytes.extend_from_slice(&64_u16.to_be_bytes());
            bytes.extend_from_slice(&digest);
        }
    }
    put_descriptor(&mut bytes, &publication.index)?;
    put_descriptor(&mut bytes, &publication.tree)?;
    put_descriptor(&mut bytes, &publication.root)?;
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    if bytes.len() > MAXIMUM_HEAD_BYTES {
        return Err(IndexOwnerError::InvalidPublication);
    }
    Ok(bytes)
}

fn decode_head(bytes: &[u8]) -> Result<IndexPublication, IndexOwnerError> {
    if bytes.len() < 32 || bytes.len() > MAXIMUM_HEAD_BYTES {
        return Err(IndexOwnerError::InvalidHead);
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(payload).as_slice() != checksum {
        return Err(IndexOwnerError::InvalidHead);
    }
    let mut cursor = Cursor::new(payload);
    if cursor.take(8)? != HEAD_MAGIC || cursor.u32()? != HEAD_VERSION {
        return Err(IndexOwnerError::InvalidHead);
    }
    let generation = cursor.u64()?;
    let file_name = cursor.string()?;
    let compiler_abi = cursor.array()?;
    let tree_features = cursor.u32()?;
    let algorithm = cursor.u16()?;
    let length = cursor.u16()?;
    let verity = match (algorithm, length) {
        (1, 32) => FsVerityDigest::Sha256(cursor.array()?),
        (2, 64) => FsVerityDigest::Sha512(cursor.array()?),
        _ => return Err(IndexOwnerError::InvalidHead),
    };
    let index = cursor.descriptor()?;
    let tree = cursor.descriptor()?;
    let root = cursor.descriptor()?;
    if !cursor.remaining().is_empty() {
        return Err(IndexOwnerError::InvalidHead);
    }
    let publication = IndexPublication {
        generation,
        file_name,
        index,
        compiler_abi,
        tree,
        root,
        tree_features,
        verity,
    };
    validate_publication(&publication)?;
    Ok(publication)
}

fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), IndexOwnerError> {
    let length = u16::try_from(value.len()).map_err(|_| IndexOwnerError::InvalidPublication)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_descriptor(
    bytes: &mut Vec<u8>,
    descriptor: &ObjectDescriptor,
) -> Result<(), IndexOwnerError> {
    put_string(bytes, descriptor.media_type().as_str())?;
    bytes.extend_from_slice(descriptor.digest().as_bytes());
    bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    Ok(())
}

fn read_bounded_at(root: &OwnedFd, name: &str, maximum: usize) -> Result<Vec<u8>, IndexOwnerError> {
    let descriptor = rustix::fs::openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&descriptor)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o022 != 0
        || stat.st_nlink != 1
    {
        return Err(IndexOwnerError::InvalidHead);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(IndexOwnerError::InvalidHead);
    }
    Ok(bytes)
}

fn open_owner_lock(root: &OwnedFd) -> Result<OwnedFd, IndexOwnerError> {
    let descriptor = rustix::fs::openat(
        root,
        ".owner.lock",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&descriptor)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(IndexOwnerError::InvalidOwnerLock);
    }
    rustix::fs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| IndexOwnerError::OwnerBusy)?;
    Ok(descriptor)
}

fn inspect_root(root: &OwnedFd) -> Result<RootIdentity, IndexOwnerError> {
    let stat = rustix::fs::fstat(root)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(IndexOwnerError::RootChanged);
    }
    Ok(RootIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: stat.st_mode & 0o7777,
    })
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn remaining(&self) -> &'a [u8] {
        self.remaining
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], IndexOwnerError> {
        let (head, tail) = self
            .remaining
            .split_at_checked(length)
            .ok_or(IndexOwnerError::InvalidHead)?;
        self.remaining = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], IndexOwnerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| IndexOwnerError::InvalidHead)
    }
    fn u16(&mut self) -> Result<u16, IndexOwnerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, IndexOwnerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, IndexOwnerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn string(&mut self) -> Result<String, IndexOwnerError> {
        let length = self.u16()? as usize;
        let value =
            std::str::from_utf8(self.take(length)?).map_err(|_| IndexOwnerError::InvalidHead)?;
        Ok(value.to_owned())
    }
    fn descriptor(&mut self) -> Result<ObjectDescriptor, IndexOwnerError> {
        let media = MediaType::new(self.string()?).map_err(|_| IndexOwnerError::InvalidHead)?;
        let digest = ObjectDigest::from_bytes(self.array()?);
        let size = self.u64()?;
        Ok(ObjectDescriptor::new(media, digest, size))
    }
}

/// Reports fixed-root, atomic-head, mapping, or validation failure.
#[derive(Debug, thiserror::Error)]
pub enum IndexOwnerError {
    /// Fixed-root or durable-head I/O failed before an ambiguous rename point.
    #[error("index owner I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Linux descriptor or fs-verity mapping validation failed.
    #[error("immutable index mapping failed: {0}")]
    Mapping(#[from] ImmutableFileError),
    /// Beneath-root adoption failed.
    #[error("index root validation failed: {0}")]
    Root(#[from] aos_sandbox_linux::Error),
    /// Protected absolute-path root validation failed.
    #[error("protected index root validation failed: {0}")]
    PublicationRoot(#[from] aos_sandbox_linux::immutable_file::PublicationRootError),
    /// Descriptor-relative fixed-root operation failed.
    #[error("index root operation failed: {0}")]
    Rustix(#[from] rustix::io::Errno),
    /// Structural validation rejected the mapped index.
    #[error("structural index validation failed: {0}")]
    Index(#[from] IndexError),
    /// Publication fields are sentinel, unsafe, or inconsistent.
    #[error("invalid index publication")]
    InvalidPublication,
    /// Another independently opened owner holds the protected-root lease.
    #[error("index protected root is owned by another process")]
    OwnerBusy,
    /// The provisioned fixed-root lease is not a safe regular file.
    #[error("invalid index owner lock")]
    InvalidOwnerLock,
    /// Current-head bytes are malformed, oversized, truncated, or corrupt.
    #[error("invalid index current-head record")]
    InvalidHead,
    /// Expected currentness no longer matches fixed-root readback.
    #[error("index currentness is stale")]
    Stale,
    /// The retained fixed root changed identity or type.
    #[error("index fixed root changed identity")]
    RootChanged,
    /// A deterministic retry temporary was not the exact expected regular file.
    #[error("index replacement temporary is foreign")]
    ForeignTemporary,
    /// Head rename may have occurred and requires exact reopen/readback recovery.
    #[error("index head replacement outcome is ambiguous: {source}")]
    Ambiguous {
        /// Rename, synchronization, or exact-readback failure.
        #[source]
        source: std::io::Error,
        /// Exact replacement recovery ownership.
        recovery: AmbiguousIndexReplacement,
    },
}
