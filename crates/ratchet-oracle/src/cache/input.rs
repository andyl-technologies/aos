//! Fingerprints for impure evaluator inputs.
//!
//! The future demand graph will turn filesystem and environment reads into
//! explicit leaves. This module owns deterministic typed identities and
//! observed-result hashes for those leaves while evaluator wiring remains
//! separate.

use crate::cache::hashing::CacheDigestHasher;
use std::cmp::Ordering;

use thiserror::Error;

use super::{DurableBlake3Hash, ImpureInputIdentityHash, ImpureInputObservationHash};

const IDENTITY_DOMAIN: &[u8] = b"aos-nix-input-identity-v1";
const IMPORT_OBSERVATION_DOMAIN: &[u8] = b"aos-nix-input-import-observation-v1";
const READ_FILE_OBSERVATION_DOMAIN: &[u8] = b"aos-nix-input-read-file-observation-v1";
const HASH_FILE_OBSERVATION_DOMAIN: &[u8] = b"aos-nix-input-hash-file-observation-v1";
const READ_DIR_OBSERVATION_DOMAIN: &[u8] = b"aos-nix-input-read-dir-observation-v1";
const READ_FILE_TYPE_OBSERVATION_DOMAIN: &[u8] = b"aos-nix-input-read-file-type-observation-v1";
const GET_ENV_OBSERVATION_DOMAIN: &[u8] = b"aos-nix-input-get-env-observation-v1";
const PATH_EXISTS_OBSERVATION_DOMAIN: &[u8] = b"aos-nix-input-path-exists-observation-v1";

/// The cache treatment for one impure input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImpureInputFingerprint {
    /// A cacheable input with stable identity and observed-result hash.
    Cacheable(CacheableInputFingerprint),
    /// An input that must not be cached.
    Uncacheable(UncacheableInput),
}

impl ImpureInputFingerprint {
    /// Creates a fingerprint for importing a Nix source file.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the path identity cannot be copied
    /// or any encoded chunk length does not fit in `u64`.
    pub fn import(path: &[u8], contents: &[u8]) -> Result<Self, InputFingerprintError> {
        let mut hasher = InputHasher::new(IMPORT_OBSERVATION_DOMAIN);
        hasher.update_chunk(contents)?;
        Self::cacheable(
            ImpureInputKind::Import,
            ImpureInputMode::Default,
            path,
            ImpureInputObservationHash::from_durable_hash(hasher.finalize()),
        )
    }

    /// Creates a fingerprint for `builtins.readFile`.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the path identity cannot be copied
    /// or any encoded chunk length does not fit in `u64`.
    pub fn read_file(path: &[u8], contents: &[u8]) -> Result<Self, InputFingerprintError> {
        let mut hasher = InputHasher::new(READ_FILE_OBSERVATION_DOMAIN);
        hasher.update_chunk(contents)?;
        Self::cacheable(
            ImpureInputKind::ReadFile,
            ImpureInputMode::Default,
            path,
            ImpureInputObservationHash::from_durable_hash(hasher.finalize()),
        )
    }

    /// Creates a fingerprint for `builtins.hashFile`.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the path identity cannot be copied
    /// or any encoded chunk length does not fit in `u64`.
    pub fn hash_file(path: &[u8], contents: &[u8]) -> Result<Self, InputFingerprintError> {
        let mut hasher = InputHasher::new(HASH_FILE_OBSERVATION_DOMAIN);
        hasher.update_chunk(contents)?;
        Self::cacheable(
            ImpureInputKind::HashFile,
            ImpureInputMode::Default,
            path,
            ImpureInputObservationHash::from_durable_hash(hasher.finalize()),
        )
    }

    /// Creates a fingerprint for `builtins.readDir`.
    ///
    /// Entries are sorted by raw name and then type before hashing, so the
    /// fingerprint is independent of host directory iteration order while still
    /// preserving duplicate entries if a caller supplies them.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the path identity cannot be copied,
    /// entry storage cannot be reserved, or any encoded chunk length does not
    /// fit in `u64`.
    pub fn read_dir<'a, I>(path: &[u8], entries: I) -> Result<Self, InputFingerprintError>
    where
        I: IntoIterator<Item = DirEntryInput<'a>>,
    {
        let mut entries = collect_dir_entries(entries)?;
        entries.sort_by(|left, right| match left.name.cmp(right.name) {
            Ordering::Equal => left.file_type.cmp(&right.file_type),
            ordering => ordering,
        });

        let mut hasher = InputHasher::new(READ_DIR_OBSERVATION_DOMAIN);
        for entry in entries {
            hasher.update_chunk(entry.name)?;
            hasher.update_chunk(entry.file_type.as_bytes())?;
        }
        Self::cacheable(
            ImpureInputKind::ReadDir,
            ImpureInputMode::Default,
            path,
            ImpureInputObservationHash::from_durable_hash(hasher.finalize()),
        )
    }

    /// Creates a fingerprint for `builtins.readFileType`.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the path identity cannot be copied
    /// or any encoded chunk length does not fit in `u64`.
    pub fn read_file_type(
        path: &[u8],
        file_type: FileTypeForInput,
    ) -> Result<Self, InputFingerprintError> {
        let mut hasher = InputHasher::new(READ_FILE_TYPE_OBSERVATION_DOMAIN);
        hasher.update_chunk(file_type.as_bytes())?;
        Self::cacheable(
            ImpureInputKind::ReadFileType,
            ImpureInputMode::Default,
            path,
            ImpureInputObservationHash::from_durable_hash(hasher.finalize()),
        )
    }

    /// Creates a fingerprint for `builtins.getEnv`.
    ///
    /// `None` represents an absent environment variable. This function hashes
    /// only the observed value supplied by the caller; it never reads the
    /// process environment itself.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the variable-name identity cannot
    /// be copied or any encoded chunk length does not fit in `u64`.
    pub fn get_env(name: &[u8], value: Option<&[u8]>) -> Result<Self, InputFingerprintError> {
        let mut hasher = InputHasher::new(GET_ENV_OBSERVATION_DOMAIN);
        match value {
            Some(value) => {
                hasher.update_tag(1);
                hasher.update_chunk(value)?;
            }
            None => hasher.update_tag(0),
        }
        Self::cacheable(
            ImpureInputKind::GetEnv,
            ImpureInputMode::Default,
            name,
            ImpureInputObservationHash::from_durable_hash(hasher.finalize()),
        )
    }

    /// Creates a fingerprint for the default `builtins.pathExists` probe.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the path identity cannot be copied
    /// or any encoded chunk length does not fit in `u64`.
    pub fn path_exists(path: &[u8], exists: bool) -> Result<Self, InputFingerprintError> {
        Self::path_exists_with_mode(path, ImpureInputMode::Default, exists)
    }

    /// Creates a fingerprint for a `builtins.pathExists` probe with a mode.
    ///
    /// The mode belongs to the input identity, not the observation hash. This
    /// lets future callers distinguish a normal existence check from a
    /// directory-required path marker while still comparing only the observed
    /// boolean during early cutoff.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the path identity cannot be copied
    /// or any encoded chunk length does not fit in `u64`.
    pub fn path_exists_with_mode(
        path: &[u8],
        mode: ImpureInputMode,
        exists: bool,
    ) -> Result<Self, InputFingerprintError> {
        let mut hasher = InputHasher::new(PATH_EXISTS_OBSERVATION_DOMAIN);
        hasher.update_tag(u8::from(exists));
        Self::cacheable(
            ImpureInputKind::PathExists,
            mode,
            path,
            ImpureInputObservationHash::from_durable_hash(hasher.finalize()),
        )
    }

    /// Creates the uncacheable fingerprint for `builtins.currentTime`.
    pub const fn current_time() -> Self {
        Self::Uncacheable(UncacheableInput::CurrentTime)
    }

    /// Returns the cacheable fingerprint, if this input is cacheable.
    pub const fn as_cacheable(&self) -> Option<&CacheableInputFingerprint> {
        match self {
            Self::Cacheable(fingerprint) => Some(fingerprint),
            Self::Uncacheable(_) => None,
        }
    }

    fn cacheable(
        kind: ImpureInputKind,
        mode: ImpureInputMode,
        subject: &[u8],
        observation_hash: ImpureInputObservationHash,
    ) -> Result<Self, InputFingerprintError> {
        Ok(Self::Cacheable(CacheableInputFingerprint::new(
            kind,
            mode,
            subject,
            observation_hash,
        )?))
    }
}

/// A cacheable impure input fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheableInputFingerprint {
    identity: ImpureInputIdentity,
    observation_hash: ImpureInputObservationHash,
}

impl CacheableInputFingerprint {
    fn new(
        kind: ImpureInputKind,
        mode: ImpureInputMode,
        subject: &[u8],
        observation_hash: ImpureInputObservationHash,
    ) -> Result<Self, InputFingerprintError> {
        validate_input_mode(kind, mode)?;
        Ok(Self {
            identity: ImpureInputIdentity::new(kind, mode, subject)?,
            observation_hash,
        })
    }

    /// Creates a cacheable input fingerprint from stable persisted parts.
    ///
    /// This constructor is for persistence formats that already carry the
    /// typed identity subject and the observed-result hash. Normal evaluator
    /// callers should prefer the operation-specific constructors on
    /// [`ImpureInputFingerprint`], which compute observation hashes from
    /// concrete input observations.
    ///
    /// # Errors
    ///
    /// Returns [`InputFingerprintError`] if the kind/mode pair is not emitted
    /// by evaluator traces, the identity subject cannot be copied, or any
    /// encoded identity chunk length does not fit in `u64`.
    pub fn from_observation_hash(
        kind: ImpureInputKind,
        mode: ImpureInputMode,
        subject: &[u8],
        observation_hash: DurableBlake3Hash,
    ) -> Result<Self, InputFingerprintError> {
        Self::new(
            kind,
            mode,
            subject,
            ImpureInputObservationHash::from_persisted_hash(observation_hash),
        )
    }

    /// Returns the typed input identity.
    pub const fn identity(&self) -> &ImpureInputIdentity {
        &self.identity
    }

    /// Returns the kind of impure input.
    pub const fn kind(&self) -> ImpureInputKind {
        self.identity.kind()
    }

    /// Returns the typed durable hash of the observed input result.
    pub const fn observation_hash(&self) -> ImpureInputObservationHash {
        self.observation_hash
    }
}

/// The stable identity of one impure input read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpureInputIdentity {
    kind: ImpureInputKind,
    mode: ImpureInputMode,
    subject: Vec<u8>,
    hash: ImpureInputIdentityHash,
}

impl ImpureInputIdentity {
    fn new(
        kind: ImpureInputKind,
        mode: ImpureInputMode,
        subject: &[u8],
    ) -> Result<Self, InputFingerprintError> {
        let mut hasher = InputHasher::new(IDENTITY_DOMAIN);
        hasher.update_chunk(kind.as_bytes())?;
        hasher.update_chunk(mode.as_bytes())?;
        hasher.update_chunk(subject)?;
        Ok(Self {
            kind,
            mode,
            subject: copy_subject(subject)?,
            hash: ImpureInputIdentityHash::from_durable_hash(hasher.finalize()),
        })
    }

    /// Returns the operation kind encoded into this identity.
    pub const fn kind(&self) -> ImpureInputKind {
        self.kind
    }

    /// Returns the operation mode encoded into this identity.
    pub const fn mode(&self) -> ImpureInputMode {
        self.mode
    }

    /// Returns the raw identity subject, usually a path or environment name.
    pub fn subject(&self) -> &[u8] {
        &self.subject
    }

    /// Returns the typed durable hash of this input identity.
    pub const fn hash(&self) -> ImpureInputIdentityHash {
        self.hash
    }
}

/// Cacheable impure input kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImpureInputKind {
    /// A filesystem import read.
    Import,
    /// A `builtins.readFile` read.
    ReadFile,
    /// A `builtins.hashFile` read.
    HashFile,
    /// A `builtins.readDir` read.
    ReadDir,
    /// A `builtins.readFileType` metadata read.
    ReadFileType,
    /// A `builtins.pathExists` probe.
    PathExists,
    /// A `builtins.getEnv` read.
    GetEnv,
}

impl ImpureInputKind {
    /// Returns the canonical bytes used in typed input identities.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Import => b"import",
            Self::ReadFile => b"read-file",
            Self::HashFile => b"hash-file",
            Self::ReadDir => b"read-dir",
            Self::ReadFileType => b"read-file-type",
            Self::PathExists => b"path-exists",
            Self::GetEnv => b"get-env",
        }
    }
}

/// Operation-specific mode encoded into an impure input identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImpureInputMode {
    /// The operation's ordinary mode.
    Default,
    /// A path probe that requires the target to be a directory.
    RequireDirectory,
    /// A `builtins.findFile` candidate probe using `metadata` existence.
    FindFileCandidate,
}

impl ImpureInputMode {
    /// Returns the canonical bytes used in typed input identities.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Default => b"default",
            Self::RequireDirectory => b"require-directory",
            Self::FindFileCandidate => b"find-file-candidate",
        }
    }
}

/// Impure inputs that must not be cached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UncacheableInput {
    /// `builtins.currentTime` depends on evaluation time rather than content.
    CurrentTime,
}

/// File types observed by filesystem-reading builtins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileTypeForInput {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symlink.
    Symlink,
    /// Another filesystem node kind, matching Nix's collapsed type surface.
    Unknown,
}

impl FileTypeForInput {
    /// Returns the canonical bytes used by Nix file-type builtins.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Regular => b"regular",
            Self::Directory => b"directory",
            Self::Symlink => b"symlink",
            Self::Unknown => b"unknown",
        }
    }
}

/// One entry observed by `builtins.readDir`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirEntryInput<'a> {
    name: &'a [u8],
    file_type: FileTypeForInput,
}

impl<'a> DirEntryInput<'a> {
    /// Creates a directory-entry observation.
    pub const fn new(name: &'a [u8], file_type: FileTypeForInput) -> Self {
        Self { name, file_type }
    }

    /// Returns the raw entry name.
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the observed file type.
    pub const fn file_type(self) -> FileTypeForInput {
        self.file_type
    }
}

/// Impure input fingerprinting failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum InputFingerprintError {
    /// An identity subject was too large to copy.
    #[error("failed to reserve impure input identity subject with {len} bytes")]
    IdentityAllocationFailed {
        /// The identity subject byte length.
        len: usize,
    },
    /// Directory-entry storage could not be reserved.
    #[error("failed to reserve {entries} impure input directory entries")]
    EntryAllocationFailed {
        /// The number of directory entries requested.
        entries: usize,
    },
    /// A length-prefixed chunk was too large to encode.
    #[error("impure input chunk length {len} does not fit in u64")]
    ChunkLengthOverflow {
        /// The chunk length that could not be represented.
        len: usize,
    },
    /// An input mode was not valid for the input kind.
    #[error("impure input kind {kind:?} cannot use mode {mode:?}")]
    InvalidInputMode {
        /// The input kind.
        kind: ImpureInputKind,
        /// The rejected input mode.
        mode: ImpureInputMode,
    },
}

fn validate_input_mode(
    kind: ImpureInputKind,
    mode: ImpureInputMode,
) -> Result<(), InputFingerprintError> {
    match (kind, mode) {
        (_, ImpureInputMode::Default)
        | (
            ImpureInputKind::PathExists,
            ImpureInputMode::RequireDirectory | ImpureInputMode::FindFileCandidate,
        ) => Ok(()),
        _ => Err(InputFingerprintError::InvalidInputMode { kind, mode }),
    }
}

struct InputHasher {
    hasher: CacheDigestHasher,
}

impl InputHasher {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(domain);
        Self { hasher }
    }

    fn update_tag(&mut self, tag: u8) {
        self.hasher.update(&[tag]);
    }

    fn update_chunk(&mut self, chunk: &[u8]) -> Result<(), InputFingerprintError> {
        let len = u64::try_from(chunk.len())
            .map_err(|_| InputFingerprintError::ChunkLengthOverflow { len: chunk.len() })?;
        self.hasher.update(&len.to_le_bytes());
        self.hasher.update(chunk);
        Ok(())
    }

    fn finalize(self) -> DurableBlake3Hash {
        DurableBlake3Hash::from_hasher(self.hasher)
    }
}

fn collect_dir_entries<'a, I>(entries: I) -> Result<Vec<DirEntryInput<'a>>, InputFingerprintError>
where
    I: IntoIterator<Item = DirEntryInput<'a>>,
{
    let iterator = entries.into_iter();
    let (lower, upper) = iterator.size_hint();
    let requested = upper.unwrap_or(lower);
    let mut collected = Vec::new();
    collected
        .try_reserve(requested)
        .map_err(|_| InputFingerprintError::EntryAllocationFailed { entries: requested })?;

    for entry in iterator {
        if collected.len() == collected.capacity() {
            let requested = collected.len().saturating_add(1);
            collected
                .try_reserve(1)
                .map_err(|_| InputFingerprintError::EntryAllocationFailed { entries: requested })?;
        }
        collected.push(entry);
    }

    Ok(collected)
}

fn copy_subject(subject: &[u8]) -> Result<Vec<u8>, InputFingerprintError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(subject.len())
        .map_err(|_| InputFingerprintError::IdentityAllocationFailed { len: subject.len() })?;
    copied.extend_from_slice(subject);
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cacheable(fingerprint: ImpureInputFingerprint) -> CacheableInputFingerprint {
        fingerprint
            .as_cacheable()
            .expect("input is cacheable")
            .clone()
    }

    #[test]
    fn identical_bytes_under_different_operations_are_separate_domains() {
        let imported =
            cacheable(ImpureInputFingerprint::import(b"/tmp/data", b"same").expect("hashes"));
        let read_file =
            cacheable(ImpureInputFingerprint::read_file(b"/tmp/data", b"same").expect("hashes"));
        let hash_file =
            cacheable(ImpureInputFingerprint::hash_file(b"/tmp/data", b"same").expect("hashes"));

        assert_eq!(imported.kind(), ImpureInputKind::Import);
        assert_eq!(read_file.kind(), ImpureInputKind::ReadFile);
        assert_eq!(hash_file.kind(), ImpureInputKind::HashFile);
        assert_ne!(imported.identity().hash(), read_file.identity().hash());
        assert_ne!(imported.observation_hash(), read_file.observation_hash());
        assert_ne!(read_file.identity().hash(), hash_file.identity().hash());
        assert_ne!(read_file.observation_hash(), hash_file.observation_hash());
    }

    #[test]
    fn read_file_hash_changes_with_contents_but_keeps_identity_separate() {
        let first =
            cacheable(ImpureInputFingerprint::read_file(b"/tmp/data", b"one").expect("hashes"));
        let second =
            cacheable(ImpureInputFingerprint::read_file(b"/tmp/data", b"two").expect("hashes"));
        let same_contents_elsewhere =
            cacheable(ImpureInputFingerprint::read_file(b"/tmp/other", b"one").expect("hashes"));

        assert_eq!(first.kind(), ImpureInputKind::ReadFile);
        assert_eq!(first.identity().subject(), b"/tmp/data");
        assert_eq!(first.identity().mode(), ImpureInputMode::Default);
        assert_eq!(first.identity().hash(), second.identity().hash());
        assert_ne!(first.observation_hash(), second.observation_hash());
        assert_eq!(
            first.observation_hash(),
            same_contents_elsewhere.observation_hash()
        );
        assert_ne!(
            first.identity().hash(),
            same_contents_elsewhere.identity().hash()
        );
    }

    #[test]
    fn hash_file_hash_accepts_binary_contents() {
        let first =
            cacheable(ImpureInputFingerprint::hash_file(b"/tmp/data", b"a\0b").expect("hashes"));
        let second =
            cacheable(ImpureInputFingerprint::hash_file(b"/tmp/data", b"a\0c").expect("hashes"));

        assert_eq!(first.kind(), ImpureInputKind::HashFile);
        assert_eq!(first.identity().subject(), b"/tmp/data");
        assert_eq!(first.identity().mode(), ImpureInputMode::Default);
        assert_eq!(first.identity().hash(), second.identity().hash());
        assert_ne!(first.observation_hash(), second.observation_hash());
    }

    #[test]
    fn read_dir_hash_is_order_independent_but_content_sensitive() {
        let ordered = cacheable(
            ImpureInputFingerprint::read_dir(
                b"/tmp/dir",
                [
                    DirEntryInput::new(b"a", FileTypeForInput::Regular),
                    DirEntryInput::new(b"b", FileTypeForInput::Directory),
                ],
            )
            .expect("hashes"),
        );
        let reversed = cacheable(
            ImpureInputFingerprint::read_dir(
                b"/tmp/dir",
                [
                    DirEntryInput::new(b"b", FileTypeForInput::Directory),
                    DirEntryInput::new(b"a", FileTypeForInput::Regular),
                ],
            )
            .expect("hashes"),
        );
        let changed_type = cacheable(
            ImpureInputFingerprint::read_dir(
                b"/tmp/dir",
                [
                    DirEntryInput::new(b"a", FileTypeForInput::Directory),
                    DirEntryInput::new(b"b", FileTypeForInput::Directory),
                ],
            )
            .expect("hashes"),
        );

        assert_eq!(ordered.observation_hash(), reversed.observation_hash());
        assert_ne!(ordered.observation_hash(), changed_type.observation_hash());
    }

    #[test]
    fn read_dir_hash_preserves_multiplicity() {
        let single = cacheable(
            ImpureInputFingerprint::read_dir(
                b"/tmp/dir",
                [DirEntryInput::new(b"a", FileTypeForInput::Regular)],
            )
            .expect("hashes"),
        );
        let duplicate = cacheable(
            ImpureInputFingerprint::read_dir(
                b"/tmp/dir",
                [
                    DirEntryInput::new(b"a", FileTypeForInput::Regular),
                    DirEntryInput::new(b"a", FileTypeForInput::Regular),
                ],
            )
            .expect("hashes"),
        );

        assert_ne!(single.observation_hash(), duplicate.observation_hash());
    }

    #[test]
    fn read_file_type_hash_uses_canonical_file_type_tags() {
        let file = cacheable(
            ImpureInputFingerprint::read_file_type(b"/tmp/x", FileTypeForInput::Regular)
                .expect("hashes"),
        );
        let dir = cacheable(
            ImpureInputFingerprint::read_file_type(b"/tmp/x", FileTypeForInput::Directory)
                .expect("hashes"),
        );

        assert_eq!(file.kind(), ImpureInputKind::ReadFileType);
        assert_eq!(FileTypeForInput::Regular.as_bytes(), b"regular");
        assert_eq!(FileTypeForInput::Directory.as_bytes(), b"directory");
        assert_eq!(FileTypeForInput::Symlink.as_bytes(), b"symlink");
        assert_eq!(FileTypeForInput::Unknown.as_bytes(), b"unknown");
        assert_ne!(file.observation_hash(), dir.observation_hash());
    }

    #[test]
    fn get_env_hash_distinguishes_absent_and_changed_values() {
        let absent = cacheable(ImpureInputFingerprint::get_env(b"HOME", None).expect("hashes"));
        let first =
            cacheable(ImpureInputFingerprint::get_env(b"HOME", Some(b"/one")).expect("hashes"));
        let second =
            cacheable(ImpureInputFingerprint::get_env(b"HOME", Some(b"/two")).expect("hashes"));
        let other_name =
            cacheable(ImpureInputFingerprint::get_env(b"SHELL", Some(b"/one")).expect("hashes"));

        assert_eq!(first.kind(), ImpureInputKind::GetEnv);
        assert_eq!(first.identity().subject(), b"HOME");
        assert_ne!(absent.observation_hash(), first.observation_hash());
        assert_ne!(first.observation_hash(), second.observation_hash());
        assert_eq!(first.observation_hash(), other_name.observation_hash());
        assert_ne!(first.identity().hash(), other_name.identity().hash());
    }

    #[test]
    fn path_exists_hash_distinguishes_booleans_and_keeps_mode_in_identity() {
        let missing =
            cacheable(ImpureInputFingerprint::path_exists(b"/tmp/x", false).expect("hashes"));
        let existing =
            cacheable(ImpureInputFingerprint::path_exists(b"/tmp/x", true).expect("hashes"));
        let directory_marker = cacheable(
            ImpureInputFingerprint::path_exists_with_mode(
                b"/tmp/x",
                ImpureInputMode::RequireDirectory,
                true,
            )
            .expect("hashes"),
        );
        let find_file_candidate = cacheable(
            ImpureInputFingerprint::path_exists_with_mode(
                b"/tmp/x",
                ImpureInputMode::FindFileCandidate,
                true,
            )
            .expect("hashes"),
        );

        assert_eq!(existing.kind(), ImpureInputKind::PathExists);
        assert_eq!(existing.identity().mode(), ImpureInputMode::Default);
        assert_eq!(
            directory_marker.identity().mode(),
            ImpureInputMode::RequireDirectory
        );
        assert_eq!(
            find_file_candidate.identity().mode(),
            ImpureInputMode::FindFileCandidate
        );
        assert_ne!(missing.observation_hash(), existing.observation_hash());
        assert_eq!(
            existing.observation_hash(),
            directory_marker.observation_hash()
        );
        assert_eq!(
            existing.observation_hash(),
            find_file_candidate.observation_hash()
        );
        assert_ne!(
            existing.identity().hash(),
            directory_marker.identity().hash()
        );
        assert_ne!(
            existing.identity().hash(),
            find_file_candidate.identity().hash()
        );
    }

    #[test]
    fn current_time_is_uncacheable() {
        assert_eq!(
            ImpureInputFingerprint::current_time(),
            ImpureInputFingerprint::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert!(
            ImpureInputFingerprint::current_time()
                .as_cacheable()
                .is_none()
        );
    }
}
