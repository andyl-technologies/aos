//! Deterministic read-only 9P2000.L served-tree model.
//!
//! The 9p sub-node exposes a content-addressed, in-memory tree to the VM. This
//! module owns the deterministic metadata layer: path-hashed QIDs, sorted
//! directory enumeration, fixed/content-derived attributes, synthetic statfs
//! values, and fixed protocol-version negotiation. It deliberately does not
//! inspect host filesystem metadata.

use crate::ContentHash;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

/// Fixed protocol version negotiated by the deterministic 9p sub-node.
pub const NINEP_PROTOCOL_VERSION: &str = "9P2000.L";

/// Fixed QID version returned for every served entry.
pub const NINEP_FIXED_QID_VERSION: u32 = 1;

/// Fixed timestamp used for all 9p attributes.
pub const NINEP_FIXED_EPOCH_SECONDS: u64 = 0;

/// Fixed root uid returned for all 9p attributes.
pub const NINEP_FIXED_UID: u32 = 0;

/// Fixed root gid returned for all 9p attributes.
pub const NINEP_FIXED_GID: u32 = 0;

/// Fixed filesystem block size used for attributes and statfs.
pub const NINEP_FIXED_BLOCK_SIZE: u64 = 4096;

/// Fixed unit used by 9p `blocks` fields.
pub const NINEP_BLOCK_COUNT_UNIT: u64 = 512;

/// Fixed server maximum message size for deterministic version negotiation.
pub const NINEP_DEFAULT_MAXIMUM_MSIZE: u32 = 262_144;

/// Fixed maximum file-name length reported by synthetic statfs.
pub const NINEP_FIXED_NAME_MAX: u32 = 255;

const NINEP_QID_TYPE_FILE: u8 = 0x00;
const NINEP_QID_TYPE_SYMLINK: u8 = 0x02;
const NINEP_QID_TYPE_DIRECTORY: u8 = 0x80;
const NINEP_MODE_DIRECTORY: u32 = 0o040000;
const NINEP_MODE_FILE: u32 = 0o100000;
const NINEP_MODE_SYMLINK: u32 = 0o120000;
const NINEP_QID_PATH_DOMAIN: &str = "crucible.9p.qid-path.v1";

/// Kind of content served by one 9p tree entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NinePEntryKind {
    /// A directory.
    Directory,
    /// A regular read-only file.
    File,
    /// A symbolic link.
    Symlink,
}

impl NinePEntryKind {
    fn qid_type(self) -> u8 {
        match self {
            Self::Directory => NINEP_QID_TYPE_DIRECTORY,
            Self::File => NINEP_QID_TYPE_FILE,
            Self::Symlink => NINEP_QID_TYPE_SYMLINK,
        }
    }

    fn mode_type(self) -> u32 {
        match self {
            Self::Directory => NINEP_MODE_DIRECTORY,
            Self::File => NINEP_MODE_FILE,
            Self::Symlink => NINEP_MODE_SYMLINK,
        }
    }
}

/// The deterministic payload represented by one served 9p entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NinePEntryContent {
    /// Directory entries derive their children from the served tree.
    Directory,
    /// Regular file bytes.
    File {
        /// Immutable file bytes served to the guest.
        bytes: Vec<u8>,
    },
    /// Symbolic-link target text.
    Symlink {
        /// Deterministic link target.
        target: String,
    },
}

impl NinePEntryContent {
    fn kind(&self) -> NinePEntryKind {
        match self {
            Self::Directory => NinePEntryKind::Directory,
            Self::File { .. } => NinePEntryKind::File,
            Self::Symlink { .. } => NinePEntryKind::Symlink,
        }
    }

    fn size(&self) -> Result<u64, NinePServerError> {
        match self {
            Self::Directory => Ok(0),
            Self::File { bytes } => {
                u64::try_from(bytes.len()).map_err(|_| NinePServerError::ContentTooLarge {
                    length: bytes.len(),
                })
            }
            Self::Symlink { target } => {
                u64::try_from(target.len()).map_err(|_| NinePServerError::ContentTooLarge {
                    length: target.len(),
                })
            }
        }
    }
}

/// One entry in the deterministic 9p served tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePServedEntry {
    /// Absolute path within the served tree.
    pub path: String,
    /// Entry payload.
    pub content: NinePEntryContent,
    /// Permission bits; write bits are ignored and file type bits are derived from [`Self::content`].
    pub permissions: u32,
}

impl NinePServedEntry {
    /// Builds a directory entry.
    #[must_use]
    pub fn directory(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            content: NinePEntryContent::Directory,
            permissions: 0o555,
        }
    }

    /// Builds a regular read-only file entry.
    #[must_use]
    pub fn file(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            content: NinePEntryContent::File {
                bytes: bytes.into(),
            },
            permissions: 0o444,
        }
    }

    /// Builds a symbolic-link entry.
    #[must_use]
    pub fn symlink(path: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            content: NinePEntryContent::Symlink {
                target: target.into(),
            },
            permissions: 0o777,
        }
    }

    /// Overrides the non-write permission bits returned by `getattr`.
    #[must_use]
    pub fn with_permissions(mut self, permissions: u32) -> Self {
        self.permissions = read_only_permissions(permissions);
        self
    }

    fn kind(&self) -> NinePEntryKind {
        self.content.kind()
    }
}

/// A deterministic 9p QID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NinePQid {
    /// 9p QID type byte.
    pub qtype: u8,
    /// Fixed QID version.
    pub version: u32,
    /// Stable path hash, never a host inode number.
    pub path: u64,
}

/// One deterministic directory entry returned by `readdir`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePDirectoryEntry {
    /// Child name relative to the enumerated directory.
    pub name: String,
    /// Absolute path within the served tree.
    pub path: String,
    /// Child QID.
    pub qid: NinePQid,
    /// Directory offset assigned after lexicographic sorting.
    pub offset: u64,
}

/// Fixed/content-derived 9p attributes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePAttributes {
    /// Entry QID.
    pub qid: NinePQid,
    /// File type plus permission bits.
    pub mode: u32,
    /// Fixed uid.
    pub uid: u32,
    /// Fixed gid.
    pub gid: u32,
    /// Content-derived size in bytes.
    pub size: u64,
    /// Fixed filesystem block size.
    pub block_size: u64,
    /// Content-derived allocated block count.
    pub blocks: u64,
    /// Fixed access timestamp.
    pub atime_sec: u64,
    /// Fixed modification timestamp.
    pub mtime_sec: u64,
    /// Fixed metadata-change timestamp.
    pub ctime_sec: u64,
}

/// Synthetic deterministic statfs output for the served tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePStatFs {
    /// Fixed filesystem block size.
    pub block_size: u64,
    /// Content-derived total block count.
    pub blocks: u64,
    /// Number of served entries, including root.
    pub files: u64,
    /// Fixed maximum file-name length.
    pub name_max: u32,
    /// Stable filesystem id derived from the served tree content hash.
    pub fsid: u64,
}

/// Result of deterministic 9p version negotiation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePVersionNegotiation {
    /// Negotiated protocol version.
    pub version: String,
    /// Negotiated message size.
    pub msize: u32,
}

/// A deterministic read-only 9p served tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NinePServedTree {
    entries: BTreeMap<String, NinePServedEntry>,
    maximum_msize: u32,
}

impl NinePServedTree {
    /// Builds a served tree using [`NINEP_DEFAULT_MAXIMUM_MSIZE`].
    ///
    /// # Errors
    ///
    /// Returns [`NinePServerError`] when paths are invalid, duplicate, missing a
    /// directory parent, or when the root is not a directory.
    pub fn new(entries: Vec<NinePServedEntry>) -> Result<Self, NinePServerError> {
        Self::with_maximum_msize(entries, NINEP_DEFAULT_MAXIMUM_MSIZE)
    }

    /// Builds a served tree with an explicit deterministic maximum message size.
    ///
    /// # Errors
    ///
    /// Returns [`NinePServerError`] when `maximum_msize` is zero or when the
    /// served entries do not form a deterministic absolute tree.
    pub fn with_maximum_msize(
        entries: Vec<NinePServedEntry>,
        maximum_msize: u32,
    ) -> Result<Self, NinePServerError> {
        if maximum_msize == 0 {
            return Err(NinePServerError::InvalidMsize {
                requested: maximum_msize,
            });
        }

        let mut normalized_entries =
            BTreeMap::from([(String::from("/"), NinePServedEntry::directory("/"))]);
        let mut seen = BTreeSet::new();

        for mut entry in entries {
            let normalized_path = normalize_served_path(&entry.path)?;
            if !seen.insert(normalized_path.clone()) {
                return Err(NinePServerError::DuplicatePath {
                    path: normalized_path,
                });
            }
            if normalized_path == "/" && entry.kind() != NinePEntryKind::Directory {
                return Err(NinePServerError::RootMustBeDirectory);
            }
            entry.path = normalized_path.clone();
            normalized_entries.insert(normalized_path, entry);
        }

        for (path, entry) in &normalized_entries {
            entry.content.size()?;
            if path == "/" {
                continue;
            }
            let parent = parent_path(path)
                .ok_or_else(|| NinePServerError::InvalidPath { path: path.clone() })?;
            match normalized_entries.get(&parent) {
                Some(parent_entry) if parent_entry.kind() == NinePEntryKind::Directory => {}
                Some(_) => {
                    return Err(NinePServerError::ParentNotDirectory {
                        path: path.clone(),
                        parent,
                    });
                }
                None => {
                    return Err(NinePServerError::MissingParent {
                        path: path.clone(),
                        parent,
                    });
                }
            }
        }

        Ok(Self {
            entries: normalized_entries,
            maximum_msize,
        })
    }

    /// Returns the server's deterministic maximum message size.
    #[must_use]
    pub const fn maximum_msize(&self) -> u32 {
        self.maximum_msize
    }

    /// Negotiates the fixed 9P2000.L version and deterministic message size.
    ///
    /// # Errors
    ///
    /// Returns [`NinePServerError::UnsupportedVersion`] if the client requests a
    /// protocol other than `9P2000.L`, or [`NinePServerError::InvalidMsize`] if
    /// the client requests an msize of zero.
    pub fn negotiate_version(
        &self,
        client_version: &str,
        client_msize: u32,
    ) -> Result<NinePVersionNegotiation, NinePServerError> {
        if client_version != NINEP_PROTOCOL_VERSION {
            return Err(NinePServerError::UnsupportedVersion {
                requested: client_version.to_owned(),
            });
        }
        if client_msize == 0 {
            return Err(NinePServerError::InvalidMsize {
                requested: client_msize,
            });
        }
        Ok(NinePVersionNegotiation {
            version: NINEP_PROTOCOL_VERSION.to_owned(),
            msize: client_msize.min(self.maximum_msize),
        })
    }

    /// Returns the QID for a served path.
    ///
    /// # Errors
    ///
    /// Returns [`NinePServerError::NotFound`] when the path is not in the served
    /// tree or [`NinePServerError::InvalidPath`] when the path is malformed.
    pub fn qid(&self, path: &str) -> Result<NinePQid, NinePServerError> {
        let path = normalize_served_path(path)?;
        let entry = self
            .entries
            .get(&path)
            .ok_or_else(|| NinePServerError::NotFound { path: path.clone() })?;
        Ok(qid_for_entry(&path, entry))
    }

    /// Enumerates a directory in deterministic lexicographic order.
    ///
    /// # Errors
    ///
    /// Returns [`NinePServerError`] when `path` is malformed, missing, not a
    /// directory, or when directory offset arithmetic overflows.
    pub fn readdir(&self, path: &str) -> Result<Vec<NinePDirectoryEntry>, NinePServerError> {
        let path = normalize_served_path(path)?;
        let entry = self
            .entries
            .get(&path)
            .ok_or_else(|| NinePServerError::NotFound { path: path.clone() })?;
        if entry.kind() != NinePEntryKind::Directory {
            return Err(NinePServerError::NotDirectory { path });
        }

        let mut children = self
            .entries
            .iter()
            .filter_map(|(child_path, child_entry)| {
                if child_path == &path {
                    return None;
                }
                let parent = parent_path(child_path)?;
                if parent == path {
                    Some((entry_name(child_path), child_path, child_entry))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        children.sort_by(|left, right| left.0.cmp(&right.0));

        let mut output = Vec::with_capacity(children.len());
        for (index, (name, child_path, child_entry)) in children.into_iter().enumerate() {
            let offset = u64::try_from(index)
                .map_err(|_| NinePServerError::DirectoryTooLarge { path: path.clone() })?
                .checked_add(1)
                .ok_or_else(|| NinePServerError::DirectoryTooLarge { path: path.clone() })?;
            output.push(NinePDirectoryEntry {
                name,
                path: child_path.clone(),
                qid: qid_for_entry(child_path, child_entry),
                offset,
            });
        }
        Ok(output)
    }

    /// Returns fixed/content-derived attributes for a served path.
    ///
    /// # Errors
    ///
    /// Returns [`NinePServerError`] when the path is malformed, missing, or when
    /// content sizes cannot be represented.
    pub fn getattr(&self, path: &str) -> Result<NinePAttributes, NinePServerError> {
        let path = normalize_served_path(path)?;
        let entry = self
            .entries
            .get(&path)
            .ok_or_else(|| NinePServerError::NotFound { path: path.clone() })?;
        let size = entry.content.size()?;
        Ok(NinePAttributes {
            qid: qid_for_entry(&path, entry),
            mode: entry.kind().mode_type() | read_only_permissions(entry.permissions),
            uid: NINEP_FIXED_UID,
            gid: NINEP_FIXED_GID,
            size,
            block_size: NINEP_FIXED_BLOCK_SIZE,
            blocks: block_count(size),
            atime_sec: NINEP_FIXED_EPOCH_SECONDS,
            mtime_sec: NINEP_FIXED_EPOCH_SECONDS,
            ctime_sec: NINEP_FIXED_EPOCH_SECONDS,
        })
    }

    /// Returns synthetic deterministic filesystem statistics.
    ///
    /// # Errors
    ///
    /// Returns [`NinePServerError`] when aggregate content sizes or file counts
    /// cannot be represented.
    pub fn statfs(&self) -> Result<NinePStatFs, NinePServerError> {
        let mut total_size = 0u64;
        for entry in self.entries.values() {
            total_size = total_size
                .checked_add(entry.content.size()?)
                .ok_or(NinePServerError::ContentSizeOverflow)?;
        }
        let files =
            u64::try_from(self.entries.len()).map_err(|_| NinePServerError::DirectoryTooLarge {
                path: String::from("/"),
            })?;
        Ok(NinePStatFs {
            block_size: NINEP_FIXED_BLOCK_SIZE,
            blocks: block_count(total_size),
            files,
            name_max: NINEP_FIXED_NAME_MAX,
            fsid: fsid_from_hash(self.content_hash()),
        })
    }

    /// Computes a deterministic content hash for the served tree.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_bytes(&served_tree_bytes(self))
    }
}

/// An error raised by the deterministic 9p served-tree model.
#[derive(Debug, PartialEq, Eq)]
pub enum NinePServerError {
    /// A served path is malformed.
    InvalidPath {
        /// Malformed path.
        path: String,
    },
    /// A path appeared more than once after normalization.
    DuplicatePath {
        /// Duplicate path.
        path: String,
    },
    /// The root entry was not a directory.
    RootMustBeDirectory,
    /// A non-root entry had no directory parent.
    MissingParent {
        /// Entry path.
        path: String,
        /// Missing parent path.
        parent: String,
    },
    /// A non-root entry's parent exists but is not a directory.
    ParentNotDirectory {
        /// Entry path.
        path: String,
        /// Non-directory parent path.
        parent: String,
    },
    /// A requested path is absent.
    NotFound {
        /// Missing path.
        path: String,
    },
    /// A requested path is not a directory.
    NotDirectory {
        /// Non-directory path.
        path: String,
    },
    /// A requested 9p protocol version is unsupported.
    UnsupportedVersion {
        /// Client-requested version.
        requested: String,
    },
    /// A requested message size is invalid.
    InvalidMsize {
        /// Invalid requested message size.
        requested: u32,
    },
    /// Content length could not be represented.
    ContentTooLarge {
        /// Platform content length.
        length: usize,
    },
    /// Aggregate content size overflowed.
    ContentSizeOverflow,
    /// A directory could not assign deterministic offsets.
    DirectoryTooLarge {
        /// Directory path.
        path: String,
    },
}

impl fmt::Display for NinePServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { path } => write!(formatter, "invalid 9p served path `{path}`"),
            Self::DuplicatePath { path } => {
                write!(formatter, "duplicate 9p served path `{path}`")
            }
            Self::RootMustBeDirectory => formatter.write_str("9p root entry must be a directory"),
            Self::MissingParent { path, parent } => write!(
                formatter,
                "9p served path `{path}` is missing directory parent `{parent}`"
            ),
            Self::ParentNotDirectory { path, parent } => write!(
                formatter,
                "9p served path `{path}` has non-directory parent `{parent}`"
            ),
            Self::NotFound { path } => write!(formatter, "9p served path `{path}` was not found"),
            Self::NotDirectory { path } => {
                write!(formatter, "9p served path `{path}` is not a directory")
            }
            Self::UnsupportedVersion { requested } => {
                write!(formatter, "unsupported 9p version `{requested}`")
            }
            Self::InvalidMsize { requested } => {
                write!(formatter, "invalid 9p msize {requested}")
            }
            Self::ContentTooLarge { length } => {
                write!(formatter, "9p content length {length} exceeds u64")
            }
            Self::ContentSizeOverflow => formatter.write_str("9p aggregate content size overflow"),
            Self::DirectoryTooLarge { path } => {
                write!(formatter, "9p directory `{path}` is too large to enumerate")
            }
        }
    }
}

impl Error for NinePServerError {}

fn normalize_served_path(path: &str) -> Result<String, NinePServerError> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.contains('\0')
        || (path.len() > 1 && path.ends_with('/'))
    {
        return Err(NinePServerError::InvalidPath {
            path: path.to_owned(),
        });
    }
    if path == "/" {
        return Ok(String::from("/"));
    }
    for component in path.split('/').skip(1) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(NinePServerError::InvalidPath {
                path: path.to_owned(),
            });
        }
    }
    Ok(path.to_owned())
}

fn parent_path(path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }
    let split = path.rfind('/')?;
    if split == 0 {
        Some(String::from("/"))
    } else {
        Some(path[..split].to_owned())
    }
}

fn entry_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

fn qid_for_entry(path: &str, entry: &NinePServedEntry) -> NinePQid {
    NinePQid {
        qtype: entry.kind().qid_type(),
        version: NINEP_FIXED_QID_VERSION,
        path: qid_path_hash(path),
    }
}

fn qid_path_hash(path: &str) -> u64 {
    let hash = ContentHash::from_canonical_material(NINEP_QID_PATH_DOMAIN, path);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.bytes[..8]);
    u64::from_le_bytes(bytes)
}

fn fsid_from_hash(hash: ContentHash) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.bytes[..8]);
    u64::from_le_bytes(bytes)
}

fn block_count(size: u64) -> u64 {
    if size == 0 {
        0
    } else {
        ((size - 1) / NINEP_BLOCK_COUNT_UNIT) + 1
    }
}

fn read_only_permissions(permissions: u32) -> u32 {
    permissions & 0o555
}

fn served_tree_bytes(tree: &NinePServedTree) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"crucible.9p-served-tree.v1\n");
    bytes.extend_from_slice(&(tree.entries.len() as u64).to_le_bytes());
    for (path, entry) in &tree.entries {
        append_str(&mut bytes, path);
        bytes.push(match entry.kind() {
            NinePEntryKind::Directory => 0,
            NinePEntryKind::File => 1,
            NinePEntryKind::Symlink => 2,
        });
        bytes.extend_from_slice(&read_only_permissions(entry.permissions).to_le_bytes());
        match &entry.content {
            NinePEntryContent::Directory => {}
            NinePEntryContent::File { bytes: content } => append_bytes(&mut bytes, content),
            NinePEntryContent::Symlink { target } => append_str(&mut bytes, target),
        }
    }
    bytes
}

fn append_str(bytes: &mut Vec<u8>, value: &str) {
    append_bytes(bytes, value.as_bytes());
}

fn append_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
}
