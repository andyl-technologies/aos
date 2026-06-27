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
const NINEP_XATTR_QID_PATH_DOMAIN: &str = "crucible.9p.xattr-qid-path.v1";

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
        if maximum_msize < NINEP_MINIMUM_MSIZE {
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
        if client_msize < NINEP_MINIMUM_MSIZE {
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

impl NinePServedTree {
    fn entry(&self, path: &str) -> Result<&NinePServedEntry, NinePServerError> {
        let path = normalize_served_path(path)?;
        self.entries
            .get(&path)
            .ok_or(NinePServerError::NotFound { path })
    }

    fn entry_kind(&self, path: &str) -> Result<NinePEntryKind, NinePServerError> {
        Ok(self.entry(path)?.kind())
    }

    fn read_file(&self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>, NinePServerError> {
        match &self.entry(path)?.content {
            NinePEntryContent::File { bytes } => Ok(read_slice(bytes, offset, count)),
            _ => Err(NinePServerError::NotFile {
                path: path.to_owned(),
            }),
        }
    }

    fn readlink(&self, path: &str) -> Result<String, NinePServerError> {
        match &self.entry(path)?.content {
            NinePEntryContent::Symlink { target } => Ok(target.clone()),
            _ => Err(NinePServerError::NotSymlink {
                path: path.to_owned(),
            }),
        }
    }
}

/// 9p header size used by msize checks.
pub const NINEP_HEADER_SIZE: u32 = 7;

const NINEP_U16_SIZE: u32 = 2;
const NINEP_U32_SIZE: u32 = 4;
const NINEP_U64_SIZE: u32 = 8;
const NINEP_QID_SIZE: u32 = 13;
const NINEP_MINIMUM_MSIZE: u32 =
    NINEP_HEADER_SIZE + NINEP_U32_SIZE + NINEP_U16_SIZE + NINEP_PROTOCOL_VERSION.len() as u32;
const NINEP_READ_RESPONSE_OVERHEAD: u32 = NINEP_HEADER_SIZE + NINEP_U32_SIZE;
const NINEP_READDIR_RESPONSE_OVERHEAD: u32 = NINEP_HEADER_SIZE + NINEP_U32_SIZE;
const NINEP_DIRECTORY_ENTRY_BASE_SIZE: u32 = NINEP_QID_SIZE + NINEP_U64_SIZE + 1 + NINEP_U16_SIZE;
const NINEP_NOTAG: u16 = u16::MAX;
const NINEP_RLERROR: u8 = 7;
const NINEP_TSTATFS: u8 = 8;
const NINEP_RSTATFS: u8 = 9;
const NINEP_TLOPEN: u8 = 12;
const NINEP_RLOPEN: u8 = 13;
const NINEP_TLCREATE: u8 = 14;
const NINEP_TREADLINK: u8 = 22;
const NINEP_RREADLINK: u8 = 23;
const NINEP_TGETATTR: u8 = 24;
const NINEP_RGETATTR: u8 = 25;
const NINEP_TSETATTR: u8 = 26;
const NINEP_TXATTRWALK: u8 = 30;
const NINEP_RXATTRWALK: u8 = 31;
const NINEP_TREADDIR: u8 = 40;
const NINEP_RREADDIR: u8 = 41;
const NINEP_TMKDIR: u8 = 72;
const NINEP_TRENAMEAT: u8 = 74;
const NINEP_TUNLINKAT: u8 = 76;
const NINEP_TVERSION: u8 = 100;
const NINEP_RVERSION: u8 = 101;
const NINEP_TATTACH: u8 = 104;
const NINEP_RATTACH: u8 = 105;
const NINEP_TFLUSH: u8 = 108;
const NINEP_RFLUSH: u8 = 109;
const NINEP_TWALK: u8 = 110;
const NINEP_RWALK: u8 = 111;
const NINEP_TREAD: u8 = 116;
const NINEP_RREAD: u8 = 117;
const NINEP_TWRITE: u8 = 118;
const NINEP_TCLUNK: u8 = 120;
const NINEP_RCLUNK: u8 = 121;
const NINEP_DT_UNKNOWN: u8 = 0;
const NINEP_DT_DIR: u8 = 4;
const NINEP_DT_REG: u8 = 8;
const NINEP_DT_LNK: u8 = 10;
const NINEP_STATFS_MAGIC: u32 = 0x0102_1997;
const NINEP_GETATTR_VALID_MASK: u64 = 0x0000_3fff;
const NINEP_OPEN_ACCMODE: u32 = 0o3;
const NINEP_OPEN_WRONLY: u32 = 0o1;
const NINEP_OPEN_RDWR: u32 = 0o2;
const NINEP_OPEN_TRUNC: u32 = 0o1000;
const NINEP_OPEN_APPEND: u32 = 0o2000;

/// POSIX errno returned for malformed 9p request bodies.
pub const NINEP_EINVAL: u32 = 22;

/// POSIX errno returned for malformed 9p bodies that cannot be trusted.
pub const NINEP_EIO: u32 = 5;

/// POSIX errno returned for mutating requests against the read-only export.
pub const NINEP_EROFS: u32 = 30;

/// POSIX errno returned for unknown 9p message types.
pub const NINEP_ENOSYS: u32 = 38;

/// A mutating 9p request that is always rejected by the read-only sub-node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NinePMutatingMessage {
    /// `Tlcreate`.
    Lcreate,
    /// `Twrite`.
    Write,
    /// `Tmkdir`.
    Mkdir,
    /// `Tunlinkat`.
    Unlinkat,
    /// `Trenameat`.
    Renameat,
    /// `Tsetattr`.
    Setattr,
}

/// A high-level 9p request handled by [`NinePSession`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePRequest {
    /// 9p request tag.
    pub tag: u16,
    /// Deterministic encoded message size used for msize enforcement.
    pub encoded_size: u32,
    /// Request payload.
    pub kind: NinePRequestKind,
}

impl NinePRequest {
    /// Builds a request with a deterministic modeled 9p encoded size.
    #[must_use]
    pub fn new(tag: u16, kind: NinePRequestKind) -> Self {
        let encoded_size = encoded_request_size(&kind);
        Self {
            tag,
            encoded_size,
            kind,
        }
    }

    /// Overrides the encoded message size used for deterministic msize checks.
    #[must_use]
    pub fn with_encoded_size(mut self, encoded_size: u32) -> Self {
        self.encoded_size = encoded_size.max(encoded_request_size(&self.kind));
        self
    }
}

/// The high-level 9p request set implemented by T-IO-7.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NinePRequestKind {
    /// `Tversion`.
    Version {
        /// Client-requested msize.
        msize: u32,
        /// Client-requested protocol version.
        version: String,
    },
    /// `Tattach`.
    Attach {
        /// Fid bound to the root of the served tree.
        fid: u32,
    },
    /// `Twalk`.
    Walk {
        /// Existing source fid.
        fid: u32,
        /// New destination fid.
        newfid: u32,
        /// Path components to walk.
        names: Vec<String>,
    },
    /// `Tlopen`.
    Lopen {
        /// Fid to open.
        fid: u32,
    },
    /// `Tread`.
    Read {
        /// Fid to read.
        fid: u32,
        /// Byte offset.
        offset: u64,
        /// Maximum bytes to return.
        count: u32,
    },
    /// `Treaddir`.
    Readdir {
        /// Directory fid to enumerate.
        fid: u32,
        /// Last returned directory offset.
        offset: u64,
        /// Maximum encoded directory-entry payload bytes to return.
        count: u32,
    },
    /// `Tgetattr`.
    GetAttr {
        /// Fid to inspect.
        fid: u32,
    },
    /// `Treadlink`.
    ReadLink {
        /// Symlink fid.
        fid: u32,
    },
    /// `Tclunk`.
    Clunk {
        /// Fid to release.
        fid: u32,
    },
    /// `Tstatfs`.
    StatFs {
        /// Fid within the served tree.
        fid: u32,
    },
    /// `Tflush`.
    Flush,
    /// `Txattrwalk`.
    XattrWalk {
        /// Existing fid.
        fid: u32,
        /// New xattr fid.
        newfid: u32,
        /// Attribute name.
        name: String,
    },
    /// Mutating request rejected with `EROFS`.
    Mutating(NinePMutatingMessage),
    /// Unknown request type rejected with `ENOSYS`.
    Unknown {
        /// Numeric 9p message type.
        message_type: u8,
    },
    /// Malformed request body rejected with a 9p error.
    Malformed {
        /// Whether the malformed body should map to `EIO` instead of `EINVAL`.
        io_error: bool,
    },
}

/// A high-level 9p response emitted by [`NinePSession`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePResponse {
    /// 9p response tag.
    pub tag: u16,
    /// Response payload.
    pub kind: NinePResponseKind,
}

/// The high-level 9p response set implemented by T-IO-7.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NinePResponseKind {
    /// `Rversion`.
    Version(NinePVersionNegotiation),
    /// `Rattach`.
    Attach {
        /// Root QID.
        qid: NinePQid,
    },
    /// `Rwalk`.
    Walk {
        /// QIDs reached by the walk.
        qids: Vec<NinePQid>,
    },
    /// `Rlopen`.
    Lopen {
        /// Opened fid QID.
        qid: NinePQid,
    },
    /// `Rread`.
    Read {
        /// File data.
        data: Vec<u8>,
    },
    /// `Rreaddir`.
    Readdir {
        /// Deterministically sorted directory entries.
        entries: Vec<NinePDirectoryEntry>,
    },
    /// `Rgetattr`.
    GetAttr(NinePAttributes),
    /// `Rreadlink`.
    ReadLink {
        /// Symlink target.
        target: String,
    },
    /// `Rclunk`.
    Clunk,
    /// `Rstatfs`.
    StatFs(NinePStatFs),
    /// `Rflush`.
    Flush,
    /// `Rxattrwalk`.
    XattrWalk {
        /// Reported xattr size.
        size: u64,
    },
    /// `Rlerror`.
    Error {
        /// Linux errno value.
        errno: u32,
    },
}

/// Restorable snapshot of deterministic 9p fid state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePSessionSnapshot {
    /// Negotiated msize at the checkpoint boundary.
    pub negotiated_msize: u32,
    /// Fid bindings in ascending fid order.
    pub fids: Vec<NinePFidSnapshot>,
}

/// Restorable snapshot of one 9p fid.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NinePFidSnapshot {
    /// Fid number.
    pub fid: u32,
    /// Absolute path within the served tree, or the source path for an xattr fid.
    pub path: String,
    /// Extended-attribute name when this snapshot represents an xattr fid.
    pub xattr_name: Option<String>,
    /// Open kind, if the fid was opened.
    pub open_kind: Option<NinePEntryKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NinePFidState {
    target: NinePFidTarget,
    open: Option<NinePOpenHandle>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NinePFidTarget {
    Entry { path: String },
    Xattr { source_path: String, name: String },
}

impl NinePFidTarget {
    fn snapshot_path(&self) -> String {
        match self {
            Self::Entry { path } => path.clone(),
            Self::Xattr { source_path, .. } => source_path.clone(),
        }
    }

    fn snapshot_xattr_name(&self) -> Option<String> {
        match self {
            Self::Entry { .. } => None,
            Self::Xattr { name, .. } => Some(name.clone()),
        }
    }

    fn diagnostic_path(&self) -> String {
        match self {
            Self::Entry { path } => path.clone(),
            Self::Xattr { source_path, name } => format!("{source_path}:xattr:{name}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NinePOpenHandle {
    File,
    Symlink,
    Directory { entries: Vec<NinePDirectoryEntry> },
    Xattr,
}

impl NinePOpenHandle {
    fn kind(&self) -> NinePEntryKind {
        match self {
            Self::File => NinePEntryKind::File,
            Self::Symlink => NinePEntryKind::Symlink,
            Self::Directory { .. } => NinePEntryKind::Directory,
            Self::Xattr => NinePEntryKind::File,
        }
    }
}

/// Deterministic 9p request/session state over a read-only served tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NinePSession {
    tree: NinePServedTree,
    negotiated_msize: u32,
    fids: BTreeMap<u32, NinePFidState>,
}

impl NinePSession {
    /// Builds a deterministic 9p session.
    #[must_use]
    pub fn new(tree: NinePServedTree) -> Self {
        let negotiated_msize = tree.maximum_msize();
        Self {
            tree,
            negotiated_msize,
            fids: BTreeMap::new(),
        }
    }

    /// Returns the negotiated msize currently enforced for requests.
    #[must_use]
    pub const fn negotiated_msize(&self) -> u32 {
        self.negotiated_msize
    }

    /// Handles one high-level 9p request.
    #[must_use]
    pub fn handle_request(&mut self, request: NinePRequest) -> NinePResponse {
        if request.encoded_size > self.negotiated_msize {
            return ninep_error(request.tag, NINEP_EINVAL);
        }

        let result = match request.kind {
            NinePRequestKind::Version { msize, version } => self.handle_version(msize, &version),
            NinePRequestKind::Attach { fid } => self.handle_attach(fid),
            NinePRequestKind::Walk { fid, newfid, names } => self.handle_walk(fid, newfid, &names),
            NinePRequestKind::Lopen { fid } => self.handle_lopen(fid),
            NinePRequestKind::Read { fid, offset, count } => self.handle_read(fid, offset, count),
            NinePRequestKind::Readdir { fid, offset, count } => {
                self.handle_readdir(fid, offset, count)
            }
            NinePRequestKind::GetAttr { fid } => self.handle_getattr(fid),
            NinePRequestKind::ReadLink { fid } => self.handle_readlink(fid),
            NinePRequestKind::Clunk { fid } => self.handle_clunk(fid),
            NinePRequestKind::StatFs { fid } => self.handle_statfs(fid),
            NinePRequestKind::Flush => Ok(NinePResponseKind::Flush),
            NinePRequestKind::XattrWalk { fid, newfid, name } => {
                self.handle_xattrwalk(fid, newfid, &name)
            }
            NinePRequestKind::Mutating(_) => return ninep_error(request.tag, NINEP_EROFS),
            NinePRequestKind::Unknown { .. } => return ninep_error(request.tag, NINEP_ENOSYS),
            NinePRequestKind::Malformed { io_error } => {
                return ninep_error(request.tag, if io_error { NINEP_EIO } else { NINEP_EINVAL });
            }
        };

        match result {
            Ok(kind) => NinePResponse {
                tag: request.tag,
                kind,
            },
            Err(error) => ninep_error(request.tag, errno_for_error(&error)),
        }
    }

    /// Handles one raw 9P2000.L request message and returns a raw response.
    #[must_use]
    pub fn handle_wire_request(&mut self, message: &[u8]) -> Vec<u8> {
        let request = match decode_wire_request(message, self.negotiated_msize) {
            Ok(request) => request,
            Err(error) => {
                return encode_wire_response_limited(
                    &ninep_error(error.tag, error.errno),
                    self.negotiated_msize,
                );
            }
        };

        let mut trial = self.clone();
        let response = trial.handle_request(request);
        let encoded = match try_encode_wire_response_limited(&response, trial.negotiated_msize) {
            Ok(encoded) => encoded,
            Err(errno) => return encode_wire_error(response.tag, errno),
        };

        if success_wire_response_type(&response.kind).is_some() {
            *self = trial;
        }
        encoded
    }

    /// Captures the deterministic fid table and negotiated msize.
    #[must_use]
    pub fn snapshot(&self) -> NinePSessionSnapshot {
        NinePSessionSnapshot {
            negotiated_msize: self.negotiated_msize,
            fids: self
                .fids
                .iter()
                .map(|(fid, state)| NinePFidSnapshot {
                    fid: *fid,
                    path: state.target.snapshot_path(),
                    xattr_name: state.target.snapshot_xattr_name(),
                    open_kind: state.open.as_ref().map(NinePOpenHandle::kind),
                })
                .collect(),
        }
    }

    /// Restores a deterministic fid table and negotiated msize.
    ///
    /// # Errors
    ///
    /// Returns [`NinePServerError`] when the snapshot is structurally invalid,
    /// references paths absent from this served tree, or carries an impossible
    /// open kind for a restored path.
    pub fn restore_snapshot(
        &mut self,
        snapshot: NinePSessionSnapshot,
    ) -> Result<(), NinePServerError> {
        if snapshot.negotiated_msize < NINEP_MINIMUM_MSIZE
            || snapshot.negotiated_msize > self.tree.maximum_msize()
        {
            return Err(NinePServerError::InvalidMsize {
                requested: snapshot.negotiated_msize,
            });
        }

        let mut restored = BTreeMap::new();
        for fid_snapshot in snapshot.fids {
            if restored.contains_key(&fid_snapshot.fid) {
                return Err(NinePServerError::DuplicateFid {
                    fid: fid_snapshot.fid,
                });
            }
            let path = normalize_served_path(&fid_snapshot.path)?;
            let (target, open) = match fid_snapshot.xattr_name {
                Some(name) => {
                    self.tree.entry(&path)?;
                    if name.contains('\0') || name.contains('/') {
                        return Err(NinePServerError::InvalidFidSnapshot {
                            fid: fid_snapshot.fid,
                        });
                    }
                    let open = match fid_snapshot.open_kind {
                        Some(NinePEntryKind::File) => Some(NinePOpenHandle::Xattr),
                        Some(_) => {
                            return Err(NinePServerError::InvalidFidSnapshot {
                                fid: fid_snapshot.fid,
                            });
                        }
                        None => None,
                    };
                    (
                        NinePFidTarget::Xattr {
                            source_path: path,
                            name,
                        },
                        open,
                    )
                }
                None => {
                    let entry_kind = self.tree.entry_kind(&path)?;
                    let open = match fid_snapshot.open_kind {
                        Some(open_kind) if open_kind != entry_kind => {
                            return Err(NinePServerError::InvalidFidSnapshot {
                                fid: fid_snapshot.fid,
                            });
                        }
                        Some(open_kind) => Some(self.open_handle_for(&path, open_kind)?),
                        None => None,
                    };
                    (NinePFidTarget::Entry { path }, open)
                }
            };
            restored.insert(fid_snapshot.fid, NinePFidState { target, open });
        }

        self.negotiated_msize = snapshot.negotiated_msize;
        self.fids = restored;
        Ok(())
    }

    fn handle_version(
        &mut self,
        msize: u32,
        version: &str,
    ) -> Result<NinePResponseKind, NinePServerError> {
        let negotiation = self.tree.negotiate_version(version, msize)?;
        self.negotiated_msize = negotiation.msize;
        self.fids.clear();
        Ok(NinePResponseKind::Version(negotiation))
    }

    fn handle_attach(&mut self, fid: u32) -> Result<NinePResponseKind, NinePServerError> {
        if self.fids.contains_key(&fid) {
            return Err(NinePServerError::FidAlreadyExists { fid });
        }
        self.fids.insert(
            fid,
            NinePFidState {
                target: NinePFidTarget::Entry {
                    path: String::from("/"),
                },
                open: None,
            },
        );
        Ok(NinePResponseKind::Attach {
            qid: self.tree.qid("/")?,
        })
    }

    fn handle_walk(
        &mut self,
        fid: u32,
        newfid: u32,
        names: &[String],
    ) -> Result<NinePResponseKind, NinePServerError> {
        let state = self.fid(fid)?;
        if state.open.is_some() {
            return Err(NinePServerError::FidAlreadyOpen { fid });
        }
        let mut path = self.entry_path_for_fid(fid)?.to_owned();
        if newfid != fid && self.fids.contains_key(&newfid) {
            return Err(NinePServerError::FidAlreadyExists { fid: newfid });
        }
        let mut qids = Vec::with_capacity(names.len());
        for name in names {
            if name.is_empty() || name == "." || name == ".." || name.contains('/') {
                return Err(NinePServerError::InvalidPath { path: name.clone() });
            }
            if self.tree.entry_kind(&path)? != NinePEntryKind::Directory {
                return Err(NinePServerError::NotDirectory { path });
            }
            path = child_path(&path, name);
            qids.push(self.tree.qid(&path)?);
        }
        self.fids.insert(
            newfid,
            NinePFidState {
                target: NinePFidTarget::Entry { path },
                open: None,
            },
        );
        Ok(NinePResponseKind::Walk { qids })
    }

    fn handle_lopen(&mut self, fid: u32) -> Result<NinePResponseKind, NinePServerError> {
        let target = self.fid(fid)?.target.clone();
        let (open, qid) = match target {
            NinePFidTarget::Entry { path } => {
                let kind = self.tree.entry_kind(&path)?;
                (self.open_handle_for(&path, kind)?, self.tree.qid(&path)?)
            }
            NinePFidTarget::Xattr { source_path, name } => {
                (NinePOpenHandle::Xattr, xattr_qid(&source_path, &name))
            }
        };
        self.fid_mut(fid)?.open = Some(open);
        Ok(NinePResponseKind::Lopen { qid })
    }

    fn handle_read(
        &self,
        fid: u32,
        offset: u64,
        count: u32,
    ) -> Result<NinePResponseKind, NinePServerError> {
        let state = self.fid(fid)?;
        let count = count.min(self.read_payload_limit());
        match (&state.target, &state.open) {
            (NinePFidTarget::Entry { path }, Some(NinePOpenHandle::File)) => {
                Ok(NinePResponseKind::Read {
                    data: self.tree.read_file(path, offset, count)?,
                })
            }
            (NinePFidTarget::Xattr { .. }, Some(NinePOpenHandle::Xattr)) => {
                Ok(NinePResponseKind::Read {
                    data: read_slice(&[], offset, count),
                })
            }
            _ => Err(NinePServerError::NotFile {
                path: state.target.diagnostic_path(),
            }),
        }
    }

    fn handle_readdir(
        &self,
        fid: u32,
        offset: u64,
        count: u32,
    ) -> Result<NinePResponseKind, NinePServerError> {
        let state = self.fid(fid)?;
        let Some(NinePOpenHandle::Directory { entries }) = &state.open else {
            return Err(NinePServerError::NotDirectory {
                path: state.target.diagnostic_path(),
            });
        };
        let budget = count.min(self.readdir_payload_limit());
        let mut used = 0u32;
        let mut output = Vec::new();
        for entry in entries.iter().filter(|entry| entry.offset > offset) {
            let entry_size = encoded_directory_entry_size(entry);
            let Some(next_used) = used.checked_add(entry_size) else {
                break;
            };
            if next_used > budget {
                break;
            }
            used = next_used;
            output.push(entry.clone());
        }
        Ok(NinePResponseKind::Readdir { entries: output })
    }

    fn handle_getattr(&self, fid: u32) -> Result<NinePResponseKind, NinePServerError> {
        match &self.fid(fid)?.target {
            NinePFidTarget::Entry { path } => {
                Ok(NinePResponseKind::GetAttr(self.tree.getattr(path)?))
            }
            NinePFidTarget::Xattr { source_path, name } => Ok(NinePResponseKind::GetAttr(
                xattr_attributes(source_path, name),
            )),
        }
    }

    fn handle_readlink(&self, fid: u32) -> Result<NinePResponseKind, NinePServerError> {
        let path = self.entry_path_for_fid(fid)?;
        Ok(NinePResponseKind::ReadLink {
            target: self.tree.readlink(path)?,
        })
    }

    fn handle_clunk(&mut self, fid: u32) -> Result<NinePResponseKind, NinePServerError> {
        self.fids
            .remove(&fid)
            .ok_or(NinePServerError::FidNotFound { fid })?;
        Ok(NinePResponseKind::Clunk)
    }

    fn handle_statfs(&self, fid: u32) -> Result<NinePResponseKind, NinePServerError> {
        self.entry_path_for_fid(fid)?;
        Ok(NinePResponseKind::StatFs(self.tree.statfs()?))
    }

    fn handle_xattrwalk(
        &mut self,
        fid: u32,
        newfid: u32,
        name: &str,
    ) -> Result<NinePResponseKind, NinePServerError> {
        if self.fids.contains_key(&newfid) {
            return Err(NinePServerError::FidAlreadyExists { fid: newfid });
        }
        if name.contains('\0') || name.contains('/') {
            return Err(NinePServerError::InvalidPath {
                path: name.to_owned(),
            });
        }
        let source_path = self.entry_path_for_fid(fid)?.to_owned();
        self.fids.insert(
            newfid,
            NinePFidState {
                target: NinePFidTarget::Xattr {
                    source_path,
                    name: name.to_owned(),
                },
                open: None,
            },
        );
        Ok(NinePResponseKind::XattrWalk { size: 0 })
    }

    fn fid(&self, fid: u32) -> Result<&NinePFidState, NinePServerError> {
        self.fids
            .get(&fid)
            .ok_or(NinePServerError::FidNotFound { fid })
    }

    fn fid_mut(&mut self, fid: u32) -> Result<&mut NinePFidState, NinePServerError> {
        self.fids
            .get_mut(&fid)
            .ok_or(NinePServerError::FidNotFound { fid })
    }

    fn entry_path_for_fid(&self, fid: u32) -> Result<&str, NinePServerError> {
        match &self.fid(fid)?.target {
            NinePFidTarget::Entry { path } => Ok(path),
            NinePFidTarget::Xattr { .. } => Err(NinePServerError::FidNotEntry { fid }),
        }
    }

    fn open_handle_for(
        &self,
        path: &str,
        kind: NinePEntryKind,
    ) -> Result<NinePOpenHandle, NinePServerError> {
        match kind {
            NinePEntryKind::Directory => Ok(NinePOpenHandle::Directory {
                entries: self.tree.readdir(path)?,
            }),
            NinePEntryKind::File => Ok(NinePOpenHandle::File),
            NinePEntryKind::Symlink => Ok(NinePOpenHandle::Symlink),
        }
    }

    fn read_payload_limit(&self) -> u32 {
        self.negotiated_msize
            .saturating_sub(NINEP_READ_RESPONSE_OVERHEAD)
    }

    fn readdir_payload_limit(&self) -> u32 {
        self.negotiated_msize
            .saturating_sub(NINEP_READDIR_RESPONSE_OVERHEAD)
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
    /// A requested path is not a regular file.
    NotFile {
        /// Non-file path.
        path: String,
    },
    /// A requested path is not a symbolic link.
    NotSymlink {
        /// Non-symlink path.
        path: String,
    },
    /// A fid was not present in the deterministic fid table.
    FidNotFound {
        /// Missing fid.
        fid: u32,
    },
    /// A fid already existed in the deterministic fid table.
    FidAlreadyExists {
        /// Duplicate fid.
        fid: u32,
    },
    /// A fid was already opened and cannot be walked.
    FidAlreadyOpen {
        /// Open fid.
        fid: u32,
    },
    /// A fid does not name a served-tree entry.
    FidNotEntry {
        /// Non-entry fid.
        fid: u32,
    },
    /// A session snapshot repeated a fid.
    DuplicateFid {
        /// Duplicate fid.
        fid: u32,
    },
    /// A session snapshot carried an impossible fid/open-state pairing.
    InvalidFidSnapshot {
        /// Invalid fid.
        fid: u32,
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
            Self::NotFile { path } => write!(formatter, "9p served path `{path}` is not a file"),
            Self::NotSymlink { path } => {
                write!(formatter, "9p served path `{path}` is not a symlink")
            }
            Self::FidNotFound { fid } => write!(formatter, "9p fid {fid} was not found"),
            Self::FidAlreadyExists { fid } => write!(formatter, "9p fid {fid} already exists"),
            Self::FidAlreadyOpen { fid } => write!(formatter, "9p fid {fid} is already open"),
            Self::FidNotEntry { fid } => {
                write!(formatter, "9p fid {fid} does not name a served-tree entry")
            }
            Self::DuplicateFid { fid } => write!(formatter, "9p snapshot repeats fid {fid}"),
            Self::InvalidFidSnapshot { fid } => {
                write!(
                    formatter,
                    "9p snapshot has invalid open state for fid {fid}"
                )
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
    match path.rsplit('/').next() {
        Some(name) => name.to_owned(),
        None => path.to_owned(),
    }
}

fn child_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn read_slice(bytes: &[u8], offset: u64, count: u32) -> Vec<u8> {
    let Ok(start) = usize::try_from(offset) else {
        return Vec::new();
    };
    if start >= bytes.len() {
        return Vec::new();
    }
    let count = match usize::try_from(count) {
        Ok(count) => count,
        Err(_) => usize::MAX,
    };
    let end = start.saturating_add(count).min(bytes.len());
    bytes[start..end].to_vec()
}

struct NinePWireDecodeError {
    tag: u16,
    errno: u32,
}

struct NinePWireCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    tag: u16,
}

impl<'a> NinePWireCursor<'a> {
    fn new(bytes: &'a [u8], tag: u16) -> Self {
        Self {
            bytes,
            offset: 0,
            tag,
        }
    }

    fn read_u16(&mut self) -> Result<u16, NinePWireDecodeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, NinePWireDecodeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, NinePWireDecodeError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string(&mut self) -> Result<String, NinePWireDecodeError> {
        let length = usize::from(self.read_u16()?);
        let bytes = self.take(length)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| wire_decode_error(self.tag, NINEP_EINVAL))
    }

    fn finish(&self) -> Result<(), NinePWireDecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(wire_decode_error(self.tag, NINEP_EINVAL))
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], NinePWireDecodeError> {
        let Some(end) = self.offset.checked_add(length) else {
            return Err(wire_decode_error(self.tag, NINEP_EINVAL));
        };
        if end > self.bytes.len() {
            return Err(wire_decode_error(self.tag, NINEP_EINVAL));
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
}

fn decode_wire_request(
    message: &[u8],
    negotiated_msize: u32,
) -> Result<NinePRequest, NinePWireDecodeError> {
    if message.len() < NINEP_HEADER_SIZE as usize {
        return Err(wire_decode_error(NINEP_NOTAG, NINEP_EINVAL));
    }

    let declared_size = u32::from_le_bytes([message[0], message[1], message[2], message[3]]);
    let message_type = message[4];
    let tag = u16::from_le_bytes([message[5], message[6]]);
    let actual_size = match u32::try_from(message.len()) {
        Ok(actual_size) => actual_size,
        Err(_) => return Err(wire_decode_error(tag, NINEP_EINVAL)),
    };
    if declared_size != actual_size {
        return Err(wire_decode_error(tag, NINEP_EINVAL));
    }
    if declared_size > negotiated_msize {
        return Err(wire_decode_error(tag, NINEP_EINVAL));
    }

    let mut cursor = NinePWireCursor::new(&message[NINEP_HEADER_SIZE as usize..], tag);
    let kind = match message_type {
        NINEP_TVERSION => {
            if tag != NINEP_NOTAG {
                return Err(wire_decode_error(tag, NINEP_EINVAL));
            }
            let msize = cursor.read_u32()?;
            let version = cursor.read_string()?;
            cursor.finish()?;
            NinePRequestKind::Version { msize, version }
        }
        NINEP_TATTACH => {
            let fid = cursor.read_u32()?;
            let _afid = cursor.read_u32()?;
            let _uname = cursor.read_string()?;
            let _aname = cursor.read_string()?;
            let _n_uname = cursor.read_u32()?;
            cursor.finish()?;
            NinePRequestKind::Attach { fid }
        }
        NINEP_TWALK => {
            let fid = cursor.read_u32()?;
            let newfid = cursor.read_u32()?;
            let name_count = cursor.read_u16()?;
            let mut names = Vec::with_capacity(usize::from(name_count));
            for _ in 0..name_count {
                names.push(cursor.read_string()?);
            }
            cursor.finish()?;
            NinePRequestKind::Walk { fid, newfid, names }
        }
        NINEP_TLOPEN => {
            let fid = cursor.read_u32()?;
            let flags = cursor.read_u32()?;
            cursor.finish()?;
            if open_flags_request_write(flags) {
                return Ok(NinePRequest::new(
                    tag,
                    NinePRequestKind::Mutating(NinePMutatingMessage::Write),
                )
                .with_encoded_size(declared_size));
            }
            NinePRequestKind::Lopen { fid }
        }
        NINEP_TREAD => {
            let fid = cursor.read_u32()?;
            let offset = cursor.read_u64()?;
            let count = cursor.read_u32()?;
            cursor.finish()?;
            NinePRequestKind::Read { fid, offset, count }
        }
        NINEP_TREADDIR => {
            let fid = cursor.read_u32()?;
            let offset = cursor.read_u64()?;
            let count = cursor.read_u32()?;
            cursor.finish()?;
            NinePRequestKind::Readdir { fid, offset, count }
        }
        NINEP_TGETATTR => {
            let fid = cursor.read_u32()?;
            let _request_mask = cursor.read_u64()?;
            cursor.finish()?;
            NinePRequestKind::GetAttr { fid }
        }
        NINEP_TREADLINK => {
            let fid = cursor.read_u32()?;
            cursor.finish()?;
            NinePRequestKind::ReadLink { fid }
        }
        NINEP_TCLUNK => {
            let fid = cursor.read_u32()?;
            cursor.finish()?;
            NinePRequestKind::Clunk { fid }
        }
        NINEP_TSTATFS => {
            let fid = cursor.read_u32()?;
            cursor.finish()?;
            NinePRequestKind::StatFs { fid }
        }
        NINEP_TFLUSH => {
            let _oldtag = cursor.read_u16()?;
            cursor.finish()?;
            NinePRequestKind::Flush
        }
        NINEP_TXATTRWALK => {
            let fid = cursor.read_u32()?;
            let newfid = cursor.read_u32()?;
            let name = cursor.read_string()?;
            cursor.finish()?;
            NinePRequestKind::XattrWalk { fid, newfid, name }
        }
        NINEP_TLCREATE => NinePRequestKind::Mutating(NinePMutatingMessage::Lcreate),
        NINEP_TWRITE => NinePRequestKind::Mutating(NinePMutatingMessage::Write),
        NINEP_TMKDIR => NinePRequestKind::Mutating(NinePMutatingMessage::Mkdir),
        NINEP_TUNLINKAT => NinePRequestKind::Mutating(NinePMutatingMessage::Unlinkat),
        NINEP_TRENAMEAT => NinePRequestKind::Mutating(NinePMutatingMessage::Renameat),
        NINEP_TSETATTR => NinePRequestKind::Mutating(NinePMutatingMessage::Setattr),
        unknown => NinePRequestKind::Unknown {
            message_type: unknown,
        },
    };

    Ok(NinePRequest::new(tag, kind).with_encoded_size(declared_size))
}

fn wire_decode_error(tag: u16, errno: u32) -> NinePWireDecodeError {
    NinePWireDecodeError { tag, errno }
}

fn encode_wire_response_limited(response: &NinePResponse, negotiated_msize: u32) -> Vec<u8> {
    match try_encode_wire_response_limited(response, negotiated_msize) {
        Ok(encoded) => encoded,
        Err(errno) => encode_wire_error(response.tag, errno),
    }
}

fn try_encode_wire_response_limited(
    response: &NinePResponse,
    negotiated_msize: u32,
) -> Result<Vec<u8>, u32> {
    let encoded = encode_wire_response(response);
    if let Some(message_type) = success_wire_response_type(&response.kind) {
        if encoded.get(4).copied() != Some(message_type) {
            return Err(NINEP_EIO);
        }
    }
    if encoded.len() <= capacity_for_u32(negotiated_msize) {
        Ok(encoded)
    } else {
        Err(NINEP_EINVAL)
    }
}

fn success_wire_response_type(kind: &NinePResponseKind) -> Option<u8> {
    Some(match kind {
        NinePResponseKind::Version(_) => NINEP_RVERSION,
        NinePResponseKind::Attach { .. } => NINEP_RATTACH,
        NinePResponseKind::Walk { .. } => NINEP_RWALK,
        NinePResponseKind::Lopen { .. } => NINEP_RLOPEN,
        NinePResponseKind::Read { .. } => NINEP_RREAD,
        NinePResponseKind::Readdir { .. } => NINEP_RREADDIR,
        NinePResponseKind::GetAttr(_) => NINEP_RGETATTR,
        NinePResponseKind::ReadLink { .. } => NINEP_RREADLINK,
        NinePResponseKind::Clunk => NINEP_RCLUNK,
        NinePResponseKind::StatFs(_) => NINEP_RSTATFS,
        NinePResponseKind::Flush => NINEP_RFLUSH,
        NinePResponseKind::XattrWalk { .. } => NINEP_RXATTRWALK,
        NinePResponseKind::Error { .. } => return None,
    })
}

fn encode_wire_response(response: &NinePResponse) -> Vec<u8> {
    match &response.kind {
        NinePResponseKind::Version(version) => {
            let mut body = Vec::new();
            append_wire_u32(&mut body, version.msize);
            if append_wire_string(&mut body, &version.version).is_err() {
                return encode_wire_error(response.tag, NINEP_EIO);
            }
            wire_message(NINEP_RVERSION, response.tag, body)
        }
        NinePResponseKind::Attach { qid } => {
            let mut body = Vec::new();
            append_wire_qid(&mut body, qid);
            wire_message(NINEP_RATTACH, response.tag, body)
        }
        NinePResponseKind::Walk { qids } => {
            let mut body = Vec::new();
            append_wire_u16(&mut body, saturating_u16(qids.len()));
            for qid in qids {
                append_wire_qid(&mut body, qid);
            }
            wire_message(NINEP_RWALK, response.tag, body)
        }
        NinePResponseKind::Lopen { qid } => {
            let mut body = Vec::new();
            append_wire_qid(&mut body, qid);
            append_wire_u32(&mut body, 0);
            wire_message(NINEP_RLOPEN, response.tag, body)
        }
        NinePResponseKind::Read { data } => {
            let mut body = Vec::new();
            append_wire_u32(&mut body, saturating_u32(data.len()));
            body.extend_from_slice(data);
            wire_message(NINEP_RREAD, response.tag, body)
        }
        NinePResponseKind::Readdir { entries } => {
            let mut entries_body = Vec::new();
            for entry in entries {
                append_wire_qid(&mut entries_body, &entry.qid);
                append_wire_u64(&mut entries_body, entry.offset);
                entries_body.push(directory_entry_type(entry.qid.qtype));
                if append_wire_string(&mut entries_body, &entry.name).is_err() {
                    return encode_wire_error(response.tag, NINEP_EIO);
                }
            }
            let mut body = Vec::new();
            append_wire_u32(&mut body, saturating_u32(entries_body.len()));
            body.extend_from_slice(&entries_body);
            wire_message(NINEP_RREADDIR, response.tag, body)
        }
        NinePResponseKind::GetAttr(attrs) => {
            let mut body = Vec::new();
            append_wire_u64(&mut body, NINEP_GETATTR_VALID_MASK);
            append_wire_qid(&mut body, &attrs.qid);
            append_wire_u32(&mut body, attrs.mode);
            append_wire_u32(&mut body, attrs.uid);
            append_wire_u32(&mut body, attrs.gid);
            append_wire_u64(&mut body, 1);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, attrs.size);
            append_wire_u64(&mut body, attrs.block_size);
            append_wire_u64(&mut body, attrs.blocks);
            append_wire_u64(&mut body, attrs.atime_sec);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, attrs.mtime_sec);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, attrs.ctime_sec);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, 0);
            wire_message(NINEP_RGETATTR, response.tag, body)
        }
        NinePResponseKind::ReadLink { target } => {
            let mut body = Vec::new();
            if append_wire_string(&mut body, target).is_err() {
                return encode_wire_error(response.tag, NINEP_EIO);
            }
            wire_message(NINEP_RREADLINK, response.tag, body)
        }
        NinePResponseKind::Clunk => wire_message(NINEP_RCLUNK, response.tag, Vec::new()),
        NinePResponseKind::StatFs(statfs) => {
            let mut body = Vec::new();
            append_wire_u32(&mut body, NINEP_STATFS_MAGIC);
            append_wire_u32(&mut body, saturating_u32_from_u64(statfs.block_size));
            append_wire_u64(&mut body, statfs.blocks);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, statfs.files);
            append_wire_u64(&mut body, 0);
            append_wire_u64(&mut body, statfs.fsid);
            append_wire_u32(&mut body, statfs.name_max);
            wire_message(NINEP_RSTATFS, response.tag, body)
        }
        NinePResponseKind::Flush => wire_message(NINEP_RFLUSH, response.tag, Vec::new()),
        NinePResponseKind::XattrWalk { size } => {
            let mut body = Vec::new();
            append_wire_u64(&mut body, *size);
            wire_message(NINEP_RXATTRWALK, response.tag, body)
        }
        NinePResponseKind::Error { errno } => encode_wire_error(response.tag, *errno),
    }
}

fn wire_message(message_type: u8, tag: u16, body: Vec<u8>) -> Vec<u8> {
    let body_len = match u32::try_from(body.len()) {
        Ok(body_len) => body_len,
        Err(_) => return encode_wire_error(tag, NINEP_EIO),
    };
    let Some(size) = NINEP_HEADER_SIZE.checked_add(body_len) else {
        return encode_wire_error(tag, NINEP_EIO);
    };
    let mut message = Vec::with_capacity(capacity_for_u32(size));
    append_wire_u32(&mut message, size);
    message.push(message_type);
    append_wire_u16(&mut message, tag);
    message.extend_from_slice(&body);
    message
}

fn encode_wire_error(tag: u16, errno: u32) -> Vec<u8> {
    let mut message = Vec::with_capacity(capacity_for_u32(NINEP_READ_RESPONSE_OVERHEAD));
    append_wire_u32(&mut message, NINEP_READ_RESPONSE_OVERHEAD);
    message.push(NINEP_RLERROR);
    append_wire_u16(&mut message, tag);
    append_wire_u32(&mut message, errno);
    message
}

fn append_wire_qid(bytes: &mut Vec<u8>, qid: &NinePQid) {
    bytes.push(qid.qtype);
    append_wire_u32(bytes, qid.version);
    append_wire_u64(bytes, qid.path);
}

fn append_wire_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ()> {
    let length = match u16::try_from(value.len()) {
        Ok(length) => length,
        Err(_) => return Err(()),
    };
    append_wire_u16(bytes, length);
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_wire_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_wire_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_wire_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn saturating_u16(value: usize) -> u16 {
    match u16::try_from(value) {
        Ok(value) => value,
        Err(_) => u16::MAX,
    }
}

fn saturating_u32(value: usize) -> u32 {
    match u32::try_from(value) {
        Ok(value) => value,
        Err(_) => u32::MAX,
    }
}

fn saturating_u32_from_u64(value: u64) -> u32 {
    match u32::try_from(value) {
        Ok(value) => value,
        Err(_) => u32::MAX,
    }
}

fn directory_entry_type(qid_type: u8) -> u8 {
    match qid_type {
        NINEP_QID_TYPE_DIRECTORY => NINEP_DT_DIR,
        NINEP_QID_TYPE_FILE => NINEP_DT_REG,
        NINEP_QID_TYPE_SYMLINK => NINEP_DT_LNK,
        _ => NINEP_DT_UNKNOWN,
    }
}

fn open_flags_request_write(flags: u32) -> bool {
    matches!(
        flags & NINEP_OPEN_ACCMODE,
        NINEP_OPEN_WRONLY | NINEP_OPEN_RDWR
    ) || flags & (NINEP_OPEN_TRUNC | NINEP_OPEN_APPEND) != 0
}

fn capacity_for_u32(value: u32) -> usize {
    match usize::try_from(value) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}

fn encoded_request_size(kind: &NinePRequestKind) -> u32 {
    match kind {
        NinePRequestKind::Version { version, .. } => NINEP_HEADER_SIZE
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(encoded_string_size(version)),
        NinePRequestKind::Attach { .. } => NINEP_HEADER_SIZE
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(encoded_string_size(""))
            .saturating_add(encoded_string_size(""))
            .saturating_add(NINEP_U32_SIZE),
        NinePRequestKind::Walk { names, .. } => NINEP_HEADER_SIZE
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(NINEP_U16_SIZE)
            .saturating_add(encoded_string_list_size(names)),
        NinePRequestKind::Lopen { .. } => NINEP_HEADER_SIZE
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(NINEP_U32_SIZE),
        NinePRequestKind::Read { .. } | NinePRequestKind::Readdir { .. } => NINEP_HEADER_SIZE
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(NINEP_U64_SIZE)
            .saturating_add(NINEP_U32_SIZE),
        NinePRequestKind::GetAttr { .. } => NINEP_HEADER_SIZE
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(NINEP_U64_SIZE),
        NinePRequestKind::ReadLink { .. }
        | NinePRequestKind::Clunk { .. }
        | NinePRequestKind::StatFs { .. } => NINEP_HEADER_SIZE.saturating_add(NINEP_U32_SIZE),
        NinePRequestKind::Flush => NINEP_HEADER_SIZE.saturating_add(NINEP_U16_SIZE),
        NinePRequestKind::XattrWalk { name, .. } => NINEP_HEADER_SIZE
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(NINEP_U32_SIZE)
            .saturating_add(encoded_string_size(name)),
        NinePRequestKind::Mutating(_)
        | NinePRequestKind::Unknown { .. }
        | NinePRequestKind::Malformed { .. } => NINEP_HEADER_SIZE,
    }
}

fn encoded_string_list_size(values: &[String]) -> u32 {
    values.iter().fold(0u32, |total, value| {
        total.saturating_add(encoded_string_size(value))
    })
}

fn encoded_string_size(value: &str) -> u32 {
    let byte_len = match u32::try_from(value.len()) {
        Ok(byte_len) => byte_len,
        Err(_) => u32::MAX,
    };
    NINEP_U16_SIZE.saturating_add(byte_len)
}

fn encoded_directory_entry_size(entry: &NinePDirectoryEntry) -> u32 {
    NINEP_DIRECTORY_ENTRY_BASE_SIZE.saturating_add(match u32::try_from(entry.name.len()) {
        Ok(byte_len) => byte_len,
        Err(_) => u32::MAX,
    })
}

fn xattr_qid(source_path: &str, name: &str) -> NinePQid {
    NinePQid {
        qtype: NinePEntryKind::File.qid_type(),
        version: NINEP_FIXED_QID_VERSION,
        path: xattr_qid_path_hash(source_path, name),
    }
}

fn xattr_attributes(source_path: &str, name: &str) -> NinePAttributes {
    NinePAttributes {
        qid: xattr_qid(source_path, name),
        mode: NinePEntryKind::File.mode_type() | 0o444,
        uid: NINEP_FIXED_UID,
        gid: NINEP_FIXED_GID,
        size: 0,
        block_size: NINEP_FIXED_BLOCK_SIZE,
        blocks: 0,
        atime_sec: NINEP_FIXED_EPOCH_SECONDS,
        mtime_sec: NINEP_FIXED_EPOCH_SECONDS,
        ctime_sec: NINEP_FIXED_EPOCH_SECONDS,
    }
}

fn ninep_error(tag: u16, errno: u32) -> NinePResponse {
    NinePResponse {
        tag,
        kind: NinePResponseKind::Error { errno },
    }
}

fn errno_for_error(error: &NinePServerError) -> u32 {
    match error {
        NinePServerError::UnsupportedVersion { .. }
        | NinePServerError::InvalidMsize { .. }
        | NinePServerError::InvalidPath { .. }
        | NinePServerError::DuplicatePath { .. }
        | NinePServerError::RootMustBeDirectory
        | NinePServerError::MissingParent { .. }
        | NinePServerError::ParentNotDirectory { .. }
        | NinePServerError::NotFound { .. }
        | NinePServerError::NotDirectory { .. }
        | NinePServerError::NotFile { .. }
        | NinePServerError::NotSymlink { .. }
        | NinePServerError::FidNotFound { .. }
        | NinePServerError::FidAlreadyExists { .. }
        | NinePServerError::FidAlreadyOpen { .. }
        | NinePServerError::FidNotEntry { .. }
        | NinePServerError::DuplicateFid { .. }
        | NinePServerError::InvalidFidSnapshot { .. }
        | NinePServerError::DirectoryTooLarge { .. } => NINEP_EINVAL,
        NinePServerError::ContentTooLarge { .. } | NinePServerError::ContentSizeOverflow => {
            NINEP_EIO
        }
    }
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

fn xattr_qid_path_hash(source_path: &str, name: &str) -> u64 {
    let material = format!("{source_path}\0{name}");
    let hash = ContentHash::from_canonical_material(NINEP_XATTR_QID_PATH_DOMAIN, &material);
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
