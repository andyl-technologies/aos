//! The deterministic in-memory filesystem tree the 9p server exports.
//!
//! This module owns [`FsTree`], a read-only, content-addressed directory tree
//! whose every observable value is a pure function of the served content and the
//! requested path — never the host filesystem ([IO-13]). The three sources of
//! host-filesystem nondeterminism the RFC names are eliminated here:
//!
//! 1. **Path-hashed QIDs.** A node's QID `path` is [`qid_path`] — a stable
//!    BLAKE3-derived hash of the node's canonical path within the tree, never a
//!    host inode. The QID `version` is the fixed [`Qid::FIXED_VERSION`].
//! 2. **Sorted enumeration.** A directory's children are stored in a
//!    [`BTreeMap`], so [`FsTree::children`] yields them in lexicographic name
//!    order with no host readdir dependence ([IO-14]).
//! 3. **Fixed/derived attributes.** [`FsTree::getattr`] returns a fixed epoch for
//!    all timestamps, root ownership, a fixed block size, and a block count
//!    derived from the file size; [`FsTree::statfs`] is a fixed synthetic
//!    snapshot ([IO-15]).
//!
//! ```text
//!   qid.path    = blake3_64("/" + canonical path within served tree)   // NOT host inode
//!   qid.version = 1                                                     // fixed
//!   qid.type    = {dir | symlink | file} from the node's content
//!   children    = BTreeMap entries (lexicographic by name)             // sorted
//!   getattr     = { mode from content; uid=gid=0; *time = 0;
//!                   blksize = 4096; blocks = ceil(size/512) }
//! ```

use std::collections::BTreeMap;

use super::codec::{GetattrReply, Qid, QidType, StatfsReply};

/// The fixed preferred block size reported by `getattr`/`statfs` ([IO-15]).
pub const BLOCK_SIZE: u64 = 4096;

/// The fixed 512-byte unit `blocks` is counted in (the POSIX `st_blocks` unit).
pub const STAT_BLOCK_UNIT: u64 = 512;

/// The synthetic filesystem-type magic reported by `statfs` ([IO-15]).
///
/// A fixed value (ASCII `"9PFS"` little-endian) so `statfs` never leaks the
/// host's real filesystem identity.
pub const STATFS_MAGIC: u32 = 0x5346_5039;

/// The fixed maximum filename length reported by `statfs`.
pub const STATFS_NAMELEN: u32 = 255;

/// The POSIX `S_IFMT` mode bits for a directory.
const S_IFDIR: u32 = 0o040000;
/// The POSIX `S_IFMT` mode bits for a regular file.
const S_IFREG: u32 = 0o100000;
/// The POSIX `S_IFMT` mode bits for a symbolic link.
const S_IFLNK: u32 = 0o120000;
/// The fixed permission bits applied to every node (read + traverse, no write).
const FIXED_PERMS: u32 = 0o555;

/// A node in the served tree: a directory, a regular file, or a symlink.
///
/// All content is owned in memory and never mutated after construction ([IO-13],
/// read-only export). Directory children are a [`BTreeMap`] so enumeration is
/// lexicographically sorted by construction ([IO-14]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// A directory holding named children in sorted order.
    Directory {
        /// The children, keyed by name; iteration is lexicographic ([IO-14]).
        children: BTreeMap<String, Node>,
    },
    /// A regular file holding its full content bytes.
    File {
        /// The file's content; its length is the reported size ([IO-15]).
        content: Vec<u8>,
    },
    /// A symbolic link holding its target path string.
    Symlink {
        /// The link target as returned by `readlink`.
        target: String,
    },
}

impl Node {
    /// Returns the QID kind for this node's content.
    #[must_use]
    pub fn qid_type(&self) -> QidType {
        match self {
            Node::Directory { .. } => QidType::Dir,
            Node::File { .. } => QidType::File,
            Node::Symlink { .. } => QidType::Symlink,
        }
    }

    /// Returns the content-derived size in bytes ([IO-15]).
    ///
    /// A file reports its content length; a symlink reports its target length; a
    /// directory reports the fixed [`BLOCK_SIZE`] (a conventional, host-
    /// independent placeholder, never a host-observed size).
    #[must_use]
    pub fn size(&self) -> u64 {
        match self {
            Node::Directory { .. } => BLOCK_SIZE,
            Node::File { content } => content.len() as u64,
            Node::Symlink { target } => target.len() as u64,
        }
    }

    /// Returns the POSIX mode (kind bits + fixed read/traverse permissions).
    #[must_use]
    pub fn mode(&self) -> u32 {
        let kind = match self {
            Node::Directory { .. } => S_IFDIR,
            Node::File { .. } => S_IFREG,
            Node::Symlink { .. } => S_IFLNK,
        };
        kind | FIXED_PERMS
    }

    /// Returns the directory `d_type` byte for a `readdir` entry naming this node.
    ///
    /// Follows the Linux `DT_*` convention: `DT_DIR=4`, `DT_REG=8`, `DT_LNK=10`.
    #[must_use]
    pub fn dirent_type(&self) -> u8 {
        match self {
            Node::Directory { .. } => 4,
            Node::File { .. } => 8,
            Node::Symlink { .. } => 10,
        }
    }
}

/// The read-only filesystem tree served over 9P2000.L ([IO-13]).
///
/// Holds the root [`Node`] and exposes deterministic lookups: path resolution,
/// sorted child enumeration, content-derived attributes, and synthetic statfs.
/// The tree is immutable after construction; every method is a pure function of
/// the content and the requested path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsTree {
    root: Node,
}

impl FsTree {
    /// Builds a tree from a root directory node without validating components.
    ///
    /// This trusts that every child name in `root` is a legal path component
    /// (see [`validate_component`]). Prefer [`FsTree::try_new`] for any tree built
    /// from untrusted input; `new` exists for the common case of a tree assembled
    /// in-process from known-good names. An illegal component does not break
    /// memory safety — it only risks a QID-space ambiguity the guest could
    /// observe — and the server's walk decode independently rejects illegal
    /// components from the wire ([IO-13]).
    #[must_use]
    pub fn new(root: Node) -> Self {
        Self { root }
    }

    /// Builds a tree, rejecting any illegal path component anywhere in it.
    ///
    /// Recursively validates every directory child name via
    /// [`validate_component`], so the resulting tree's path-to-QID map is provably
    /// unambiguous ([IO-13]). Use this for any tree assembled from untrusted
    /// metadata.
    ///
    /// # Errors
    ///
    /// Returns [`BadComponent`] for the first child name that is empty, contains
    /// `/`, or contains a NUL byte.
    pub fn try_new(root: Node) -> Result<Self, BadComponent> {
        validate_node(&root)?;
        Ok(Self { root })
    }

    /// Returns the root node.
    #[must_use]
    pub fn root(&self) -> &Node {
        &self.root
    }

    /// Resolves a slash-joined path to its node, or `None` when absent.
    ///
    /// `path` is the canonical path *within the served tree* (no leading slash;
    /// the empty path is the root). Resolution walks the [`BTreeMap`] children by
    /// name, so it never consults host directory order.
    #[must_use]
    pub fn resolve(&self, path: &[String]) -> Option<&Node> {
        let mut node = &self.root;
        for component in path {
            match node {
                Node::Directory { children } => {
                    node = children.get(component)?;
                }
                // A non-directory cannot be walked into.
                _ => return None,
            }
        }
        Some(node)
    }

    /// Returns the QID for the node at `path`, or `None` when absent.
    #[must_use]
    pub fn qid(&self, path: &[String]) -> Option<Qid> {
        let node = self.resolve(path)?;
        Some(Qid::new(node.qid_type(), qid_path(path)))
    }

    /// Returns the sorted children of the directory at `path`.
    ///
    /// Each entry is `(name, qid, dirent_type)` in lexicographic name order
    /// ([IO-14]). Returns `None` when `path` is absent or is not a directory.
    /// Offsets are assigned by the caller *after* this sorted order, never from a
    /// host readdir cursor.
    #[must_use]
    pub fn children(&self, path: &[String]) -> Option<Vec<DirEntry>> {
        match self.resolve(path)? {
            Node::Directory { children } => {
                let mut out = Vec::with_capacity(children.len());
                for (name, child) in children {
                    // The child's canonical path is the parent path plus its name.
                    let mut child_path = path.to_vec();
                    child_path.push(name.clone());
                    out.push(DirEntry {
                        name: name.clone(),
                        qid: Qid::new(child.qid_type(), qid_path(&child_path)),
                        dtype: child.dirent_type(),
                    });
                }
                Some(out)
            }
            _ => None,
        }
    }

    /// Returns the fixed/content-derived attributes for the node at `path`.
    ///
    /// Timestamps are a fixed epoch, ownership is root, the block size is fixed,
    /// and the block count is `ceil(size / 512)` — never host metadata ([IO-15]).
    /// The `request_mask` is echoed as the valid mask.
    #[must_use]
    pub fn getattr(&self, path: &[String], request_mask: u64) -> Option<GetattrReply> {
        let node = self.resolve(path)?;
        let size = node.size();
        let blocks = size.div_ceil(STAT_BLOCK_UNIT);
        Some(GetattrReply {
            valid: request_mask,
            qid: Qid::new(node.qid_type(), qid_path(path)),
            mode: node.mode(),
            uid: 0,
            gid: 0,
            nlink: 1,
            rdev: 0,
            size,
            blksize: BLOCK_SIZE,
            blocks,
        })
    }

    /// Returns the synthetic, host-independent filesystem statistics ([IO-15]).
    ///
    /// Every field is a fixed constant; usage counters are zero (a read-only
    /// export has no free space and reports none), so `statfs` reveals nothing
    /// about the host's real device accounting.
    #[must_use]
    pub fn statfs(&self) -> StatfsReply {
        StatfsReply {
            fs_type: STATFS_MAGIC,
            bsize: BLOCK_SIZE as u32,
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            fsid: 0,
            namelen: STATFS_NAMELEN,
        }
    }
}

/// A single sorted directory entry from [`FsTree::children`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry name (the [`BTreeMap`] key, lexicographically ordered).
    pub name: String,
    /// The entry's path-hashed QID.
    pub qid: Qid,
    /// The Linux `DT_*` directory-entry type byte.
    pub dtype: u8,
}

/// Computes the stable QID `path` hash for a canonical path within the tree.
///
/// The hash is the low 64 bits of BLAKE3 over an **unambiguous, length-prefixed**
/// encoding of the component vector: the component count as a little-endian `u64`,
/// then for each component its byte length as a little-endian `u64` followed by
/// its raw bytes. Because every component is length-delimited, no two distinct
/// component vectors can produce the same byte stream — unlike a `/`-joined string
/// where `["a", "b"]` and `["a/b"]` (or `[]` and `[""]`) would collide. The hash
/// depends only on the structured path — never on a host inode number, mount, or
/// allocation order — so the identifiers a guest caches are identical across runs
/// and hosts ([IO-13]).
///
/// This is injective over component vectors whose components contain no embedded
/// length ambiguity; combined with [`validate_component`] (which rejects empty,
/// `/`-bearing, and NUL-bearing components at tree construction and walk decode),
/// the QID space served to a guest is collision-free.
///
/// # Examples
///
/// ```no_run
/// use crucible_device::ninep::tree::qid_path;
/// // The root and a child hash to distinct, stable values, and the length
/// // prefixing makes the encoding injective: these never collide.
/// let nested = qid_path(&["a".to_string(), "b".to_string()]);
/// let joined = qid_path(&["a/b".to_string()]);
/// assert_ne!(nested, joined);
/// let root = qid_path(&[]);
/// let empty_child = qid_path(&[String::new()]);
/// assert_ne!(root, empty_child);
/// ```
#[must_use]
pub fn qid_path(path: &[String]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    // Domain-separate by the component count, then length-prefix each component,
    // so the encoded byte stream is an injective function of the vector.
    hasher.update(&(path.len() as u64).to_le_bytes());
    for component in path {
        hasher.update(&(component.len() as u64).to_le_bytes());
        hasher.update(component.as_bytes());
    }
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    // The low 8 bytes, little-endian: a stable, content-derived 64-bit id.
    let mut le = [0u8; 8];
    le.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(le)
}

/// Validates a single path component for the served tree ([IO-13]).
///
/// A legal component is non-empty and contains neither a `/` (which would make
/// the component span a directory boundary) nor a NUL byte (which a guest cannot
/// represent in a path). Rejecting these at tree construction and at walk decode
/// keeps the path-to-QID map unambiguous and the export boundary intact.
///
/// # Errors
///
/// Returns [`BadComponent`] when `name` is empty, contains `/`, or contains a NUL.
pub fn validate_component(name: &str) -> Result<(), BadComponent> {
    if name.is_empty() {
        return Err(BadComponent::Empty);
    }
    if name.contains('/') {
        return Err(BadComponent::Slash {
            name: name.to_string(),
        });
    }
    if name.contains('\0') {
        return Err(BadComponent::Nul {
            name: name.to_string(),
        });
    }
    Ok(())
}

/// Recursively validates every directory child name in `node` ([IO-13]).
///
/// # Errors
///
/// Returns the first [`BadComponent`] encountered in a depth-first walk.
fn validate_node(node: &Node) -> Result<(), BadComponent> {
    if let Node::Directory { children } = node {
        for (name, child) in children {
            validate_component(name)?;
            validate_node(child)?;
        }
    }
    Ok(())
}

/// An illegal path component rejected by [`validate_component`] ([IO-13]).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BadComponent {
    /// The component was the empty string.
    #[error("path component must not be empty")]
    Empty,
    /// The component contained a `/` directory separator.
    #[error("path component {name:?} must not contain '/'")]
    Slash {
        /// The offending component.
        name: String,
    },
    /// The component contained a NUL byte.
    #[error("path component {name:?} must not contain a NUL byte")]
    Nul {
        /// The offending component.
        name: String,
    },
}
