//! The deterministic in-memory filesystem tree the 9p server exports.
//!
//! This module owns [`FsTree`], a read-only, content-addressed directory tree
//! whose every observable value is a pure function of the served content and the
//! requested path — never the host filesystem ([IO-13]). The three sources of
//! host-filesystem nondeterminism the RFC names are eliminated here:
//!
//! 1. **Path-hashed QIDs.** A node's QID `path` is [`qid_path`] — a stable,
//!    collision-resistant BLAKE3-derived identifier for the node's canonical
//!    path within the tree, never a host inode. The QID `version` is the fixed
//!    [`Qid::FIXED_VERSION`].
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
//!
//! The immutable artifact encoding used by [`FsTree::canonical_bytes`] and
//! [`FsTree::from_canonical_bytes`] is:
//!
//! ```text
//! magic = "crucible.device.ninep.fs-tree.v1\\0"
//! node  = tag:u8 payload
//! tag 0 = child_count:u64le { name_len:u64le name:utf8 node }*
//! tag 1 = content_len:u64le content:bytes
//! tag 2 = target_len:u64le target:utf8
//! ```
//!
//! Directory entries must be strictly lexicographically ordered in the encoded
//! bytes. The decoder rejects non-canonical ordering, duplicate/illegal names,
//! invalid UTF-8, unknown tags, truncation, excessive nesting, and trailing data.

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

/// Versioned prefix for the canonical immutable-tree artifact encoding.
const FS_TREE_CANONICAL_MAGIC: &[u8] = b"crucible.device.ninep.fs-tree.v1\0";

/// Maximum accepted directory nesting in a canonical tree artifact.
const MAX_CANONICAL_DEPTH: usize = 1024;

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
    /// Builds a tree, rejecting any illegal path component anywhere in it.
    ///
    /// Recursively validates every directory child name via
    /// [`validate_component`], so the resulting tree's path-to-QID map is provably
    /// unambiguous ([IO-13]). Use this for any tree assembled from untrusted
    /// metadata.
    ///
    /// # Errors
    ///
    /// Returns [`BadComponent`] for the first child name that is empty, is `.` or
    /// `..`, contains `/`, or contains a NUL byte.
    pub fn try_new(root: Node) -> Result<Self, BadComponent> {
        validate_node(&root)?;
        Ok(Self { root })
    }

    /// Decodes and validates a canonical immutable-tree artifact.
    ///
    /// The accepted format is documented in the module-level `text` block. In
    /// addition to structural decoding, this enforces the same recursive
    /// component validation as [`FsTree::try_new`] and requires directory entries
    /// to already be in canonical sorted order. It never normalizes malformed or
    /// non-canonical bytes into a valid tree with a different identity.
    ///
    /// # Errors
    ///
    /// Returns [`FsTreeDecodeError`] for a wrong version tag, truncation, numeric
    /// overflow, excessive nesting, invalid UTF-8, an unknown node tag,
    /// non-canonical directory ordering, an illegal component, or trailing data.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FsTreeDecodeError> {
        let payload = bytes
            .strip_prefix(FS_TREE_CANONICAL_MAGIC)
            .ok_or(FsTreeDecodeError::WrongMagic)?;
        let mut reader = CanonicalReader::new(payload);
        let root = reader.read_node(0)?;
        if !reader.is_empty() {
            return Err(FsTreeDecodeError::TrailingBytes {
                remaining: reader.remaining(),
            });
        }
        Self::try_new(root).map_err(FsTreeDecodeError::InvalidComponent)
    }

    /// Returns the root node.
    #[must_use]
    pub fn root(&self) -> &Node {
        &self.root
    }

    /// Serializes the immutable tree into its canonical content-artifact bytes.
    ///
    /// The encoding begins with a versioned domain tag, then recursively writes
    /// explicit node-kind tags, little-endian counts and lengths, and the exact
    /// file/symlink bytes. Directory entries follow their [`BTreeMap`] order, so
    /// construction order cannot affect the result. Fixed synthetic attributes
    /// are covered by the versioned domain because they carry no per-node state.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FS_TREE_CANONICAL_MAGIC);
        write_canonical_node(&self.root, &mut bytes);
        bytes
    }

    /// Returns the BLAKE3 content hash of [`FsTree::canonical_bytes`].
    ///
    /// This is the immutable artifact identity stored by a world 9p sub-node and
    /// checked again when the concrete runtime device is instantiated.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
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

/// Writes one tree node in the versioned canonical artifact encoding.
fn write_canonical_node(node: &Node, bytes: &mut Vec<u8>) {
    match node {
        Node::Directory { children } => {
            bytes.push(0);
            write_canonical_len(children.len(), bytes);
            for (name, child) in children {
                write_canonical_slice(name.as_bytes(), bytes);
                write_canonical_node(child, bytes);
            }
        }
        Node::File { content } => {
            bytes.push(1);
            write_canonical_slice(content, bytes);
        }
        Node::Symlink { target } => {
            bytes.push(2);
            write_canonical_slice(target.as_bytes(), bytes);
        }
    }
}

/// Writes one collection length using the fixed canonical integer width.
fn write_canonical_len(len: usize, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&(len as u64).to_le_bytes());
}

/// Writes one length-prefixed byte slice.
fn write_canonical_slice(value: &[u8], bytes: &mut Vec<u8>) {
    write_canonical_len(value.len(), bytes);
    bytes.extend_from_slice(value);
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
/// The byte encoding fed to BLAKE3 is injective over component vectors, but the
/// returned QID is a 64-bit truncation and therefore is not mathematically
/// collision-free. It provides deterministic, collision-resistant identity; it
/// does not claim an impossible injective map from arbitrary paths to `u64`.
///
/// # Examples
///
/// ```no_run
/// use crucible_device::ninep::tree::qid_path;
/// // These adversarial structured paths hash to distinct, stable sample values;
/// // length prefixing removes the old delimiter ambiguity before hashing.
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
/// A legal stored component is non-empty, is neither `.` nor `..`, and contains
/// neither a `/` (which would make the component span a directory boundary) nor a
/// NUL byte (which a guest cannot represent in a path). The server reserves `.`
/// and `..` for traversal, so allowing either as stored children would make those
/// children unreachable and would give the artifact a misleading namespace.
///
/// # Errors
///
/// Returns [`BadComponent`] when `name` is empty, reserved, contains `/`, or
/// contains a NUL.
pub fn validate_component(name: &str) -> Result<(), BadComponent> {
    if name.is_empty() {
        return Err(BadComponent::Empty);
    }
    if name == "." {
        return Err(BadComponent::Dot);
    }
    if name == ".." {
        return Err(BadComponent::DotDot);
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
    /// The component was the traversal token `.`.
    #[error("path component '.' is reserved for traversal")]
    Dot,
    /// The component was the traversal token `..`.
    #[error("path component '..' is reserved for traversal")]
    DotDot,
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

/// Error returned while decoding a canonical [`FsTree`] artifact.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FsTreeDecodeError {
    /// The versioned artifact prefix is absent or unsupported.
    #[error("9p tree artifact has an unsupported canonical encoding")]
    WrongMagic,
    /// A fixed-width field or declared byte string is truncated.
    #[error("9p tree artifact is truncated while reading {field}")]
    Truncated {
        /// The field that could not be read completely.
        field: &'static str,
    },
    /// A canonical `u64` length cannot be represented on this host.
    #[error("9p tree artifact {field} length does not fit in memory")]
    LengthOverflow {
        /// The collection or byte-string length that overflowed.
        field: &'static str,
    },
    /// The tree exceeds the decoder's stack-safety depth bound.
    #[error("9p tree artifact exceeds maximum nesting depth {maximum}")]
    NestingTooDeep {
        /// Maximum accepted node depth.
        maximum: usize,
    },
    /// A node used an unknown kind tag.
    #[error("9p tree artifact contains unknown node tag {tag}")]
    UnknownNodeTag {
        /// Unrecognized tag byte.
        tag: u8,
    },
    /// A name or symlink target is not valid UTF-8.
    #[error("9p tree artifact {field} is not valid UTF-8")]
    InvalidUtf8 {
        /// Text field that failed UTF-8 decoding.
        field: &'static str,
    },
    /// Directory names were duplicated or not in canonical sorted order.
    #[error("9p tree artifact directory entries are not strictly sorted at {name:?}")]
    NonCanonicalDirectoryOrder {
        /// First entry that did not sort strictly after its predecessor.
        name: String,
    },
    /// A decoded directory name is not a legal stored component.
    #[error("9p tree artifact contains an invalid path component: {0}")]
    InvalidComponent(BadComponent),
    /// Structurally valid root bytes were followed by unrelated bytes.
    #[error("9p tree artifact contains {remaining} trailing bytes")]
    TrailingBytes {
        /// Number of bytes after the complete root node.
        remaining: usize,
    },
}

/// Bounds-checked reader for the canonical immutable-tree artifact.
struct CanonicalReader<'a> {
    remaining: &'a [u8],
}

impl<'a> CanonicalReader<'a> {
    /// Builds a reader over bytes after the versioned prefix.
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    /// Returns whether the artifact was consumed exactly.
    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    /// Returns the unconsumed byte count.
    fn remaining(&self) -> usize {
        self.remaining.len()
    }

    /// Reads one recursively encoded node.
    fn read_node(&mut self, depth: usize) -> Result<Node, FsTreeDecodeError> {
        if depth > MAX_CANONICAL_DEPTH {
            return Err(FsTreeDecodeError::NestingTooDeep {
                maximum: MAX_CANONICAL_DEPTH,
            });
        }
        match self.read_u8("node tag")? {
            0 => {
                let count = self.read_len("directory child count")?;
                let mut children = BTreeMap::new();
                let mut previous: Option<String> = None;
                for _ in 0..count {
                    let name = self.read_string("directory entry name")?;
                    if previous.as_ref().is_some_and(|value| value >= &name) {
                        return Err(FsTreeDecodeError::NonCanonicalDirectoryOrder { name });
                    }
                    validate_component(&name).map_err(FsTreeDecodeError::InvalidComponent)?;
                    let child = self.read_node(depth.saturating_add(1))?;
                    previous = Some(name.clone());
                    children.insert(name, child);
                }
                Ok(Node::Directory { children })
            }
            1 => Ok(Node::File {
                content: self.read_slice("file content")?.to_vec(),
            }),
            2 => Ok(Node::Symlink {
                target: self.read_string("symlink target")?,
            }),
            tag => Err(FsTreeDecodeError::UnknownNodeTag { tag }),
        }
    }

    /// Reads one byte.
    fn read_u8(&mut self, field: &'static str) -> Result<u8, FsTreeDecodeError> {
        let Some((&value, remaining)) = self.remaining.split_first() else {
            return Err(FsTreeDecodeError::Truncated { field });
        };
        self.remaining = remaining;
        Ok(value)
    }

    /// Reads one little-endian `u64` length as `usize`.
    fn read_len(&mut self, field: &'static str) -> Result<usize, FsTreeDecodeError> {
        let raw = self.read_exact(8, field)?;
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(raw);
        usize::try_from(u64::from_le_bytes(bytes))
            .map_err(|_| FsTreeDecodeError::LengthOverflow { field })
    }

    /// Reads a length-prefixed byte string.
    fn read_slice(&mut self, field: &'static str) -> Result<&'a [u8], FsTreeDecodeError> {
        let len = self.read_len(field)?;
        self.read_exact(len, field)
    }

    /// Reads a length-prefixed UTF-8 string.
    fn read_string(&mut self, field: &'static str) -> Result<String, FsTreeDecodeError> {
        let bytes = self.read_slice(field)?;
        let value =
            std::str::from_utf8(bytes).map_err(|_| FsTreeDecodeError::InvalidUtf8 { field })?;
        Ok(value.to_owned())
    }

    /// Reads exactly `len` bytes without indexing past the artifact.
    fn read_exact(
        &mut self,
        len: usize,
        field: &'static str,
    ) -> Result<&'a [u8], FsTreeDecodeError> {
        let Some((value, remaining)) = self.remaining.split_at_checked(len) else {
            return Err(FsTreeDecodeError::Truncated { field });
        };
        self.remaining = remaining;
        Ok(value)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- unit-test fixtures and assertions fail loudly.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn tree(entries: impl IntoIterator<Item = (&'static str, Node)>) -> FsTree {
        FsTree::try_new(Node::Directory {
            children: entries
                .into_iter()
                .map(|(name, node)| (name.to_owned(), node))
                .collect(),
        })
        .expect("test tree components are valid")
    }

    #[test]
    fn canonical_tree_identity_is_order_independent_and_field_sensitive() {
        let file = || Node::File {
            content: vec![0, 1, 2, 3],
        };
        let link = || Node::Symlink {
            target: "target".to_owned(),
        };
        let first = tree([("z-file", file()), ("a-link", link())]);
        let reordered = tree([("a-link", link()), ("z-file", file())]);

        assert_eq!(first.canonical_bytes(), reordered.canonical_bytes());
        assert_eq!(first.content_hash(), reordered.content_hash());
        assert!(first.canonical_bytes().starts_with(FS_TREE_CANONICAL_MAGIC));

        let changed_name = tree([("a-link", link()), ("different", file())]);
        let changed_content = tree([
            ("a-link", link()),
            (
                "z-file",
                Node::File {
                    content: vec![0, 1, 2, 4],
                },
            ),
        ]);
        let changed_kind = tree([
            ("a-link", link()),
            (
                "z-file",
                Node::Symlink {
                    target: String::from("\0\u{1}\u{2}\u{3}"),
                },
            ),
        ]);

        assert_ne!(first.content_hash(), changed_name.content_hash());
        assert_ne!(first.content_hash(), changed_content.content_hash());
        assert_ne!(first.content_hash(), changed_kind.content_hash());
    }

    #[test]
    fn canonical_tree_encoding_length_prefixes_adversarial_shapes() {
        let nested = tree([(
            "a",
            Node::Directory {
                children: [(
                    String::from("b"),
                    Node::File {
                        content: Vec::new(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        )]);
        let flat = tree([(
            "a-b",
            Node::File {
                content: Vec::new(),
            },
        )]);
        let file = tree([(
            "entry",
            Node::File {
                content: b"target".to_vec(),
            },
        )]);
        let symlink = tree([(
            "entry",
            Node::Symlink {
                target: String::from("target"),
            },
        )]);

        assert_ne!(nested.canonical_bytes(), flat.canonical_bytes());
        assert_ne!(file.content_hash(), symlink.content_hash());
    }

    #[test]
    fn canonical_tree_decoder_round_trips_and_rejects_noncanonical_artifacts() {
        let original = tree([
            (
                "directory",
                Node::Directory {
                    children: [(
                        String::from("file"),
                        Node::File {
                            content: vec![1, 2],
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            ),
            (
                "link",
                Node::Symlink {
                    target: String::from("directory/file"),
                },
            ),
        ]);
        let encoded = original.canonical_bytes();
        assert_eq!(
            FsTree::from_canonical_bytes(&encoded).expect("canonical bytes decode"),
            original
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            FsTree::from_canonical_bytes(&trailing),
            Err(FsTreeDecodeError::TrailingBytes { remaining: 1 })
        ));

        let mut wrong_magic = encoded;
        wrong_magic[0] ^= 1;
        assert!(matches!(
            FsTree::from_canonical_bytes(&wrong_magic),
            Err(FsTreeDecodeError::WrongMagic)
        ));
    }

    #[test]
    fn tree_construction_rejects_reserved_and_ambiguous_components() {
        for name in ["", ".", "..", "a/b", "a\0b"] {
            let root = Node::Directory {
                children: [(
                    String::from(name),
                    Node::File {
                        content: Vec::new(),
                    },
                )]
                .into_iter()
                .collect(),
            };
            assert!(FsTree::try_new(root).is_err(), "component {name:?}");
        }
    }

    #[test]
    fn canonical_decoder_rejects_illegal_and_unsorted_directory_names() {
        for name in ["", ".", "..", "a/b", "a\0b"] {
            let mut illegal = FS_TREE_CANONICAL_MAGIC.to_vec();
            illegal.push(0);
            write_canonical_len(1, &mut illegal);
            write_canonical_slice(name.as_bytes(), &mut illegal);
            illegal.push(1);
            write_canonical_slice(b"", &mut illegal);
            assert!(
                matches!(
                    FsTree::from_canonical_bytes(&illegal),
                    Err(FsTreeDecodeError::InvalidComponent(_))
                ),
                "decoder must reject illegal component {name:?}"
            );
        }

        let mut unsorted = FS_TREE_CANONICAL_MAGIC.to_vec();
        unsorted.push(0);
        write_canonical_len(2, &mut unsorted);
        for name in ["z", "a"] {
            write_canonical_slice(name.as_bytes(), &mut unsorted);
            unsorted.push(1);
            write_canonical_slice(b"", &mut unsorted);
        }
        assert!(matches!(
            FsTree::from_canonical_bytes(&unsorted),
            Err(FsTreeDecodeError::NonCanonicalDirectoryOrder { name }) if name == "a"
        ));

        let mut duplicate = FS_TREE_CANONICAL_MAGIC.to_vec();
        duplicate.push(0);
        write_canonical_len(2, &mut duplicate);
        for _ in 0..2 {
            write_canonical_slice(b"same", &mut duplicate);
            duplicate.push(1);
            write_canonical_slice(b"", &mut duplicate);
        }
        assert!(matches!(
            FsTree::from_canonical_bytes(&duplicate),
            Err(FsTreeDecodeError::NonCanonicalDirectoryOrder { name }) if name == "same"
        ));
    }

    #[test]
    fn canonical_decoder_rejects_truncation_invalid_utf8_unknown_tags_and_excessive_depth() {
        let mut truncated = FS_TREE_CANONICAL_MAGIC.to_vec();
        truncated.push(1);
        assert!(matches!(
            FsTree::from_canonical_bytes(&truncated),
            Err(FsTreeDecodeError::Truncated {
                field: "file content"
            })
        ));

        let mut invalid_utf8 = FS_TREE_CANONICAL_MAGIC.to_vec();
        invalid_utf8.push(0);
        write_canonical_len(1, &mut invalid_utf8);
        write_canonical_slice(&[0xff], &mut invalid_utf8);
        invalid_utf8.push(1);
        write_canonical_slice(b"", &mut invalid_utf8);
        assert!(matches!(
            FsTree::from_canonical_bytes(&invalid_utf8),
            Err(FsTreeDecodeError::InvalidUtf8 {
                field: "directory entry name"
            })
        ));

        let mut unknown_tag = FS_TREE_CANONICAL_MAGIC.to_vec();
        unknown_tag.push(0xff);
        assert!(matches!(
            FsTree::from_canonical_bytes(&unknown_tag),
            Err(FsTreeDecodeError::UnknownNodeTag { tag: 0xff })
        ));

        let mut too_deep = FS_TREE_CANONICAL_MAGIC.to_vec();
        for _ in 0..=MAX_CANONICAL_DEPTH {
            too_deep.push(0);
            write_canonical_len(1, &mut too_deep);
            write_canonical_slice(b"child", &mut too_deep);
        }
        too_deep.push(1);
        write_canonical_slice(b"", &mut too_deep);
        assert!(matches!(
            FsTree::from_canonical_bytes(&too_deep),
            Err(FsTreeDecodeError::NestingTooDeep {
                maximum: MAX_CANONICAL_DEPTH
            })
        ));
    }
}
