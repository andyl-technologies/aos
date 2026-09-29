//! Owns signed root/path entry origins in the commit profile pair.
//!
//! Receipts avoid embedding a containing commit's identity in its own tree.
//! Their wire form is defined by `entry-receipt` in the v1 CDDL:
//!
//! ```text
//! [root_digest, path_bytes, 0]
//! [root_digest, path_bytes, [source_commit, source_root, source_path]]
//! ```

use alloc::{string::String, vec::Vec};

use crate::identity::Digest;

/// Identifies the verified source location of carried entry content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntrySource {
    /// Signed source commit identity.
    pub commit: Digest,
    /// Root reachable from the source commit.
    pub root: Digest,
    /// Relative namespace path or opaque index key within that root.
    pub path: Vec<u8>,
}

/// Resolves an introduction without embedding a self-referential commit hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryOrigin {
    /// The externally identified containing signed commit introduces the value.
    Current,
    /// Verified source evidence preserves the source's introduction.
    Source(EntrySource),
}

/// Binds an entry's content and attribute origins into a signed commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryReceipt {
    /// Root containing the entry whose origins are recorded.
    pub root: Digest,
    /// Relative namespace path or opaque index key within that root.
    pub path: Vec<u8>,
    /// Introduction of the entry's content.
    pub origin: EntryOrigin,
    /// Separate producer origins for named attributes, when supplied.
    pub attributes: Option<Vec<(String, EntryOrigin)>>,
    /// Verified original source for an explicit current reintroduction.
    pub reintroduced_from: Option<EntrySource>,
}
