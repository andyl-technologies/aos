//! Assigns bounded, connection-local inode numbers to structural identities.
//!
//! Internal identities depend on the governing root and canonical path, not
//! access order. Presented inode numbers are allocated only when touched and
//! never recycled, including after a kernel FORGET. Hard-link aliases must use
//! their validated set's canonical first path. This module does not authenticate
//! metadata, operate a FUSE connection or register a surface. Checked index
//! entries provide canonical hard-link paths through [`InodeTable::touch_entry`].

use std::{collections::BTreeMap, fmt};

use terrane_format::{identity::Digest, tree_format::validate_key};

mod reserved;

const FIRST_INODE: u32 = 16;
const LAST_INODE: u32 = u32::MAX - 1;

/// Identifies one canonical entry independently of lookup order.
///
/// The path is relative to the complete served namespace. A hard-link alias
/// supplies its set's canonical first path in that namespace; repeated grafts
/// retain their distinct prefixes. Neither this value nor its digest proves
/// that a path is present, reachable or authorized in an exposure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeIdentity {
    digest: Digest,
    node_id: u64,
}

impl NodeIdentity {
    /// Derives an identity from a governing root and canonical namespace path.
    ///
    /// The empty path identifies the root. Other paths obey Terrane's tree key
    /// grammar. The fixed domain prefix and length framing separate this use
    /// from content identities and ambiguous concatenations.
    ///
    /// # Errors
    /// Refuses invalid paths and a digest whose truncated kernel identifier
    /// occupies the reserved zero or root slot. These cases never get remapped
    /// according to lookup order.
    pub fn new(governing_root: Digest, canonical_path: &[u8]) -> Result<Self, Error> {
        if !canonical_path.is_empty() {
            validate_key(canonical_path).map_err(|_| Error::Path)?;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"terrane.fuse.node.v1\0");
        hasher.update(&governing_root);
        hasher.update(&(canonical_path.len() as u64).to_le_bytes());
        hasher.update(canonical_path);
        let digest = *hasher.finalize().as_bytes();
        let mut prefix = [0; 8];
        prefix.copy_from_slice(&digest[..8]);
        let node_id = u64::from_le_bytes(prefix);
        if node_id < 2 {
            return Err(Error::Collision);
        }

        Ok(Self { digest, node_id })
    }

    /// Returns the full identity used to detect truncated kernel-ID collisions.
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns the deterministic structural node identifier.
    ///
    /// FUSE's connection root is separately fixed at `FUSE_ROOT_ID` (one). Its
    /// structural identity can still receive a normal presented `st_ino`.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node_id
    }
}

/// Preserves one entry's presented number and immutable hard-link count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inode {
    number: u32,
    links: u32,
}

impl Inode {
    /// Returns the presented 32-bit `st_ino` in the RFC's permitted range.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Returns the validated link count supplied for this canonical identity.
    #[must_use]
    pub fn links(&self) -> u32 {
        self.links
    }
}

/// Refuses invalid metadata, an exhausted connection or identity aliasing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A canonical entry path violates the tree key grammar.
    Path,
    /// The configured touched-inode limit is zero or exceeds the numeric range.
    Configuration,
    /// The reserved table would exceed its explicit startup byte budget.
    MemoryBudget,
    /// The allocator could not reserve the bounded startup table.
    Allocation,
    /// Another first lookup would exceed the connection's retained-inode limit.
    Capacity,
    /// A kernel node identifier is reserved or aliases a distinct full digest.
    Collision,
    /// A link count is zero or differs from the same retained immutable entry.
    Links,
    /// A checked structural entry cannot supply its canonical identity.
    Index(crate::structural_index::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Path => "invalid canonical inode path",
            Self::Configuration => "invalid connection inode limit",
            Self::MemoryBudget => "connection inode memory budget exceeded",
            Self::Allocation => "connection inode reservation failed",
            Self::Capacity => "connection inode limit exceeded",
            Self::Collision => "kernel node identity collision",
            Self::Links => "inconsistent canonical inode link count",
            Self::Index(_) => "invalid structural inode metadata",
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Index(error) => Some(error),
            _ => None,
        }
    }
}

/// Retains numbers for the entries touched on exactly one connection.
///
/// The explicit limit bounds retained rows independently of total tree size.
/// Forgetting an inode must not remove its row: a later lookup must return the
/// original number, and its old number must never name a different entry. A
/// connection owner discards this entire table only after that connection ends.
pub struct InodeTable {
    limit: u32,
    entries: Entries,
}

/// Keeps the maintenance constructor lazy while allowing a worker to reserve
/// its entire bounded table before servicing requests.
enum Entries {
    Lazy(BTreeMap<u64, (Digest, Inode)>),
    Reserved(reserved::Slots),
}

impl Entries {
    fn len(&self) -> usize {
        match self {
            Self::Lazy(entries) => entries.len(),
            Self::Reserved(entries) => entries.len(),
        }
    }
}

impl InodeTable {
    /// Creates an empty connection table with a finite touched-inode limit.
    ///
    /// # Examples
    /// ```no_run
    /// use terrane_linux::inode_policy::{InodeTable, NodeIdentity};
    ///
    /// let mut table = InodeTable::new(1024)?;
    /// let identity = NodeIdentity::new([7; 32], b"README")?;
    /// let inode = table.touch(identity, 1)?;
    /// assert_eq!(inode.number(), 16);
    /// assert_eq!(table.touch(identity, 1)?, inode);
    /// # Ok::<(), terrane_linux::inode_policy::Error>(())
    /// ```
    ///
    /// First touches may allocate. A worker that must not allocate while serving
    /// metadata uses [`Self::with_reserved_capacity`] before accepting requests.
    ///
    /// # Errors
    /// Refuses zero and limits larger than the available presented-inode range.
    pub fn new(limit: u32) -> Result<Self, Error> {
        if limit == 0 || limit > LAST_INODE - FIRST_INODE + 1 {
            return Err(Error::Configuration);
        }

        Ok(Self {
            limit,
            entries: Entries::Lazy(BTreeMap::new()),
        })
    }

    /// Reserves a connection table before any metadata requests are served.
    ///
    /// The table checks its complete slot-storage requirement against
    /// `max_bytes` before allocating. This budget covers requested slot bytes,
    /// not allocator overhead or total process RSS. The limit depends on the
    /// worker's configured touched-inode bound, never the served tree's size.
    /// Presented numbers are still assigned lazily at first lookup. Neither
    /// first touches, repeated lookups nor refusals allocate after construction.
    ///
    /// # Errors
    /// Refuses invalid inode limits, unrepresentable slot counts or sizes,
    /// insufficient byte budgets and failed startup allocation.
    pub fn with_reserved_capacity(limit: u32, max_bytes: usize) -> Result<Self, Error> {
        if limit == 0 || limit > LAST_INODE - FIRST_INODE + 1 {
            return Err(Error::Configuration);
        }

        Ok(Self {
            limit,
            entries: Entries::Reserved(reserved::Slots::new(limit, max_bytes)?),
        })
    }

    /// Returns or first assigns one canonical entry's connection-local number.
    ///
    /// Callers must obtain the identity and exact link count from checked
    /// structural metadata, including hard-link resolution. Existing lookups
    /// allocate nothing, including when the table is full. An error changes no
    /// retained entry and consumes no presented inode number.
    ///
    /// # Errors
    /// Refuses zero or inconsistent link counts, a truncated identity collision
    /// and a first lookup beyond the configured limit. A worker must fault the
    /// affected exposure rather than recycle a number or alias a distinct entry.
    pub fn touch(&mut self, identity: NodeIdentity, links: u32) -> Result<Inode, Error> {
        if links == 0 {
            return Err(Error::Links);
        }
        let entries = match &mut self.entries {
            Entries::Lazy(entries) => entries,
            Entries::Reserved(entries) => return entries.touch(identity, links, self.limit),
        };
        if let Some((digest, inode)) = entries.get(&identity.node_id) {
            if *digest != identity.digest {
                return Err(Error::Collision);
            }
            if inode.links != links {
                return Err(Error::Links);
            }
            return Ok(*inode);
        }
        let assigned = u32::try_from(entries.len()).map_err(|_| Error::Capacity)?;
        if assigned >= self.limit {
            return Err(Error::Capacity);
        }

        let inode = Inode {
            number: FIRST_INODE.checked_add(assigned).ok_or(Error::Capacity)?,
            links,
        };
        entries.insert(identity.node_id, (identity.digest, inode));
        Ok(inode)
    }

    /// Assigns an inode using only a checked index's canonical path and count.
    ///
    /// Hard-link aliases share one row. Repeated graft prefixes remain distinct.
    /// The index's caller must separately authenticate and authorize its root;
    /// structural validity alone does not grant access to an exposure.
    ///
    /// # Errors
    /// Returns structural metadata errors and the same limit, count and collision
    /// refusals as [`Self::touch`], without consuming an inode on failure.
    pub fn touch_entry(
        &mut self,
        entry: crate::structural_index::Entry<'_>,
    ) -> Result<(NodeIdentity, Inode), Error> {
        let canonical = entry.canonical_inode().map_err(Error::Index)?;
        let root = canonical.governing_root().map_err(Error::Index)?;
        let identity = NodeIdentity::new(root, canonical.path())?;
        let links = canonical.link_count().map_err(Error::Index)?;
        let inode = self.touch(identity, links)?;
        Ok((identity, inode))
    }

    /// Returns the number of distinct entries ever touched on this connection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no entry has been touched on this connection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.len() == 0
    }
}

#[cfg(test)]
mod tests;
