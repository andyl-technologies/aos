//! Names exact destination proof batches and canonical root occurrences.
//!
//! ```text
//! gc-proof-context = [destination-commit32, root32, absolute-root-path]
//! ```
//!
//! A context identifies a traversal position. It does not certify a disclosure
//! boundary; only complete provenance verification can authorize pruning.

use alloc::vec::Vec;

use super::GcError;
use crate::{identity::Digest, tree_format};

/// Identifies one destination commit's exact canonical root occurrence.
///
/// Ordering compares unsigned destination, root and path bytes fieldwise.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProofContext {
    destination: Digest,
    root: Digest,
    absolute_path: Vec<u8>,
}

impl ProofContext {
    /// Constructs a context with a canonical absolute root occurrence path.
    ///
    /// # Errors
    /// Rejects relative paths, invalid path components and paths beyond 4,097 bytes.
    pub fn new(destination: Digest, root: Digest, absolute_path: Vec<u8>) -> Result<Self, GcError> {
        if !(1..=4097).contains(&absolute_path.len()) {
            return Err(GcError::Schema);
        }
        if absolute_path != b"/" {
            let relative = absolute_path.strip_prefix(b"/").ok_or(GcError::Schema)?;
            tree_format::validate_key(relative).map_err(|_| GcError::Schema)?;
        }
        Ok(Self {
            destination,
            root,
            absolute_path,
        })
    }

    /// Returns the signed destination commit identifying the proof batch.
    pub const fn destination(&self) -> &Digest {
        &self.destination
    }

    /// Returns the root identity at this occurrence.
    pub const fn root(&self) -> &Digest {
        &self.root
    }

    /// Borrows the canonical absolute root occurrence path.
    pub fn absolute_path(&self) -> &[u8] {
        &self.absolute_path
    }

    /// Descends through a graft whose key is complete and relative to this root.
    ///
    /// # Errors
    /// Rejects noncanonical graft keys or a resulting absolute path beyond the limit.
    pub fn descend(&self, root: Digest, key: &[u8]) -> Result<Self, GcError> {
        tree_format::validate_key(key).map_err(|_| GcError::Schema)?;
        let separator = usize::from(self.absolute_path != b"/");
        let length = self
            .absolute_path
            .len()
            .checked_add(separator)
            .and_then(|length| length.checked_add(key.len()))
            .ok_or(GcError::Schema)?;
        if length > 4097 {
            return Err(GcError::Schema);
        }

        let mut path = self.absolute_path.clone();
        if path != b"/" {
            path.push(b'/');
        }
        path.extend_from_slice(key);
        Self::new(self.destination, root, path)
    }
}
