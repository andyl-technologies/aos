//! Binds publication bytes to compilation from actual canonical tree metadata.
//!
//! A checked [`super::Index`] proves layout consistency, not that its root tag
//! describes its entries. This producer-owned value retains the exact canonical
//! projection for verification before and after a funded native copy. It grants
//! no disclosure permission, reservation, filesystem custody or cache pin.

use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
};

use terrane_format::{identity::Digest, tree_builder::Tree};

use super::{Error, VERSION, compile_nodes, compile_tree};

/// Names one derived surface projection without using a Terrane content identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IndexKey {
    root: Digest,
    version: u16,
}

impl IndexKey {
    /// Returns the actual canonical tree root from which the index was compiled.
    #[must_use]
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Returns the derived structural-index format version.
    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }
}

/// Retains a bounded projection compiled from identity-checked tree metadata.
///
/// No constructor accepts a root tag and arbitrary already-compiled bytes.
/// Native publication must preserve this value through copy, synchronization
/// and sealing, and retain physical progress independently of reply waiters.
/// A caller must separately authenticate and authorize disclosure of the root.
#[derive(Debug)]
pub struct CompiledIndex {
    key: IndexKey,
    bytes: Vec<u8>,
}

impl CompiledIndex {
    /// Compiles actual canonical trees and their complete reachable graft graph.
    ///
    /// # Errors
    /// Returns the same identity, graft, geometry and bound refusals as
    /// [`compile_tree`]. No content body or native filesystem is accessed.
    pub fn from_tree(
        root: &Tree<'_>,
        grafts: &BTreeMap<Digest, Tree<'_>>,
        max_entries: u32,
        max_bytes: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            key: IndexKey {
                root: root.root_identity(),
                version: VERSION,
            },
            bytes: compile_tree(root, grafts, max_entries, max_bytes)?,
        })
    }

    /// Compiles only after checking actual canonical node identities and summaries.
    ///
    /// The raw-node byte bound charges every supplied body, including unreachable
    /// nodes. Output bounds separately cover the expanded graft projection.
    ///
    /// # Errors
    /// Returns the same malformed-node, identity, graph and bound refusals as
    /// [`compile_nodes`]. No root tag can substitute for its actual node bytes.
    pub fn from_nodes(
        root: Digest,
        nodes: &BTreeMap<Digest, Vec<u8>>,
        minimum_chunk_size: u64,
        max_entries: u32,
        max_bytes: usize,
        max_node_bytes: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            key: IndexKey {
                root,
                version: VERSION,
            },
            bytes: compile_nodes(
                root,
                nodes,
                minimum_chunk_size,
                max_entries,
                max_bytes,
                max_node_bytes,
            )?,
        })
    }

    /// Returns the exact root and derived version established by compilation.
    #[must_use]
    pub fn key(&self) -> IndexKey {
        self.key
    }

    /// Borrows the canonical projection without copying its payload.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copies the complete projection to an already funded native writer.
    ///
    /// This performs no reservation, synchronization, writer closure or sealing.
    /// An error may leave an actual written prefix; the physical owner must
    /// retain that progress and its funding for reconciliation.
    ///
    /// # Errors
    /// Returns write failures without altering the original compilation.
    pub fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&self.bytes)
    }

    /// Checks exact copied bytes using a fixed-size buffer and no heap allocation.
    ///
    /// The reader must start at offset zero. Native callers must additionally
    /// establish descriptor identity, permanent sealing and synchronized custody;
    /// successful byte comparison alone establishes none of those boundaries.
    ///
    /// # Errors
    /// Rejects short, changed or trailing data, and propagates actual read errors.
    pub fn verify_reader(&self, reader: &mut impl Read) -> io::Result<()> {
        let mut buffer = [0u8; 4096];
        for expected in self.bytes.chunks(buffer.len()) {
            let actual = &mut buffer[..expected.len()];
            reader.read_exact(actual)?;
            if actual != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "structural index differs from canonical compilation",
                ));
            }
        }
        loop {
            match reader.read(&mut buffer[..1]) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "structural index has trailing bytes",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}
