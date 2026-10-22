//! Discloses complete ordinary root metadata only after every path passes Read.

use std::collections::BTreeMap;

use terrane_format::{
    identity::Digest,
    surface::ViewTarget,
    tree_format::{self, EntryKind, validate_graft_chain},
};

use crate::{
    guard::{AuthorizedSnapshot, SnapshotPathBatch},
    store::{Clock, LocalFs, Store},
};

use super::{Error, Repository};

/// Bounds a complete root's metadata disclosure and expanded path inventory.
#[derive(Clone, Copy, Debug)]
pub struct RootNodeLimits {
    /// Maximum expanded entries, including the implicit root directory.
    pub max_entries: usize,
    /// Maximum sum of all encoded Node bytes and their 32-byte inventory keys.
    pub max_metadata_bytes: usize,
    /// Maximum sum of expanded absolute path lengths, including the root slash.
    pub max_path_bytes: usize,
}

/// Retains canonical Nodes disclosed by one successful full-root Read operation.
///
/// Construction checks signed history, provenance, current Read permission and
/// the selected storage domain for every expanded path. Partial subtrees and
/// filtered projections cannot be represented as the original root here: a
/// denied or untrusted descendant refuses the entire disclosure.
///
/// This immutable result contains no file bodies, credentials, backend handles,
/// live lease or enduring authorization. Later content access and exposure
/// installation must independently check their current authority.
pub struct RootNodes {
    commit: Digest,
    root: Digest,
    minimum_chunk_size: u64,
    nodes: BTreeMap<Digest, Vec<u8>>,
}

impl RootNodes {
    /// Returns the exact signed commit selected by this read.
    pub const fn commit(&self) -> Digest {
        self.commit
    }

    /// Returns the canonical root addressed by the selected signed commit.
    pub const fn root(&self) -> Digest {
        self.root
    }

    /// Returns the immutable chunk geometry used to validate these Nodes.
    pub const fn minimum_chunk_size(&self) -> u64 {
        self.minimum_chunk_size
    }

    /// Borrows the complete reached Node inventory without storage access.
    pub fn nodes(&self) -> &BTreeMap<Digest, Vec<u8>> {
        &self.nodes
    }
}

impl<S, C, F> Repository<S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Reads complete canonical root Nodes without requesting any file content.
    ///
    /// Unlike a scoped view projection, this operation exports a complete root
    /// and its reachable graft Nodes. Every expanded path must pass the ordinary
    /// current Read and provenance checks; permission to one subtree cannot
    /// disclose its siblings. Original canonical symlink targets, attributes,
    /// hard-link identities and graft properties remain in the Node bytes.
    /// All path checks and the closing check must observe the same complete
    /// live policy reference, independently of the selected immutable commit.
    ///
    /// Limits bound the returned inventory and the temporary expanded path
    /// inventory. The ordinary authenticated history loader retains its own
    /// validation behavior before these additional output bounds are checked.
    ///
    /// # Errors
    /// Refuses zero or exceeded bounds, unavailable or unauthenticated history,
    /// missing canonical metadata, invalid graft expansion and any descendant
    /// lacking current Read, domain permission or verified provenance trust,
    /// and a policy reference that changes during the complete read.
    /// No partial metadata inventory is returned.
    pub async fn read_root_nodes(
        &self,
        target: &ViewTarget,
        token: &[u8],
        surface: &str,
        limits: RootNodeLimits,
    ) -> Result<RootNodes, Error> {
        if limits.max_entries == 0 || limits.max_metadata_bytes == 0 || limits.max_path_bytes == 0 {
            return Err(tree_format::Error::Limit.into());
        }
        let guard = self.coordinator.guard();
        let snapshot = match target {
            ViewTarget::Ref(reference) => {
                guard
                    .read_snapshot(reference.as_str(), token, b"/", surface)
                    .await?
            }
            ViewTarget::Commit(identity) => {
                guard
                    .read_commit_snapshot(*identity, token, b"/", surface)
                    .await?
            }
        };
        let minimum = self.chunk_profile().minimum() as u64;
        let paths = expanded_paths(&snapshot, minimum, limits)?;
        let authorization = SnapshotPathBatch::begin(guard, &snapshot).await?;
        for path in &paths {
            authorization.authorize_path(path).await?;
        }

        let result = RootNodes {
            commit: snapshot.commit.identity(),
            root: snapshot.evidence.root,
            minimum_chunk_size: minimum,
            nodes: snapshot.evidence.nodes.clone(),
        };
        // Allocation and the empty-root case still precede a fresh authority
        // check. Retained immutable bytes do not keep a former Read alive.
        authorization.finish().await?;
        Ok(result)
    }
}

fn expanded_paths(
    snapshot: &AuthorizedSnapshot,
    minimum: u64,
    limits: RootNodeLimits,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut metadata_bytes = 0usize;
    for bytes in snapshot.evidence.nodes.values() {
        metadata_bytes = metadata_bytes
            .checked_add(32)
            .and_then(|size| size.checked_add(bytes.len()))
            .ok_or(tree_format::Error::Limit)?;
        if metadata_bytes > limits.max_metadata_bytes {
            return Err(tree_format::Error::Limit.into());
        }
    }

    let mut paths = vec![b"/".to_vec()];
    let mut path_bytes = 1usize;
    let mut pending = vec![(snapshot.evidence.root, b"/".to_vec(), Vec::new())];
    while let Some((root, prefix, mut ancestors)) = pending.pop() {
        ancestors.push(root);
        validate_graft_chain(&ancestors)?;
        let tree = snapshot.evidence.tree(root, minimum)?;
        for item in tree.iter() {
            if paths.len() >= limits.max_entries {
                return Err(tree_format::Error::Limit.into());
            }
            let mut path = prefix.clone();
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(&item.key);
            tree_format::validate_key(path.strip_prefix(b"/").ok_or(Error::PathEscape)?)?;
            path_bytes = path_bytes
                .checked_add(path.len())
                .ok_or(tree_format::Error::Limit)?;
            if path_bytes > limits.max_path_bytes {
                return Err(tree_format::Error::Limit.into());
            }
            if let EntryKind::Tree { root, .. } = &item.entry.kind {
                pending.push((*root, path.clone(), ancestors.clone()));
            }
            paths.push(path);
        }
    }
    paths.sort_unstable();
    Ok(paths)
}
