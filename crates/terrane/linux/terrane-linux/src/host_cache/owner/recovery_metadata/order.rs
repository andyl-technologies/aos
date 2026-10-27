//! Orders combined cold chunk and pair imports using inspected source inodes.
//!
//! Identities alone cannot choose a substitute dictionary source. Every edge
//! names an actual independently verified standalone inode or an original pair
//! in the same complete inventory. Pair-unit cycles need coordinated import and
//! lifetime handling; they remain an explicit refusal in this sequential path.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Identifies one original source in the retained complete recovery inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::host_cache::owner) enum Source {
    /// Imports the pair at its original position in the retained pair vector.
    Pair(usize),
    /// Imports the chunk at its original position in the retained chunk vector.
    Chunk(usize),
}

/// Orders pairs by the complete chunk-and-pair dependency graph.
///
/// # Errors
/// Refuses changed native custody, aliases, missing dictionary sources or cycles.
pub(super) fn original_sources(
    inventory: &NativeRecoveryInspection,
    sources: Vec<Arc<DerivedIndexRepair>>,
) -> io::Result<Vec<Arc<DerivedIndexRepair>>> {
    let chunks = super::super::recovery_encoded::select(inventory)?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(sources.len())
        .map_err(io::Error::other)?;
    for source in imports(&chunks, &sources)? {
        if let Source::Pair(position) = source {
            ordered.push(Arc::clone(&sources[position]));
        }
    }
    Ok(ordered)
}

/// Orders every exact original source before any dependent admission.
///
/// Pairs precede unrelated chunks to preserve existing allocation order. An
/// edge follows the independently inspected inode, never an identity-based
/// substitute. The complete order is resolved before any import has effects.
///
/// # Errors
/// Refuses changed custody, aliases, missing original sources or unit cycles.
pub(in crate::host_cache::owner) fn imports(
    chunks: &[Arc<crate::host_cache::VerifiedStandaloneChunk>],
    pairs: &[Arc<DerivedIndexRepair>],
) -> io::Result<Vec<Source>> {
    let total = pairs
        .len()
        .checked_add(chunks.len())
        .ok_or_else(|| io::Error::other("cold source graph bound overflow"))?;
    let mut originals = BTreeMap::new();
    let mut sources = Vec::new();
    sources.try_reserve_exact(total).map_err(io::Error::other)?;
    for (position, pair) in pairs.iter().enumerate() {
        pair.check_current()?;
        if originals
            .insert(inode(pair.pack_file())?, sources.len())
            .is_some()
        {
            return Err(io::Error::other(
                "cold pairs alias an original source inode",
            ));
        }
        sources.push(Source::Pair(position));
    }
    for (position, chunk) in chunks.iter().enumerate() {
        chunk.check_current()?;
        if originals
            .insert(inode(chunk.file())?, sources.len())
            .is_some()
        {
            return Err(io::Error::other(
                "cold chunks alias an original source inode",
            ));
        }
        sources.push(Source::Chunk(position));
    }

    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(total)
        .map_err(io::Error::other)?;
    for source in &sources {
        let files = match *source {
            Source::Pair(position) => pairs[position].dictionary_sources()?,
            Source::Chunk(position) => chunks[position].dictionary_source()?.into_iter().collect(),
        };
        let mut parents = Vec::new();
        parents
            .try_reserve_exact(files.len())
            .map_err(io::Error::other)?;
        for (_, file) in files {
            let parent = originals.get(&inode(file)?).copied().ok_or_else(|| {
                io::Error::other("cold dictionary lacks its independently verified original source")
            })?;
            if !parents.contains(&parent) {
                parents.push(parent);
            }
        }
        dependencies.push(parents);
    }
    dependency_order(&dependencies)?
        .into_iter()
        .map(|position| {
            sources
                .get(position)
                .copied()
                .ok_or_else(|| io::Error::other("cold source order disappeared"))
        })
        .collect()
}

fn inode(file: &std::fs::File) -> io::Result<(u64, u64)> {
    let value = file.metadata()?;
    Ok((value.dev(), value.ino()))
}

/// Resolves pair dependencies without recursive graph traversal or native effects.
fn dependency_order(dependencies: &[Vec<usize>]) -> io::Result<Vec<usize>> {
    let mut remaining = Vec::new();
    remaining
        .try_reserve_exact(dependencies.len())
        .map_err(io::Error::other)?;
    remaining.extend(dependencies.iter().map(Vec::len));
    let mut ready = remaining
        .iter()
        .enumerate()
        .filter_map(|(position, count)| (*count == 0).then_some(position))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::new();
    order
        .try_reserve_exact(dependencies.len())
        .map_err(io::Error::other)?;
    while let Some(position) = ready.pop_first() {
        order.push(position);
        for (child, parents) in dependencies.iter().enumerate() {
            if parents.contains(&position) {
                let count = remaining
                    .get_mut(child)
                    .ok_or_else(|| io::Error::other("cold dictionary order lost its bound"))?;
                *count = count
                    .checked_sub(1)
                    .ok_or_else(|| io::Error::other("cold dictionary order repeated an edge"))?;
                if *count == 0 {
                    ready.insert(child);
                }
            }
        }
    }
    if order.len() != dependencies.len() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cyclic cold source units require coordinated admission and lifetime handling",
        ));
    }
    Ok(order)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn original_pack_order_preserves_dependencies_and_stable_unrelated_sources() {
        // Pure order selection supplies no original native custody or authority.
        let order = dependency_order(&[vec![2], vec![], vec![3], vec![], vec![2, 3]]).unwrap();
        assert_eq!(order, [1, 3, 2, 0, 4]);
        assert_eq!(dependency_order(&[vec![], vec![]]).unwrap(), [0, 1]);
        assert!(dependency_order(&[]).unwrap().is_empty());

        // Pair 0 needs chunk 3, which needs pair 1; chunk 2 needs pair 0.
        // The combined source order must cross both kinds more than once.
        assert_eq!(
            dependency_order(&[vec![3], vec![], vec![0], vec![1]]).unwrap(),
            [1, 3, 0, 2],
        );
    }

    #[test]
    fn cyclic_or_missing_original_pack_units_never_produce_partial_import_order() {
        for graph in [vec![vec![0]], vec![vec![1], vec![0]], vec![vec![2], vec![]]] {
            assert_eq!(
                dependency_order(&graph).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }
}
