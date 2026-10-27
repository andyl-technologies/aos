//! Orders cold pair imports using inspected dictionary-to-inode bindings.
//!
//! Identities alone cannot choose a substitute dictionary source. Every edge
//! names an actual independently verified standalone inode or an original pair
//! in the same complete inventory. Pair-unit cycles need coordinated import and
//! lifetime handling; they remain an explicit refusal in this sequential path.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Orders exact original pairs while keeping unrelated source order stable.
///
/// # Errors
/// Refuses changed native custody, aliases, missing dictionary sources or cycles.
pub(super) fn original_sources(
    inventory: &NativeRecoveryInspection,
    sources: Vec<Arc<DerivedIndexRepair>>,
) -> io::Result<Vec<Arc<DerivedIndexRepair>>> {
    let mut packs = BTreeMap::new();
    for (position, source) in sources.iter().enumerate() {
        source.check_current()?;
        if packs.insert(inode(source.pack_file())?, position).is_some() {
            return Err(io::Error::other(
                "cold data pairs alias an original source inode",
            ));
        }
    }
    let mut standalone = BTreeSet::new();
    for candidate in inventory.candidates() {
        if let Some(VerifiedEncodedBody::Chunk(chunk)) = candidate.verified() {
            chunk.check_current()?;
            let key = inode(chunk.file())?;
            if packs.contains_key(&key) || !standalone.insert(key) {
                return Err(io::Error::other(
                    "cold dictionary sources alias original inodes",
                ));
            }
        }
    }

    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(sources.len())
        .map_err(io::Error::other)?;
    for source in &sources {
        let mut parents = Vec::new();
        for (_, file) in source.dictionary_sources()? {
            let key = inode(file)?;
            if standalone.contains(&key) {
                continue;
            }
            let parent = packs.get(&key).copied().ok_or_else(|| {
                io::Error::other("cold dictionary lacks its independently verified original pair")
            })?;
            if !parents.contains(&parent) {
                parents.try_reserve_exact(1).map_err(io::Error::other)?;
                parents.push(parent);
            }
        }
        dependencies.push(parents);
    }
    let order = dependency_order(&dependencies)?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(sources.len())
        .map_err(io::Error::other)?;
    for position in order {
        let source = sources
            .get(position)
            .ok_or_else(|| io::Error::other("cold dictionary source order disappeared"))?;
        source.check_current()?;
        ordered.push(Arc::clone(source));
    }
    Ok(ordered)
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
            "cyclic cold pack units require coordinated admission and lifetime handling",
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
