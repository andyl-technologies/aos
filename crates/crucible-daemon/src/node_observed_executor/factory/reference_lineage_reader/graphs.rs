//! Checks original installed reference-graph closure without inventing NAR proofs.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use crucible_node_contract::canonical;
use serde::Deserialize;

use super::super::{NodeObservedError, refused};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceGraph {
    schema: String,
    roots: Vec<PathBuf>,
    #[serde(rename = "subtractRoots")]
    subtract_roots: Vec<PathBuf>,
    paths: Vec<ReferencePath>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferencePath {
    path: PathBuf,
    #[serde(rename = "narHash")]
    nar_hash: String,
    #[serde(rename = "narSize")]
    nar_size: u64,
    references: Vec<PathBuf>,
}

/// Returns the exact reachable roster from hash-authenticated original metadata.
///
/// `narHash` and `narSize` retain original daemon observations; this routine
/// does not claim to reserialize or verify a NAR. Executable object bytes are
/// independently measured by the installed package and native enrollment.
pub(super) fn validate_graph(
    bytes: &[u8],
    expected_roots: Option<&BTreeSet<PathBuf>>,
) -> Result<BTreeSet<PathBuf>, NodeObservedError> {
    let value = canonical::parse_json(bytes, 1024 * 1024)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(refused("installed reference graph is not canonical"));
    }
    let graph: ReferenceGraph = serde_json::from_value(value)?;
    if graph.schema != "aos.reference-graph/v1"
        || graph.roots.is_empty()
        || graph.roots.len() > 512
        || !graph.subtract_roots.is_empty()
        || graph.paths.is_empty()
        || graph.paths.len() > 512
        || graph
            .paths
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(refused("invalid original installed reference graph"));
    }
    let roots = graph.roots.iter().cloned().collect::<BTreeSet<_>>();
    if roots.len() != graph.roots.len() || expected_roots.is_some_and(|expected| expected != &roots)
    {
        return Err(refused("original reference graph roots differ"));
    }
    let paths = graph
        .paths
        .iter()
        .map(|row| (row.path.clone(), row))
        .collect::<BTreeMap<_, _>>();
    for row in &graph.paths {
        if store_root(&row.path)? != row.path
            || row.nar_hash.is_empty()
            || row.nar_hash.len() > 128
            || row.nar_size == 0
            || row.references.len() > 512
            || row.references.windows(2).any(|pair| pair[0] >= pair[1])
            || row
                .references
                .iter()
                .any(|reference| !paths.contains_key(reference))
        {
            return Err(refused("invalid installed reference graph row"));
        }
    }
    let mut reachable = BTreeSet::new();
    let mut pending = roots.into_iter().collect::<Vec<_>>();
    while let Some(path) = pending.pop() {
        if !reachable.insert(path.clone()) {
            continue;
        }
        let row = paths
            .get(&path)
            .ok_or_else(|| refused("installed reference graph root is absent"))?;
        for reference in &row.references {
            if !reachable.contains(reference) && !pending.contains(reference) {
                pending.push(reference.clone());
            }
        }
    }
    if reachable.len() != paths.len() {
        return Err(refused("installed reference graph has unreachable paths"));
    }
    Ok(reachable)
}

pub(super) fn store_root(path: &Path) -> Result<PathBuf, NodeObservedError> {
    if path.components().collect::<PathBuf>().as_os_str() != path.as_os_str() {
        return Err(refused("installed reference graph path is not canonical"));
    }
    let mut parts = path.components();
    if parts.next() != Some(std::path::Component::RootDir)
        || parts.next().is_none_or(|part| part.as_os_str() != "nix")
        || parts.next().is_none_or(|part| part.as_os_str() != "store")
    {
        return Err(refused("installed reference graph path is outside store"));
    }
    let object = parts
        .next()
        .filter(|part| matches!(part, std::path::Component::Normal(_)))
        .ok_or_else(|| refused("installed reference graph store root is absent"))?;
    let name = object
        .as_os_str()
        .to_str()
        .ok_or_else(|| refused("installed store name is not UTF-8"))?;
    let (hash, suffix) = name
        .split_once('-')
        .ok_or_else(|| refused("installed store name is malformed"))?;
    if hash.len() != 32
        || suffix.is_empty()
        || !hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        || suffix.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(refused("installed reference graph store name is malformed"));
    }
    if parts.any(|part| !matches!(part, std::path::Component::Normal(_))) {
        return Err(refused("installed reference graph path has traversal"));
    }
    Ok(Path::new("/nix/store").join(object.as_os_str()))
}

#[cfg(test)]
#[path = "graphs_tests.rs"]
mod tests;
