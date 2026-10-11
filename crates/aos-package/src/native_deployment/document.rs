//! Bounded immutable document reads through the caller-selected Nix store.
//!
//! Canonical identities never become host paths derived from a store URI.
//! Nix's typed filesystem accessor reads exact members of the selected store;
//! immutable aliases retain their targets before subsequent reads.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_ability_runtime::adapter::CancellationToken;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum DocumentNode {
    #[serde(rename = "regular")]
    Regular {
        size: u64,
        #[serde(default)]
        executable: bool,
    },
    #[serde(rename = "symlink")]
    Symlink { target: String },
    #[serde(rename = "directory")]
    Directory {
        entries: BTreeMap<String, serde_json::Value>,
    },
}

/// Reads an immutable regular document using an explicit store executable.
///
/// The logical locator may name a root file or a directory member. Immutable
/// aliases must target canonical absolute store locators, remain within sixteen
/// hops and contain no loop. Reading establishes neither admission nor authority.
///
/// # Errors
/// Returns an error for invalid locators or alias targets, store failures,
/// oversized or nonregular files, timeout, or cancellation.
pub fn read_immutable_document_in(
    path: &Path,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    read_descriptor_in(path, nix_store, cancellation).map(|(_, bytes)| bytes)
}

fn run_accessor(
    identity: &Path,
    nix_store: &Path,
    arguments: &[&str],
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    let mut command = aos_core::nix::identity::store_command(nix_store)?;
    command.arg("store").args(arguments).arg(identity);
    let environment = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect::<Vec<_>>();
    let output = crate::deployment::process::run_bounded(
        &mut command,
        None,
        limit,
        &super::ImportControl(cancellation),
        &environment,
    )?;
    ensure!(
        output.status.success(),
        "immutable document read failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

struct ResolvedNode {
    identity: PathBuf,
    node: DocumentNode,
    _roots: crate::store::temp_roots::TemporaryRoots,
}

/// Resolves retained aliases and returns the exact selected-store file identity.
pub(crate) fn read_descriptor_in(
    path: &Path,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<(PathBuf, Vec<u8>)> {
    let resolved = resolve_node_in(path, nix_store, cancellation, true)?;
    let DocumentNode::Regular { size, executable } = resolved.node else {
        bail!("immutable document is not a regular file");
    };
    ensure!(
        !executable && size <= GRAPH_LIMITS.max_bytes as u64,
        "immutable document must be a bounded non-executable regular file"
    );
    let bytes = run_accessor(
        &resolved.identity,
        nix_store,
        &["cat"],
        GRAPH_LIMITS.max_bytes,
        cancellation,
    )?;
    ensure!(
        bytes.len() as u64 == size,
        "immutable document size changed during reading"
    );
    Ok((resolved.identity, bytes))
}

/// Reads a canonical companion document without following any store symlink.
pub(crate) fn read_regular_store_document_in(
    path: &Path,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    crate::deployment::nix::store_root_and_suffix(path)?;
    let resolved = resolve_node_in(path, nix_store, cancellation, false)?;
    let DocumentNode::Regular { size, executable } = resolved.node else {
        bail!("native artifact document is not a regular file");
    };
    ensure!(
        !executable && size <= GRAPH_LIMITS.max_bytes as u64,
        "native artifact document must be bounded and non-executable"
    );
    let bytes = run_accessor(
        &resolved.identity,
        nix_store,
        &["cat"],
        GRAPH_LIMITS.max_bytes,
        cancellation,
    )?;
    ensure!(
        bytes.len() as u64 == size,
        "native artifact document size changed"
    );
    Ok(bytes)
}

/// Resolves one immutable directory and returns its bounded immediate member names.
pub(crate) fn read_directory_in(
    path: &Path,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<(PathBuf, Vec<String>)> {
    let resolved = resolve_node_in(path, nix_store, cancellation, true)?;
    let DocumentNode::Directory { entries } = resolved.node else {
        bail!("immutable input is not a directory");
    };
    Ok((resolved.identity, entries.into_keys().collect()))
}

fn resolve_node_in(
    path: &Path,
    nix_store: &Path,
    cancellation: &CancellationToken,
    allow_aliases: bool,
) -> Result<ResolvedNode> {
    let mut identity = if path.starts_with("/nix/store") {
        path.to_owned()
    } else {
        // Profile and image aliases are protected metadata; their targets need
        // not exist in the host filesystem when Nix selects an isolated store.
        match std::fs::read_link(path) {
            Ok(target) => target,
            Err(_) => std::fs::canonicalize(path)?,
        }
    };
    let mut visited = BTreeSet::new();
    let mut roots = crate::store::temp_roots::TemporaryRoots::open(nix_store, cancellation)?;
    'aliases: for _ in 0..=16 {
        let (root, suffix) = crate::deployment::nix::store_root_and_suffix(&identity)?;
        ensure!(
            visited.insert(identity.clone()),
            "immutable document alias loop"
        );
        roots.retain(
            [root
                .to_str()
                .context("document root is not UTF-8")?
                .to_owned()],
            cancellation,
        )?;
        let components = suffix
            .components()
            .map(|part| part.as_os_str().to_owned())
            .collect::<Vec<_>>();
        let mut prefix = root;
        for depth in 0..=components.len() {
            if depth > 0 {
                prefix.push(&components[depth - 1]);
            }
            let metadata = run_accessor(
                &prefix,
                nix_store,
                &["ls", "--json"],
                64 * 1024,
                cancellation,
            )?;
            let node = serde_json::from_slice::<DocumentNode>(&metadata)?;
            match node {
                DocumentNode::Symlink { target } => {
                    ensure!(allow_aliases, "native artifact document contains a symlink");
                    ensure!(
                        target.len() <= 4096,
                        "immutable document alias target exceeds its bound"
                    );
                    identity = PathBuf::from(target);
                    crate::deployment::nix::store_root_and_suffix(&identity)?;
                    for remaining in &components[depth..] {
                        identity.push(remaining);
                    }
                    // Resolve all aliases ourselves: the local store accessor
                    // must never kernel-follow a parent link into the host store.
                    // The next iteration registers the target before any read.
                    continue 'aliases;
                }
                node if depth == components.len() => {
                    return Ok(ResolvedNode {
                        identity,
                        node,
                        _roots: roots,
                    });
                }
                DocumentNode::Directory { .. } => {}
                DocumentNode::Regular { .. } => {
                    bail!("immutable document parent is not a directory")
                }
            }
        }
    }
    bail!("immutable document alias depth exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_store_documents_resolve_aliases_and_reject_companion_links() {
        let Ok(fixture) = std::env::var("AOS_TEST_IMMUTABLE_DOCUMENT_FIXTURE") else {
            return;
        };
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
        let executable = Path::new(fixture["nixStore"].as_str().unwrap());
        let cancellation = CancellationToken::default();
        let expected = fixture["expected"].as_str().unwrap().as_bytes();
        let read = |key: &str| {
            read_immutable_document_in(
                Path::new(fixture[key].as_str().unwrap()),
                executable,
                &cancellation,
            )
        };

        assert_eq!(read("regular").unwrap(), expected);
        assert_eq!(read("alias").unwrap(), expected);
        assert_eq!(read("parentAlias").unwrap(), expected);
        assert!(read("relativeAlias").is_err());
        assert!(read("executable").is_err());
        assert_eq!(read("sixteenAliases").unwrap(), expected);
        assert!(read("seventeenAliases").is_err());
        assert_eq!(
            read_regular_store_document_in(
                Path::new(fixture["regular"].as_str().unwrap()),
                executable,
                &cancellation,
            )
            .unwrap(),
            expected
        );
        let regular = Path::new(fixture["regular"].as_str().unwrap());
        let mut artifact = crate::types::NativeArtifactMeta {
            store_path: regular.parent().unwrap().to_str().unwrap().into(),
            nar_hash: fixture["narHash"].as_str().unwrap().into(),
            nar_size: fixture["narSize"].as_u64().unwrap(),
            references: Vec::new(),
            document_sha256: aos_contract::Sha256Digest::of_bytes(expected).to_string(),
            document_size: expected.len() as u64,
        };
        assert_eq!(
            crate::native_artifact::read_document_in(
                &artifact,
                "options.json",
                executable,
                &cancellation,
            )
            .unwrap(),
            expected
        );
        artifact.document_sha256 = aos_contract::Sha256Digest::of_bytes(b"different").to_string();
        assert!(
            crate::native_artifact::read_document_in(
                &artifact,
                "options.json",
                executable,
                &cancellation,
            )
            .is_err()
        );

        for key in ["alias", "parentAlias", "relativeAlias"] {
            assert!(
                read_regular_store_document_in(
                    Path::new(fixture[key].as_str().unwrap()),
                    executable,
                    &cancellation,
                )
                .is_err()
            );
        }
    }
}
