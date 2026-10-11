//! Bounded artifact identities from Nix's sandbox-exported reference graph.
//!
//! This private build helper retains the existing path-independent NAR and
//! closure identities. It reads the named graph from Nix's structured attributes;
//! it never substitutes authored dependency metadata or runs a store query.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{
    ArtifactClosureMemberInput, ArtifactReference, artifact_closure_identity,
    artifact_content_identity,
};
use aos_contract::{Sha256Digest, limits::JsonLimits};
use aos_core::nar::cache::canonical_sha256_hex;
use serde::Serialize;

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 32 * 1024 * 1024,
    max_depth: 16,
    max_items: 1_000_000,
    max_string_bytes: 16 * 1024,
};

#[derive(Serialize)]
struct ResolvedArtifact {
    artifact: ArtifactReference,
    closure_paths: Vec<String>,
}

/// Resolves one realized root and writes a new exact artifact/closure document.
///
/// # Errors
/// Returns an error for excessive or nonregular input, malformed graph custody,
/// unsafe store locators, missing edges, duplicate/unreachable nodes or I/O.
pub(super) fn resolve(arguments: &[String]) -> Result<()> {
    let [root, graph, input, output] = arguments else {
        anyhow::bail!("usage: resolve-exported-artifact ROOT GRAPH ATTRIBUTES OUTPUT");
    };
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(input)?;
    let metadata = input.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= LIMITS.max_bytes as u64,
        "exported graph attributes are not a bounded regular file"
    );
    let mut bytes = Vec::new();
    input
        .take(LIMITS.max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    let resolved = project(root, graph, &bytes)?;
    let bytes = serde_json::to_vec(&resolved)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(output)?;
    output.write_all(&bytes)?;
    Ok(())
}

fn project(root: &str, graph: &str, bytes: &[u8]) -> Result<ResolvedArtifact> {
    validate_path(root)?;
    ensure!(
        !graph.is_empty()
            && graph.len() <= 128
            && graph
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "invalid exported graph selector"
    );
    let attributes: serde_json::Value = LIMITS.decode(bytes, "Nix exported graph attributes")?;
    let rows = attributes
        .get(graph)
        .and_then(serde_json::Value::as_array)
        .context("named exported reference graph is absent")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 65_536,
        "exported graph exceeds node allowance"
    );
    let mut members = BTreeMap::new();
    for row in rows {
        let path = row
            .get("path")
            .and_then(serde_json::Value::as_str)
            .context("exported graph path")?;
        validate_path(path)?;
        let hash = row
            .get("narHash")
            .and_then(serde_json::Value::as_str)
            .context("exported graph NAR identity")?;
        let hash = Sha256Digest::parse(&format!("sha256:{}", canonical_sha256_hex(hash)?))?;
        let edges = row
            .get("references")
            .and_then(serde_json::Value::as_array)
            .context("exported graph references")?;
        ensure!(
            edges.len() <= 65_536,
            "exported node exceeds edge allowance"
        );
        let mut references = BTreeSet::new();
        for edge in edges {
            let path = edge
                .as_str()
                .context("exported graph edge is not a locator")?;
            validate_path(path)?;
            ensure!(
                references.insert(path.to_owned()),
                "exported graph repeats an edge"
            );
        }
        ensure!(
            members
                .insert(
                    path.to_owned(),
                    ArtifactClosureMemberInput {
                        key: path.to_owned(),
                        nar_hash: hash,
                        references: references.into_iter().collect(),
                    }
                )
                .is_none(),
            "exported graph repeats a node"
        );
    }

    let root_member = members
        .get(root)
        .context("realized root is absent from exported graph")?;
    let mut reachable = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(path) = pending.pop() {
        if !reachable.insert(path) {
            continue;
        }
        let member = members
            .get(path)
            .context("exported graph reference has no member")?;
        pending.extend(member.references.iter().map(String::as_str));
    }
    ensure!(
        reachable.len() == members.len(),
        "exported graph contains unreachable members"
    );
    let normalized = members.values().cloned().collect::<Vec<_>>();
    Ok(ResolvedArtifact {
        artifact: ArtifactReference {
            content: artifact_content_identity(&root_member.nar_hash),
            store_path: root.into(),
            nar_hash: root_member.nar_hash,
            closure: artifact_closure_identity(root, &normalized)?,
        },
        closure_paths: members.keys().cloned().collect(),
    })
}

fn validate_path(path: &str) -> Result<()> {
    let name = path
        .strip_prefix("/nix/store/")
        .context("exported graph locator is outside the store")?;
    let (hash, name) = name
        .split_once('-')
        .context("exported graph locator has no store hash")?;
    ensure!(
        hash.len() == 32
            && hash
                .bytes()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
            && !name.is_empty()
            && name.len() <= 211
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+._?=-".contains(&byte)),
        "exported graph locator is not a canonical store root"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/nix/store/00000000000000000000000000000000-root";
    const DEP: &str = "/nix/store/11111111111111111111111111111111-dependency";

    fn attributes() -> serde_json::Value {
        serde_json::json!({"graph":[
            {"path": ROOT, "narHash": Sha256Digest::of_bytes("root"), "narSize": 42, "references": [DEP]},
            {"path": DEP, "narHash": Sha256Digest::of_bytes("dependency"), "narSize": 12, "references": []}
        ], "unrelatedNixAttribute": "not artifact authority"})
    }

    #[test]
    fn resolver_binds_realized_nars_and_topology_and_is_independent_of_row_order() -> Result<()> {
        let mut value = attributes();
        let original = project(ROOT, "graph", &serde_json::to_vec(&value)?)?;
        assert_eq!(
            original.closure_paths,
            vec![ROOT.to_owned(), DEP.to_owned()]
        );
        value["graph"].as_array_mut().unwrap().reverse();
        let reordered = project(ROOT, "graph", &serde_json::to_vec(&value)?)?;
        assert_eq!(original.artifact, reordered.artifact);
        value["graph"][0]["narHash"] = serde_json::to_value(Sha256Digest::of_bytes("changed"))?;
        let changed = project(ROOT, "graph", &serde_json::to_vec(&value)?)?;
        assert_ne!(changed.artifact.closure, original.artifact.closure);
        assert_eq!(changed.artifact.content, original.artifact.content);
        Ok(())
    }

    #[test]
    fn resolver_refuses_missing_duplicate_unreachable_or_unsafe_custody() -> Result<()> {
        let value = attributes();
        let mut duplicate = value.clone();
        duplicate["graph"]
            .as_array_mut()
            .unwrap()
            .push(value["graph"][0].clone());
        assert!(project(ROOT, "graph", &serde_json::to_vec(&duplicate)?).is_err());
        let mut missing = value.clone();
        missing["graph"].as_array_mut().unwrap().pop();
        assert!(project(ROOT, "graph", &serde_json::to_vec(&missing)?).is_err());
        let mut unreachable = value.clone();
        unreachable["graph"][0]["references"] = serde_json::json!([]);
        assert!(project(ROOT, "graph", &serde_json::to_vec(&unreachable)?).is_err());
        for path in [
            "/tmp/claimed-root",
            "/nix/store/00000000000000000000000000000000-root/../escape",
            "/nix/store/00000000000000000000000000000000-root/file",
        ] {
            assert!(project(path, "graph", &serde_json::to_vec(&value)?).is_err());
        }
        assert!(project(ROOT, "missing", &serde_json::to_vec(&value)?).is_err());
        assert!(project(ROOT, "graph", b"{\"graph\":[],\"graph\":[]}").is_err());
        Ok(())
    }
}
