//! Immutable artifact locators and path-independent content and closure identities.
//!
//! Store paths locate bytes; NAR hashes and semantic digests identify them. The
//! digest domains intentionally retain their version-1 spellings across crate
//! moves so existing authenticated documents remain valid.
//!
//! An authenticated locator has this closed JSON shape:
//!
//! ```json
//! {"content":"sha256:<digest>","store_path":"/nix/store/<output>","nar_hash":"sha256:<digest>","closure":"sha256:<digest>"}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use aos_core::identity::{IdentityError, LocalKey};

/// Identifies an exact immutable artifact and its authenticated closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    /// Identifies the artifact's exact bytes or canonical semantic content.
    pub content: Sha256Digest,
    /// Preserves the exact Nix store path selected by the authenticated release.
    pub store_path: String,
    /// Preserves the artifact's NAR identity.
    pub nar_hash: Sha256Digest,
    /// Identifies the authenticated transitive closure association.
    pub closure: Sha256Digest,
}

/// Carries the locator-independent semantic identity of an immutable artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    /// Names the domain-specific content represented by the artifact.
    pub content: Sha256Digest,
    /// Authenticates the exact immutable NAR bytes.
    pub nar_hash: Sha256Digest,
    /// Identifies the artifact's path-independent dependency graph.
    pub closure: Sha256Digest,
}

impl ArtifactReference {
    /// Projects this authenticated locator to its semantic artifact identity.
    #[must_use]
    pub const fn identity(&self) -> ArtifactIdentity {
        ArtifactIdentity {
            content: self.content,
            nar_hash: self.nar_hash,
            closure: self.closure,
        }
    }
}

/// Describes one closure member before locator-independent projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactClosureMemberInput {
    /// Gives this member its temporary graph-local lookup key.
    pub key: String,
    /// Preserves the exact immutable NAR identity.
    pub nar_hash: Sha256Digest,
    /// Lists direct dependency keys within the same closure.
    pub references: Vec<String>,
}

/// Reports malformed closure graphs during semantic identity projection.
#[derive(Debug, Error)]
pub enum ArtifactClosureError {
    /// The requested root is absent from the supplied closure.
    #[error("artifact closure omits root '{root}'")]
    MissingRoot {
        /// Names the absent graph-local root key.
        root: String,
    },
    /// Two closure members use the same graph-local lookup key.
    #[error("artifact closure repeats member key '{key}'")]
    DuplicateMember {
        /// Names the repeated graph-local key.
        key: String,
    },
    /// A member references a key outside the supplied closure.
    #[error("artifact closure member '{member}' references absent member '{reference}'")]
    MissingReference {
        /// Names the member containing the edge.
        member: String,
        /// Names the missing edge target.
        reference: String,
    },
    /// Canonical encoding of the normalized graph failed.
    #[error("encoding the semantic artifact closure failed")]
    Encode {
        /// Retains the canonical encoder error.
        #[source]
        source: anyhow::Error,
    },
}

/// Computes a path-independent identity for an immutable artifact closure.
///
/// Member keys only join the input graph. The encoded identity contains the
/// root's content/NAR identity plus sorted member identities and edges, so a
/// store relocation cannot change it while bytes or topology changes do.
///
/// # Errors
///
/// Returns an error when the root or an edge target is absent, member keys are
/// duplicated, or the normalized graph cannot be canonically encoded.
pub fn artifact_closure_identity(
    root: &str,
    members: &[ArtifactClosureMemberInput],
) -> Result<Sha256Digest, ArtifactClosureError> {
    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
    struct NodeIdentity {
        content: Sha256Digest,
        nar_hash: Sha256Digest,
    }

    #[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
    struct ClosureMember {
        identity: NodeIdentity,
        references: Vec<NodeIdentity>,
    }

    #[derive(Serialize)]
    struct ClosureDocument {
        root: NodeIdentity,
        members: Vec<ClosureMember>,
    }

    let mut identities = BTreeMap::new();
    for member in members {
        let identity = NodeIdentity {
            content: artifact_content_identity(&member.nar_hash),
            nar_hash: member.nar_hash,
        };
        if identities.insert(member.key.as_str(), identity).is_some() {
            return Err(ArtifactClosureError::DuplicateMember {
                key: member.key.clone(),
            });
        }
    }
    let root_identity =
        identities
            .get(root)
            .copied()
            .ok_or_else(|| ArtifactClosureError::MissingRoot {
                root: root.to_string(),
            })?;

    let mut normalized = Vec::with_capacity(members.len());
    for member in members {
        let mut references = BTreeSet::new();
        for reference in &member.references {
            let identity = identities.get(reference.as_str()).copied().ok_or_else(|| {
                ArtifactClosureError::MissingReference {
                    member: member.key.clone(),
                    reference: reference.clone(),
                }
            })?;
            references.insert(identity);
        }
        normalized.push(ClosureMember {
            identity: identities[member.key.as_str()],
            references: references.into_iter().collect(),
        });
    }
    normalized.sort();

    Sha256Digest::of_canonical(
        "aos.ability.semantic-closure/v1",
        &ClosureDocument {
            root: root_identity,
            members: normalized,
        },
    )
    .map_err(|source| ArtifactClosureError::Encode { source })
}

/// Computes the semantic content identity for one immutable NAR.
///
/// The Nix store path is an authenticated locator and does not participate in
/// this identity. Two releases that retain byte-identical NARs therefore name
/// the same content even when their input-addressed store paths differ.
#[must_use]
pub fn artifact_content_identity(nar_hash: &Sha256Digest) -> Sha256Digest {
    Sha256Digest::separated("aos.ability.artifact/v1", nar_hash.as_bytes())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn artifact_content_identity_depends_only_on_the_nar() {
        let nar_hash = Sha256Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("valid test NAR identity");

        assert_eq!(
            artifact_content_identity(&nar_hash).to_string(),
            "sha256:d79a5482e516d2659bd271d08dc6b6a0358eb75402da659e368136554b133331"
        );
    }

    #[test]
    fn artifact_closure_identity_excludes_locators_and_binds_bytes_and_topology() {
        let root_nar = Sha256Digest::of_bytes(b"root NAR");
        let dependency_nar = Sha256Digest::of_bytes(b"dependency NAR");
        let closure = vec![
            ArtifactClosureMemberInput {
                key: "root-path-hash".to_string(),
                nar_hash: root_nar,
                references: vec!["dependency-path-hash".to_string()],
            },
            ArtifactClosureMemberInput {
                key: "dependency-path-hash".to_string(),
                nar_hash: dependency_nar,
                references: Vec::new(),
            },
        ];
        let relocated = vec![
            ArtifactClosureMemberInput {
                key: "relocated-root".to_string(),
                nar_hash: root_nar,
                references: vec!["relocated-dependency".to_string()],
            },
            ArtifactClosureMemberInput {
                key: "relocated-dependency".to_string(),
                nar_hash: dependency_nar,
                references: Vec::new(),
            },
        ];

        let identity = artifact_closure_identity("root-path-hash", &closure).unwrap();
        assert_eq!(
            identity,
            artifact_closure_identity("relocated-root", &relocated).unwrap()
        );

        let mut changed_dependency = closure.clone();
        changed_dependency[1].nar_hash = Sha256Digest::of_bytes(b"changed dependency NAR");
        assert_ne!(
            identity,
            artifact_closure_identity("root-path-hash", &changed_dependency).unwrap()
        );

        let mut changed_topology = closure.clone();
        changed_topology[0].references.clear();
        assert_ne!(
            identity,
            artifact_closure_identity("root-path-hash", &changed_topology).unwrap()
        );
    }
}
