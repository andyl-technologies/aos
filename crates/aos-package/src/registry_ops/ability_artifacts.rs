//! Canonical realization of package ability artifact selectors.
//!
//! Publication resolves one selected Nix output through this module. The
//! resulting semantic reference and retention record come from the same store
//! graph inspection, so callers cannot compute or rewrite either identity on a
//! separate path.

use crate::ability_package::canonical_nar_hash;
use crate::registry_ops::store_paths::{
    introspect_closure_nars, introspect_direct_reference_hashes, introspect_store_path,
    validate_store_path_release_policy,
};
use crate::types::{AbilityArtifactRetentionMeta, AbilityClosureMemberMeta};
use anyhow::{Context, Result, bail};
use aos_ability_model::ArtifactReference;
use aos_contract::Sha256Digest;
use serde::Serialize;

/// An ability artifact reference and the exact closure retained for it.
pub(in crate::registry_ops) struct ResolvedAbilityArtifact {
    /// Semantic reference embedded in the checked package document.
    pub(in crate::registry_ops) reference: ArtifactReference,
    /// Complete realization metadata retained by the registry.
    pub(in crate::registry_ops) retention: AbilityArtifactRetentionMeta,
}

#[derive(Serialize)]
struct ArtifactContent<'a> {
    nar_hash: &'a str,
    store_path: &'a str,
}

/// Resolves one selected store output into its canonical ability identities.
///
/// # Errors
///
/// Returns an error when the store output is unavailable, violates release
/// policy, has malformed NAR metadata, or its complete closure cannot be
/// inspected and canonically encoded.
pub(in crate::registry_ops) fn resolve_store_artifact(
    store_path: &str,
) -> Result<ResolvedAbilityArtifact> {
    let artifact = introspect_store_path(store_path)
        .with_context(|| format!("introspecting ability artifact {store_path}"))?;
    validate_store_path_release_policy(&artifact)?;

    let nar_hash = canonical_nar_hash(&artifact.nar_hash)?;
    let nar_digest = Sha256Digest::parse(&nar_hash)
        .with_context(|| format!("parsing canonical NAR identity for {store_path}"))?;

    let mut closure = introspect_closure_nars(store_path)?
        .into_iter()
        .map(|member| {
            let references = introspect_direct_reference_hashes(&member.path)?;
            Ok(AbilityClosureMemberMeta {
                store_path: member.path,
                nar_hash: canonical_nar_hash(&member.nar_hash)?,
                nar_size: member.nar_size,
                references,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    closure.sort();

    if !closure.iter().any(|member| member.store_path == store_path) {
        bail!("ability artifact closure omits its root {store_path}");
    }

    let closure_digest = Sha256Digest::of_canonical("aos.ability.closure/v1", &closure)?;
    let content = Sha256Digest::of_canonical(
        "aos.ability.artifact/v1",
        &ArtifactContent {
            nar_hash: &nar_hash,
            store_path,
        },
    )?;

    Ok(ResolvedAbilityArtifact {
        reference: ArtifactReference {
            content,
            store_path: store_path.to_string(),
            nar_hash: nar_digest,
            closure: closure_digest,
        },
        retention: AbilityArtifactRetentionMeta {
            content: content.to_string(),
            store_path: store_path.to_string(),
            nar_hash,
            nar_size: artifact.nar_size,
            closure_digest: closure_digest.to_string(),
            closure,
        },
    })
}
