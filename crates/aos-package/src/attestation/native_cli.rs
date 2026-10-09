//! Verifier-owned native source authentication for the package CLI.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_contract::Sha256Digest;
use serde::Deserialize;

use super::native::{
    GenerationEvidence, ImageAdmission, InputEvidence, MeasuredImageEvidence, VerifiedRelease,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub schema: String,
    pub image: MeasuredImageEvidence,
    pub expected_pcr7: String,
    pub expected_pcr12: String,
    pub library_nar_hash: Sha256Digest,
    pub image_roots: Vec<(ImageAdmission, BTreeMap<String, InputEvidence>)>,
    #[serde(default)]
    pub allow_local_root_runtime_modules: bool,
    #[serde(default)]
    pub source_authorities: Vec<super::native::VerifiedSourceAuthorization>,
}

pub(crate) fn authenticate_releases(
    cache: &Path,
    trusted_keys: Vec<PathBuf>,
    record: &GenerationEvidence,
) -> Result<(Vec<String>, Vec<String>, Vec<VerifiedRelease>)> {
    let keys = crate::security::KeyStore::new(trusted_keys);
    let mut active = Vec::new();
    let mut revoked = Vec::new();
    let mut releases: Vec<VerifiedRelease> = Vec::new();
    for evidence in record.inputs.values() {
        let Some(receipt) = &evidence.release else {
            continue;
        };
        crate::types::validate_registry_name(&receipt.registry)?;
        if releases.iter().any(|release| &release.receipt == receipt) {
            continue;
        }
        ensure!(
            receipt.schema == "aos.registry-release-trust/v1",
            "unsupported release authority"
        );
        semver::Version::parse(&receipt.release_tag)?;
        let roster = keys.lookup_all(&receipt.registry);
        let revoked_keys = keys.revoked_fingerprints(&receipt.registry);
        ensure!(
            !revoked_keys.contains(&receipt.tag_signer_key),
            "native source release signer is revoked"
        );
        let signer = roster
            .iter()
            .find(|key| key.fingerprint == receipt.tag_signer_key)
            .context("native source release signer is not active")?;
        let repository = cache.join(&receipt.registry).join("repo.git");
        let object = crate::registry::repo::rev_parse_blocking(
            &repository,
            &format!("{}^{{tag}}", receipt.release_tag),
        )?;
        ensure!(
            crate::security::verify_tag_signature(&repository, &object, &[signer.key_line()])?,
            "native source release signature failed"
        );
        let tag = crate::registry::verify::read_tag_object(&repository, &object)?;
        crate::registry::verify::verify_name_binding(&tag, &receipt.release_tag)?;
        ensure!(
            tag.target_type == crate::registry::verify::TagTarget::Commit
                && tag.object == receipt.commit,
            "native source receipt differs from its authenticated release tag"
        );
        active.extend(roster.into_iter().map(|key| key.fingerprint));
        revoked.extend(revoked_keys);
        let mut roots = BTreeMap::new();
        for input in record
            .inputs
            .values()
            .filter(|input| input.release.as_ref() == Some(receipt))
        {
            let hash = crate::registry::store_path_hash(&input.store_path);
            let shard = hash
                .get(..2)
                .context("native source has an invalid store component")?;
            let path = format!("store/{shard}/{hash}");
            let bytes =
                crate::registry::repo::read_blob_at_blocking(&repository, &tag.object, &path)?
                    .context("native source is absent from its authenticated release graph")?;
            let entry = crate::registry::store::parse_entry(std::str::from_utf8(&bytes)?)?;
            ensure!(
                entry.realisations.iter().any(|realisation| {
                    let mut references: Vec<_> = realisation
                        .deps
                        .iter()
                        .map(|edge| edge.dep_ia.clone())
                        .filter(|dependency| dependency != hash)
                        .collect();
                    references.sort();
                    references.dedup();
                    realisation
                        .nar
                        .matches(&input.nar_hash.to_string(), input.nar_size)
                        && references == input.references
                }),
                "native source NAR or direct references differ from its authenticated release graph"
            );
            roots.insert(input.store_path.clone(), input.clone());
        }
        releases.push(VerifiedRelease {
            receipt: receipt.clone(),
            roots,
        });
    }
    active.sort();
    active.dedup();
    revoked.sort();
    revoked.dedup();
    Ok((active, revoked, releases))
}
