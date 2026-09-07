//! Signed static-cache validation and logical NAR projection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use aos_core::nar::cache::{canonical_sha256_hex, NarInfoSigner};
use aos_core::nar::info::{self, NarInfo};
use aos_release::artifact::{
    require_store_path, ArtifactKind, ArtifactRelation, ArtifactRelationship, Compression,
};
use aos_release::build::BuildReportV1;
use aos_release::digest::Sha256Digest;
use aos_release::signing::TrustedEd25519Key;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

use super::{ArtifactAttributes, PayloadBuilder};

pub(super) struct CacheAssembly {
    pub(super) source_ids: BTreeMap<String, String>,
    output_source_ids: BTreeMap<String, Vec<String>>,
}

struct CacheEntry {
    narinfo_path: PathBuf,
    nar_path: PathBuf,
    info: NarInfo,
    narinfo_id: String,
    narinfo_identity: (u64, Sha256Digest),
}

pub(super) fn assemble(
    cache: &Path,
    report: &BuildReportV1,
    key: &TrustedEd25519Key,
    payload: &mut PayloadBuilder,
) -> Result<CacheAssembly> {
    let entries = read_cache(cache, key)?;
    validate_report_paths(&entries, report)?;

    payload.copy(
        &cache.join("nix-cache-info"),
        "cache/configuration".to_owned(),
        ArtifactKind::RegistryObject,
        "cache/nix-cache-info".to_owned(),
        ArtifactAttributes::plain("text/x-nix-cache-info"),
    )?;
    for entry in entries.values() {
        payload.copy(
            &entry.narinfo_path,
            entry.narinfo_id.clone(),
            ArtifactKind::NarInfo,
            format!(
                "cache/narinfo/{}.narinfo",
                info::store_hash(&entry.info.store_path)
            ),
            ArtifactAttributes {
                expected: Some(entry.narinfo_identity),
                ..ArtifactAttributes::plain("text/x-nix-narinfo")
            },
        )?;
    }

    let source_ids = report
        .sources
        .iter()
        .map(|source| {
            (
                source.store_path.clone(),
                format!("source/{}", info::store_hash(&source.store_path)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let planned_ids =
        report
            .outputs
            .iter()
            .fold(BTreeMap::<String, Vec<String>>::new(), |mut ids, output| {
                ids.entry(output.store_path.clone())
                    .or_default()
                    .push(output.id.clone());
                ids
            });
    let mut canonical_ids = BTreeMap::new();
    for (store_path, ids) in &planned_ids {
        let id = ids
            .iter()
            .min()
            .context("planned store path has no artifact id")?;
        canonical_ids.insert(store_path.clone(), id.clone());
    }
    for (store_path, id) in &source_ids {
        canonical_ids
            .entry(store_path.clone())
            .or_insert(id.clone());
    }
    for store_path in entries.keys() {
        canonical_ids
            .entry(store_path.clone())
            .or_insert_with(|| format!("closure/{}", info::store_hash(store_path)));
    }

    let output_source_ids = report
        .outputs
        .iter()
        .map(|output| {
            let ids = output
                .source_store_paths
                .iter()
                .map(|path| {
                    source_ids
                        .get(path)
                        .cloned()
                        .with_context(|| format!("missing source artifact id for {path}"))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((output.id.clone(), ids))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    for output in &report.outputs {
        let entry = entries
            .get(&output.store_path)
            .with_context(|| format!("cache lacks planned output {}", output.store_path))?;
        let relationships = cache_relationships(entry, &entries, &canonical_ids)?;
        let attributes = ArtifactAttributes {
            platform: Some(output.platform),
            system_variant: None,
            media_type: "application/x-nix-nar".to_owned(),
            compression: compression(&entry.info.compression)?,
            derivation: Some(output.derivation.clone()),
            output: Some(output.output.clone()),
            store_path: Some(output.store_path.clone()),
            nar_hash: Some(nar_hash(&entry.info.nar_hash)?),
            relationships,
            expected: Some(nar_identity(entry)?),
        };
        payload.copy(
            &entry.nar_path,
            output.id.clone(),
            ArtifactKind::PackageNar,
            format!(
                "packages/{}{}",
                output.id,
                nar_suffix(&entry.info.compression)?
            ),
            attributes,
        )?;
    }

    for source in &report.sources {
        let entry = entries
            .get(&source.store_path)
            .with_context(|| format!("cache lacks retained source {}", source.store_path))?;
        let id = source_ids[&source.store_path].clone();
        let attributes = ArtifactAttributes {
            media_type: "application/x-nix-nar".to_owned(),
            compression: compression(&entry.info.compression)?,
            nar_hash: None,
            relationships: cache_relationships(entry, &entries, &canonical_ids)?,
            expected: Some(nar_identity(entry)?),
            ..ArtifactAttributes::plain("application/x-nix-nar")
        };
        payload.copy(
            &entry.nar_path,
            id,
            ArtifactKind::Source,
            format!(
                "sources/{}{}",
                info::store_hash(&source.store_path),
                nar_suffix(&entry.info.compression)?
            ),
            attributes,
        )?;
    }

    let direct = planned_ids
        .keys()
        .chain(source_ids.keys())
        .collect::<BTreeSet<_>>();
    for (store_path, entry) in &entries {
        if direct.contains(store_path) {
            continue;
        }
        let id = canonical_ids[store_path].clone();
        let attributes = ArtifactAttributes {
            media_type: "application/x-nix-nar".to_owned(),
            compression: compression(&entry.info.compression)?,
            relationships: cache_relationships(entry, &entries, &canonical_ids)?,
            expected: Some(nar_identity(entry)?),
            ..ArtifactAttributes::plain("application/x-nix-nar")
        };
        payload.copy(
            &entry.nar_path,
            id,
            ArtifactKind::RegistryObject,
            format!(
                "closure/{}{}",
                info::store_hash(store_path),
                nar_suffix(&entry.info.compression)?
            ),
            attributes,
        )?;
    }

    Ok(CacheAssembly {
        source_ids,
        output_source_ids,
    })
}

pub(super) fn attach_supply_chain_relationships(
    artifacts: &mut [aos_release::artifact::ArtifactRecord],
    cache: &CacheAssembly,
) -> Result<()> {
    for artifact in artifacts
        .iter_mut()
        .filter(|artifact| artifact.kind == ArtifactKind::PackageNar)
    {
        let sources = cache
            .output_source_ids
            .get(&artifact.id)
            .with_context(|| format!("missing source relationship map for {}", artifact.id))?;
        for source in sources {
            artifact.relationships.push(ArtifactRelationship {
                relation: ArtifactRelation::CorrespondingSource,
                target: source.clone(),
            });
        }
        artifact.relationships.push(ArtifactRelationship {
            relation: ArtifactRelation::LicensedBy,
            target: "license/release-inventory".to_owned(),
        });
    }
    Ok(())
}

fn read_cache(cache: &Path, key: &TrustedEd25519Key) -> Result<BTreeMap<String, CacheEntry>> {
    let cache_info = cache.join("nix-cache-info");
    if !cache_info.is_file() {
        bail!("static cache lacks nix-cache-info");
    }
    let mut paths = fs::read_dir(cache)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    let mut entries = BTreeMap::new();
    for path in paths {
        if path.extension().and_then(|extension| extension.to_str()) != Some("narinfo") {
            continue;
        }
        let bytes = super::super::capture::control_file(&path, "signed narinfo")?;
        let text = std::str::from_utf8(&bytes).context("narinfo is not UTF-8")?;
        let parsed = info::parse(text)?;
        require_store_path(&parsed.store_path, false)?;
        verify_signature(&parsed, key)
            .with_context(|| format!("verifying signed narinfo {}", path.display()))?;
        let expected_name = format!("{}.narinfo", info::store_hash(&parsed.store_path));
        if path.file_name().and_then(|name| name.to_str()) != Some(&expected_name) {
            bail!("cache narinfo filename differs from its StorePath");
        }
        let relative = aos_release::artifact::BundlePath::parse(parsed.url.clone())?;
        if !relative.as_str().starts_with("nar/") {
            bail!("cache narinfo URL is outside the nar directory");
        }
        let nar_path = cache.join(relative.as_str());
        aos_package::verify::verify_nar_identity_with_compression(
            &nar_path,
            &parsed.nar_hash,
            parsed.nar_size,
            &parsed.compression,
        )
        .with_context(|| format!("verifying NAR payload {}", nar_path.display()))?;
        let narinfo_id = format!("narinfo/{}", info::store_hash(&parsed.store_path));
        let store_path = parsed.store_path.clone();
        if entries
            .insert(
                store_path.clone(),
                CacheEntry {
                    narinfo_path: path,
                    nar_path,
                    info: parsed,
                    narinfo_id,
                    narinfo_identity: (u64::try_from(bytes.len())?, Sha256Digest::of_bytes(&bytes)),
                },
            )
            .is_some()
        {
            bail!("static cache repeats StorePath {store_path}");
        }
    }
    if entries.is_empty() {
        bail!("static cache contains no signed narinfos");
    }
    Ok(entries)
}

fn validate_report_paths(
    entries: &BTreeMap<String, CacheEntry>,
    report: &BuildReportV1,
) -> Result<()> {
    for output in &report.outputs {
        let entry = entries
            .get(&output.store_path)
            .with_context(|| format!("cache lacks build output {}", output.id))?;
        if canonical_sha256_hex(&entry.info.nar_hash)? != canonical_sha256_hex(&output.nar_hash)?
            || entry.info.nar_size != output.nar_size
        {
            bail!("cache narinfo differs from build output {}", output.id);
        }
    }
    for source in &report.sources {
        let entry = entries
            .get(&source.store_path)
            .with_context(|| format!("cache lacks build source {}", source.store_path))?;
        if canonical_sha256_hex(&entry.info.nar_hash)? != canonical_sha256_hex(&source.nar_hash)?
            || entry.info.nar_size != source.nar_size
        {
            bail!(
                "cache narinfo differs from retained source {}",
                source.store_path
            );
        }
    }
    for entry in entries.values() {
        for reference in reference_paths(&entry.info)? {
            if !entries.contains_key(&reference) {
                bail!(
                    "static cache closure for {} lacks reference {reference}",
                    entry.info.store_path
                );
            }
        }
    }
    Ok(())
}

fn verify_signature(info: &NarInfo, key: &TrustedEd25519Key) -> Result<()> {
    let [value] = info.signatures.as_slice() else {
        bail!("narinfo must contain one exact cache signature");
    };
    let (key_id, encoded) = value
        .split_once(':')
        .context("narinfo signature does not use KEY_ID:BASE64")?;
    if key_id != key.key_id || encoded.contains(':') {
        bail!("narinfo signature key differs from the release plan");
    }
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("decoding narinfo signature")?;
    let signature = Signature::from_slice(&signature_bytes)
        .context("narinfo signature is not an Ed25519 signature")?;
    let public_key = VerifyingKey::from_bytes(&key.public_key)
        .context("cache public key is not a valid Ed25519 key")?;
    let store = Path::new(&info.store_path)
        .parent()
        .and_then(Path::to_str)
        .context("narinfo StorePath has no UTF-8 store directory")?;
    let references = info
        .references
        .iter()
        .map(|reference| format!("{store}/{}", info::basename(reference)))
        .collect::<Vec<_>>();
    let fingerprint = NarInfoSigner::fingerprint(
        &info.store_path,
        &info.nar_hash,
        i64::try_from(info.nar_size)?,
        &references,
    );
    public_key
        .verify(fingerprint.as_bytes(), &signature)
        .context("narinfo signature verification failed")
}

fn cache_relationships(
    entry: &CacheEntry,
    entries: &BTreeMap<String, CacheEntry>,
    canonical_ids: &BTreeMap<String, String>,
) -> Result<Vec<ArtifactRelationship>> {
    let mut relationships = vec![ArtifactRelationship {
        relation: ArtifactRelation::AuthenticatedBy,
        target: entry.narinfo_id.clone(),
    }];
    for reference in reference_paths(&entry.info)? {
        if !entries.contains_key(&reference) {
            bail!("cache relationship names absent reference {reference}");
        }
        relationships.push(ArtifactRelationship {
            relation: ArtifactRelation::Contains,
            target: canonical_ids
                .get(&reference)
                .cloned()
                .with_context(|| format!("cache reference lacks artifact id {reference}"))?,
        });
    }
    Ok(relationships)
}

fn reference_paths(info: &NarInfo) -> Result<Vec<String>> {
    let store = Path::new(&info.store_path)
        .parent()
        .and_then(Path::to_str)
        .context("narinfo StorePath has no UTF-8 store directory")?;
    let paths = info
        .references
        .iter()
        .map(|reference| format!("{store}/{}", info::basename(reference)))
        .collect::<Vec<_>>();
    for path in &paths {
        require_store_path(path, false)?;
    }
    Ok(paths)
}

fn nar_identity(entry: &CacheEntry) -> Result<(u64, Sha256Digest)> {
    let size = entry
        .info
        .file_size
        .context("signed narinfo has no FileSize")?;
    let hash = entry
        .info
        .file_hash
        .as_deref()
        .context("signed narinfo has no FileHash")?;
    Ok((size, nar_hash(hash)?))
}

fn nar_hash(value: &str) -> Result<Sha256Digest> {
    Sha256Digest::parse(&format!("sha256:{}", canonical_sha256_hex(value)?))
}

fn compression(value: &str) -> Result<Compression> {
    match value {
        "none" => Ok(Compression::None),
        "zstd" => Ok(Compression::Zstd),
        other => bail!("unsupported cache compression {other}"),
    }
}

fn nar_suffix(value: &str) -> Result<&'static str> {
    match value {
        "none" => Ok(".nar"),
        "zstd" => Ok(".nar.zst"),
        other => bail!("unsupported cache compression {other}"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use aos_release::build::BUILD_REPORT_V1;

    use super::*;

    #[test]
    fn narinfo_signature_binds_the_complete_nix_fingerprint() -> Result<()> {
        let seed = [19_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let encoded = base64::engine::general_purpose::STANDARD.encode(seed);
        let signer = NarInfoSigner::from_key_content(&format!("cache-1:{encoded}"))?;
        let key =
            TrustedEd25519Key::from_encoded("cache-1", &signing_key.verifying_key().to_bytes())?;
        let mut info = NarInfo {
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package".to_owned(),
            url: "nar/archive.nar.zst".to_owned(),
            compression: "zstd".to_owned(),
            file_hash: Some(format!("sha256:{}", "11".repeat(32))),
            file_size: Some(128),
            nar_hash: format!("sha256:{}", "22".repeat(32)),
            nar_size: 256,
            references: vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-runtime".to_owned()],
            deriver: None,
            signatures: Vec::new(),
        };
        let references = vec!["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-runtime".to_owned()];
        let fingerprint = NarInfoSigner::fingerprint(
            &info.store_path,
            &info.nar_hash,
            i64::try_from(info.nar_size)?,
            &references,
        );
        info.signatures.push(
            signer
                .sign(&fingerprint)
                .context("test signer did not produce a signature")?,
        );

        verify_signature(&info, &key)?;
        info.nar_size += 1;
        assert!(verify_signature(&info, &key).is_err());
        Ok(())
    }

    #[test]
    fn cache_assembly_checks_the_declared_compressed_identity() -> Result<()> {
        let (valid_cache, key) = signed_cache(false)?;
        let output = tempfile::tempdir()?;
        let mut payload = PayloadBuilder::new(output.path().join("valid"))?;
        assemble(valid_cache.path(), &empty_report(), &key, &mut payload)?;
        assert_eq!(payload.artifacts.len(), 3);

        let (invalid_cache, key) = signed_cache(true)?;
        let mut payload = PayloadBuilder::new(output.path().join("invalid"))?;
        let Err(error) = assemble(invalid_cache.path(), &empty_report(), &key, &mut payload) else {
            panic!("cache assembly should reject a false compressed identity");
        };
        assert!(error
            .to_string()
            .contains("differs from its finalized identity"));
        Ok(())
    }

    fn signed_cache(
        use_incorrect_file_hash: bool,
    ) -> Result<(tempfile::TempDir, TrustedEd25519Key)> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("nar"))?;
        fs::write(
            root.path().join("nix-cache-info"),
            b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n",
        )?;

        let nar_bytes = b"signed cache identity fixture";
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
        encoder.write_all(nar_bytes)?;
        let compressed = encoder.finish()?;
        let nar_path = root.path().join("nar/fixture.nar.zst");
        fs::write(&nar_path, &compressed)?;

        let seed = [23_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let encoded = base64::engine::general_purpose::STANDARD.encode(seed);
        let signer = NarInfoSigner::from_key_content(&format!("cache-1:{encoded}"))?;
        let key =
            TrustedEd25519Key::from_encoded("cache-1", &signing_key.verifying_key().to_bytes())?;
        let store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture";
        let file_hash = if use_incorrect_file_hash {
            format!("sha256:{}", "00".repeat(32))
        } else {
            Sha256Digest::of_bytes(&compressed).to_string()
        };
        let mut narinfo = NarInfo {
            store_path: store_path.to_owned(),
            url: "nar/fixture.nar.zst".to_owned(),
            compression: "zstd".to_owned(),
            file_hash: Some(file_hash),
            file_size: Some(u64::try_from(compressed.len())?),
            nar_hash: Sha256Digest::of_bytes(nar_bytes).to_string(),
            nar_size: u64::try_from(nar_bytes.len())?,
            references: Vec::new(),
            deriver: None,
            signatures: Vec::new(),
        };
        let fingerprint = NarInfoSigner::fingerprint(
            store_path,
            &narinfo.nar_hash,
            i64::try_from(narinfo.nar_size)?,
            &[],
        );
        narinfo.signatures.push(
            signer
                .sign(&fingerprint)
                .context("test signer did not produce a signature")?,
        );
        fs::write(
            root.path().join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo"),
            info::format(&narinfo),
        )?;
        Ok((root, key))
    }

    fn empty_report() -> BuildReportV1 {
        BuildReportV1 {
            schema_version: BUILD_REPORT_V1.to_owned(),
            plan_digest: Sha256Digest::of_bytes(b"plan"),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            outputs: Vec::new(),
            sources: Vec::new(),
            completed_at: "2026-09-03T13:00:00Z".to_owned(),
        }
    }
}
