//! Authenticated public ability-reference extraction for registry indexing.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use aos_ability_model::VersionedDocument as _;
use sha2::{Digest, Sha256};

use crate::db::IndexedPackageAbilityReference;
use crate::fetch::SurfaceFetch;

use super::{MAX_IMAGE_NARINFO_BYTES, parse_documentation_narinfo};

/// Fetches and verifies one ability companion and derives its public reference.
///
/// The signed registry entry supplies the companion NAR, exact package-manifest
/// identity, semantic package identity, and primary payload identity. Only
/// bounded public package and interface documents cross into the generated
/// reference.
///
/// # Errors
///
/// Returns an error when cache metadata or bytes disagree with signed metadata,
/// the companion archive is malformed or oversized, a document is noncanonical,
/// or package/interface identities are inconsistent.
pub async fn fetch_package_ability_reference(
    fetch: &dyn SurfaceFetch,
    package_name: &str,
    package_version: &str,
    platform: &str,
    primary_store_path: &str,
    primary_nar_hash: &str,
    ability: &aos_registry_surface::manifest::AbilityPackageMeta,
) -> Result<aos_doc_model::PackageAbilityReference> {
    anyhow::ensure!(
        ability.nar_size > 0
            && ability.nar_size as usize <= aos_doc_model::MAX_ABILITY_COMPANION_NAR_BYTES,
        "package ability companion exceeds the Hub reference bound"
    );
    let store_hash = aos_registry_surface::store::store_path_hash(&ability.store_path)?;
    let narinfo_key = format!("{store_hash}.narinfo");
    let narinfo_bytes = fetch
        .fetch_bounded(&narinfo_key, MAX_IMAGE_NARINFO_BYTES)
        .await?
        .with_context(|| format!("package ability narinfo '{narinfo_key}' is unavailable"))?;
    let narinfo = parse_documentation_narinfo(
        std::str::from_utf8(&narinfo_bytes).context("package ability narinfo is not UTF-8")?,
    )?;
    let actual_references = narinfo
        .references
        .iter()
        .map(|reference| {
            reference
                .split_once('-')
                .map(|(hash, _)| hash)
                .filter(|hash| hash.len() == 32)
                .context("package ability narinfo contains an invalid reference")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected_references = ability
        .references
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        narinfo.store_path == ability.store_path
            && narinfo.compression == "none"
            && narinfo.nar_size == ability.nar_size
            && actual_references == expected_references
            && aos_registry_surface::store::normalize_digest(&narinfo.nar_hash)?
                == aos_registry_surface::store::normalize_digest(&ability.nar_hash)?,
        "package ability narinfo disagrees with signed metadata for {package_name}/{package_version}/{platform}"
    );
    anyhow::ensure!(
        narinfo.url.starts_with("nar/")
            && narinfo.url.ends_with(".nar")
            && narinfo
                .url
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."),
        "package ability narinfo has an unsafe URL"
    );
    let nar_bytes = fetch
        .fetch_bounded(&narinfo.url, aos_doc_model::MAX_ABILITY_COMPANION_NAR_BYTES)
        .await?
        .with_context(|| format!("package ability NAR '{}' is unavailable", narinfo.url))?;
    anyhow::ensure!(
        nar_bytes.len() as u64 == narinfo.file_size
            && hex::encode(Sha256::digest(&nar_bytes))
                == aos_registry_surface::store::canonical_digest_hex(&narinfo.file_hash)?,
        "package ability cache-file identity mismatch"
    );
    anyhow::ensure!(
        nar_bytes.len() as u64 == ability.nar_size
            && hex::encode(Sha256::digest(&nar_bytes))
                == aos_registry_surface::store::canonical_digest_hex(&ability.nar_hash)?,
        "package ability NAR identity mismatch"
    );

    let documents = aos_doc_model::decode_ability_companion_nar(&nar_bytes)?;
    anyhow::ensure!(
        documents.package.len() as u64 == ability.manifest_size
            && hex::encode(Sha256::digest(&documents.package))
                == aos_registry_surface::store::canonical_digest_hex(&ability.manifest_sha256)?,
        "package ability manifest identity mismatch"
    );
    let supported_features = aos_doc_model::ability_reference_supported_features()?;
    let package = aos_ability_model::decode_canonical::<aos_ability_model::PackageDocument>(
        &documents.package,
        aos_ability_model::ABILITY_LIMITS_V1,
        &supported_features,
    )?;
    let primary_nar_hash = format!(
        "sha256:{}",
        aos_registry_surface::store::canonical_digest_hex(primary_nar_hash)?
    );
    anyhow::ensure!(
        package.package.name.as_str() == package_name
            && package.package.version == package_version
            && package.package.payload.store_path == primary_store_path
            && package.package.payload.nar_hash.to_string() == primary_nar_hash
            && package.content_digest()?.to_string() == ability.package_digest
            && match package.activation_mode {
                aos_ability_model::AbilityActivationMode::ContractsOnly => {
                    ability.activation_mode == "contracts-only"
                }
                aos_ability_model::AbilityActivationMode::StructuredEffects => {
                    ability.activation_mode == "structured-effects"
                }
            },
        "package ability selection identity mismatch for {package_name}/{package_version}/{platform}"
    );

    let expected_interface_files = package
        .exports
        .iter()
        .map(|export| format!("{}.json", export.interface.descriptor.hex()))
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        expected_interface_files == documents.interfaces.keys().cloned().collect(),
        "package ability companion interface inventory does not exactly match its exports"
    );
    let mut interfaces = Vec::with_capacity(expected_interface_files.len());
    for file_name in expected_interface_files {
        let bytes = documents
            .interfaces
            .get(&file_name)
            .context("authenticated interface inventory changed during indexing")?;
        let interface = aos_ability_model::decode_canonical::<aos_ability_model::InterfaceDocument>(
            bytes,
            aos_ability_model::ABILITY_LIMITS_V1,
            &supported_features,
        )?;
        anyhow::ensure!(
            format!("{}.json", interface.interface_key()?.descriptor.hex()) == file_name,
            "package ability interface identity mismatch"
        );
        interfaces.push(interface);
    }
    aos_doc_model::PackageAbilityReference::from_documents(&package, &interfaces)
        .context("generating authenticated package ability reference")
}

pub(super) async fn verify_package_ability_references(
    fetch: &dyn SurfaceFetch,
    packages: &[aos_registry_surface::manifest::PackageToml],
) -> Result<Vec<IndexedPackageAbilityReference>> {
    let mut indexed = Vec::new();
    for package in packages {
        for version in &package.versions {
            for (platform, entry) in &version.platforms {
                let Some(ability) = &entry.ability else {
                    continue;
                };
                let reference = fetch_package_ability_reference(
                    fetch,
                    &package.package.name,
                    &version.version,
                    platform,
                    &entry.store_path,
                    &entry.nar_hash,
                    ability,
                )
                .await?;
                indexed.push(IndexedPackageAbilityReference {
                    package_name: package.package.name.clone(),
                    package_version: version.version.clone(),
                    platform: platform.clone(),
                    manifest_sha256: reference.manifest_sha256.to_string(),
                    package_digest: reference.package_digest.to_string(),
                    canonical_json: reference.canonical_json()?,
                });
            }
        }
    }
    indexed.sort_by(|left, right| {
        (&left.package_name, &left.package_version, &left.platform).cmp(&(
            &right.package_name,
            &right.package_version,
            &right.platform,
        ))
    });
    Ok(indexed)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aos_ability_model::{
        AbilityActivationMode, ArtifactReference, ExportDeclaration, PackageDocument,
        PackageImplementation, RequiredFeature, VersionedDocument, decode_canonical,
        encode_canonical,
    };
    use aos_contract::Sha256Digest;

    use super::*;

    struct AbilityFetch {
        objects: BTreeMap<String, Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for AbilityFetch {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.objects.get(path).cloned())
        }

        fn describe(&self) -> String {
            "ability-reference-fixture".into()
        }
    }

    fn nar_field(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u64).to_le_bytes());
        output.extend_from_slice(value);
        output.resize(output.len().div_ceil(8) * 8, 0);
    }

    fn companion_nar(package: &[u8], interface_name: &str, interface: &[u8]) -> Vec<u8> {
        let mut nar = Vec::new();
        for value in [b"nix-archive-1".as_slice(), b"(", b"type", b"directory"] {
            nar_field(&mut nar, value);
        }
        for value in [
            b"entry".as_slice(),
            b"(",
            b"name",
            b"interfaces",
            b"node",
            b"(",
            b"type",
            b"directory",
            b"entry",
            b"(",
            b"name",
        ] {
            nar_field(&mut nar, value);
        }
        nar_field(&mut nar, interface_name.as_bytes());
        for value in [b"node".as_slice(), b"(", b"type", b"regular", b"contents"] {
            nar_field(&mut nar, value);
        }
        nar_field(&mut nar, interface);
        for value in [
            b")".as_slice(),
            b")",
            b")",
            b")",
            b"entry",
            b"(",
            b"name",
            b"package.json",
            b"node",
            b"(",
            b"type",
            b"regular",
            b"contents",
        ] {
            nar_field(&mut nar, value);
        }
        nar_field(&mut nar, package);
        for value in [b")".as_slice(), b")", b")"] {
            nar_field(&mut nar, value);
        }
        nar
    }

    fn signed_fixture() -> (
        AbilityFetch,
        aos_registry_surface::manifest::AbilityPackageMeta,
        Sha256Digest,
    ) {
        let features =
            BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid feature")]);
        let interface_bytes = include_bytes!("../../../../tests/abilities/fixtures/interface.json");
        let interface = decode_canonical::<aos_ability_model::InterfaceDocument>(
            interface_bytes,
            aos_ability_model::ABILITY_LIMITS_V1,
            &features,
        )
        .expect("decode interface fixture");
        let interface_key = interface.interface_key().expect("interface key");
        let artifact = ArtifactReference {
            content: Sha256Digest::from_bytes([1; 32]),
            store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-demo".into(),
            nar_hash: Sha256Digest::from_bytes([2; 32]),
            closure: Sha256Digest::from_bytes([3; 32]),
        };
        let package = PackageDocument {
            schema: PackageDocument::SCHEMA.into(),
            required_features: features.into_iter().collect(),
            activation_mode: AbilityActivationMode::ContractsOnly,
            package: aos_ability_model::document::PackageSubject {
                name: aos_ability_model::LocalKey::new("demo").expect("valid package"),
                version: "1.0.0".into(),
                payload: artifact.clone(),
                source: artifact,
            },
            artifacts: Vec::new(),
            exports: vec![
                ExportDeclaration {
                    name: aos_ability_model::LocalKey::new("echo").expect("valid export"),
                    interface: interface_key.clone(),
                    aggregation: None,
                    implementation: Sha256Digest::from_bytes([4; 32]),
                },
                ExportDeclaration {
                    name: aos_ability_model::LocalKey::new("echo-alias")
                        .expect("valid export alias"),
                    interface: interface_key.clone(),
                    aggregation: None,
                    implementation: Sha256Digest::from_bytes([4; 32]),
                },
            ],
            requirements: Vec::new(),
            module_entry_points: BTreeMap::new(),
            implementation: PackageImplementation {
                providers: Vec::new(),
                handlers: BTreeMap::new(),
            },
            ownership: Vec::new(),
        };
        let package_bytes = encode_canonical(&package).expect("encode package");
        let interface_name = format!("{}.json", interface_key.descriptor.hex());
        let nar = companion_nar(&package_bytes, &interface_name, interface_bytes);
        let nar_digest = hex::encode(Sha256::digest(&nar));
        let store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo-abilities";
        let nar_url = format!("nar/{nar_digest}.nar");
        let narinfo = format!(
            "StorePath: {store_path}\nURL: {nar_url}\nCompression: none\nFileHash: sha256:{nar_digest}\nFileSize: {}\nNarHash: sha256:{nar_digest}\nNarSize: {}\nReferences: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-demo\n",
            nar.len(),
            nar.len(),
        );
        let ability = aos_registry_surface::manifest::AbilityPackageMeta {
            store_path: store_path.into(),
            nar_hash: format!("sha256:{nar_digest}"),
            nar_size: nar.len() as u64,
            references: vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()],
            manifest_sha256: Sha256Digest::of_bytes(&package_bytes).to_string(),
            manifest_size: package_bytes.len() as u64,
            package_digest: package
                .content_digest()
                .expect("package digest")
                .to_string(),
            activation_mode: "contracts-only".into(),
            artifacts: Vec::new(),
            provenance: "provenance/demo.ability.intoto.jsonl".into(),
        };
        let fetch = AbilityFetch {
            objects: BTreeMap::from([
                (
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo".into(),
                    narinfo.into_bytes(),
                ),
                (nar_url, nar),
            ]),
        };
        (fetch, ability, interface_key.descriptor)
    }

    #[tokio::test]
    async fn derives_reference_only_from_exact_signed_companion_bytes() {
        let (fetch, ability, interface_digest) = signed_fixture();

        let reference = fetch_package_ability_reference(
            &fetch,
            "demo",
            "1.0.0",
            "x86_64-linux",
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-demo",
            &Sha256Digest::from_bytes([2; 32]).to_string(),
            &ability,
        )
        .await
        .expect("derive authenticated reference");

        assert_eq!(
            reference.manifest_sha256.to_string(),
            ability.manifest_sha256
        );
        assert_eq!(reference.package_digest.to_string(), ability.package_digest);
        assert_eq!(reference.exports.len(), 2);
        assert_eq!(
            reference.exports[0].interface.content_digest().unwrap(),
            interface_digest
        );
    }

    #[tokio::test]
    async fn rejects_a_signed_locator_with_different_manifest_identity() {
        let (fetch, mut ability, _) = signed_fixture();
        ability.manifest_sha256 = Sha256Digest::from_bytes([9; 32]).to_string();

        assert!(
            fetch_package_ability_reference(
                &fetch,
                "demo",
                "1.0.0",
                "x86_64-linux",
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-demo",
                &Sha256Digest::from_bytes([2; 32]).to_string(),
                &ability,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_a_signed_companion_for_a_different_primary_payload() {
        let (fetch, ability, _) = signed_fixture();

        let error = fetch_package_ability_reference(
            &fetch,
            "demo",
            "1.0.0",
            "x86_64-linux",
            "/nix/store/cccccccccccccccccccccccccccccccc-other",
            &Sha256Digest::from_bytes([2; 32]).to_string(),
            &ability,
        )
        .await
        .expect_err("companion payload must equal the signed primary package");

        assert!(error.to_string().contains("selection identity mismatch"));
    }
}
