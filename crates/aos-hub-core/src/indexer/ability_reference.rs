//! Authenticated public ability-reference extraction for registry indexing.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use aos_ability_model::ArtifactReference;
use aos_ability_validate::{
    AbilityContractData, CheckedAbilityContract, PackageOutputSelector, decode_package_projection,
    resolve_package_projection, validate_ability_contract,
};
use aos_contract::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::db::IndexedPackageAbilityReference;
use crate::fetch::SurfaceFetch;

use super::{MAX_IMAGE_NARINFO_BYTES, parse_documentation_narinfo};

/// Fetches and verifies one signed package ability publication and derives its public reference.
///
/// The signed registry entry supplies the package ability NAR, exact package-manifest
/// identity, semantic package identity, and primary payload identity. Only
/// bounded public package and interface documents cross into the generated
/// reference.
///
/// # Errors
///
/// Returns an error when cache metadata or bytes disagree with signed metadata,
/// the package publication archive is malformed or oversized, a document is noncanonical,
/// or package/interface identities are inconsistent.
pub async fn fetch_package_ability_reference(
    fetch: &dyn SurfaceFetch,
    package_name: &str,
    package_version: &str,
    platform: &str,
    primary_store_path: &str,
    primary_nar_hash: &str,
    contract: &aos_registry_surface::manifest::PackageContractMeta,
) -> Result<aos_doc_model::PackageAbilityReference> {
    let document = &contract.document;
    anyhow::ensure!(
        document.nar_size > 0
            && document.nar_size as usize <= aos_doc_model::MAX_PACKAGE_ABILITY_NAR_BYTES,
        "package signed package ability publication exceeds the Hub reference bound"
    );
    let store_hash = aos_registry_surface::store::store_path_hash(&document.store_path)?;
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
    let expected_references = document
        .references
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        narinfo.store_path == document.store_path
            && narinfo.compression == "none"
            && narinfo.nar_size == document.nar_size
            && actual_references == expected_references
            && aos_registry_surface::store::normalize_digest(&narinfo.nar_hash)?
                == aos_registry_surface::store::normalize_digest(&document.nar_hash)?,
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
        .fetch_bounded(&narinfo.url, aos_doc_model::MAX_PACKAGE_ABILITY_NAR_BYTES)
        .await?
        .with_context(|| format!("package ability NAR '{}' is unavailable", narinfo.url))?;
    anyhow::ensure!(
        nar_bytes.len() as u64 == narinfo.file_size
            && hex::encode(Sha256::digest(&nar_bytes))
                == aos_registry_surface::store::canonical_digest_hex(&narinfo.file_hash)?,
        "package ability cache-file identity mismatch"
    );
    anyhow::ensure!(
        nar_bytes.len() as u64 == document.nar_size
            && hex::encode(Sha256::digest(&nar_bytes))
                == aos_registry_surface::store::canonical_digest_hex(&document.nar_hash)?,
        "package ability NAR identity mismatch"
    );

    let projection_bytes = aos_doc_model::decode_single_file_nar(&nar_bytes)?;
    anyhow::ensure!(
        projection_bytes.len() as u64 == document.document_size
            && hex::encode(Sha256::digest(projection_bytes))
                == aos_registry_surface::store::canonical_digest_hex(&document.document_sha256)?,
        "package contract document identity mismatch"
    );
    let projection = decode_package_projection(projection_bytes)?;
    anyhow::ensure!(
        projection.package.name.as_str() == package_name
            && projection.package.version == package_version,
        "package contract coordinate mismatch"
    );
    let retained_interfaces = projection
        .interface_documents
        .iter()
        .map(|entry| aos_ability_model::encode_canonical(&entry.document))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let bindings = contract
        .selectors
        .iter()
        .map(|selector| {
            Ok((
                PackageOutputSelector {
                    package: aos_ability_model::LocalKey::new(&selector.package)?,
                    output: aos_ability_model::LocalKey::new(&selector.output)?,
                },
                contract_artifact_reference(&selector.artifact)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let package = resolve_package_projection(
        projection,
        contract_artifact_reference(&contract.payload)?,
        contract_artifact_reference(&contract.source)?,
        |selector| {
            bindings
                .get(selector)
                .cloned()
                .with_context(|| format!("package contract selector {selector:?} is unbound"))
        },
    )?;
    let package_bytes = aos_ability_model::encode_canonical(&package)?;
    let checked = validate_ability_contract(AbilityContractData::PackageSource {
        manifest: &package_bytes,
        retained_interfaces: &retained_interfaces,
    })
    .context("checking authenticated package signed package ability publication")?;
    let CheckedAbilityContract::PackageSource(checked) = checked else {
        anyhow::bail!("package source validation returned another contract family");
    };
    let package = checked.package();
    let primary_nar_hash = format!(
        "sha256:{}",
        aos_registry_surface::store::canonical_digest_hex(primary_nar_hash)?
    );
    anyhow::ensure!(
        package.package.name.as_str() == package_name
            && package.package.version == package_version
            && package.package.payload.store_path == primary_store_path
            && package.package.payload.nar_hash.to_string() == primary_nar_hash,
        "package ability selection identity mismatch for {package_name}/{package_version}/{platform}"
    );

    aos_doc_model::PackageAbilityReference::from_checked_contract(&checked)
        .context("generating authenticated package ability reference")
}

fn contract_artifact_reference(
    artifact: &aos_registry_surface::manifest::PackageContractArtifactMeta,
) -> Result<ArtifactReference> {
    Ok(ArtifactReference {
        content: Sha256Digest::parse(&artifact.content)?,
        store_path: artifact.store_path.clone(),
        nar_hash: Sha256Digest::parse(&artifact.nar_hash)?,
        closure: Sha256Digest::parse(&artifact.closure_digest)?,
    })
}

pub(super) async fn verify_package_ability_references(
    fetch: &dyn SurfaceFetch,
    packages: &[aos_registry_surface::manifest::PackageToml],
) -> Result<Vec<IndexedPackageAbilityReference>> {
    let mut indexed = Vec::new();
    for package in packages {
        for version in &package.versions {
            for (platform, entry) in &version.platforms {
                let Some(ability) = &entry.contract else {
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
        ArtifactReference, ExportDeclaration, GuaranteeDeclaration, ModuleLocator, PackageDocument,
        PackageImplementation, ProviderImplementation, RelativePath, RequiredFeature,
        VersionedDocument, decode_canonical, encode_canonical,
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

    fn regular_nar(contents: &[u8]) -> Vec<u8> {
        let mut nar = Vec::new();
        for value in [
            b"nix-archive-1".as_slice(),
            b"(",
            b"type",
            b"regular",
            b"contents",
            contents,
            b")",
        ] {
            nar_field(&mut nar, value);
        }
        nar
    }

    fn signed_fixture() -> (
        AbilityFetch,
        aos_registry_surface::manifest::PackageContractMeta,
        Sha256Digest,
        Sha256Digest,
        Sha256Digest,
        PackageDocument,
    ) {
        let features = BTreeSet::from([
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITIES_V1).expect("valid feature"),
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
                .expect("valid effect feature"),
        ]);
        let interface_bytes = include_bytes!("../../../../tests/abilities/fixtures/interface.json");
        let interface = decode_canonical::<aos_ability_model::InterfaceDocument>(
            interface_bytes,
            aos_ability_model::ABILITY_LIMITS_V1,
            &features,
        )
        .expect("decode interface fixture");
        let interface_key = interface.interface_key().expect("interface key");
        let readiness = GuaranteeDeclaration {
            name: interface.interface.guarantees[0].name.clone(),
            version: interface.interface.guarantees[0].version,
            semantics: "the provider reports readiness for the requested revision".into(),
            description: "Reports readiness for the requested revision.".into(),
        };
        assert_eq!(
            readiness.key().expect("readiness guarantee key"),
            interface.interface.guarantees[0]
        );
        let artifact = ArtifactReference {
            content: Sha256Digest::from_bytes([1; 32]),
            store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-demo".into(),
            nar_hash: Sha256Digest::from_bytes([2; 32]),
            closure: Sha256Digest::from_bytes([3; 32]),
        };
        let provider = ProviderImplementation {
            name: aos_ability_model::LocalKey::new("provider").expect("valid implementation name"),
            description: "Hub reference test provider.".to_string(),
            interface: interface_key.clone(),
            guarantees: Vec::new(),
            artifact: artifact.clone(),
            requirements: Vec::new(),
            desired_schema: None,
            provider_module: Some(ModuleLocator {
                artifact: artifact.clone(),
                path: RelativePath::new("default.nix").expect("valid module path"),
            }),
            handler: None,
            owns_resource_kinds: Vec::new(),
            state_format: None,
        };
        let provider_digest = provider.descriptor_digest().expect("provider digest");
        let package = PackageDocument {
            schema: PackageDocument::SCHEMA.into(),
            required_features: features.into_iter().collect(),
            package: aos_ability_model::document::PackageSubject {
                name: aos_ability_model::LocalKey::new("demo").expect("valid package"),
                version: "1.0.0".into(),
                payload: artifact.clone(),
                source: artifact.clone(),
            },
            artifacts: vec![artifact.clone()],
            interfaces: BTreeMap::from([(
                aos_ability_model::LocalKey::new("echo-interface").expect("valid interface alias"),
                interface_key.clone(),
            )]),
            guarantees: BTreeMap::from([(
                aos_ability_model::LocalKey::new("readiness").expect("valid guarantee alias"),
                readiness,
            )]),
            package_module: Some(aos_ability_model::ModuleLocator {
                artifact: artifact.clone(),
                path: aos_ability_model::RelativePath::new("module.nix")
                    .expect("fixture package module path is valid"),
            }),
            option_declarations: Vec::new(),
            exports: vec![
                ExportDeclaration {
                    name: aos_ability_model::LocalKey::new("echo").expect("valid export"),
                    interface: interface_key.clone(),
                    implementation_name: aos_ability_model::LocalKey::new("provider")
                        .expect("valid implementation name"),
                    implementation: provider_digest,
                },
                ExportDeclaration {
                    name: aos_ability_model::LocalKey::new("echo-alias")
                        .expect("valid export alias"),
                    interface: interface_key.clone(),
                    implementation_name: aos_ability_model::LocalKey::new("provider")
                        .expect("valid implementation name"),
                    implementation: provider_digest,
                },
            ],
            requirements: Vec::new(),
            implementation: PackageImplementation {
                providers: vec![provider],
                handlers: BTreeMap::new(),
            },
            qualification: aos_ability_model::PackageQualification::default(),
        };
        let package_bytes = encode_canonical(&package).expect("encode package");
        let selector = serde_json::json!({"package": "self", "output": "out"});
        let mut projection = serde_json::to_value(&package).expect("serialize package projection");
        let projection = projection.as_object_mut().expect("package object");
        projection.insert(
            "schema".into(),
            serde_json::Value::String(aos_ability_validate::PACKAGE_PROJECTION_SCHEMA.into()),
        );
        let subject = projection
            .get_mut("package")
            .and_then(serde_json::Value::as_object_mut)
            .expect("package subject");
        subject.remove("payload");
        subject.remove("source");
        projection.insert("artifacts".into(), serde_json::json!([selector.clone()]));
        projection["package_module"]["artifact"] = selector.clone();
        projection["implementation"]["providers"][0]["artifact"] = selector.clone();
        projection["implementation"]["providers"][0]["provider_module"]["artifact"] = selector;
        for export in projection["exports"]
            .as_array_mut()
            .expect("package exports")
        {
            let export = export.as_object_mut().expect("package export");
            let implementation_name = export
                .remove("implementation_name")
                .expect("resolved export implementation name");
            export.insert("implementation".into(), implementation_name);
        }
        projection.insert(
            "interface_documents".into(),
            serde_json::json!([{"descriptor": interface_key.descriptor, "document": interface}]),
        );
        let projection_bytes =
            aos_contract::canonical::to_vec(&projection).expect("encode symbolic package contract");
        let nar = regular_nar(&projection_bytes);
        let nar_digest = hex::encode(Sha256::digest(&nar));
        let store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo-abilities";
        let nar_url = format!("nar/{nar_digest}.nar");
        let narinfo = format!(
            "StorePath: {store_path}\nURL: {nar_url}\nCompression: none\nFileHash: sha256:{nar_digest}\nFileSize: {}\nNarHash: sha256:{nar_digest}\nNarSize: {}\nReferences: \n",
            nar.len(),
            nar.len(),
        );
        let closure_member = aos_registry_surface::manifest::PackageContractClosureMemberMeta {
            store_path: artifact.store_path.clone(),
            nar_hash: artifact.nar_hash.to_string(),
            nar_size: 10,
            references: Vec::new(),
        };
        let retained = aos_registry_surface::manifest::PackageContractArtifactMeta {
            content: artifact.content.to_string(),
            store_path: artifact.store_path.clone(),
            nar_hash: artifact.nar_hash.to_string(),
            nar_size: 10,
            closure_digest: artifact.closure.to_string(),
            closure: vec![closure_member],
        };
        let ability = aos_registry_surface::manifest::PackageContractMeta {
            document: aos_registry_surface::manifest::PackageContractDocumentMeta {
                store_path: store_path.into(),
                nar_hash: format!("sha256:{nar_digest}"),
                nar_size: nar.len() as u64,
                document_sha256: Sha256Digest::of_bytes(&projection_bytes).to_string(),
                document_size: projection_bytes.len() as u64,
                references: Vec::new(),
            },
            payload: retained.clone(),
            source: retained.clone(),
            selectors: vec![
                aos_registry_surface::manifest::PackageContractSelectorMeta {
                    package: "self".into(),
                    output: "out".into(),
                    artifact: retained,
                },
            ],
            provenance: "provenance/demo.contract.intoto.jsonl".into(),
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
        (
            fetch,
            ability,
            interface_key.descriptor,
            Sha256Digest::of_bytes(&package_bytes),
            package.content_digest().expect("package digest"),
            package,
        )
    }

    #[tokio::test]
    async fn derives_reference_only_from_exact_signed_package_bytes() {
        let (fetch, ability, interface_digest, manifest_digest, package_digest, package) =
            signed_fixture();

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
            manifest_digest.to_string()
        );
        assert_eq!(
            reference.package_digest.to_string(),
            package_digest.to_string()
        );
        assert_eq!(reference.required_features, package.required_features);
        assert_eq!(reference.guarantees, package.guarantees);
        assert_eq!(reference.option_declarations, package.option_declarations);
        assert_eq!(reference.implementations, package.implementation.providers);
        assert_eq!(reference.requirements, package.requirements);
        assert_eq!(
            reference.handlers.len(),
            package.implementation.handlers.len()
        );
        assert_eq!(reference.interfaces.len(), package.interfaces.len());
        for (alias, expected) in &package.interfaces {
            let actual = reference
                .interfaces
                .get(alias)
                .expect("Hub reference retains every package interface alias")
                .interface_key()
                .expect("Hub reference interface remains valid");
            assert_eq!(&actual, expected);
        }
        assert_eq!(reference.exports.len(), package.exports.len());
        for (actual, expected) in reference.exports.iter().zip(&package.exports) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.interface, expected.interface);
            assert_eq!(actual.implementation, expected.implementation);
        }
        assert_eq!(reference.exports[0].interface.descriptor, interface_digest);
    }

    #[tokio::test]
    async fn rejects_a_signed_locator_with_different_manifest_identity() {
        let (fetch, mut ability, _, _, _, _) = signed_fixture();
        ability.document.document_sha256 = Sha256Digest::from_bytes([9; 32]).to_string();

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
    async fn rejects_a_signed_package_projection_for_a_different_primary_payload() {
        let (fetch, ability, _, _, _, _) = signed_fixture();

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
        .expect_err("package projection must equal the signed primary package");

        assert!(error.to_string().contains("selection identity mismatch"));
    }
}
