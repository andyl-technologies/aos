//! Authenticated demo configuration used by the native browser fixture.
//!
//! The seed writes a real canonical document and regular-file NAR, then returns
//! its signed package metadata. Its wide and deep paths exercise lazy browsing
//! through the production indexer and object verifier.

use anyhow::{Context as _, Result};
use aos_ability_model::{
    AbilityActivationMode, AbilityValue, ArtifactReference, DocumentedValue, LocalKey,
    ModuleLocator, OptionEnumValue, OptionSource, OptionType, OptionVisibility, PackageDocument,
    PackageImplementation, PackageOptionDeclaration, PackageQualification, RequiredFeature,
    VersionedDocument, encode_canonical,
};
use aos_ability_model::document::PackageSubject;
use aos_contract::Sha256Digest;
use aos_doc_model::PackageDocumentation;
use sha2::{Digest as _, Sha256};
use std::path::Path;

fn option(
    path: &[&str],
    option_type: OptionType,
    signature: &str,
    description: &str,
) -> Result<PackageOptionDeclaration> {
    Ok(PackageOptionDeclaration {
        path: path.iter().map(|value| (*value).to_string()).collect(),
        type_signature: signature.to_string(),
        structured_type: option_type,
        description: description.to_string(),
        default: None,
        example: None,
        visibility: OptionVisibility::Public,
        read_only: false,
        deprecated: None,
        replacement: None,
        contributable: false,
        source: OptionSource {
            path: aos_ability_model::RelativePath::new("module.nix")?,
        },
    })
}

pub(super) fn write(root: &Path) -> Result<String> {
    let mut option_declarations = Vec::new();
    let mut enable = option(
        &["services", "demo", "enable"],
        OptionType::Bool,
        "bool",
        "Enables the demo service and its runtime configuration.",
    )?;
    enable.default = Some(DocumentedValue::Literal {
        value: AbilityValue::new(false.into())?,
    });
    enable.example = Some(DocumentedValue::Literal {
        value: AbilityValue::new(true.into())?,
    });
    option_declarations.push(enable);
    let mut backend = option(
        &["services", "demo", "storage", "backend"],
        OptionType::Enum {
            values: vec![
                OptionEnumValue {
                    value: "memory".into(),
                },
                OptionEnumValue {
                    value: "disk".into(),
                },
            ],
        },
        "enum [ memory disk ]",
        "Selects where the demo service stores its working data.",
    )?;
    backend.default = Some(DocumentedValue::Literal {
        value: AbilityValue::new("memory".into())?,
    });
    backend.example = Some(DocumentedValue::Literal {
        value: AbilityValue::new("disk".into())?,
    });
    option_declarations.push(backend);
    for index in 0..137 {
        let name = format!("worker{index:03}");
        option_declarations.push(option(
            &["services", "demo", "workers", &name, "enable"],
            OptionType::Bool,
            "bool",
            "Enables this worker in the wide configuration subtree.",
        )?);
    }

    let payload = ArtifactReference {
        content: Sha256Digest::from_bytes([0x11; 32]),
        store_path: format!("/nix/store/{}-config-demo", "c".repeat(32)),
        nar_hash: Sha256Digest::from_bytes([0x11; 32]),
        closure: Sha256Digest::from_bytes([0x22; 32]),
    };
    let package_document = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: vec![RequiredFeature::new("abilities-v1")?],
        activation_mode: AbilityActivationMode::ContractsOnly,
        package: PackageSubject {
            name: LocalKey::new("config-demo")?,
            version: "1.0.0".to_string(),
            payload: payload.clone(),
            source: payload.clone(),
        },
        artifacts: Vec::new(),
        interfaces: Default::default(),
        guarantees: Default::default(),
        package_module: Some(ModuleLocator {
            artifact: payload,
            path: aos_ability_model::RelativePath::new("module.nix")?,
        }),
        option_declarations,
        exports: Vec::new(),
        requirements: Vec::new(),
        implementation: PackageImplementation {
            providers: Vec::new(),
            handlers: Default::default(),
        },
        qualification: PackageQualification::default(),
    };
    let package_document_bytes = encode_canonical(&package_document)?;
    let ability_nar = package_ability_nar(&package_document_bytes);
    let ability_nar_digest = hex::encode(Sha256::digest(&ability_nar));
    let ability_store_hash = "f".repeat(32);
    let ability_store_path = format!("/nix/store/{ability_store_hash}-config-demo-abilities");
    let ability_nar_key = format!("nar/{ability_store_hash}.nar");
    std::fs::write(root.join(&ability_nar_key), &ability_nar)?;
    std::fs::write(
        root.join(format!("{ability_store_hash}.narinfo")),
        format!(
            "StorePath: {ability_store_path}\nURL: {ability_nar_key}\nCompression: none\nFileHash: sha256:{ability_nar_digest}\nFileSize: {}\nNarHash: sha256:{ability_nar_digest}\nNarSize: {}\nReferences: {}-config-demo\n",
            ability_nar.len(),
            ability_nar.len(),
            "c".repeat(32),
        ),
    )?;
    let ability = aos_registry_surface::manifest::AbilityPackageMeta {
        store_path: ability_store_path,
        nar_hash: format!("sha256:{ability_nar_digest}"),
        nar_size: u64::try_from(ability_nar.len())?,
        references: vec!["c".repeat(32)],
        manifest_sha256: Sha256Digest::of_bytes(&package_document_bytes).to_string(),
        manifest_size: u64::try_from(package_document_bytes.len())?,
        package_digest: package_document.content_digest()?.to_string(),
        activation_mode: "contracts-only".to_string(),
        artifacts: Vec::new(),
        provenance: "provenance/config-demo.ability.intoto.jsonl".to_string(),
    };

    let mut document = PackageDocumentation {
        schema: aos_doc_model::DOCUMENT_SCHEMA.into(),
        package: aos_doc_model::DocumentedPackage {
            name: "config-demo".into(),
            version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            summary: "Demo service configuration and runtime reference".into(),
            homepage: None,
            license: "MIT".into(),
        },
        identity: aos_doc_model::DocumentationIdentity {
            semantic_schema_sha256: format!("sha256:{}", "0".repeat(64)),
            runtime_nar_hash: format!("sha256:{}", "1".repeat(64)),
            source_nar_hash: format!("sha256:{}", "2".repeat(64)),
            config_module_nar_hash: None,
            expose_artifact_nar_hash: None,
        },
    };
    document.identity.semantic_schema_sha256 = document.computed_semantic_schema_sha256()?;
    let contents = document.canonical_json()?;
    let nar = regular_nar(&contents);
    let nar_digest = hex::encode(Sha256::digest(&nar));
    let store_hash = "d".repeat(32);
    let store_path = format!("/nix/store/{store_hash}-config-demo-docs.json");
    let nar_key = format!("nar/{store_hash}.nar");
    std::fs::create_dir_all(root.join("nar"))?;
    std::fs::write(root.join(&nar_key), &nar)?;
    std::fs::write(root.join(format!("{store_hash}.narinfo")), format!(
        "StorePath: {store_path}\nURL: {nar_key}\nCompression: none\nFileHash: sha256:{nar_digest}\nFileSize: {}\nNarHash: sha256:{nar_digest}\nNarSize: {}\nReferences: \n", nar.len(), nar.len()))?;
    let metadata = aos_registry_surface::manifest::DocumentationArtifactMeta {
        format: aos_doc_model::DOCUMENT_FORMAT.into(),
        store_path,
        nar_hash: format!("sha256:{nar_digest}"),
        nar_size: u64::try_from(nar.len())?,
        document_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&contents))),
        document_size: u64::try_from(contents.len())?,
        semantic_schema_sha256: document.identity.semantic_schema_sha256,
        references: Vec::new(),
    };
    let mut package: toml::Value = toml::from_str(&format!(
        "[package]\nname = \"config-demo\"\ndescription = \"Demo service configuration\"\nlicense = \"MIT\"\nmaintainer = \"aos\"\n\n[[versions]]\nversion = \"1.0.0\"\n[versions.platforms.x86_64-linux]\nstore_path = \"/nix/store/{}-config-demo\"\nnar_hash = \"sha256:{}\"\nnar_size = 10\nclosure_size = 10\nsource_drv = \"/nix/store/{}-config-demo.drv\"\nsource_nar_hash = \"sha256:{}\"\nreferences = []\n",
        "c".repeat(32), "1".repeat(64), "e".repeat(32), "2".repeat(64)))?;
    package
        .get_mut("versions")
        .and_then(toml::Value::as_array_mut)
        .and_then(|versions| versions.first_mut())
        .and_then(|version| version.get_mut("platforms"))
        .and_then(|platforms| platforms.get_mut("x86_64-linux"))
        .and_then(toml::Value::as_table_mut)
        .context("seed documentation platform is missing")?
        .insert("documentation".into(), toml::Value::try_from(metadata)?);
    package
        .get_mut("versions")
        .and_then(toml::Value::as_array_mut)
        .and_then(|versions| versions.first_mut())
        .and_then(|version| version.get_mut("platforms"))
        .and_then(|platforms| platforms.get_mut("x86_64-linux"))
        .and_then(toml::Value::as_table_mut)
        .context("seed documentation platform is missing")?
        .insert("ability".into(), toml::Value::try_from(ability)?);
    Ok(toml::to_string(&package)?)
}

/// Encodes the public NAR regular-file framing around canonical JSON bytes.
fn regular_nar(contents: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"regular",
        b"contents",
        contents,
        b")",
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value);
        while bytes.len() % 8 != 0 {
            bytes.push(0);
        }
    }
    bytes
}

/// Encodes the strict signed package ability publication shape used by the indexer.
fn package_ability_nar(package: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"directory",
        b"entry",
        b"(",
        b"name",
        b"interfaces",
        b"node",
        b"(",
        b"type",
        b"directory",
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
        package,
        b")",
        b")",
        b")",
    ] {
        nar_field(&mut bytes, value);
    }
    bytes
}

fn nar_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
    output.resize(output.len().div_ceil(8) * 8, 0);
}
