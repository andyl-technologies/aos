//! Authenticated demo configuration used by the native browser fixture.
//!
//! The seed writes a real canonical document and regular-file NAR, then returns
//! its signed package metadata. Its wide and deep paths exercise lazy browsing
//! through the production indexer and object verifier.

use anyhow::{Context as _, Result};
use aos_doc_model::{
    AbilityValue, DocumentedValue, EnumValue, InlineSpan, OptionDocument, OptionOwner, OptionType,
    PackageDocumentation, PathSegment, ProseBlock, RelativePath, Visibility,
};
use sha2::{Digest as _, Sha256};
use std::path::Path;

fn paragraph(text: &str) -> Vec<ProseBlock> {
    vec![ProseBlock::Paragraph {
        spans: vec![InlineSpan::Text { text: text.into() }],
    }]
}

fn option(
    path: &[&str],
    option_type: OptionType,
    signature: &str,
    description: &str,
) -> Result<OptionDocument> {
    Ok(OptionDocument {
        path: path
            .iter()
            .map(|value| PathSegment::Literal {
                value: (*value).into(),
            })
            .collect(),
        display_path: path.join("."),
        option_type,
        type_signature: signature.into(),
        description: paragraph(description),
        default: None,
        example: None,
        visibility: Visibility::Public,
        read_only: false,
        deprecated: None,
        replacement: None,
        owner: OptionOwner {
            package: "config-demo".into(),
            root: "services".into(),
            interface_abi: None,
        },
        contributable: false,
        source: Some(aos_doc_model::SourceLocator {
            path: RelativePath::new("modules/services/demo.nix")?,
        }),
    })
}

pub(super) fn write(root: &Path) -> Result<String> {
    let mut options = Vec::new();
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
    options.push(enable);
    let mut backend = option(
        &["services", "demo", "storage", "backend"],
        OptionType::Enum {
            values: vec![
                EnumValue {
                    value: "memory".into(),
                },
                EnumValue {
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
    options.push(backend);
    for index in 0..137 {
        let name = format!("worker{index:03}");
        options.push(option(
            &["services", "demo", "workers", &name, "enable"],
            OptionType::Bool,
            "bool",
            "Enables this worker in the wide configuration subtree.",
        )?);
    }
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
        options,
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
