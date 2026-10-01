//! Integration of Worker NAR parsing with Native's production result validator.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use anyhow::Result;
use aos_doc_model::*;
use aos_hub_core::{fetch::SurfaceFetch, storage_work::*};
use aos_registry_surface::manifest::DocumentationArtifactMeta;
use sha2::{Digest as _, Sha256};

use super::inspect_content;

struct Objects {
    objects: BTreeMap<String, Vec<u8>>,
    reads: Mutex<Vec<(String, usize)>>,
}

#[async_trait::async_trait]
impl SurfaceFetch for Objects {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let bytes = self.objects.get(path).cloned();
        if let Some(bytes) = &bytes {
            self.reads.lock().unwrap().push((path.into(), bytes.len()));
        }
        Ok(bytes)
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        Ok(self.objects.get(path).map(|bytes| bytes.len() as u64))
    }

    fn describe(&self) -> String {
        "documentation-object-storage-fixture".into()
    }
}

struct NativeDetail {
    plan: StorageWorkPlan,
    body: Vec<u8>,
    fetches: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl SurfaceFetch for NativeDetail {
    async fn fetch(&self, _: &str) -> Result<Option<Vec<u8>>> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("Native generic object fetch is forbidden")
    }

    fn storage_local_documentation_inspection(&self) -> bool {
        true
    }

    async fn package_documentation_content(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &DocumentationArtifactMeta,
    ) -> Result<PackageDocumentation> {
        anyhow::ensure!(self.body.len() <= self.plan.operation.maximum_result_bytes());
        let result: StorageWorkResult = serde_json::from_slice(&self.body)?;
        aos_hub::storage_work::validate_result_for_test(&self.plan, &result)?;
        let StorageWorkOutcome::DocumentationContent { document } = result.outcome else {
            anyhow::bail!("unexpected documentation outcome");
        };
        Ok(document)
    }

    fn describe(&self) -> String {
        "Native-typed-documentation-fixture".into()
    }
}

fn document(blocks: usize) -> PackageDocumentation {
    let mut document = PackageDocumentation {
        schema: DOCUMENT_SCHEMA.into(),
        package: DocumentedPackage {
            name: "fixture-package".into(),
            version: "1.0".into(),
            platform: "x86_64-linux".into(),
            summary: "Documented fixture".into(),
            homepage: None,
            license: "MIT".into(),
        },
        identity: DocumentationIdentity {
            semantic_schema_sha256: format!("sha256:{}", "0".repeat(64)),
            runtime_nar_hash: format!("sha256:{}", "1".repeat(64)),
            config_module_nar_hash: None,
            system_module_nar_hash: None,
            expose_artifact_nar_hash: None,
            source_nar_hash: format!("sha256:{}", "2".repeat(64)),
        },
        sections: (0..blocks)
            .map(|index| Section {
                id: format!("section-{index}"),
                title: format!("Section {index}"),
                blocks: vec![ProseBlock::Code {
                    language: "text".into(),
                    text: "x".repeat(255 * 1024),
                }],
            })
            .collect(),
        options: Vec::new(),
        runtime: RuntimeSurface::default(),
    };
    document.identity.semantic_schema_sha256 = document.computed_semantic_schema_sha256().unwrap();
    document
}

fn objects(document: &PackageDocumentation) -> (Objects, DocumentationArtifactMeta) {
    let bytes = document.canonical_json().unwrap();
    let mut nar = Vec::new();
    for value in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"regular",
        b"contents",
        &bytes,
        b")",
    ] {
        nar.extend_from_slice(&(value.len() as u64).to_le_bytes());
        nar.extend_from_slice(value);
        nar.resize(nar.len() + (8 - value.len() % 8) % 8, 0);
    }
    let nar_hash = format!("sha256:{}", hex::encode(Sha256::digest(&nar)));
    let store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture-doc.json";
    let narinfo = format!("StorePath: {store_path}\nURL: nar/document.nar\nCompression: none\nFileHash: {nar_hash}\nFileSize: {}\nNarHash: {nar_hash}\nNarSize: {}\nReferences: \n", nar.len(), nar.len()).into_bytes();
    let artifact = DocumentationArtifactMeta {
        format: DOCUMENT_FORMAT.into(),
        store_path: store_path.into(),
        nar_hash,
        nar_size: nar.len() as u64,
        document_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        document_size: bytes.len() as u64,
        semantic_schema_sha256: document.identity.semantic_schema_sha256.clone(),
        system_module_nar_hash: None,
        references: Vec::new(),
    };
    (
        Objects {
            objects: BTreeMap::from([
                ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo".into(), narinfo),
                ("nar/document.nar".into(), nar),
            ]),
            reads: Mutex::new(Vec::new()),
        },
        artifact,
    )
}

fn plan(artifact: DocumentationArtifactMeta) -> StorageWorkPlan {
    StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "fixture-deployment".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 12,
        placement_resource_version: 4,
        binding_id: 3,
        binding_resource_version: 2,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: Vec::new(),
        placement_prefix: "fixture/".into(),
        operation: StorageWorkOperation::InspectDocumentationContent {
            package_name: "fixture-package".into(),
            package_version: "1.0".into(),
            platform: "x86_64-linux".into(),
            artifact,
        },
    }
}

async fn project(blocks: usize) -> (Objects, StorageWorkPlan, StorageWorkResult) {
    let document = document(blocks);
    let (objects, artifact) = objects(&document);
    let (outcome, source_bytes) = inspect_content(
        &objects,
        "fixture-package",
        "1.0",
        "x86_64-linux",
        &artifact,
    )
    .await
    .unwrap();
    let plan = plan(artifact);
    plan.validate("fixture-deployment", 101).unwrap();
    let result = StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes,
        outcome,
    };
    (objects, plan, result)
}

#[tokio::test]
async fn worker_parses_once_and_native_detail_receives_only_canonical_content() {
    let (objects, plan, result) = project(2).await;
    let request = serde_json::to_vec(&plan).unwrap();
    let body = serde_json::to_vec(&result).unwrap();
    let reads = objects.reads.lock().unwrap();
    assert_eq!(reads.len(), 2);
    assert_eq!(
        reads
            .iter()
            .filter(|(key, _)| key.starts_with("nar/"))
            .count(),
        1
    );
    let input_bytes = reads.iter().map(|(_, bytes)| *bytes as u64).sum::<u64>();
    assert_eq!(input_bytes, result.source_bytes);
    assert!(request.len() < 64 * 1024);
    assert!(!request
        .windows(b"nix-archive-1".len())
        .any(|bytes| bytes == b"nix-archive-1"));
    assert!(body.len() > MAX_RESULT_BYTES);
    assert!(body.len() <= plan.operation.maximum_result_bytes());
    assert!(!body
        .windows(b"nix-archive-1".len())
        .any(|bytes| bytes == b"nix-archive-1"));
    drop(reads);

    let fetches = Arc::new(AtomicUsize::new(0));
    let native = NativeDetail {
        plan: plan.clone(),
        body: body.clone(),
        fetches: Arc::clone(&fetches),
    };
    let StorageWorkOperation::InspectDocumentationContent { artifact, .. } = &plan.operation else {
        panic!("content plan")
    };
    let loaded = aos_hub_core::indexer::fetch_package_documentation(
        &native,
        "fixture-package",
        "1.0",
        "x86_64-linux",
        artifact,
    )
    .await
    .unwrap();
    assert_eq!(loaded, document(2));
    assert_eq!(fetches.load(Ordering::SeqCst), 0);
    eprintln!("documentation content request_bytes={} input_bytes={input_bytes} output_bytes={} nar_reads=1 Native_fetches=0", request.len(), body.len());
}

#[tokio::test]
async fn native_rejects_changed_content_fences_selection_and_cost() {
    let (_, plan, result) = project(1).await;
    aos_hub::storage_work::validate_result_for_test(&plan, &result).unwrap();
    let mut changed = result.clone();
    changed.binding_resource_version += 1;
    assert!(aos_hub::storage_work::validate_result_for_test(&plan, &changed).is_err());
    changed = result.clone();
    changed.source_bytes = u64::MAX;
    assert!(aos_hub::storage_work::validate_result_for_test(&plan, &changed).is_err());
    changed = result.clone();
    if let StorageWorkOutcome::DocumentationContent { document } = &mut changed.outcome {
        document.package.summary = "substituted content".into();
    }
    assert!(aos_hub::storage_work::validate_result_for_test(&plan, &changed).is_err());
    let mut changed_plan = plan.clone();
    if let StorageWorkOperation::InspectDocumentationContent { package_name, .. } =
        &mut changed_plan.operation
    {
        *package_name = "foreign-package".into();
    }
    assert!(aos_hub::storage_work::validate_result_for_test(&changed_plan, &result).is_err());

    let (mut objects, artifact) = objects(&document(1));
    objects.objects.get_mut("nar/document.nar").unwrap()[100] ^= 1;
    assert!(inspect_content(
        &objects,
        "fixture-package",
        "1.0",
        "x86_64-linux",
        &artifact
    )
    .await
    .is_err());
}

#[tokio::test]
async fn documentation_has_an_explicit_four_mib_content_bound() {
    let (objects, plan, result) = project(16).await;
    let body = serde_json::to_vec(&result).unwrap();
    aos_hub::storage_work::validate_result_for_test(&plan, &result).unwrap();
    assert!(body.len() < MAX_DOCUMENTATION_CONTENT_RESULT_BYTES);
    assert!(body.len() > 4_000_000);
    assert_eq!(objects.reads.lock().unwrap().len(), 2);
    let ordinary = match plan.operation.clone() {
        StorageWorkOperation::InspectDocumentationContent {
            package_name,
            package_version,
            platform,
            artifact,
        } => StorageWorkOperation::InspectDocumentation {
            package_name,
            package_version,
            platform,
            artifact,
            cursor: 0,
        },
        _ => panic!("content operation"),
    };
    assert_eq!(ordinary.maximum_result_bytes(), MAX_RESULT_BYTES);
    assert_eq!(
        StorageWorkOperation::Head {
            path: "nar/document.nar".into()
        }
        .maximum_result_bytes(),
        MAX_RESULT_BYTES
    );
    let mut oversized = document(16);
    let mut extra = oversized.sections[0].clone();
    extra.id = "overflow-section".into();
    oversized.sections.push(extra);
    assert!(oversized.canonical_json().is_err());
    eprintln!("documentation maximum query input_bytes={} output_bytes={} limit={MAX_DOCUMENTATION_CONTENT_RESULT_BYTES}", result.source_bytes, body.len());
}
