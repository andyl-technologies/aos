//! Controlled provider dispatch, Native result validation and indexer parity.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result};
use aos_hub_core::{
    fetch::{StreamedRead, SurfaceFetch},
    storage_work::*,
    tree_projection::*,
};
use aos_registry_surface::object::{self, ObjectKind, Oid, TreeEntry};

use super::inspect;

struct Objects {
    objects: BTreeMap<String, Vec<u8>>,
    reads: Mutex<Vec<String>>,
    etag: String,
}

#[async_trait::async_trait]
impl SurfaceFetch for Objects {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        self.reads.lock().unwrap().push(path.into());
        Ok(self.objects.get(path).cloned())
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        anyhow::ensure!(range.is_none());
        let Some(bytes) = self.fetch(path).await? else {
            return Ok(None);
        };
        Ok(Some(StreamedRead {
            total: bytes.len() as u64,
            body: axum::body::Body::from(bytes),
            range: None,
            strong_etag: Some(self.etag.clone()),
            snapshot_lease_id: None,
        }))
    }

    fn describe(&self) -> String {
        "controlled-tree-storage".into()
    }
}

fn plan(oid: Oid, names: Vec<String>, cursor: Option<GitTreeCursor>) -> StorageWorkPlan {
    StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "tree-fixture".into(),
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
        operation: StorageWorkOperation::FilterGitTreeEntries {
            oid: oid.to_hex(),
            names,
            cursor,
        },
    }
}

async fn execute(objects: &dyn SurfaceFetch, plan: &StorageWorkPlan) -> Result<StorageWorkResult> {
    plan.validate("tree-fixture", 101)?;
    let StorageWorkOperation::FilterGitTreeEntries { oid, names, cursor } = &plan.operation else {
        anyhow::bail!("unexpected operation")
    };
    let (outcome, source_bytes) = inspect(objects, plan, oid, names, cursor.as_ref()).await?;
    let result = StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes,
        outcome,
    };
    let body = serde_json::to_vec(&result)?;
    anyhow::ensure!(body.len() <= plan.operation.maximum_result_bytes());
    let result = serde_json::from_slice(&body)?;
    aos_hub::storage_work::validate_result_for_test(plan, &result)?;
    Ok(result)
}

fn fixture(count: usize, etag: &str) -> (Objects, Oid, Vec<String>) {
    let entries = (0..count)
        .map(|index| TreeEntry {
            name: format!("package-{index:03}.toml"),
            mode: "100644".into(),
            oid: object::hash_object(ObjectKind::Blob, format!("package {index}").as_bytes()),
        })
        .collect::<Vec<_>>();
    let names = entries.iter().map(|entry| entry.name.clone()).collect();
    let content = object::encode_tree(&entries);
    let oid = object::hash_object(ObjectKind::Tree, &content);
    let loose = object::encode_loose(ObjectKind::Tree, &content).unwrap();
    (
        Objects {
            objects: BTreeMap::from([(oid.loose_path(), loose)]),
            reads: Mutex::new(Vec::new()),
            etag: etag.into(),
        },
        oid,
        names,
    )
}

#[tokio::test]
async fn provider_snapshots_dispatch_the_same_bounded_pages_and_native_rejects_drift() {
    let (r2, oid, names) = fixture(40, "\"r2-snapshot\"");
    let (s3, _, _) = fixture(40, "\"s3-snapshot\"");
    let first_plan = plan(oid, names.clone(), None);
    let first = execute(&r2, &first_plan).await.unwrap();
    let s3_first = execute(&s3, &first_plan).await.unwrap();
    let StorageWorkOutcome::GitTreeEntries { page, .. } = &first.outcome else {
        panic!()
    };
    let StorageWorkOutcome::GitTreeEntries { page: s3_page, .. } = s3_first.outcome else {
        panic!()
    };
    assert_eq!(page.entries, s3_page.entries);
    let local_page = r2
        .inspect_git_tree_entries(oid, &names, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(page.entries, local_page.entries);
    assert_eq!(page.selection_digest, s3_page.selection_digest);
    assert_eq!(page.entries.len(), MAX_TREE_PAGE_ENTRIES);

    let mut rows = page.entries.clone();
    let mut cursor = page.next_cursor.clone();
    while cursor.is_some() {
        let result = execute(&r2, &plan(oid, names.clone(), cursor.clone()))
            .await
            .unwrap();
        let StorageWorkOutcome::GitTreeEntries { page, .. } = result.outcome else {
            panic!()
        };
        rows.extend(page.entries);
        cursor = page.next_cursor;
    }
    assert_eq!(rows.len(), 40);
    assert_eq!(
        rows.iter().map(|row| row.name.clone()).collect::<Vec<_>>(),
        names
    );
    assert!(serde_json::to_vec(&first).unwrap().len() < MAX_TREE_PAGE_BYTES + 1024);

    let continued = plan(oid, names.clone(), page.next_cursor.clone());
    assert!(execute(&s3, &continued).await.is_err());
    let mut changed = first.clone();
    if let StorageWorkOutcome::GitTreeEntries { source, .. } = &mut changed.outcome {
        source.key = "another/source".into();
    }
    assert!(aos_hub::storage_work::validate_result_for_test(&first_plan, &changed).is_err());
    let mut changed = first;
    if let StorageWorkOutcome::GitTreeEntries { page, .. } = &mut changed.outcome {
        page.entries[0].name = "unselected.toml".into();
    }
    assert!(aos_hub::storage_work::validate_result_for_test(&first_plan, &changed).is_err());
}

struct RemoteIndex {
    objects: Arc<Objects>,
    root_tree: Oid,
    selections: Mutex<Vec<Vec<String>>>,
}

#[async_trait::async_trait]
impl SurfaceFetch for RemoteIndex {
    async fn fetch(&self, _: &str) -> Result<Option<Vec<u8>>> {
        anyhow::bail!("Native generic fetch is forbidden")
    }

    fn storage_local_git_inspection(&self) -> bool {
        true
    }

    fn storage_local_tree_projection(&self) -> bool {
        true
    }

    async fn inspect_git_object(&self, oid: Oid) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        anyhow::ensure!(
            oid != self.root_tree,
            "source tree crossed the Native boundary"
        );
        self.objects
            .objects
            .get(&oid.loose_path())
            .map(|loose| object::decode_loose(loose, Some(oid)))
            .transpose()
    }

    async fn inspect_git_tree_entries(
        &self,
        oid: Oid,
        names: &[String],
        cursor: Option<&GitTreeCursor>,
    ) -> Result<Option<GitTreeEntriesPage>> {
        self.selections.lock().unwrap().push(names.to_vec());
        match execute(
            self.objects.as_ref(),
            &plan(oid, names.to_vec(), cursor.cloned()),
        )
        .await?
        .outcome
        {
            StorageWorkOutcome::GitTreeEntries { page, .. } => Ok(Some(page)),
            StorageWorkOutcome::NotFound => Ok(None),
            _ => anyhow::bail!("unexpected projection result"),
        }
    }

    fn describe(&self) -> String {
        "Native-selected-tree-fixture".into()
    }
}

#[tokio::test]
async fn actual_indexer_selects_root_fields_without_raw_tree_fetch_and_matches_local_modes() {
    let (mut objects, _, _) = fixture(1, "\"fixture-source\"");
    let registry = b"[registry]\nname = 'tree-fixture'\n";
    let registry_oid = object::hash_object(ObjectKind::Blob, registry);
    objects.objects.insert(
        registry_oid.loose_path(),
        object::encode_loose(ObjectKind::Blob, registry).unwrap(),
    );
    let ignored_oid = object::hash_object(ObjectKind::Blob, b"ignored source");
    let tree = object::encode_tree(&[
        TreeEntry {
            name: "ignored.txt".into(),
            mode: "100644".into(),
            oid: ignored_oid,
        },
        TreeEntry {
            name: "registry.toml".into(),
            mode: "100644".into(),
            oid: registry_oid,
        },
    ]);
    let tree_oid = object::hash_object(ObjectKind::Tree, &tree);
    objects.objects.insert(
        tree_oid.loose_path(),
        object::encode_loose(ObjectKind::Tree, &tree).unwrap(),
    );
    let commit = format!("tree {tree_oid}\nauthor Fixture <fixture@example.test> 100 +0000\ncommitter Fixture <fixture@example.test> 100 +0000\n\nfixture\n");
    let commit_oid = object::hash_object(ObjectKind::Commit, commit.as_bytes());
    objects.objects.insert(
        commit_oid.loose_path(),
        object::encode_loose(ObjectKind::Commit, commit.as_bytes()).unwrap(),
    );
    let objects = Arc::new(objects);
    let remote = RemoteIndex {
        objects: objects.clone(),
        root_tree: tree_oid,
        selections: Mutex::new(Vec::new()),
    };

    let hybrid = aos_hub_core::indexer::load::load_registry_tree(&remote, commit_oid)
        .await
        .context("hybrid load")
        .unwrap();
    let native = aos_hub_core::indexer::load::load_registry_tree(objects.as_ref(), commit_oid)
        .await
        .context("local Native load")
        .unwrap();
    let worker = aos_hub_core::indexer::load::load_registry_tree(objects.as_ref(), commit_oid)
        .await
        .context("local Worker load")
        .unwrap();
    assert_eq!(hybrid.root.registry.name, native.root.registry.name);
    assert_eq!(hybrid.root.registry.name, worker.root.registry.name);
    assert!(hybrid.packages.is_empty());
    assert_eq!(remote.selections.lock().unwrap().len(), 1);
    assert!(!remote.selections.lock().unwrap()[0]
        .iter()
        .any(|name| name == "ignored.txt"));
}

#[tokio::test]
async fn malformed_source_and_invalid_cursor_fail_before_any_native_rows_are_accepted() {
    let (mut objects, oid, names) = fixture(20, "\"source\"");
    let original_plan = plan(oid, names.clone(), None);
    let first = execute(&objects, &original_plan).await.unwrap();
    let StorageWorkOutcome::GitTreeEntries { page, .. } = first.outcome else {
        panic!()
    };
    let mut cursor = page.next_cursor.unwrap();
    cursor.next_index = 0;
    let before = objects.reads.lock().unwrap().len();
    assert!(execute(&objects, &plan(oid, names.clone(), Some(cursor)))
        .await
        .is_err());
    assert_eq!(objects.reads.lock().unwrap().len(), before);

    objects.objects.insert(
        oid.loose_path(),
        object::encode_loose(ObjectKind::Tree, b"different tree").unwrap(),
    );
    assert!(execute(&objects, &original_plan).await.is_err());
}

#[tokio::test]
async fn empty_matching_page_is_distinct_from_an_absent_tree() {
    let (objects, oid, _) = fixture(0, "\"empty-tree-source\"");
    let request = plan(oid, vec!["absent.toml".into()], None);
    let result = execute(&objects, &request).await.unwrap();
    let StorageWorkOutcome::GitTreeEntries { page, .. } = result.outcome else {
        panic!()
    };
    assert!(page.entries.is_empty());
    assert_eq!(page.end_index, 1);
    assert!(page.next_cursor.is_none());

    let absent = Objects {
        objects: BTreeMap::new(),
        reads: Mutex::new(Vec::new()),
        etag: "\"source\"".into(),
    };
    let result = execute(&absent, &request).await.unwrap();
    assert_eq!(result.outcome, StorageWorkOutcome::NotFound);
    assert_eq!(result.source_bytes, 0);
}

struct MisreportedSource {
    objects: Objects,
    total: u64,
}

#[async_trait::async_trait]
impl SurfaceFetch for MisreportedSource {
    async fn fetch(&self, _: &str) -> Result<Option<Vec<u8>>> {
        anyhow::bail!("unbounded tree source fetch is forbidden")
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        let mut read = self.objects.fetch_stream(path, range).await?;
        if let Some(read) = &mut read {
            read.total = self.total;
        }
        Ok(read)
    }

    fn describe(&self) -> String {
        "misreported-tree-source".into()
    }
}

#[tokio::test]
async fn provider_source_limits_and_declared_lengths_are_checked_before_accepting_rows() {
    for total in [1, object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES + 1] {
        let (objects, oid, names) = fixture(1, "\"source\"");
        let source = MisreportedSource { objects, total };
        assert!(execute(&source, &plan(oid, names, None)).await.is_err());
    }
}
