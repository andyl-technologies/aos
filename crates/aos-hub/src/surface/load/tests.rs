//! Native reader parity across canonical loose and verified semantic tree ports.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct ProjectedTree {
    oid: Oid,
    rows: Vec<object::TreeEntry>,
    body_fetches: AtomicUsize,
}

#[async_trait::async_trait]
impl SurfaceFetch for ProjectedTree {
    async fn fetch(&self, _: &str) -> Result<Option<Vec<u8>>> {
        self.body_fetches.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("this semantic source has no Native body transport")
    }

    fn storage_local_git_projection(&self) -> bool {
        true
    }

    async fn inspect_git_tree_inventory(&self, oid: Oid) -> Result<Vec<object::TreeEntry>> {
        anyhow::ensure!(oid == self.oid, "changed selected tree");
        Ok(self.rows.clone())
    }

    fn describe(&self) -> String {
        "verified semantic tree fixture".into()
    }
}

#[tokio::test]
async fn actual_large_packed_tree_reaches_native_as_complete_rows_without_body_fallback() {
    use aos_registry_surface::pack_index::projection::PairReader;

    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../aos-registry-surface/src/pack_index/fixtures/large-tree.json"
    ))
    .unwrap();
    let path = manifest["path"].as_str().unwrap();
    let oid = Oid::from_hex(manifest["treeOid"].as_str().unwrap()).unwrap();
    let mut reader = PairReader::new(path).unwrap();
    reader
        .feed_pack(include_bytes!(
            "../../../../aos-registry-surface/src/pack_index/fixtures/large-tree.pack"
        ))
        .unwrap();
    reader
        .feed_index(include_bytes!(
            "../../../../aos-registry-surface/src/pack_index/fixtures/large-tree.idx"
        ))
        .unwrap();
    let verified = reader
        .finish_tree_projection(oid, |content| {
            aos_hub_core::mirror_tree_inventory::project_pages(
                &oid.to_hex(),
                content,
                &"a".repeat(64),
            )
        })
        .unwrap();
    let mut rows = Vec::new();
    for page in verified.tree.unwrap().projection {
        rows.extend(page.entries.iter().map(|row| row.tree_entry().unwrap()));
    }
    let source = ProjectedTree {
        oid,
        rows,
        body_fetches: AtomicUsize::new(0),
    };
    let reader = ObjectReader::new(&source);

    let tree = reader.tree_map(oid).await.unwrap();

    assert_eq!(tree.len(), 4096);
    assert!(tree.contains_key("entry-00000.toml"));
    assert!(tree.contains_key("entry-04095.toml"));
    assert_eq!(source.body_fetches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_only_loose_tree_preserves_modes_and_semantic_duplicate_refusal() {
    let temporary = tempfile::tempdir().unwrap();
    let mut content = b"100755 executable\0".to_vec();
    content.extend_from_slice(&[7; 32]);
    let oid = object::hash_object(ObjectKind::Tree, &content);
    let full = temporary.path().join(oid.loose_path());
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(
        &full,
        object::encode_loose(ObjectKind::Tree, &content).unwrap(),
    )
    .unwrap();
    let source = crate::fetch::LocalFsFetch::new(temporary.path());

    let tree = ObjectReader::new(&source).tree_map(oid).await.unwrap();
    assert_eq!(tree["executable"].mode, "100755");
    let row = tree["executable"].clone();
    let duplicate = ProjectedTree {
        oid,
        rows: vec![row.clone(), row],
        body_fetches: AtomicUsize::new(0),
    };
    assert!(ObjectReader::new(&duplicate).tree_map(oid).await.is_err());
    assert_eq!(duplicate.body_fetches.load(Ordering::SeqCst), 0);
}
