//! Complete inventories from actual verified Git pairs and refusal boundaries.

use super::*;
use aos_registry_surface::object::Oid;
use aos_registry_surface::pack_index::projection::PairReader;

fn query(path: &str, oid: &str) -> MirrorTreeInventoryQuery {
    MirrorTreeInventoryQuery {
        source: MirrorTreeInventorySource::Pack {
            inspection: MirrorPackInspection {
                registry_id: 1,
                registry_resource_version: 2,
                mirror_resource_version: 3,
                upstream_base: "https://upstream.example.invalid".into(),
                index_path: path.into(),
                protected_profile_digest: "1".repeat(64),
                selections: Vec::new(),
            },
        },
        tree_oid: oid.into(),
        cursor: None,
    }
}

#[test]
fn verified_large_pair_projects_every_row_once_without_source_bodies() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../aos-registry-surface/src/pack_index/fixtures/large-tree.json"
    ))
    .unwrap();
    let path = manifest["path"].as_str().unwrap();
    let oid = manifest["treeOid"].as_str().unwrap();
    let mut reader = PairReader::new(path).unwrap();
    for chunk in
        include_bytes!("../../../aos-registry-surface/src/pack_index/fixtures/large-tree.pack")
            .chunks(64)
    {
        reader.feed_pack(chunk).unwrap();
    }
    reader
        .feed_index(include_bytes!(
            "../../../aos-registry-surface/src/pack_index/fixtures/large-tree.idx"
        ))
        .unwrap();
    let verified = reader
        .finish_tree_projection(Oid::from_hex(oid).unwrap(), |tree| {
            project_pages(oid, tree, &"0".repeat(64))
        })
        .unwrap();
    let pair = MirrorPackProjection::from_verified(
        verified.pair,
        "\"original-pack\"".into(),
        "\"original-index\"".into(),
    )
    .unwrap();
    let tree = verified.tree.unwrap();
    let source = pair.source_commitment().unwrap();
    let mut selected = query(path, oid);
    let mut names = Vec::new();
    let mut returned_bytes = 0;

    assert_eq!(tree.object_size, 229376);
    assert_eq!(tree.projection.len(), 256);
    for mut page in tree.projection {
        page.source_commitment = source.clone();
        if let Some(cursor) = &mut page.next_cursor {
            cursor.source_commitment = source.clone();
        }
        let projection = MirrorTreeInventoryProjection {
            source: MirrorTreeInventoryCommitment::Pack { pair: pair.clone() },
            tree_oid: oid.into(),
            object_size: Some(tree.object_size),
            page: Some(page.clone()),
        };
        projection.validate(&selected).unwrap();
        let encoded = serde_json::to_vec(&projection).unwrap();
        assert!(encoded.len() < MAX_INVENTORY_PAGE_BYTES);
        returned_bytes += encoded.len();
        assert!(pair.objects.is_empty());
        names.extend(page.entries.iter().map(|row| row.name.clone()));
        selected.cursor = page.next_cursor;
    }

    assert_eq!(names.len(), 4096);
    assert!(names.windows(2).all(|rows| rows[0] < rows[1]));
    assert!(selected.cursor.is_none());
    assert_eq!(names.first().unwrap(), "entry-00000.toml");
    assert_eq!(names.last().unwrap(), "entry-04095.toml");
    assert!(returned_bytes < MAX_INVENTORY_CACHE_BYTES);
    // Both encoded sources are read once, independently of the 256 page count.
    assert_eq!(pair.pack.size + pair.index.size, 11871);
}

#[test]
fn pages_refuse_gaps_changed_sources_hidden_terminal_rows_and_duplicates() {
    let mut content = Vec::new();
    for index in 0..17 {
        content.extend_from_slice(format!("100644 item-{index:02}\0").as_bytes());
        content.extend_from_slice(&[7; 32]);
    }
    let oid = object::hash_object(ObjectKind::Tree, &content).to_hex();
    let source = "a".repeat(64);
    let pages = project_pages(&oid, &content, &source).unwrap();
    let mut selected = query(&format!("objects/pack/pack-{}.idx", "b".repeat(64)), &oid);

    pages[0].validate(&selected, &source).unwrap();
    let mut changed = pages[0].clone();
    changed.next_cursor = None;
    assert!(changed.validate(&selected, &source).is_err());
    changed = pages[0].clone();
    changed.entries.pop();
    assert!(changed.validate(&selected, &source).is_err());
    changed = pages[0].clone();
    changed.entries[1] = changed.entries[0].clone();
    assert!(changed.validate(&selected, &source).is_err());

    selected.cursor = pages[0].next_cursor.clone();
    pages[1].validate(&selected, &source).unwrap();
    assert!(pages[1].validate(&selected, &"c".repeat(64)).is_err());
    changed = pages[1].clone();
    changed.start_index += 1;
    assert!(changed.validate(&selected, &source).is_err());
    changed = pages[1].clone();
    changed.total_entries = 16;
    changed.entries.clear();
    assert!(changed.validate(&selected, &source).is_err());

    content.extend_from_slice(b"100644 item-00\0");
    content.extend_from_slice(&[7; 32]);
    let duplicate_oid = object::hash_object(ObjectKind::Tree, &content).to_hex();
    assert!(project_pages(&duplicate_oid, &content, &source).is_err());
}

#[test]
fn empty_tree_has_one_explicit_terminal_page_and_identity_is_independent() {
    let oid = object::hash_object(ObjectKind::Tree, &[]).to_hex();
    let source = "a".repeat(64);
    let pages = project_pages(&oid, &[], &source).unwrap();
    let selected = query(&format!("objects/pack/pack-{}.idx", "b".repeat(64)), &oid);

    assert_eq!(pages.len(), 1);
    pages[0].validate(&selected, &source).unwrap();
    assert_eq!(pages[0].total_entries, 0);
    assert!(pages[0].entries.is_empty());
    assert!(pages[0].next_cursor.is_none());
    assert!(project_pages(&"f".repeat(64), &[], &source).is_err());
    assert!(project_pages(&oid, &[], "not-a-source-commitment").is_err());
}

#[test]
fn canonical_loose_projection_preserves_incarnation_and_refuses_representation_change() {
    use sha2::{Digest as _, Sha256};

    let mut content = b"100755 executable\0".to_vec();
    content.extend_from_slice(&[9; 32]);
    let oid = object::hash_object(ObjectKind::Tree, &content);
    let encoded = object::encode_loose(ObjectKind::Tree, &content).unwrap();
    let (kind, decoded) = object::decode_loose(&encoded, Some(oid)).unwrap();
    assert_eq!(kind, ObjectKind::Tree);
    let source = MirrorTreeInventoryCommitment::Loose {
        object: MirrorPackSource {
            path: oid.loose_path(),
            sha256: hex::encode(Sha256::digest(&encoded)),
            size: encoded.len() as u64,
            etag: "\"exact-loose-incarnation\"".into(),
        },
    };
    let selected = MirrorTreeInventoryQuery {
        source: MirrorTreeInventorySource::Loose {
            registry_id: 1,
            registry_resource_version: 2,
            mirror_resource_version: 3,
            upstream_base: "https://upstream.example.invalid".into(),
            protected_profile_digest: "a".repeat(64),
        },
        tree_oid: oid.to_hex(),
        cursor: None,
    };
    let pages = project_pages(
        &oid.to_hex(),
        &decoded,
        &source.source_commitment().unwrap(),
    )
    .unwrap();
    let projected = MirrorTreeInventoryProjection {
        source,
        tree_oid: oid.to_hex(),
        object_size: Some(decoded.len() as u64),
        page: Some(pages[0].clone()),
    };

    projected.validate(&selected).unwrap();
    assert_eq!(
        projected.page.as_ref().unwrap().entries[0].kind,
        GitTreeEntryKind::ExecutableBlob
    );
    let mut changed = projected.clone();
    let MirrorTreeInventoryCommitment::Loose { object } = &mut changed.source else {
        unreachable!();
    };
    object.etag = "\"another-incarnation\"".into();
    assert!(changed.validate(&selected).is_err());
    changed = projected.clone();
    changed.object_size = None;
    changed.page = None;
    assert!(changed.validate(&selected).is_err());
    let pack_query = query(
        &format!("objects/pack/pack-{}.idx", "b".repeat(64)),
        &oid.to_hex(),
    );
    assert!(projected.validate(&pack_query).is_err());
}
