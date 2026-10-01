//! Real Git pair projection identity and bounded Native output checks.

use super::*;
use aos_registry_surface::object::Oid;
use aos_registry_surface::pack_index::projection::{PairReader, Selection};

fn projection() -> (MirrorPackProjection, Vec<MirrorPackSelection>) {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../aos-registry-surface/src/pack_index/fixtures/manifest.json"
    ))
    .unwrap();
    let path = manifest["ofs"]["path"].as_str().unwrap();
    let oid = manifest["objects"]["small"]["oid"].as_str().unwrap();
    let mut reader = PairReader::new(path).unwrap();
    reader
        .feed_pack(include_bytes!(
            "../../../aos-registry-surface/src/pack_index/fixtures/ofs.pack"
        ))
        .unwrap();
    reader
        .feed_index(include_bytes!(
            "../../../aos-registry-surface/src/pack_index/fixtures/ofs.idx"
        ))
        .unwrap();
    let pair = reader
        .finish(&[Selection {
            oid: Oid::from_hex(oid).unwrap(),
            range: None,
        }])
        .unwrap();
    let projected = MirrorPackProjection::from_verified(
        pair,
        "\"pack-original\"".into(),
        "\"index-original\"".into(),
    )
    .unwrap();
    (
        projected,
        vec![MirrorPackSelection {
            oid: oid.into(),
            range: None,
        }],
    )
}

#[test]
fn real_pair_returns_selected_content_without_encoded_source_bodies() {
    let (projection, selection) = projection();
    projection
        .validate(&projection.index.path, &selection)
        .unwrap();
    assert_eq!(projection.pack.size, 1196);
    assert_eq!(projection.index.size, 1336);
    assert_eq!(projection.objects[0].object_size, 28);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&projection.objects[0].content_base64)
            .unwrap()
            .len(),
        28
    );
    let encoded = serde_json::to_vec(&projection).unwrap();
    assert!(encoded.len() < 2048);
    assert!(!String::from_utf8(encoded).unwrap().contains("UEFDSw"));
}

#[test]
fn exact_source_and_whole_object_identity_refuse_substitution() {
    let (projection, selection) = projection();
    let mut changed = projection.clone();
    changed.pack.path = "objects/pack/other.pack".into();
    assert!(changed
        .validate(&projection.index.path, &selection)
        .is_err());
    changed = projection.clone();
    changed.pack.etag = "W/\"weak\"".into();
    assert!(changed
        .validate(&projection.index.path, &selection)
        .is_err());
    changed = projection.clone();
    changed.objects[0].content_base64 = base64::engine::general_purpose::STANDARD.encode([0; 28]);
    assert!(changed
        .validate(&projection.index.path, &selection)
        .is_err());
    changed = projection.clone();
    changed.objects[0].range.end += 1;
    assert!(changed
        .validate(&projection.index.path, &selection)
        .is_err());
    changed = projection.clone();
    changed.peak_decoded_graph_bytes = 12 * 1024 * 1024 + 1;
    assert!(changed
        .validate(&projection.index.path, &selection)
        .is_err());
    assert!(projection
        .validate(
            &projection.index.path,
            &[selection[0].clone(), selection[0].clone()]
        )
        .is_err());
}

#[test]
fn available_partition_cannot_omit_repeat_or_invent_an_oid() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../aos-registry-surface/src/pack_index/fixtures/manifest.json"
    ))
    .unwrap();
    let path = manifest["ofs"]["path"].as_str().unwrap();
    let present = manifest["objects"]["small"]["oid"].as_str().unwrap();
    let absent = "f".repeat(64);
    let selections = vec![
        MirrorPackSelection {
            oid: present.into(),
            range: None,
        },
        MirrorPackSelection {
            oid: absent.clone(),
            range: None,
        },
    ];
    let mut reader = PairReader::new(path).unwrap();
    reader
        .feed_pack(include_bytes!(
            "../../../aos-registry-surface/src/pack_index/fixtures/ofs.pack"
        ))
        .unwrap();
    reader
        .feed_index(include_bytes!(
            "../../../aos-registry-surface/src/pack_index/fixtures/ofs.idx"
        ))
        .unwrap();
    let available = reader
        .finish_available(&[
            Selection {
                oid: Oid::from_hex(present).unwrap(),
                range: None,
            },
            Selection {
                oid: Oid::from_hex(&absent).unwrap(),
                range: None,
            },
        ])
        .unwrap();
    let projected = MirrorPackProjection::from_available(
        available,
        "\"pack-original\"".into(),
        "\"index-original\"".into(),
    )
    .unwrap();

    projected.validate(path, &selections).unwrap();
    assert_eq!(projected.objects.len(), 1);
    assert_eq!(projected.missing_oids, [absent.clone()]);
    let mut changed = projected.clone();
    changed.missing_oids.clear();
    assert!(changed.validate(path, &selections).is_err());
    changed = projected.clone();
    changed.missing_oids[0] = present.into();
    assert!(changed.validate(path, &selections).is_err());
    changed = projected;
    changed.missing_oids[0] = "e".repeat(64);
    assert!(changed.validate(path, &selections).is_err());
}

#[test]
fn large_packed_tree_returns_only_pages_bound_to_the_verified_pair() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../aos-registry-surface/src/pack_index/fixtures/large-tree.json"
    ))
    .unwrap();
    let path = manifest["path"].as_str().unwrap();
    let oid = manifest["treeOid"].as_str().unwrap();
    let names = (0..32)
        .map(|index| format!("entry-{index:05}.toml"))
        .collect::<Vec<_>>();
    let query = MirrorPackTreeQuery {
        index_path: path.into(),
        oid: oid.into(),
        names,
        cursor: None,
        protected_profile_digest: "1".repeat(64),
    };
    let mut reader = PairReader::new(path).unwrap();
    for bytes in
        include_bytes!("../../../aos-registry-surface/src/pack_index/fixtures/large-tree.pack")
            .chunks(64)
    {
        reader.feed_pack(bytes).unwrap();
    }
    reader
        .feed_index(include_bytes!(
            "../../../aos-registry-surface/src/pack_index/fixtures/large-tree.idx"
        ))
        .unwrap();
    let verified = reader
        .finish_tree_projection(Oid::from_hex(oid).unwrap(), |content| {
            crate::tree_projection::project_tree(oid, content, &query.names, None, &"0".repeat(64))
        })
        .unwrap();
    let pair = MirrorPackProjection::from_verified(
        verified.pair,
        "\"pack-original\"".into(),
        "\"index-original\"".into(),
    )
    .unwrap();
    let tree = verified.tree.unwrap();
    let mut page = tree.projection;
    let commitment = pair.source_commitment().unwrap();
    page.source_commitment = commitment.clone();
    if let Some(cursor) = &mut page.next_cursor {
        cursor.source_commitment = commitment;
    }
    let projected = MirrorPackTreeProjection {
        pair,
        tree_oid: oid.into(),
        object_size: Some(tree.object_size),
        page: Some(page),
    };

    projected.validate(&query).unwrap();
    assert_eq!(projected.object_size, Some(229376));
    assert_eq!(projected.page.as_ref().unwrap().entries.len(), 16);
    assert!(projected.page.as_ref().unwrap().next_cursor.is_some());
    assert!(serde_json::to_vec(&projected).unwrap().len() < 16 * 1024);
    assert!(projected.pair.objects.is_empty());
    let mut changed = projected.clone();
    changed.pair.pack.etag = "\"another-incarnation\"".into();
    assert!(changed.validate(&query).is_err());
    changed = projected;
    changed.object_size = None;
    assert!(changed.validate(&query).is_err());
}
