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
fn projection_counters_use_distinct_semantic_and_live_byte_bounds() {
    let (mut projection, selections) = projection();
    projection.inflated_entry_bytes =
        aos_registry_surface::pack_index::MAX_DECODED_PACK_BYTES as u64;
    projection.peak_decoded_graph_bytes =
        aos_registry_surface::pack_index::MAX_LIVE_DECODED_PACK_BYTES as u64;
    projection.validate(&projection.index.path, &selections).unwrap();

    projection.inflated_entry_bytes += 1;
    assert!(projection.validate(&projection.index.path, &selections).is_err());
    projection.inflated_entry_bytes -= 1;
    projection.peak_decoded_graph_bytes += 1;
    assert!(projection.validate(&projection.index.path, &selections).is_err());
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
    changed.peak_decoded_graph_bytes =
        aos_registry_surface::pack_index::MAX_LIVE_DECODED_PACK_BYTES as u64 + 1;
    assert!(changed
        .validate(&projection.index.path, &selection)
        .is_err());
    changed = projection.clone();
    changed.inflated_entry_bytes =
        aos_registry_surface::pack_index::MAX_DECODED_PACK_BYTES as u64 + 1;
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

#[test]
fn guarded_pair_cursor_refuses_replacement_even_when_selected_tree_is_missing() {
    use crate::storage_authority::{control::StorageAuthorityObjectScope,
        external_object::copy::source::CopySourceClosure, lease::LeaseInteger,
        GuardIncarnation, PhysicalStorageAuthorityId, StorageGuardStamp};
    use crate::storage_work::protected_inspection::ProtectedInspectionSource;

    let (mut pair, _) = projection();
    pair.objects.clear();
    for source in [&mut pair.pack, &mut pair.index] {
        let authority = PhysicalStorageAuthorityId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        source.guarded_source = Some(ProtectedInspectionSource {
            version: 1,
            scope: StorageAuthorityObjectScope { guard_namespace_id: "actual-namespace".into(),
                physical_authority_id: authority.clone(), full_key: format!("binding/placement/{}", source.path) },
            closure: CopySourceClosure { guard_stamp: StorageGuardStamp {
                physical_authority_id: authority, incarnation: GuardIncarnation::parse("1").unwrap() },
                receipt_digest: "a".repeat(64), sha256: source.sha256.clone(),
                bytes: LeaseInteger::new(source.size as i64).unwrap(), etag: Some(source.etag.clone()) },
        });
    }
    let oid = "b".repeat(64);
    let names = vec!["first".into(), "selected".into()];
    let query = MirrorPackTreeQuery { index_path: pair.index.path.clone(), oid: oid.clone(), names: names.clone(),
        cursor: Some(crate::tree_projection::GitTreeCursor { tree_oid: oid.clone(),
            selection_digest: crate::tree_projection::selection_digest(&names).unwrap(),
            source_commitment: pair.source_commitment().unwrap(), next_index: 1 }),
        protected_profile_digest: "c".repeat(64) };
    let original = MirrorPackTreeProjection { pair, tree_oid: oid, object_size: None, page: None };
    original.validate(&query).unwrap();

    let mut changed = original.clone();
    changed.pair.pack.guarded_source.as_mut().unwrap().closure.guard_stamp.incarnation =
        GuardIncarnation::parse("2").unwrap();
    assert!(changed.validate(&query).is_err());
    changed = original;
    changed.pair.index.guarded_source.as_mut().unwrap().closure.receipt_digest = "d".repeat(64);
    assert!(changed.validate(&query).is_err());
}
