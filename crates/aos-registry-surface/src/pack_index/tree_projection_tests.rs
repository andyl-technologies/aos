//! Complete-integrity ordering and storage-local tree projection regressions.

use std::cell::Cell;

use sha2::{Digest as _, Sha256};

use super::{PairReader, Selection, MAX_FEED_BYTES, MAX_SELECTED_CONTENT_BYTES};
use crate::object::{hash_object, parse_tree, ObjectKind, Oid};

fn pair(large: bool) -> (String, Oid, &'static [u8], &'static [u8]) {
    let (manifest, index, pack) = if large {
        (
            include_str!("fixtures/large-tree.json"),
            include_bytes!("fixtures/large-tree.idx").as_slice(),
            include_bytes!("fixtures/large-tree.pack").as_slice(),
        )
    } else {
        (
            include_str!("fixtures/manifest.json"),
            include_bytes!("fixtures/ofs.idx").as_slice(),
            include_bytes!("fixtures/ofs.pack").as_slice(),
        )
    };
    let manifest: serde_json::Value = serde_json::from_str(manifest).unwrap();
    let (path, oid) = if large {
        (&manifest["path"], &manifest["treeOid"])
    } else {
        (
            &manifest["ofs"]["path"],
            &manifest["objects"]["tree"]["oid"],
        )
    };
    (
        path.as_str().unwrap().to_owned(),
        Oid::from_hex(oid.as_str().unwrap()).unwrap(),
        index,
        pack,
    )
}

fn reader(path: &str, index: &[u8], pack: &[u8]) -> PairReader {
    let mut reader = PairReader::new(path).unwrap();
    for bytes in pack.chunks(37) {
        reader.feed_pack(bytes).unwrap();
    }
    for bytes in index.chunks(17) {
        reader.feed_index(bytes).unwrap();
    }
    reader
}

#[test]
fn canonical_tree_callback_matches_verified_raw_selection_and_commitments() {
    let (path, oid, index, pack) = pair(false);
    let exact = reader(&path, index, pack)
        .finish(&[Selection { oid, range: None }])
        .unwrap();
    let calls = Cell::new(0);
    let projected = reader(&path, index, pack)
        .finish_tree_projection(oid, |bytes| {
            calls.set(calls.get() + 1);
            assert_eq!(hash_object(ObjectKind::Tree, bytes), oid);
            parse_tree(bytes)
        })
        .unwrap();

    let tree = projected.tree.unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(tree.oid, oid);
    assert_eq!(tree.object_size, exact.objects[0].object_size);
    let rows = |entries: Vec<crate::object::TreeEntry>| {
        entries
            .into_iter()
            .map(|entry| (entry.mode, entry.name, entry.oid))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        rows(tree.projection),
        rows(parse_tree(&exact.objects[0].content).unwrap())
    );
    let mut commitments = exact;
    commitments.objects.clear();
    assert_eq!(projected.pair, commitments);
}

#[test]
fn large_verified_tree_projects_bounded_rows_without_enlarging_raw_selection() {
    let (path, oid, index, pack) = pair(true);
    let selection = Selection { oid, range: None };
    assert!(reader(&path, index, pack)
        .finish(&[selection.clone()])
        .is_err());
    assert!(reader(&path, index, pack)
        .finish_available(&[selection])
        .is_err());

    let projected = reader(&path, index, pack)
        .finish_tree_projection(oid, |bytes| {
            assert_eq!(bytes.len(), 229376);
            assert_eq!(hash_object(ObjectKind::Tree, bytes), oid);
            // This controlled callback reads eight rows; production page/cursor
            // validation belongs to the caller's closed tree projection format.
            let mut position = 0;
            let mut rows = Vec::new();
            for _ in 0..8 {
                let end = position
                    + bytes[position..]
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap();
                let row = std::str::from_utf8(&bytes[position..end])
                    .unwrap()
                    .to_owned();
                let object = Oid::from_bytes(&bytes[end + 1..end + 33]).unwrap();
                rows.push((row, object));
                position = end + 33;
            }
            Ok(rows)
        })
        .unwrap();

    let tree = projected.tree.unwrap();
    assert!(tree.object_size > MAX_SELECTED_CONTENT_BYTES as u64);
    assert_eq!(tree.projection.len(), 8);
    assert_eq!(tree.projection[0].0, "100644 entry-00000.toml");
    assert_eq!(tree.projection[7].0, "100644 entry-00007.toml");
    assert!(
        tree.projection
            .iter()
            .map(|(row, _)| row.len() + 32)
            .sum::<usize>()
            < 16 * 1024
    );
    assert!(projected.pair.objects.is_empty());
    assert_eq!(
        projected.pair.pack.sha256,
        <[u8; 32]>::from(Sha256::digest(pack))
    );
    assert!(projected.pair.peak_decoded_graph_bytes <= super::super::MAX_DECODED_PACK_BYTES as u64);
}

#[test]
fn missing_tree_and_present_non_tree_never_invoke_callback() {
    let (path, _, index, pack) = pair(true);
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/large-tree.json")).unwrap();
    let blob = Oid::from_hex(manifest["blobOid"].as_str().unwrap()).unwrap();
    let absent = Oid::from_bytes(&[0; 32]).unwrap();
    let called = Cell::new(false);
    let missing = reader(&path, index, pack)
        .finish_tree_projection(absent, |_| {
            called.set(true);
            Ok(())
        })
        .unwrap();
    assert!(missing.tree.is_none());
    assert_eq!(
        missing.pair,
        reader(&path, index, pack).finish(&[]).unwrap()
    );
    assert!(!called.get());

    assert!(reader(&path, index, pack)
        .finish_tree_projection(blob, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
}

#[test]
fn full_pair_integrity_precedes_callback_or_absence() {
    let (path, tree, index, pack) = pair(true);
    let mut changed = index.to_vec();
    let crc_start =
        super::super::HEADER_BYTES + super::super::FANOUT_BYTES + 2 * super::super::OBJECT_ID_BYTES;
    changed[crc_start] ^= 1;
    let checksum_start = changed.len() - 32;
    let checksum = Sha256::digest(&changed[..checksum_start]);
    changed[checksum_start..].copy_from_slice(&checksum);
    let called = Cell::new(false);

    for oid in [tree, Oid::from_bytes(&[0; 32]).unwrap()] {
        for (index, pack) in [
            (changed.as_slice(), pack),
            (&index[..index.len() - 1], pack),
            (index, &pack[..pack.len() - 1]),
        ] {
            assert!(reader(&path, index, pack)
                .finish_tree_projection(oid, |_| {
                    called.set(true);
                    Ok(())
                })
                .is_err());
            assert!(!called.get());
        }
    }
}

#[test]
fn callback_failure_returns_no_projection_and_failed_feed_never_calls_it() {
    let (path, oid, index, pack) = pair(true);
    let error = reader(&path, index, pack)
        .finish_tree_projection::<()>(oid, |_| anyhow::bail!("controlled projection refusal"))
        .unwrap_err();
    assert_eq!(error.to_string(), "controlled projection refusal");

    let mut failed = reader(&path, index, pack);
    assert!(failed.feed_index(&vec![0; MAX_FEED_BYTES + 1]).is_err());
    let called = Cell::new(false);
    assert!(failed
        .finish_tree_projection(oid, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
}
