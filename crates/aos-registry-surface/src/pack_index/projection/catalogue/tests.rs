//! Full semantic coverage and corruption refusal using real Git fixtures.

use super::*;
use crate::pack_index::projection::{Selection, MAX_FEED_BYTES};

fn fixture(kind: &str) -> (String, &'static [u8], &'static [u8], serde_json::Value) {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/manifest.json")).unwrap();
    let (pack, index) = match kind {
        "ofs" => (
            include_bytes!("../../fixtures/ofs.pack").as_slice(),
            include_bytes!("../../fixtures/ofs.idx").as_slice(),
        ),
        "ref" => (
            include_bytes!("../../fixtures/ref.pack").as_slice(),
            include_bytes!("../../fixtures/ref.idx").as_slice(),
        ),
        _ => panic!("unsupported test fixture"),
    };
    (
        manifest[kind]["path"].as_str().unwrap().into(),
        pack,
        index,
        manifest,
    )
}

fn reader(path: &str, pack: &[u8], index: &[u8]) -> PairReader {
    let mut reader = PairReader::new(path).unwrap();
    for chunk in pack.chunks(37) {
        reader.feed_pack(chunk).unwrap();
    }
    for chunk in index.chunks(17) {
        reader.feed_index(chunk).unwrap();
    }
    reader
}

#[test]
fn complete_catalogues_match_exact_content_projection_for_all_git_kinds() {
    for kind in ["ofs", "ref"] {
        let (path, pack, index, manifest) = fixture(kind);
        let catalogue = reader(&path, pack, index).finish_catalogue().unwrap();
        assert!(catalogue.pair.objects.is_empty());
        assert!(catalogue
            .objects
            .windows(2)
            .all(|rows| rows[0].oid < rows[1].oid));
        assert!(catalogue.objects.len() <= MAX_CATALOGUE_OBJECTS);
        assert_eq!(catalogue.pair.pack.size, pack.len() as u64);
        assert_eq!(catalogue.pair.index.size, index.len() as u64);

        for name in ["small", "tree", "commit", "tag"] {
            let oid = Oid::from_hex(manifest["objects"][name]["oid"].as_str().unwrap()).unwrap();
            let position = catalogue
                .objects
                .binary_search_by_key(&oid, |row| row.oid)
                .unwrap();
            let selected = reader(&path, pack, index)
                .finish(&[Selection { oid, range: None }])
                .unwrap();
            let summary = &catalogue.objects[position];
            assert_eq!(summary.kind, selected.objects[0].kind);
            assert_eq!(summary.object_size, selected.objects[0].object_size);
            let mut identity = selected;
            identity.objects.clear();
            assert_eq!(catalogue.pair, identity);
        }
        let absent = Oid::from_hex(&"f".repeat(64)).unwrap();
        assert!(catalogue
            .objects
            .binary_search_by_key(&absent, |row| row.oid)
            .is_err());
    }
}

#[test]
fn full_catalogue_refuses_corruption_truncation_and_poisoned_feeds() {
    let (path, pack, index, _) = fixture("ofs");
    let mut corrupt = pack.to_vec();
    corrupt[20] ^= 1;
    let mut invalid = PairReader::new(&path).unwrap();
    if invalid.feed_pack(&corrupt).is_ok() {
        invalid.feed_index(index).unwrap();
        assert!(invalid.finish_catalogue().is_err());
    }
    assert!(reader(&path, &pack[..pack.len() - 1], index)
        .finish_catalogue()
        .is_err());
    assert!(reader(&path, pack, &index[..index.len() - 1])
        .finish_catalogue()
        .is_err());

    let mut invalid = reader(&path, pack, index);
    assert!(invalid.feed_index(&vec![0; MAX_FEED_BYTES + 1]).is_err());
    assert!(invalid.finish_catalogue().is_err());
}
