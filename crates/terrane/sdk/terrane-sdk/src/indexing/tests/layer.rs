//! Checks explicit Layer context without weakening owner-bound relationships.

use super::*;

fn layered_small() -> Fixture {
    let mut fixture = Fixture::small();
    let old_child = fixture.child;
    let old_owner = fixture.owner;
    fixture.replace_child(leaf(
        &[
            (b"a".to_vec(), file(OBJECT, Some(1), 10, false)),
            (b"d".to_vec(), file(OBJECT, None, 10, false)),
            (b"z".to_vec(), vec![0xa1, 1, 5]),
        ],
        None,
    ));
    fixture.owner_rows.push((b"z".to_vec(), vec![0xa1, 1, 5]));
    fixture.rebuild_owner();
    fixture.expected_requests.remove(&old_child);
    fixture.expected_requests.remove(&old_owner);
    fixture.expected_requests.insert(fixture.child);
    fixture.expected_requests.insert(fixture.owner);
    fixture
}

#[test]
fn load_layer_source_preserves_explicit_usage_and_canonical_closure() {
    for large in [false, true] {
        let fixture = if large {
            let mut fixture = Fixture::large();
            fixture.owner_rows.push((b"z".to_vec(), vec![0xa1, 1, 5]));
            fixture.rebuild_owner();
            fixture
        } else {
            layered_small()
        };
        let store = ReadOnly::new(fixture.nodes.clone());
        let loaded = ready(load_source_for(
            &store,
            fixture.owner,
            REVISIONS,
            MINIMUM,
            TreeUse::OverlayLayer,
        ))
        .require();
        let sources = loaded.sources().require();
        assert_eq!(loaded.owner(), fixture.owner);
        for (root, tree) in &sources.trees {
            assert_eq!(tree.usage(), TreeUse::OverlayLayer);
            assert_eq!(tree.root_identity(), *root);
            for node in tree.nodes() {
                assert_eq!(node.encoded(), fixture.nodes[&node.identity()]);
            }
        }
        assert!(sources.trees[&fixture.owner].iter().any(|item| matches!(
            item.entry.kind,
            terrane_format::tree_format::EntryKind::Whiteout
        )));
        if large {
            assert!(sources.trees[&fixture.owner].root().level() > 0);
            assert!(sources.work.compared_nodes > 1);
        } else {
            assert!(sources.trees[&fixture.child].iter().any(|item| matches!(
                item.entry.kind,
                terrane_format::tree_format::EntryKind::Whiteout
            )));
            assert_eq!(loaded.loading().namespace_roots, 3);
        }
        let requests = store.gets.lock().require();
        assert!(!requests.contains(&fixture.primary));
        drop(requests);

        let ordinary = ReadOnly::new(fixture.nodes);
        assert_eq!(
            ready(load_source(&ordinary, fixture.owner, REVISIONS, MINIMUM))
                .err()
                .require()
                .kind(),
            ErrorKind::Invalid
        );
    }
    for usage in [TreeUse::Index, TreeUse::Surface, TreeUse::ConflictSurface] {
        let store = ReadOnly::new(BTreeMap::new());
        let error = ready(load_source_for(&store, [0; 32], REVISIONS, MINIMUM, usage))
            .err()
            .require();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert!(store.gets.lock().require().is_empty());
    }
}

#[test]
fn load_layer_index_checks_complete_owner_binding_without_ordinary_fallback() {
    let fixture = layered_small();
    let store = ReadOnly::new(fixture.nodes.clone());
    let loaded = ready(load_for(
        &store,
        fixture.owner,
        "uid",
        REVISIONS,
        MINIMUM,
        TreeUse::OverlayLayer,
    ))
    .require();
    let sources = loaded.sources().require();
    let prepared = loaded.prepare(&sources.trees).require();
    assert_eq!(prepared.owner(), fixture.owner);
    assert_eq!(loaded.index_root(), fixture.primary);
    assert_eq!(prepared.preparation().verification.candidates, 2);
    assert_eq!(prepared.preparation().verification.missing_objects, 1);
    let candidates = prepared.candidates(&[1]).require();
    assert_eq!(candidates.rows.len(), 1);
    assert_eq!(candidates.rows[0].object(), OBJECT);
    let occurrences = candidates.rows[0].occurrences().require();
    assert_eq!(occurrences.rows.len(), 3);
    assert_eq!(
        occurrences
            .rows
            .iter()
            .filter(|occurrence| !occurrence.hops.is_empty())
            .count(),
        2
    );
    let missing = prepared.missing(OBJECT).require();
    assert_eq!(missing.rows.len(), 1);
    assert_eq!(missing.rows[0].occurrences().require().rows.len(), 3);
    assert_requests(&store, &fixture.expected_requests);

    let ordinary = ReadOnly::new(fixture.nodes.clone());
    assert_eq!(
        ready(load(&ordinary, fixture.owner, "uid", REVISIONS, MINIMUM))
            .err()
            .require()
            .kind(),
        ErrorKind::Invalid
    );
    assert!(!ordinary.gets.lock().require().contains(&fixture.primary));

    for missing in [true, false] {
        let mut fixture = layered_small();
        if missing {
            fixture.owner = store_node(&mut fixture.nodes, leaf(&fixture.owner_rows, None));
            let store = ReadOnly::new(fixture.nodes);
            let error = ready(load_for(
                &store,
                fixture.owner,
                "uid",
                REVISIONS,
                MINIMUM,
                TreeUse::OverlayLayer,
            ))
            .err()
            .require();
            assert!(matches!(error, Error::MissingBinding(owner) if owner == fixture.owner));
            assert_eq!(error.kind(), ErrorKind::Incomplete);
        } else {
            fixture.diverge(0);
            let store = ReadOnly::new(fixture.nodes);
            let loaded = ready(load_for(
                &store,
                fixture.owner,
                "uid",
                REVISIONS,
                MINIMUM,
                TreeUse::OverlayLayer,
            ))
            .require();
            let sources = loaded.sources().require();
            assert_eq!(
                loaded.prepare(&sources.trees).err().require().kind(),
                ErrorKind::Invalid
            );
        }
    }
}
