//! Proves namespace-only requests and contextual physical reconstruction.

use super::*;
use terrane_core::cbor;

pub(super) fn source(store: &ReadOnly, owner: Digest) -> LoadedSource {
    let raw = ready(load_source(store, owner, REVISIONS, MINIMUM)).require();
    assert_eq!(
        *store.returned_bytes.lock().require(),
        raw.loading().fetched_bytes
    );
    eprintln!(
        "source acquisition owner={owner:?} work={:?} requests={:?}",
        raw.loading(),
        store.gets.lock().require()
    );
    raw
}

pub(super) fn namespace(fixture: &Fixture) -> BTreeMap<Digest, Vec<u8>> {
    BTreeMap::from([
        (fixture.owner, fixture.nodes[&fixture.owner].clone()),
        (fixture.child, fixture.nodes[&fixture.child].clone()),
    ])
}

pub(super) fn assert_small_source(raw: &LoadedSource, expected: &BTreeMap<Digest, Vec<u8>>) {
    assert_eq!(&raw.namespace, expected);
    assert_eq!(raw.roots, expected.keys().copied().collect());
    assert_eq!(raw.context, SemanticContext::new(3, 2, 1).require());
    assert_eq!(raw.minimum, MINIMUM);
    assert_eq!(
        raw.loading(),
        Loading {
            gets: 2,
            fetched_bytes: expected.values().map(Vec::len).sum(),
            identity_checks: 3,
            node_decodes: 3,
            namespace_roots: 3,
            carrier_checks: 0,
        }
    );

    let sources = raw.sources().require();
    assert_eq!(
        sources.work,
        Reconstruction {
            node_decodes: 4,
            identity_checks: 2,
            trees: 2,
            entries: 7,
            compared_nodes: 2,
        }
    );
    for (root, tree) in &sources.trees {
        assert_eq!(tree.root_identity(), *root);
        assert_eq!(tree.root().encoded(), expected[root]);
    }
    assert_eq!(raw.sources().require().work, sources.work);
}

fn without_selected_binding(fixture: &mut Fixture, absent: bool) {
    let properties = if absent {
        None
    } else {
        let mut empty = vec![0xa1];
        cbor::write_text(&mut empty, "index-roots");
        empty.push(0xa2);
        cbor::write_text(&mut empty, "value");
        empty.push(0xa0);
        cbor::write_text(&mut empty, "inherit");
        empty.push(0xf4);
        Some(empty)
    };
    fixture.owner = store_node(&mut fixture.nodes, leaf(&fixture.owner_rows, properties));
}

pub(super) fn prove_auxiliary_independence() {
    for absent in [true, false] {
        let mut fixture = Fixture::small();
        without_selected_binding(&mut fixture, absent);
        let expected = namespace(&fixture);
        let mut stored = fixture.nodes.clone();
        let unrelated = store_node(
            &mut stored,
            leaf(
                &[(b"unrelated".to_vec(), file([9; 32], Some(3), 10, false))],
                None,
            ),
        );
        assert!(!expected.contains_key(&unrelated));
        let store = ReadOnly::new(stored);
        let raw = source(&store, fixture.owner);
        assert_eq!(raw.owner(), fixture.owner);
        assert_small_source(&raw, &expected);
        assert_requests(&store, &expected.keys().copied().collect());

        let strict = ReadOnly::new(fixture.nodes);
        let error = ready(load(&strict, fixture.owner, "uid", REVISIONS, MINIMUM))
            .err()
            .require();
        assert!(matches!(error, Error::MissingBinding(subject) if subject == fixture.owner));
        assert_eq!(error.kind(), ErrorKind::Incomplete);
        assert_requests(&strict, &expected.keys().copied().collect());
    }

    // Source acquisition has the same independently enumerated namespace when
    // its selected binding names absent, wrongly addressed or divergent I.
    for evidence in 0..3 {
        let mut fixture = Fixture::small();
        if evidence == 2 {
            fixture.diverge(0);
        }
        let expected = namespace(&fixture);
        if evidence == 0 {
            fixture.nodes.remove(&fixture.primary);
        } else if evidence == 1 {
            fixture.nodes.get_mut(&fixture.primary).require().push(0);
        }
        let store = ReadOnly::new(fixture.nodes.clone());
        let raw = source(&store, fixture.owner);
        assert_small_source(&raw, &expected);
        assert_requests(&store, &expected.keys().copied().collect());

        let strict = ReadOnly::new(fixture.nodes);
        if evidence == 2 {
            let bound = loaded(&strict, fixture.owner);
            let sources = bound.sources().require();
            let error = bound.prepare(&sources.trees).err().require();
            assert_eq!(error.kind(), ErrorKind::Invalid);
            assert_eq!(error.subject(), Some(fixture.owner));
            assert!(matches!(
                error,
                Error::Invalid {
                    failure: evaluation::Error::Relationship,
                    ..
                }
            ));
        } else {
            let error = ready(load(&strict, fixture.owner, "uid", REVISIONS, MINIMUM))
                .err()
                .require();
            assert_eq!(error.subject(), Some(fixture.primary));
            if evidence == 0 {
                let Error::Store { failure, .. } = error else {
                    panic!("missing original failure")
                };
                assert!(matches!(failure.kind(), StoreErrorKind::Absent(_)));
            } else {
                assert!(matches!(
                    error,
                    Error::Invalid {
                        failure: evaluation::Error::Relationship,
                        ..
                    }
                ));
            }
        }
        assert!(strict.gets.lock().require().contains(&fixture.primary));
    }
}

pub(super) fn prove_physical_contexts() {
    // The independent boundary model creates raw internal ordinary Nodes. Only
    // this namespace is stored; two grafts repeat every child physical context.
    // A third graft uses one of those exact internal leaves as a legal root.
    let rows: Vec<_> = (0..POPULATION)
        .map(|index| {
            (
                format!("file{index:05}").into_bytes(),
                file(OBJECT, Some(1), 10, false),
            )
        })
        .collect();
    let mut nodes = BTreeMap::new();
    let child = build(&mut nodes, &rows, None);
    assert_eq!(nodes[&child][2], 1);
    let physical = nodes.len();
    let shared_leaf = *nodes.iter().find(|(_, bytes)| bytes[2] == 0).require().0;
    let mut leaf_header = cbor::Decoder::new(&nodes[&shared_leaf]);
    assert_eq!(leaf_header.map(2).require(), 2);
    assert_eq!(leaf_header.uint().require(), 1);
    assert_eq!(leaf_header.uint().require(), 0);
    assert_eq!(leaf_header.uint().require(), 2);
    let shared_entries = leaf_header.array(POPULATION).require();
    let owner_rows = vec![
        (b"g".to_vec(), graft(child)),
        (b"h".to_vec(), graft(child)),
        (b"i".to_vec(), graft(shared_leaf)),
    ];
    let owner = store_node(&mut nodes, leaf(&owner_rows, None));
    let store = ReadOnly::new(nodes.clone());
    let raw = source(&store, owner);
    assert_eq!(raw.namespace, nodes);
    assert_eq!(raw.roots, BTreeSet::from([owner, child, shared_leaf]));
    assert_requests(&store, &nodes.keys().copied().collect());
    assert_eq!(
        raw.loading(),
        Loading {
            gets: physical + 1,
            fetched_bytes: nodes.values().map(Vec::len).sum(),
            identity_checks: 2 + physical * 2,
            node_decodes: 2 + physical * 2,
            namespace_roots: 4,
            carrier_checks: 0,
        }
    );
    let rebuilt = raw.sources().require();
    assert_eq!(
        rebuilt.work,
        Reconstruction {
            node_decodes: physical + 5,
            identity_checks: physical + 2,
            trees: 3,
            entries: POPULATION + shared_entries + 3,
            compared_nodes: physical + 2,
        }
    );
    assert_eq!(rebuilt.trees[&child].iter().count(), POPULATION);
    assert_eq!(raw.sources().require().work, rebuilt.work);

    for change in [
        ChildChange::Count,
        ChildChange::Weight,
        ChildChange::Separator,
        ChildChange::Level,
    ] {
        let mut changed = nodes.clone();
        let wrong = changed_internal(&mut changed, child, change);
        let owner = store_node(&mut changed, leaf(&[(b"g".to_vec(), graft(wrong))], None));
        let store = ReadOnly::new(changed);
        let raw = source(&store, owner);
        let error = raw.sources().err().require();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{change:?}");
        assert_eq!(error.subject(), Some(wrong));
        assert!(matches!(
            error,
            Error::Invalid {
                failure: evaluation::Error::Relationship,
                ..
            }
        ));
    }

    prove_noncanonical_grouping();
    prove_depth();
    let fixture = Fixture::small();
    let store = ReadOnly::new(fixture.nodes);
    ready(loading::check_source_cached_context_guards(
        &store,
        fixture.owner,
    ));
}

fn prove_noncanonical_grouping() {
    // Both leaves and all summaries are valid, but two tiny leaves violate the
    // independently known canonical boundary: these two rows fit one leaf.
    let mut nodes = BTreeMap::new();
    let first = store_node(
        &mut nodes,
        leaf(&[(b"a".to_vec(), file(OBJECT, Some(1), 10, false))], None),
    );
    let second = store_node(
        &mut nodes,
        leaf(&[(b"b".to_vec(), file(OBJECT, None, 10, false))], None),
    );
    let mut parent = vec![0xa2, 1, 1, 2, 0x82];
    for (key, child) in [(b"a", first), (b"b", second)] {
        parent.push(0x84);
        cbor::write_bytes(&mut parent, key);
        cbor::write_bytes(&mut parent, &child);
        cbor::write_uint(&mut parent, 1);
        cbor::write_uint(&mut parent, nodes[&child].len() as u64);
    }
    let owner = store_node(&mut nodes, parent);
    let store = ReadOnly::new(nodes);
    let raw = source(&store, owner);
    let error = raw.sources().err().require();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(error.subject(), Some(owner));
    assert!(matches!(
        error,
        Error::Invalid {
            failure: evaluation::Error::Relationship,
            ..
        }
    ));
}

fn prove_depth() {
    for depth in [64, 65] {
        let mut nodes = BTreeMap::new();
        let empty = store_node(&mut nodes, leaf(&[], None));
        let mut owner = empty;
        for _ in 0..depth {
            owner = store_node(&mut nodes, leaf(&[(b"g".to_vec(), graft(owner))], None));
        }
        let store = ReadOnly::new(nodes.clone());
        if depth == 64 {
            let raw = source(&store, owner);
            assert_eq!(raw.loading().namespace_roots, 65);
            assert_eq!(raw.sources().require().work.trees, 65);
            assert_requests(&store, &nodes.keys().copied().collect());
        } else {
            let error = ready(load_source(&store, owner, REVISIONS, MINIMUM))
                .err()
                .require();
            assert_eq!(error.subject(), Some(empty));
            assert!(matches!(
                error,
                Error::Invalid {
                    failure: evaluation::Error::Limit,
                    ..
                }
            ));
            assert!(!store.gets.lock().require().contains(&empty));
        }
    }
}
