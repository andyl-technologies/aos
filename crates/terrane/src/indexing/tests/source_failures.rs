//! Retains original source failure subjects and rejects contextual misuse.

use super::*;
use terrane_core::cbor;

pub(super) fn prove_failures() {
    let fixture = Fixture::small();
    // Establish the valid baseline before isolating each source mutation.
    let baseline = ReadOnly::new(fixture.nodes.clone());
    source::assert_small_source(
        &source::source(&baseline, fixture.owner),
        &source::namespace(&fixture),
    );

    for subject in [fixture.owner, fixture.child] {
        let identity = terrane_core::identity::TERRANE_V1
            .from_digest(IdentityKind::Node, &subject)
            .require();
        for (kind, outcome) in [
            (
                StoreErrorKind::Absent(identity.clone()),
                ErrorKind::Incomplete,
            ),
            (
                StoreErrorKind::Unavailable { retry_after: None },
                ErrorKind::Incomplete,
            ),
            (
                StoreErrorKind::Corrupt(CorruptSubject::Identity(identity)),
                ErrorKind::Invalid,
            ),
            (StoreErrorKind::Unsupported, ErrorKind::Unsupported),
            (StoreErrorKind::ReadOnly, ErrorKind::Store),
        ] {
            let mut store = ReadOnly::new(fixture.nodes.clone());
            store.failure = Some((subject, kind.clone()));
            let error = failure(&store, fixture.owner);
            assert_eq!(error.subject(), Some(subject));
            assert_eq!(error.kind(), outcome);
            let Error::Store {
                failure: original, ..
            } = &error
            else {
                panic!("original store failure lost")
            };
            assert_eq!(original.kind(), &kind);
            assert_eq!(
                error.source().require().source().require().to_string(),
                "retained backend witness"
            );
            assert!(store.gets.lock().require().contains(&subject));
        }

        let mut absent = fixture.nodes.clone();
        absent.remove(&subject);
        let store = ReadOnly::new(absent);
        let error = failure(&store, fixture.owner);
        assert_eq!(error.subject(), Some(subject));
        assert_eq!(error.kind(), ErrorKind::Incomplete);
        assert!(
            matches!(error, Error::Store { failure, .. } if matches!(failure.kind(), StoreErrorKind::Absent(_)))
        );

        let mut wrong_address = fixture.nodes.clone();
        wrong_address.get_mut(&subject).require().push(0);
        let store = ReadOnly::new(wrong_address);
        let error = failure(&store, fixture.owner);
        assert_eq!(error.subject(), Some(subject));
        assert!(matches!(
            error,
            Error::Invalid {
                failure: evaluation::Error::Relationship,
                ..
            }
        ));
        assert!(error.source().is_some());

        let denied = StoreErrorKind::Denied {
            verb: "read",
            pattern: "selected-root".to_owned(),
        };
        let mut store = ReadOnly::new(fixture.nodes.clone());
        store.failure = Some((subject, denied.clone()));
        let error = failure(&store, fixture.owner);
        assert_eq!(error.subject(), Some(subject));
        assert_eq!(error.kind(), ErrorKind::Store);
        let Error::Store {
            failure: original, ..
        } = &error
        else {
            panic!("store permission refusal lost")
        };
        assert_eq!(original.kind(), &denied);
        // The original store taxonomy intentionally omits denied diagnostics.
        assert!(error.source().require().source().is_none());
    }

    let store = ReadOnly::new(fixture.nodes.clone());
    for revisions in [
        SemanticRevisions {
            property: 2,
            ..REVISIONS
        },
        SemanticRevisions {
            attribute: 1,
            ..REVISIONS
        },
        SemanticRevisions {
            tree: 2,
            ..REVISIONS
        },
    ] {
        let error = ready(load_source(&store, fixture.owner, revisions, MINIMUM))
            .err()
            .require();
        assert!(matches!(error, Error::Unsupported));
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert_eq!(error.subject(), None);
    }
    let error = ready(load_source(&store, fixture.owner, REVISIONS, MINIMUM + 1))
        .err()
        .require();
    assert!(matches!(error, Error::Unsupported));
    assert!(store.gets.lock().require().is_empty());

    prove_malformed_nodes();
    prove_structural_properties();
    prove_structural_attributes();
}

fn failure(store: &ReadOnly, owner: Digest) -> Error {
    let error = ready(load_source(store, owner, REVISIONS, MINIMUM))
        .err()
        .require();
    eprintln!(
        "source refusal owner={owner:?} error={error:?} requests={:?} returned_bytes={}",
        store.gets.lock().require(),
        store.returned_bytes.lock().require()
    );
    error
}

fn assert_invalid(nodes: BTreeMap<Digest, Vec<u8>>, owner: Digest, subject: Digest) {
    let store = ReadOnly::new(nodes);
    let error = failure(&store, owner);
    assert_eq!(error.subject(), Some(subject));
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert!(error.source().is_some());
}

fn prove_malformed_nodes() {
    // Readdress malformed immutable data so these checks reach the decoder,
    // rather than failing only the identity check.
    for bytes in [
        vec![0xa2, 1, 0x18, 0, 2, 0x80],
        vec![0xa2, 1, 0, 2, 0x80, 0],
    ] {
        let mut nodes = BTreeMap::new();
        let owner = store_node(&mut nodes, bytes.clone());
        assert_invalid(nodes, owner, owner);

        let mut fixture = Fixture::small();
        fixture.replace_child(bytes);
        assert_invalid(fixture.nodes, fixture.owner, fixture.child);
    }
    let mut fixture = Fixture::small();
    fixture.owner_rows[0].1 = file(OBJECT, Some(1), MINIMUM + 1, false);
    fixture.rebuild_owner();
    assert_invalid(fixture.nodes, fixture.owner, fixture.owner);
}

fn malformed_bindings() -> Vec<Vec<u8>> {
    let valid = binding("index-roots", [4; 32], true);
    let mut inherited = valid.clone();
    *inherited.last_mut().require() = 0xf5;
    let mut wrong_width = vec![0xa1];
    cbor::write_text(&mut wrong_width, "index-roots");
    wrong_width.push(0xa2);
    cbor::write_text(&mut wrong_width, "value");
    wrong_width.push(0xa1);
    cbor::write_text(&mut wrong_width, "uid");
    cbor::write_text(&mut wrong_width, &"0".repeat(63));
    cbor::write_text(&mut wrong_width, "inherit");
    wrong_width.push(0xf4);
    let mut bare = vec![0xa1];
    cbor::write_text(&mut bare, "index-roots");
    bare.push(0xa1);
    cbor::write_text(&mut bare, "uid");
    cbor::write_text(&mut bare, &"0".repeat(64));
    vec![inherited, wrong_width, bare]
}

fn prove_structural_properties() {
    for properties in malformed_bindings() {
        let mut fixture = Fixture::small();
        fixture.owner = store_node(
            &mut fixture.nodes,
            leaf(&fixture.owner_rows, Some(properties.clone())),
        );
        assert_invalid(fixture.nodes, fixture.owner, fixture.owner);

        let mut fixture = Fixture::small();
        fixture.replace_child(leaf(
            &[(b"a".to_vec(), file(OBJECT, Some(1), 10, false))],
            Some(properties),
        ));
        assert_invalid(fixture.nodes, fixture.owner, fixture.child);
    }

    // A syntactically valid local child binding is retained but never followed.
    let mut fixture = Fixture::small();
    let missing_index = [4; 32];
    let child_rows = vec![
        (b"a".to_vec(), file(OBJECT, Some(1), 10, false)),
        (b"d".to_vec(), file(OBJECT, None, 10, false)),
    ];
    fixture.replace_child(leaf(
        &child_rows,
        Some(binding("index-roots", missing_index, true)),
    ));
    let store = ReadOnly::new(fixture.nodes.clone());
    let raw = source::source(&store, fixture.owner);
    source::assert_small_source(&raw, &source::namespace(&fixture));
    assert_requests(&store, &BTreeSet::from([fixture.owner, fixture.child]));

    for properties in [binding("index-roots", [4; 32], true), gap_binding([4; 32])] {
        let mut fixture = Fixture::small();
        let mut entry = graft(fixture.child);
        entry[0] = 0xa3;
        entry.push(7);
        entry.extend(properties);
        fixture.owner_rows[3].1 = entry;
        fixture.rebuild_owner();
        assert_invalid(fixture.nodes, fixture.owner, fixture.owner);
    }
    for descendant in [false, true] {
        let mut fixture = Fixture::small();
        if descendant {
            fixture.replace_child(leaf(&child_rows, Some(gap_binding([4; 32]))));
        } else {
            fixture.owner = store_node(
                &mut fixture.nodes,
                leaf(&fixture.owner_rows, Some(gap_binding([4; 32]))),
            );
        }
        let subject = if descendant {
            fixture.child
        } else {
            fixture.owner
        };
        assert_invalid(fixture.nodes, fixture.owner, subject);
    }
}

fn prove_structural_attributes() {
    for descendant in [false, true] {
        let mut entry = file(OBJECT, None, 10, false);
        entry[0] = 0xa5;
        entry.extend_from_slice(&[9, 0xa1]);
        cbor::write_text(&mut entry, "index.occurrences");
        cbor::write_bytes(&mut entry, &[4; 32]);
        let mut fixture = Fixture::small();
        if descendant {
            fixture.replace_child(leaf(&[(b"a".to_vec(), entry)], None));
        } else {
            fixture.owner_rows[0].1 = entry;
            fixture.rebuild_owner();
        }
        let subject = if descendant {
            fixture.child
        } else {
            fixture.owner
        };
        assert_invalid(fixture.nodes, fixture.owner, subject);
    }
}
