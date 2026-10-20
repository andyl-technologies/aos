//! Rejects retained public records whose complete metadata closure is private.

use super::*;

#[derive(Clone, Copy)]
enum PrivateEdge {
    SiblingGraft,
    OrdinaryAncestor,
    UnselectedOrigin,
}

fn retained_source(fixture: &Fixture, edge: PrivateEdge) -> (VerifiedHistory, VerifiedCommit) {
    let mut history = fixture.source.clone();
    let mut items = vec![item(b"other", file())];
    let mut claims = vec![RequestRoot {
        path: b"/",
        domain: PUBLIC,
    }];
    let mut commit = unsigned_commit();
    let mut receipts = Vec::new();

    match edge {
        PrivateEdge::SiblingGraft => {
            let (private, bytes) = root_tree(
                vec![item(b"secret", entry(b"private sibling metadata"))],
                SOURCE_DOMAIN,
            );
            history.insert_tree(private, &[(private, bytes)]).unwrap();
            let mut graft = entry(b"");
            graft.kind = EntryKind::Tree {
                root: private,
                props: None,
            };
            items.push(item(b"vault", graft));
            claims.push(RequestRoot {
                path: b"/vault",
                domain: SOURCE_DOMAIN,
            });
        }
        PrivateEdge::OrdinaryAncestor => {
            commit.parents = vec![fixture.source_commit.identity()];
            claims.push(RequestRoot {
                path: b"/",
                domain: SOURCE_DOMAIN,
            });
        }
        PrivateEdge::UnselectedOrigin => {
            items.insert(0, item(b"hidden", file()));
        }
    }

    let (root, bytes) = root_tree(items, PUBLIC);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    commit.tree = root;
    let mut other = receipt(root, EntryOrigin::Current);
    other.path = b"other".to_vec();
    receipts.push(other);
    if matches!(edge, PrivateEdge::UnselectedOrigin) {
        let mut hidden = receipt(
            root,
            EntryOrigin::Source(EntrySource {
                commit: fixture.source_commit.identity(),
                root: fixture.source_root,
                path: b"file".to_vec(),
            }),
        );
        hidden.path = b"hidden".to_vec();
        receipts.insert(0, hidden);
    }
    commit.profile_pair.entry_receipts = Some(receipts);
    let signed = authored_claims(commit, &claims, &[9; 32], true);
    history.insert_commit(signed.clone()).unwrap();
    verify_fixture_scope(&mut history, signed.identity(), defaults()).unwrap();

    // The selected entry is genuinely public, signed and independently new.
    let (location, _) = history.locate(signed.identity(), b"other").unwrap();
    assert_eq!(history.introducing_commit(&location), Ok(signed.identity()));
    (history, signed)
}

fn assert_private_retention_rejected(edge: PrivateEdge) {
    let fixture = fixture(file());
    let (retained, public_source) = retained_source(&fixture, edge);
    let disclosed = fixture.destination.entry(&fixture.target).unwrap();
    let (root, bytes) = root_tree(
        vec![item(b"file", disclosed), item(b"other", file())],
        PUBLIC,
    );
    let mut destination = fixture.destination.clone();
    destination.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = fixture.destination_commit.commit().clone();
    commit.tree = root;
    commit.parents = vec![public_source.identity(), fixture.source_commit.identity()];
    let receipts = commit.profile_pair.entry_receipts.as_mut().unwrap();
    receipts[0].root = root;
    let mut other = receipt(
        root,
        EntryOrigin::Source(EntrySource {
            commit: public_source.identity(),
            root: public_source.commit().tree,
            path: b"other".to_vec(),
        }),
    );
    other.path = b"other".to_vec();
    receipts.push(other);
    let signed = resign_certificate(&fixture, commit, &destination);
    destination.insert_commit(signed.clone()).unwrap();

    let mut candidate =
        disclosed_candidate(&destination, signed.identity(), &[authority()], defaults()).unwrap();
    assert_eq!(candidate.required_commits(), &[public_source.identity()]);
    // Supplying every genuine private record cannot make retention permissible.
    candidate.insert_history(&retained).unwrap();
    assert!(candidate.finish().is_err());
}

#[test]
fn prov_disclosure_public_selected_entry_cannot_retain_private_sibling_graft() {
    assert_private_retention_rejected(PrivateEdge::SiblingGraft);
}

#[test]
fn prov_disclosure_public_selected_entry_cannot_retain_private_ordinary_ancestor() {
    assert_private_retention_rejected(PrivateEdge::OrdinaryAncestor);
}

#[test]
fn prov_disclosure_public_selected_entry_cannot_retain_unselected_private_origin() {
    assert_private_retention_rejected(PrivateEdge::UnselectedOrigin);
}
