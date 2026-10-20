//! Builds genuine signed mixed histories and independently encoded certificates.
//!
//! The retained ordinary dependency is PUBLIC. The private source graph remains
//! only in the independent issuer fixture; destination validation gets its real
//! certificate and complete public dependency, never fabricated checked scopes.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;
use crate::auth::RequestRoot;
use crate::cbor;
use crate::refs::{Commit, EntryOrigin, EntrySource};
use crate::tree_format::Property;

/// Retains actual public dependency and certified destination metadata.
pub(super) struct MixedFixture {
    /// Complete ordinary destination history without private source records.
    pub(super) history: VerifiedHistory,
    /// Genuine signed public dependency, with its own independently selected mode.
    pub(super) parent: VerifiedCommit,
    /// Genuine signed certified destination with its final certificate.
    pub(super) candidate: VerifiedCommit,
    /// Actual independently verified source used to issue the certificate.
    pub(super) source: disclosure::Fixture,
    /// Canonical properties on the public dependency, including optional inert names.
    pub(super) parent_properties: Vec<Property<'static>>,
}

/// Creates an ordinary exact association without supplying provenance authority.
///
/// # Panics
/// Panics if the literal revision or preservation registrations are invalid.
pub(super) fn association(
    record: &VerifiedCommit,
    revision: u64,
    later: &[&str],
) -> RecordedAssociation {
    RecordedAssociation::new(
        record.identity(),
        record.commit().tree,
        RecordedContext::new(revision, 3, later).unwrap(),
    )
}

/// Independently reauthenticates finalized signed metadata and original claims.
///
/// # Panics
/// Panics if genuine token, signature, claim or immutable identity checks fail.
fn reverified(record: VerifiedCommit) -> VerifiedCommit {
    let roots = record
        .commit()
        .profile_pair
        .commit_context
        .as_ref()
        .unwrap()
        .roots()
        .iter()
        .map(|root| RequestRoot {
            path: root.path(),
            domain: root.domain(),
        })
        .collect::<Vec<_>>();
    let checked = verify_history(
        record.commit(),
        &issuer_keys(),
        &roots,
        &[("refs/heads/main", 4)],
    )
    .unwrap();
    assert_eq!(checked.identity(), record.identity());
    checked
}

/// Signs an independently assembled registered disclosure statement.
///
/// # Panics
/// Panics if genuine source introduction, typed certificate slots or signing fail.
fn certify(source: &disclosure::Fixture, mut commit: Commit) -> VerifiedCommit {
    let binding = disclosure_target_binding(&commit).unwrap();
    let receipt = &mut commit.profile_pair.entry_receipts.as_mut().unwrap()[0];
    let origin = receipt.reintroduced_from.as_ref().unwrap();
    let introduced = source
        .source
        .introducing_commit(&EntryLocation {
            commit: origin.commit,
            root: origin.root,
            path: origin.path.clone(),
        })
        .unwrap();
    assert_eq!(introduced, source.source_commit.identity());
    let proof = receipt.disclosure_proof.as_mut().unwrap();

    let mut preimage = b"terrane-disclosure-proof-v1\0".to_vec();
    cbor::write_array(&mut preimage, 8);
    cbor::write_text(&mut preimage, &proof.authority_key);
    cbor::write_text(&mut preimage, &proof.source_domain);
    cbor::write_uint(&mut preimage, proof.observed_at);
    cbor::write_array(&mut preimage, 3);
    cbor::write_bytes(&mut preimage, &origin.commit);
    cbor::write_bytes(&mut preimage, &origin.root);
    cbor::write_bytes(&mut preimage, &origin.path);
    cbor::write_bytes(&mut preimage, &introduced);
    cbor::write_array(&mut preimage, 4);
    cbor::write_text(&mut preimage, "refs/heads/main");
    cbor::write_bytes(&mut preimage, &receipt.root);
    cbor::write_bytes(&mut preimage, &receipt.path);
    cbor::write_text(&mut preimage, "public");
    cbor::write_array(&mut preimage, 3);
    cbor::write_uint(&mut preimage, 1);
    cbor::write_uint(&mut preimage, 3);
    cbor::write_array(&mut preimage, 2);
    cbor::write_uint(&mut preimage, 0);
    cbor::write_bytes(&mut preimage, &[31; 32]);
    cbor::write_bytes(&mut preimage, &binding);
    proof.signature = SigningKey::from_bytes(&[21; 32]).sign(&preimage).to_bytes();

    reverified(disclosure::authored(commit, "public", &[11; 32], false))
}

/// Produces genuine canonical public ancestry and a separately certified source edge.
///
/// # Panics
/// Panics if actual canonical encodings, signatures, certificate issuance or
/// immutable history consistency fail before the test's verification action.
pub(super) fn fixture(inert_parent: bool) -> MixedFixture {
    let later_properties = if inert_parent {
        vec![
            Property {
                name: "index-roots",
                value: &[0],
            },
            Property {
                name: "index-gaps",
                value: &[0],
            },
        ]
    } else {
        Vec::new()
    };
    with_parent_properties(
        &later_properties,
        if inert_parent {
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap(),
            )
        } else {
            crate::properties::selected::Selection::Legacy
        },
    )
}

/// Signs a parent whose later binding stays inert under Recorded-1 and valid under Recorded-3.
///
/// # Panics
/// Panics if the genuine signed fixture or its exact canonical witnesses are invalid.
pub(super) fn valid_later_binding_fixture() -> MixedFixture {
    with_parent_properties(
        &[Property {
            name: "index-roots",
            value: b"\xa2\x65value\xa0\x67inherit\xf4",
        }],
        crate::properties::selected::Selection::Recorded(
            RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap(),
        ),
    )
}

fn with_parent_properties(
    later_properties: &[Property<'static>],
    parent_selection: crate::properties::selected::Selection,
) -> MixedFixture {
    let source = disclosure::fixture(disclosure::file());
    let mut parent_properties = vec![
        Property {
            name: "domain",
            value: b"\x66public",
        },
        Property {
            name: "trust",
            value: b"\x63any",
        },
    ];
    parent_properties.extend_from_slice(later_properties);
    parent_properties.sort_by_key(|property| property.name);
    let (parent_root, parent_bytes) = tree(
        vec![item(b"other", disclosure::file())],
        Some(parent_properties.clone()),
    );
    let mut parent_receipt = receipt(parent_root, EntryOrigin::Current);
    parent_receipt.path = b"other".to_vec();
    let mut parent_commit = unsigned_commit();
    parent_commit.tree = parent_root;
    parent_commit.profile_pair.entry_receipts = Some(vec![parent_receipt]);
    let parent = reverified(disclosure::authored(
        parent_commit,
        "public",
        &[9; 32],
        true,
    ));
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(parent_root, &[(parent_root, parent_bytes)])
        .unwrap();
    history
        .insert_commit_selected(parent.clone(), parent_selection)
        .unwrap();

    let disclosed = source.destination.entry(&source.target).unwrap();
    let (root, bytes) = disclosure::root_tree(
        vec![item(b"file", disclosed), item(b"other", disclosure::file())],
        "public",
    );
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = source.destination_commit.commit().clone();
    commit.tree = root;
    commit.parents = vec![parent.identity(), source.source_commit.identity()];
    commit.profile_pair.entry_receipts.as_mut().unwrap()[0].root = root;
    let mut other = receipt(
        root,
        EntryOrigin::Source(EntrySource {
            commit: parent.identity(),
            root: parent_root,
            path: b"other".to_vec(),
        }),
    );
    other.path = b"other".to_vec();
    commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .push(other);
    let candidate = certify(&source, commit);
    history
        .insert_commit_selected(
            candidate.clone(),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
        )
        .unwrap();

    MixedFixture {
        history,
        parent,
        candidate,
        source,
        parent_properties,
    }
}

/// Completes actual dependency scope and the real mixed candidate with bootstrap input.
///
/// # Errors
/// Preserves actual candidate, dependency, original-scope and complete Finish refusals.
///
/// # Panics
/// Panics if the actual planned dependencies differ from the genuine public parent.
pub(super) fn finish(
    fixture: &MixedFixture,
    selections: &ViewPropertySelections,
) -> Result<(VerifiedHistory, VerifiedDisclosureBatch), Rejected> {
    let mut candidate = DisclosureCandidate::new_with_property_selections_and_bootstrap(
        &fixture.history,
        fixture.candidate.identity(),
        &[disclosure::authority()],
        disclosure::defaults(),
        selections,
        fixture_bootstrap().authority,
        fixture_bootstrap(),
    )?;
    assert_eq!(candidate.required_commits(), &[fixture.parent.identity()]);
    candidate.validate_dependency_scope_with_bootstrap(
        fixture.parent.identity(),
        fixture_bootstrap().authority,
        fixture_bootstrap(),
    )?;
    candidate.finish()
}
