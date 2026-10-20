//! Applies actual whiteouts before public admission and preserves independent origins.

use super::witness_support::*;
use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{InvalidReason, RefStore, StoreErrorKind};
use terrane_format::algebra::Overlay;
use terrane_format::tree_format::Attribute;

mod native;

/// Materializes an ordinary public removal without certifying an absence claim.
///
/// # Panics
/// Panics if actual algebra/publication fails, origins change, raw whiteouts gain
/// certificate authority, denied removal has effects, or destination reopen fails.
pub(super) async fn materialize_public_removal() {
    let (destination, authority, public_credentials) = independent_factory("public").await;
    let destination = native::production(destination, &authority).await;
    let survivor = b"a public survivor predates its public attribute";
    let removed = b"the overlay removes this public file";
    let baseline = Tree::build(
        vec![
            LeafItem {
                key: b"gone".to_vec(),
                entry: file(removed),
            },
            LeafItem {
                key: b"keep".to_vec(),
                entry: file(survivor),
            },
        ],
        materialization::properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut session = destination
        .begin(REFERENCE, authority.token(), "sdk")
        .await
        .unwrap();
    let introduced = destination
        .advance(
            &mut session,
            proposal(&authority, Vec::new(), &baseline, &[removed, survivor]),
        )
        .await
        .unwrap();
    let mut with_attribute = file(survivor);
    with_attribute.attrs_present = true;
    with_attribute.attrs.push(Attribute {
        name: "note",
        value: b"\x61y",
    });
    let produced = Tree::build(
        vec![
            LeafItem {
                key: b"gone".to_vec(),
                entry: file(removed),
            },
            LeafItem {
                key: b"keep".to_vec(),
                entry: with_attribute.clone(),
            },
        ],
        materialization::properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let producer = destination
        .advance(
            &mut session,
            proposal(
                &authority,
                vec![introduced.commit],
                &produced,
                &[removed, survivor],
            ),
        )
        .await
        .unwrap();
    let layer = Tree::build(
        vec![LeafItem {
            key: b"gone".to_vec(),
            entry: entry(EntryKind::Whiteout),
        }],
        materialization::properties(false),
        MINIMUM,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let layers = [&layer, &produced];
    let overlay = Overlay::new(&layers);
    assert!(overlay.get(b"gone").is_none());
    assert_eq!(overlay.get(b"keep"), Some(&with_attribute));
    let materialized = overlay.materialize().unwrap();

    // A separate point update determines the ordinary result, with no overlay
    // traversal or recipe constructor in the expected path.
    let expected = Tree::build(
        vec![LeafItem {
            key: b"keep".to_vec(),
            entry: with_attribute,
        }],
        materialization::properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    assert_eq!(materialized.root_identity(), expected.root_identity());
    assert_eq!(materialized.root().encoded(), expected.root().encoded());
    assert_eq!(materialized.usage(), TreeUse::Ordinary);
    assert_eq!(materialized.props(), produced.props());

    let mut denied = proposal(
        &authority,
        vec![producer.commit],
        &materialized,
        &[survivor],
    );
    let terminal = [0x76; 32];
    denied.token = terrane_format::auth::Token::decode(authority.token())
        .unwrap()
        .attenuate(
            terrane_format::auth::Attenuation {
                not_after: None,
                not_before: None,
                grants: Some(vec![
                    terrane_format::auth::Grant::new(
                        REFERENCE.into(),
                        terrane_format::auth::Verbs::new(1).unwrap(),
                    )
                    .unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &denied.terminal_secret,
            terrane_format::auth::public_key_from_secret(&terminal),
        )
        .unwrap()
        .encode();
    denied.terminal_secret = terminal;
    let denied_ids = offered(&denied);
    let before = destination.store().has(&denied_ids).await.unwrap();
    let physical_before = physical_snapshot(destination.store().root()).await;
    let denied_removal = destination.advance(&mut session, denied).await;
    assert!(matches!(
        denied_removal,
        Err(AdvanceError::Store(error))
            if matches!(error.kind(), StoreErrorKind::Denied { verb: "commit", .. })
    ));
    assert_eq!(destination.store().has(&denied_ids).await.unwrap(), before);
    assert_eq!(
        physical_snapshot(destination.store().root()).await,
        physical_before
    );
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(producer.clone())
    );

    // A real source file cannot certify a raw whiteout, even with current Read
    // and destination Commit authority. No source/private absence is imported.
    let (source, source_authority, credentials) = independent_factory("private:writer").await;
    let source = native::production(source, &source_authority).await;
    let private = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: file(removed),
        }],
        materialization::properties(true),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut source_session = source
        .begin(REFERENCE, source_authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source
        .advance(
            &mut source_session,
            proposal(&source_authority, Vec::new(), &private, &[removed]),
        )
        .await
        .unwrap();
    let raw = proposal(&authority, vec![producer.commit], &layer, &[]);
    let raw_ids = offered(&raw);
    let before = destination.store().has(&raw_ids).await.unwrap();
    let physical_before = physical_snapshot(destination.store().root()).await;
    let raw_whiteout = destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            DisclosureCommitRequest {
                proposal: raw,
                selections: vec![DisclosureCommitSelection {
                    source_reference: REFERENCE.into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/gone".to_vec(),
                }],
            },
        )
        .await;
    assert!(matches!(
        raw_whiteout,
        Err(AdvanceError::Store(error))
            if error.kind() == &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    ));
    assert_eq!(destination.store().has(&raw_ids).await.unwrap(), before);
    assert_eq!(
        physical_snapshot(destination.store().root()).await,
        physical_before
    );
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(producer.clone())
    );

    // The destination baseline differs from both ordered input commits. The
    // native recipe must retain this actual current head independently of input
    // precedence instead of treating the first layer as a serving baseline.
    let baseline_head = destination
        .advance(
            &mut session,
            proposal(
                &authority,
                vec![producer.commit],
                &produced,
                &[removed, survivor],
            ),
        )
        .await
        .unwrap();
    assert_ne!(baseline_head.commit, producer.commit);
    let upper = destination
        .repository
        .publish_overlay_layer(
            &mut session,
            proposal(&authority, vec![baseline_head.commit], &layer, &[]),
        )
        .await
        .unwrap();
    assert_eq!(upper.root, layer.root_identity());
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(baseline_head.clone())
    );
    assert_eq!(
        destination
            .guard()
            .original_commit(&upper.commit)
            .unwrap_or_else(|error| {
                panic!(
                    "the signed overlay layer must retain its actual protected Original: {error}"
                )
            })
            .commit(),
        &upper.commit
    );
    assert!(
        destination
            .guard()
            .verified_history(upper.commit)
            .await
            .is_err()
    );

    let applied = destination
        .repository
        .overlay(
            &mut session,
            &[
                crate::guard::OverlayInput {
                    reference: REFERENCE.into(),
                    commit: upper.commit,
                },
                crate::guard::OverlayInput {
                    reference: REFERENCE.into(),
                    commit: producer.commit,
                },
            ],
            proposal(
                &authority,
                vec![baseline_head.commit],
                &expected,
                &[survivor],
            ),
        )
        .await
        .unwrap();
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/keep", "sdk")
        .await
        .unwrap();
    let (location, _) = checked.history.locate(applied.commit, b"keep").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        introduced.commit
    );
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        producer.commit
    );
    assert_eq!(
        checked.history.entry(&location).unwrap().attrs,
        expected.get(b"keep").unwrap().attrs
    );
    assert!(checked.history.locate(applied.commit, b"gone").is_err());
    assert_eq!(
        checked.commit.commit().parents,
        vec![baseline_head.commit, upper.commit, producer.commit]
    );
    let recipe = terrane_format::algebra::Recipe::decode(
        checked
            .commit
            .commit()
            .profile_pair
            .recipe
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    match recipe.as_recipe() {
        terrane_format::algebra::Recipe::OverlayWithDomains { roots, .. } => {
            assert_eq!(roots, &[upper.root, produced.root_identity()])
        }
        other => panic!("actual signed overlay recipe: {other:?}"),
    }
    assert!(checked.history.commit(&upper.commit).is_some());
    assert_eq!(checked.evidence.root, expected.root_identity());
    assert!(
        checked
            .commit
            .commit()
            .profile_pair
            .entry_receipts
            .as_deref()
            .unwrap_or_default()
            .iter()
            .all(|receipt| receipt.disclosure_proof.is_none())
    );
    let forbidden = [
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &source_head.commit)
            .unwrap(),
        TERRANE_V1
            .from_digest(IdentityKind::Node, &private.root_identity())
            .unwrap(),
    ];
    assert_eq!(
        destination.store().has(&forbidden).await.unwrap(),
        [false; 2]
    );
    let retained_layer = [
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &upper.commit)
            .unwrap(),
        TERRANE_V1
            .from_digest(IdentityKind::Node, &upper.root)
            .unwrap(),
    ];
    assert_eq!(
        destination.store().has(&retained_layer).await.unwrap(),
        [true; 2]
    );
    drop(checked);
    drop(source_session);
    drop(source_authority);
    native::erase_source(source, credentials).await;
    drop(session);
    let destination = native::reopen(destination, &authority).await;
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/keep", "sdk")
        .await
        .unwrap();
    assert_eq!(checked.commit.identity(), applied.commit);
    assert_eq!(
        checked.commit.commit().parents,
        vec![baseline_head.commit, upper.commit, producer.commit]
    );
    assert_eq!(
        terrane_format::algebra::Recipe::decode(
            checked
                .commit
                .commit()
                .profile_pair
                .recipe
                .as_deref()
                .unwrap()
        )
        .unwrap(),
        recipe
    );
    let (location, _) = checked.history.locate(applied.commit, b"keep").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        introduced.commit
    );
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        producer.commit
    );
    assert!(checked.history.locate(applied.commit, b"gone").is_err());
    assert_eq!(
        destination.store().has(&forbidden).await.unwrap(),
        [false; 2]
    );
    assert!(checked.history.commit(&upper.commit).is_some());
    assert_eq!(
        destination.store().has(&retained_layer).await.unwrap(),
        [true; 2]
    );
    assert!(
        destination
            .guard()
            .verified_history(upper.commit)
            .await
            .is_err()
    );
    drop(checked);
    native::disclose_and_reopen(
        destination,
        authority,
        public_credentials,
        native::MaterializedOrigins {
            materialized: applied.commit,
            introducer: introduced.commit,
            producer: producer.commit,
        },
        &expected,
        survivor,
    )
    .await;
}
