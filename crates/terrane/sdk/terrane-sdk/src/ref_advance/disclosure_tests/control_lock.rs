//! Keeps an actual destination Original reader alive across disclosure installation.
//!
//! The retained native descriptor outlives its backend holder and blocks the
//! real import writer; releasing it permits the same signed route and selected ACK.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{LocalFs, RefStore, StoreErrorKind};
use witness_support::{MINIMUM, REFERENCE, file, physical_snapshot, proposal};

#[tokio::test]
async fn disclosure_install_refuses_retained_original_reader_after_backend_release() {
    let (source, source_authority, source_credentials) =
        independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let plaintext = b"disclosure imports require an actual exclusive Original control lock";
    let tree = |private| {
        Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: file(plaintext),
            }],
            materialization::properties(private),
            MINIMUM,
            TreeUse::Ordinary,
        )
        .unwrap()
    };
    let private_tree = tree(true);
    let public_tree = tree(false);
    let mut source_writer = source
        .begin(REFERENCE, source_authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source
        .advance(
            &mut source_writer,
            proposal(&source_authority, Vec::new(), &private_tree, &[plaintext]),
        )
        .await
        .unwrap();
    let mut writer = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let previous = writer.record().cloned();
    let request = || DisclosureCommitRequest {
        proposal: proposal(
            &destination_authority,
            Vec::new(),
            &public_tree,
            &[plaintext],
        ),
        selections: vec![DisclosureCommitSelection {
            source_reference: REFERENCE.into(),
            source_commit: source_head.commit,
            source_path: b"/file".to_vec(),
            source_token: source_authority.token().to_vec(),
            destination_path: b"/file".to_vec(),
        }],
    };
    let (entered, resume) =
        crate::selected_bridge::native_guard::disclosure::pause_next_after_baseline(
            destination.store().root(),
        )
        .unwrap();
    let publish = destination.advance_disclosure(source.guard(), &mut writer, request());
    let retain_reader = async {
        entered.await.unwrap();
        // Baseline retention has already completed. The subsequent writer must
        // therefore refuse in the actual destination import transition.
        let before = physical_snapshot(destination.store().root()).await;
        let authority = destination.guard().configured_original_authority().unwrap();
        let holder = SingleHeld::acquire(destination.store()).await.unwrap();
        let held = holder.destination();
        let identity = held.identity_proof();
        let mut controls = destination
            .guard()
            .hold_original_registration(&authority, &identity)
            .await
            .unwrap();
        let registration = TokioLocalFs
            .read_nofollow(&authority.control().join("registration.cbor"))
            .await
            .unwrap();
        let receipt = controls
            .retain_named(&[("registration.cbor".into(), registration)])
            .await
            .unwrap();
        let exclusions = receipt.exclusions();
        assert!(!exclusions.is_empty());
        drop(receipt);
        drop(controls);
        drop(held);
        drop(holder);
        resume.send(()).unwrap();
        (exclusions, before)
    };
    let (result, (exclusions, before)) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(publish, retain_reader)
    })
    .await
    .unwrap();
    let Err(AdvanceError::Store(failure)) = result else {
        panic!("the actual disclosure writer must refuse the retained destination reader");
    };
    assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
    assert_eq!(writer.record(), previous.as_ref());
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        previous
    );
    assert_eq!(
        source.store().ref_get(REFERENCE).await.unwrap(),
        Some(source_head.clone())
    );
    assert_eq!(physical_snapshot(destination.store().root()).await, before);
    assert!(
        destination
            .guard()
            .original_commit(&source_head.commit)
            .is_err()
    );

    // A fresh backend exclusion succeeds while the retained Original read lock
    // remains live: the failed producer and the reader released their holders.
    let holder = tokio::time::timeout(
        Duration::from_secs(5),
        SingleHeld::acquire(destination.store()),
    )
    .await
    .unwrap()
    .unwrap();
    drop(holder);
    drop(exclusions);
    let published = destination
        .advance_disclosure(source.guard(), &mut writer, request())
        .await
        .unwrap();
    assert_eq!(writer.record(), Some(&published));
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(published.clone())
    );
    assert!(
        destination
            .guard()
            .original_commit(&source_head.commit)
            .is_ok()
    );
    drop(source_writer);
    drop(source_authority);
    witness_support::erase_source(source, source_credentials).await;
    drop(writer);
    let reopened = witness_support::reopen(destination, &destination_authority).await;
    let snapshot = reopened
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(snapshot.commit.identity(), published.commit);
    assert!(snapshot.history.commit(&source_head.commit).is_none());
    let (location, _) = snapshot.history.locate(published.commit, b"file").unwrap();
    let EntryKind::File { content, size, .. } = snapshot.history.entry(&location).unwrap().kind
    else {
        panic!("disclosed entry is a file");
    };
    assert_eq!(
        reopened
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
}
