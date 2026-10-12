//! Separates retained signed-time key evidence from independently current ACLs.

use super::witness_support::*;
use super::*;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{RefStore, StoreErrorKind};
use terrane_core::provenance::{DisclosureAuthority, DisclosureCandidate, OriginalBootstrapPolicy};

/// Retains genuine old certificate evidence and refuses a freshly revoked Read.
///
/// # Panics
/// Panics if native publication/reopening fails, pure issue windows disagree,
/// retained keys change, or a current denied read borrows historical authority.
pub(super) async fn retain_keys_and_revoke_current_read() {
    let (source, authority, credentials) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let plaintext = b"signed issue time is independent of later destination policy";
    let private = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: file(plaintext),
        }],
        materialization::properties(true),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let public = Tree::build(
        private.iter().cloned().collect(),
        materialization::properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut source_session = source
        .begin(REFERENCE, authority.token(), "sdk")
        .await
        .unwrap();
    let original = source
        .advance(
            &mut source_session,
            proposal(&authority, Vec::new(), &private, &[plaintext]),
        )
        .await
        .unwrap();
    let imported = source
        .guard()
        .original_commit(&original.commit)
        .unwrap()
        .retained_import_record()
        .unwrap();
    let mut target = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&destination_authority, Vec::new(), &public, &[plaintext]),
                selections: vec![DisclosureCommitSelection {
                    source_reference: REFERENCE.into(),
                    source_commit: original.commit,
                    source_path: b"/file".to_vec(),
                    source_token: authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    assert_ne!(
        authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key
    );
    assert_eq!(
        destination
            .guard()
            .original_commit(&original.commit)
            .unwrap()
            .retained_import_record()
            .unwrap(),
        imported
    );
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let roles = destination.guard().history_disclosure_roles().unwrap();
    let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
    let baseline = destination
        .guard()
        .original_commit(&published.commit)
        .unwrap();
    let baseline = baseline.baseline();
    let original_authority = baseline
        .authority()
        .id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let acl = baseline
        .acl()
        .iter()
        .map(|(subject, verbs)| (subject.as_str(), *verbs))
        .collect::<Vec<_>>();
    let verify = |roles: &[DisclosureAuthority<'_>]| {
        DisclosureCandidate::new_with_bootstrap(
            &checked.history,
            published.commit,
            roles,
            destination.guard().defaults_for(&checked.evidence),
            &original_authority,
            OriginalBootstrapPolicy {
                authority: &original_authority,
                reference: baseline.reference(),
                writer_epoch: baseline.epoch(),
                acl: &acl,
            },
        )
        .and_then(|candidate| candidate.finish())
    };
    let (_, batch) = verify(&authorities).unwrap();
    assert_eq!(batch.boundaries().len(), 1);
    let boundary = &batch.boundaries()[0];
    assert_eq!(boundary.source().commit, original.commit);
    assert_eq!(boundary.original_introducer(), original.commit);
    let issued = boundary.observed_at();
    let after = issued.checked_add(1).unwrap();
    let old = DisclosureAuthority {
        repository: boundary.authority_repository(),
        domain: boundary.authority_domain(),
        public_key: *boundary.authority_key(),
        not_before: issued,
        not_after: Some(after),
    };

    // These are pure interval/rotation oracles on an actual signed receipt.
    // Native additive rotation has its own real selected-transition fixture;
    // these interval oracles never edit protected historical role rows.
    assert!(verify(&[old]).is_ok());
    assert!(
        verify(&[DisclosureAuthority {
            not_before: after,
            not_after: None,
            ..old
        }])
        .is_err()
    );
    assert!(
        verify(&[DisclosureAuthority {
            not_before: issued.saturating_sub(1),
            not_after: Some(issued),
            ..old
        }])
        .is_err()
    );
    assert!(verify(&[]).is_err());
    let later = DisclosureAuthority {
        public_key: terrane_core::auth::public_key_from_secret(&[0x79; 32]),
        not_before: after,
        not_after: None,
        ..old
    };
    assert!(verify(&[old, later]).is_ok());
    assert!(checked.history.commit(&original.commit).is_none());
    let (location, _) = checked.history.locate(published.commit, b"file").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        published.commit
    );
    let retained_tree = checked
        .evidence
        .tree(checked.evidence.root, MINIMUM)
        .unwrap();
    let absent = [
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &original.commit)
            .unwrap(),
        TERRANE_V1
            .from_digest(IdentityKind::Node, &private.root_identity())
            .unwrap(),
    ];
    assert_eq!(destination.store().has(&absent).await.unwrap(), [false; 2]);
    drop(source_session);
    drop(authority);
    drop(target);
    erase_source(source, credentials).await;
    let destination = reopen(destination, &destination_authority).await;
    assert_eq!(
        destination
            .guard()
            .original_commit(&original.commit)
            .unwrap()
            .retained_import_record()
            .unwrap(),
        imported
    );
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(checked.commit.identity(), published.commit);
    assert!(checked.history.commit(&original.commit).is_none());
    drop(checked);

    // Genuine Admin authority from the old policy admits its own narrowing.
    let mut properties = retained_tree.props().unwrap().to_vec();
    properties
        .iter_mut()
        .find(|property| property.name == "acl")
        .unwrap()
        .value = b"\x81\x82\x66writer\x00";
    let revoked = retained_tree
        .with_properties(Some(properties))
        .unwrap()
        .tree;
    let mut target = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let narrowed = destination
        .advance(
            &mut target,
            proposal(
                &destination_authority,
                vec![published.commit],
                &revoked,
                &[plaintext],
            ),
        )
        .await
        .unwrap();
    assert!(
        destination
            .guard()
            .verified_history(narrowed.commit)
            .await
            .is_ok()
    );
    let physical_before = physical_snapshot(destination.store().root()).await;
    let denied = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await;
    let observed = denied
        .as_ref()
        .err()
        .map(|error| format!("{error:?}"))
        .unwrap_or_else(|| "authorized current Read".into());
    assert!(
        matches!(denied, Err(error) if matches!(error.kind(), StoreErrorKind::Denied { verb: "read", .. })),
        "observed current decision: {observed}"
    );
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(narrowed)
    );
    assert_eq!(destination.store().has(&absent).await.unwrap(), [false; 2]);
    assert_eq!(
        physical_snapshot(destination.store().root()).await,
        physical_before
    );
}
