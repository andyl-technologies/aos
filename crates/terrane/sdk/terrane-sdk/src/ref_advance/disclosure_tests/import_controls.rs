//! Refuses canonical imported controls copied between actual physical destinations.

use super::*;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::local_authority::{
    LocalAuthority, import_binding::ImportBindingRecord, public_trust::PublicTrustRecord,
    retention::Record,
};
use crate::store::{InvalidReason, RefStore, StoreErrorKind};
use terrane_format::refs::RefRecord;

fn control(root: &std::path::Path) -> std::path::PathBuf {
    root.with_file_name(format!(
        "{}-original-control",
        root.file_name().unwrap().to_string_lossy()
    ))
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn publish(
    source: &NativeFixture<TokioLocalFs>,
    source_authority: &LocalAuthority,
    source_head: &RefRecord,
    destination: &NativeFixture<TokioLocalFs>,
    destination_authority: &LocalAuthority,
    plaintext: &[u8],
) -> RefRecord {
    let reference = "refs/heads/_/main";
    let mut session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(Vec::new(), plaintext);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap()
}

async fn reject_changed_control(
    destination: &NativeFixture<TokioLocalFs>,
    authority: &LocalAuthority,
    head: &RefRecord,
    path: &std::path::Path,
    changed: &[u8],
    expected: &[u8],
) {
    let reference = "refs/heads/_/main";
    tokio::fs::write(path, changed).await.unwrap();
    let Err(failure) = destination
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
    else {
        panic!("copied or conflicting retained controls must refuse original verification");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    assert_eq!(
        destination.store().ref_get(reference).await.unwrap(),
        Some(head.clone())
    );
    tokio::fs::write(path, expected).await.unwrap();
    let checked = destination
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(checked.commit.identity(), head.commit);
}

/// Checks physical destination scope and exact historical key rows independently.
///
/// # Panics
/// Panics if genuine publication fails, canonical copied controls remain accepted,
/// a conflicting genuine issuer key verifies the original, or restoration fails.
pub(super) async fn reject_copied_controls() {
    let (source, source_authority, _) = independent_factory("public").await;
    let (other_source, other_authority, _) = independent_factory("public").await;
    let (first, first_authority, _) = independent_factory("public").await;
    let (second, second_authority, _) = independent_factory("public").await;
    assert_eq!(
        source_authority.issuer_key().issuer,
        other_authority.issuer_key().issuer
    );
    assert_eq!(
        source_authority.issuer_key().key_id,
        other_authority.issuer_key().key_id
    );
    assert_ne!(
        source_authority.issuer_key().public_key,
        other_authority.issuer_key().public_key
    );
    assert_ne!(
        first_authority.issuer_key().public_key,
        second_authority.issuer_key().public_key
    );
    let reference = "refs/heads/_/main";
    let plaintext = b"physical import bindings cannot move between destinations";
    let mut session = source
        .begin(reference, source_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(Vec::new(), plaintext);
    let mut proposal = source_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let source_head = source.advance(&mut session, proposal).await.unwrap();
    let first_head = publish(
        &source,
        &source_authority,
        &source_head,
        &first,
        &first_authority,
        plaintext,
    )
    .await;
    let second_head = publish(
        &source,
        &source_authority,
        &source_head,
        &second,
        &second_authority,
        plaintext,
    )
    .await;
    assert_ne!(first_head.commit, second_head.commit);
    let selector = format!("import-binding-{}.cbor", hex(&source_head.commit));
    let first_binding_bytes = tokio::fs::read(control(first.store().root()).join(&selector))
        .await
        .unwrap();
    let second_binding_path = control(second.store().root()).join(&selector);
    let second_binding_bytes = tokio::fs::read(&second_binding_path).await.unwrap();
    let first_binding = ImportBindingRecord::decode(&first_binding_bytes).unwrap();
    let second_binding = ImportBindingRecord::decode(&second_binding_bytes).unwrap();
    assert_eq!(
        first_binding.source_authority,
        second_binding.source_authority
    );
    assert_eq!(first_binding.import_digest, second_binding.import_digest);
    assert_ne!(
        first_binding.destination_authority,
        second_binding.destination_authority
    );
    reject_changed_control(
        &second,
        &second_authority,
        &second_head,
        &second_binding_path,
        &first_binding_bytes,
        &second_binding_bytes,
    )
    .await;

    let trust_selector = format!("import-trust-{}.cbor", hex(&second_binding.import_digest));
    let first_trust_bytes = tokio::fs::read(control(first.store().root()).join(&trust_selector))
        .await
        .unwrap();
    let second_trust_path = control(second.store().root()).join(&trust_selector);
    let second_trust_bytes = tokio::fs::read(&second_trust_path).await.unwrap();
    let first_trust = PublicTrustRecord::decode(&first_trust_bytes).unwrap();
    let second_trust = PublicTrustRecord::decode(&second_trust_bytes).unwrap();
    assert_eq!(first_trust.source_authority, second_trust.source_authority);
    assert_ne!(
        first_trust.destination_authority,
        second_trust.destination_authority
    );
    reject_changed_control(
        &second,
        &second_authority,
        &second_head,
        &second_trust_path,
        &first_trust_bytes,
        &second_trust_bytes,
    )
    .await;

    let mut conflicting = second_trust;
    let original_key = conflicting
        .issuer_keys
        .iter_mut()
        .find(|key| {
            key.issuer == source_authority.issuer_key().issuer
                && key.key_id == source_authority.issuer_key().key_id
        })
        .unwrap();
    assert_eq!(
        original_key.public_key,
        source_authority.issuer_key().public_key
    );
    original_key.public_key = other_authority.issuer_key().public_key;
    let conflicting_bytes = conflicting.encode().unwrap();
    assert_eq!(
        PublicTrustRecord::decode(&conflicting_bytes)
            .unwrap()
            .issuer_keys[0]
            .public_key,
        other_authority.issuer_key().public_key
    );
    reject_changed_control(
        &second,
        &second_authority,
        &second_head,
        &second_trust_path,
        &conflicting_bytes,
        &second_trust_bytes,
    )
    .await;

    let checked = second
        .guard()
        .read_snapshot(reference, second_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = checked.history.locate(second_head.commit, b"file").unwrap();
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        source_head.commit
    );
    let entry = checked.history.entry(&location).unwrap();
    let EntryKind::File { content, size, .. } = entry.kind else {
        panic!("restored import changed file kind")
    };
    assert_eq!(
        second
            .guard()
            .read_content(&checked, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
    drop(other_source);
}
