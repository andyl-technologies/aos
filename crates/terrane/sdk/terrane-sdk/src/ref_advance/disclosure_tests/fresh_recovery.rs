//! Checks fresh recovery after dropping the original destination factory.

use super::*;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::{
    LocalAuthorityIdentity, LocalAuthorityParameters, LocalRepositoryLocation,
    LocalRepositoryPolicy, MetadataValidator, Repository,
};
use crate::store::{LocalFs, RefStore};
use std::error::Error as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use terrane_format::auth::{Authority, Grant, Token, Verb, Verbs};
use terrane_format::refs::{Locality, PrincipalKind};

type NativeRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;

fn policy() -> LocalRepositoryPolicy {
    LocalRepositoryPolicy {
        store_name: "local".into(),
        domain: "public".into(),
        default_private_domain: "private:writer".into(),
        acl: vec![("writer".into(), 31)],
        locality: Locality::default(),
        timing: CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        policy_authority: Some("refs/heads/_/main".into()),
        bootstrap_properties: Vec::new(),
    }
}

async fn factory() -> (
    NativeRepository,
    crate::repository::LocalAuthority,
    LocalRepositoryLocation,
) {
    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = std::env::temp_dir().join(format!("terrane-fresh-disclosure-{suffix}"));
    TokioLocalFs.create_dir_new(&parent).await.unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let owner_uid = TokioLocalFs.metadata(&parent).await.unwrap().uid();
    let location = LocalRepositoryLocation {
        bucket: parent.join("bucket"),
        authority: parent.join("authority"),
    };
    let (repository, authority) = Repository::initialize_local(
        &location,
        LocalAuthorityParameters {
            owner_uid,
            authority: Authority {
                issuer: "local".into(),
                key_id: "initial".into(),
                subject: "writer".into(),
                kind: PrincipalKind::Human,
                groups: Vec::new(),
                not_before: None,
                not_after: u64::MAX,
                token_id: entropy.try_into().unwrap(),
                grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
                workload: None,
            },
        },
        policy(),
        "refs/heads/_/main",
        TokioLocalFs,
        TokioClock,
    )
    .await
    .unwrap();
    (repository, authority, location)
}

/// Checks fresh paired recovery and destination-only reopening after source erasure.
///
/// Drops the interrupted destination factory, checks current authorization and
/// exact retained trust, then recovers through a new factory and reads the
/// certified file after deleting the source bucket and authority records.
///
/// # Panics
/// Panics if fixture setup, retained-file I/O, source erasure, or any refusal,
/// recovery, reopening, or content assertion fails.
pub(super) async fn recover_fresh_transition() {
    let (source, source_authority, source_location) = factory().await;
    let (destination, destination_authority, destination_location) = factory().await;
    assert_ne!(
        source_authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key,
    );
    assert_ne!(
        source.chunk_profile().seed(),
        destination.chunk_profile().seed()
    );
    let reference = "refs/heads/_/main";
    let plaintext = b"fresh factory recovery retains the checked original author";
    let mut source_session = source
        .begin(reference, source_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(vec![source_session.record().unwrap().commit], plaintext);
    let mut proposal = source_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    for upload in &mut proposal.uploads {
        if let StagedUpload::Chunk { profile, .. } = upload {
            **profile = source.chunk_profile().clone();
        }
    }
    let source_terminal_secret = proposal.terminal_secret;
    let source_head = source
        .commit_request(&mut source_session, proposal)
        .await
        .unwrap();
    let mut destination_session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let previous = destination_session.record().unwrap().clone();
    let destination_profile = destination.chunk_profile().clone();
    let request = || {
        let staged = request_file(vec![previous.commit], plaintext);
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        for upload in &mut proposal.uploads {
            if let StagedUpload::Chunk { profile, .. } = upload {
                **profile = destination_profile.clone();
            }
        }
        DisclosureCommitRequest {
            proposal,
            selections: vec![DisclosureCommitSelection {
                source_reference: reference.into(),
                source_commit: source_head.commit,
                source_path: b"/file".to_vec(),
                source_token: source_authority.token().to_vec(),
                destination_path: b"/file".to_vec(),
            }],
        }
    };
    crate::selected_bridge::native_guard::disclosure::interrupt_next_import_selection(
        &destination_location.bucket,
    )
    .unwrap();
    let interrupted = destination
        .commit_disclosure(&source, &mut destination_session, request())
        .await;
    assert!(interrupted.is_err());
    assert!(
        destination
            .coordinator()
            .guard()
            .original_commit(&source_head.commit)
            .is_ok(),
        "expected installed original context after interruption: {interrupted:?}",
    );
    assert_eq!(destination_session.record(), Some(&previous));
    let installed = destination
        .coordinator()
        .guard()
        .original_commit(&source_head.commit)
        .unwrap();
    drop(destination_session);
    drop(destination);

    let identity = LocalAuthorityIdentity {
        issuer: "local".into(),
        key_id: "initial".into(),
        owner_uid: TokioLocalFs
            .metadata(&destination_location.authority)
            .await
            .unwrap()
            .uid(),
    };
    assert!(
        NativeRepository::open_local(
            &destination_location,
            &identity,
            policy(),
            reference,
            TokioLocalFs,
            TokioClock,
        )
        .await
        .is_err()
    );
    // Compare the actual retained files, rather than the cached Original handle.
    let retained_control = || {
        let mut files = std::fs::read_dir(&destination_location.authority)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect::<Vec<_>>();
        files.sort_by(|left, right| left.0.cmp(&right.0));
        files
    };
    let before_denial = retained_control();

    let mut source_denied = request();
    source_denied.selections[0].source_token = super::recovery::restricted_token(
        source_authority.token(),
        &source_terminal_secret,
        Grant::new("refs/heads/_/other".into(), Verbs::new(1).unwrap()).unwrap(),
    );
    assert!(
        Token::decode(&source_denied.selections[0].source_token)
            .unwrap()
            .verify(
                std::slice::from_ref(source_authority.issuer_key()),
                source
                    .coordinator()
                    .guard()
                    .now(reference, Verb::Read)
                    .unwrap()
            )
            .is_ok()
    );
    let denied = NativeRepository::recover_local_disclosure(
        &destination_location,
        &identity,
        policy(),
        reference,
        &source,
        source_denied,
        (TokioLocalFs, TokioClock),
    )
    .await;
    assert!(
        matches!(&denied, Err(crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(error)))
        if error.kind() == &crate::store::StoreErrorKind::Denied { verb: "read", pattern: reference.into() }
            && error.source().is_none()),
        "fresh paired recovery must preserve source Read refusal: {:?}",
        denied.as_ref().err(),
    );
    assert_eq!(retained_control(), before_denial);

    let mut destination_denied = request();
    destination_denied.proposal.token = super::recovery::restricted_token(
        destination_authority.token(),
        &destination_denied.proposal.terminal_secret,
        Grant::new("refs/**".into(), Verbs::new(1).unwrap()).unwrap(),
    );
    assert!(
        Token::decode(&destination_denied.proposal.token)
            .unwrap()
            .verify(
                std::slice::from_ref(destination_authority.issuer_key()),
                source
                    .coordinator()
                    .guard()
                    .now(reference, Verb::Read)
                    .unwrap()
            )
            .is_ok()
    );
    let denied = NativeRepository::recover_local_disclosure(
        &destination_location,
        &identity,
        policy(),
        reference,
        &source,
        destination_denied,
        (TokioLocalFs, TokioClock),
    )
    .await;
    assert!(
        matches!(&denied, Err(crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(error)))
        if error.kind() == &crate::store::StoreErrorKind::Denied { verb: "commit", pattern: reference.into() }
            && error.source().is_none()),
        "fresh paired recovery must preserve destination Commit refusal: {:?}",
        denied.as_ref().err(),
    );
    assert_eq!(retained_control(), before_denial);

    // The fresh destination must compare exact expected trust, even when a
    // changed row remains well formed and uses the genuine historical key.
    use crate::repository::local_authority::{public_trust::PublicTrustRecord, retention::Record};
    let import = installed.retained_import_record().unwrap();
    let import_digest = blake3::hash(&import.encode().unwrap());
    let trust_path = destination_location
        .authority
        .join(format!("import-trust-{}.cbor", import_digest.to_hex()));
    let retained = tokio::fs::read(&trust_path).await.unwrap();
    let mut changed = PublicTrustRecord::decode(&retained).unwrap();
    changed.disclosure_roles.first_mut().unwrap().not_after = Some(u64::MAX);
    changed.validate().unwrap();
    tokio::fs::write(&trust_path, changed.encode().unwrap())
        .await
        .unwrap();
    assert!(
        NativeRepository::recover_local_disclosure(
            &destination_location,
            &identity,
            policy(),
            reference,
            &source,
            request(),
            (TokioLocalFs, TokioClock),
        )
        .await
        .is_err()
    );
    tokio::fs::write(&trust_path, retained).await.unwrap();

    let (recovered, _, record) = NativeRepository::recover_local_disclosure(
        &destination_location,
        &identity,
        policy(),
        reference,
        &source,
        request(),
        (TokioLocalFs, TokioClock),
    )
    .await
    .unwrap();
    assert_ne!(record.commit, previous.commit);
    assert_eq!(
        recovered
            .coordinator()
            .store()
            .ref_get(reference)
            .await
            .unwrap(),
        Some(record.clone())
    );
    drop(recovered);
    drop(source_session);
    drop(source);
    drop(source_authority);
    tokio::fs::remove_dir_all(&source_location.bucket)
        .await
        .unwrap();
    tokio::fs::remove_dir_all(&source_location.authority)
        .await
        .unwrap();
    let (reopened, authority) = NativeRepository::open_local(
        &destination_location,
        &identity,
        policy(),
        reference,
        TokioLocalFs,
        TokioClock,
    )
    .await
    .unwrap();
    let snapshot = reopened
        .coordinator()
        .guard()
        .read_snapshot(reference, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = snapshot.history.locate(record.commit, b"file").unwrap();
    let entry = snapshot.history.entry(&location).unwrap();
    let EntryKind::File { content, size, .. } = entry.kind else {
        panic!("expected retained file")
    };
    assert_eq!(
        reopened
            .coordinator()
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
}
