//! Exercises selected reflog proposals and authoritative complete ref inventories.

#![allow(clippy::unwrap_used)]

use super::tests::{PreparedCas, Selected, Validator, config, fixture, log};
use super::*;
use crate::store::{RefCasOutcome, RefLogAppendOutcome, RefStore, TokioClock, TokioLocalFs};
use terrane_core::refs::RefRecord;

#[tokio::test]
async fn abandoned_candidates_leave_the_same_sequence_available_to_a_new_writer() {
    let bucket = fixture().await;
    let name = "refs/heads/_/main";
    let abandoned = RefRecord::first([7; 32], 1, Locality::default()).selected();
    bucket
        .ref_log_append(name, 1, &log(abandoned.clone(), None))
        .await
        .unwrap();
    assert!(bucket.ref_log_read(name, 1).await.unwrap().is_empty());

    let mut chosen = abandoned.clone();
    chosen.candidate_id = Some([8; 32]);
    chosen.writer_epoch = 2;
    let chosen_log = log(chosen.clone(), None);
    bucket.ref_log_append(name, 1, &chosen_log).await.unwrap();
    assert_eq!(
        bucket.ref_cas(name, None, &chosen).await.unwrap(),
        RefCasOutcome::Applied
    );
    assert_eq!(
        bucket.ref_log_read(name, 1).await.unwrap(),
        vec![chosen_log.clone()]
    );
    assert!(bucket.ref_log_read(name, 2).await.unwrap().is_empty());

    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.ref_log_read(name, 1).await.unwrap(),
        vec![chosen_log]
    );
    assert_eq!(reopened.ref_get(name).await.unwrap(), Some(chosen.clone()));
    // A caller that lost the successful response re-reads the authority. An
    // obsolete expectation cannot apply the same proposal again.
    assert_eq!(
        reopened.ref_cas(name, None, &chosen).await.unwrap(),
        RefCasOutcome::Conflict(Some(Box::new(chosen)))
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn candidates_bind_the_complete_proposal_and_predecessor_before_head_cas() {
    let bucket = fixture().await;
    let name = "refs/jobs/_/work";
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    assert!(matches!(
        bucket.ref_cas(name, None, &first).await.unwrap_err().kind(),
        StoreErrorKind::Invalid(_)
    ));
    bucket.prepared_cas(name, None, &first).await.unwrap();

    let mut wrong_previous = first.clone();
    wrong_previous.policy = Some(terrane_core::refs::RefPolicy::default());
    let next = first.advance([2; 32], 2).unwrap().selected();
    bucket
        .ref_log_append(name, 2, &log(next.clone(), Some(wrong_previous)))
        .await
        .unwrap();
    assert!(bucket.ref_cas(name, Some(&first), &next).await.is_err());
    assert_eq!(bucket.ref_get(name).await.unwrap(), Some(first.clone()));

    let mut correct = next.clone();
    correct.candidate_id = Some([42; 32]);
    bucket
        .ref_log_append(name, 2, &log(correct.clone(), Some(first.clone())))
        .await
        .unwrap();
    let mut unproposed_policy = correct.clone();
    unproposed_policy.policy = Some(terrane_core::refs::RefPolicy::default());
    assert!(matches!(
        bucket
            .ref_cas(name, Some(&first), &unproposed_policy)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Invalid(_)
    ));
    assert_eq!(bucket.ref_get(name).await.unwrap(), Some(first.clone()));
    assert_eq!(
        bucket.ref_cas(name, Some(&first), &correct).await.unwrap(),
        RefCasOutcome::Applied
    );
    assert_eq!(
        bucket.ref_log_read(name, 1).await.unwrap(),
        vec![
            log(first.clone(), None),
            log(correct.clone(), Some(first.clone()))
        ]
    );
    let mut changed_policy = correct.clone();
    changed_policy.policy = Some(terrane_core::refs::RefPolicy::default());
    assert_eq!(
        bucket
            .ref_log_append(name, 2, &log(changed_policy, Some(first)))
            .await
            .unwrap(),
        RefLogAppendOutcome::Exists
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn independent_candidates_select_one_history_under_concurrent_cas() {
    let bucket = fixture().await;
    let other = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    for name in [
        "refs/heads/_/main",
        "refs/jobs/_/work",
        "refs/conflicts/_/main/00000000000000000001",
        "refs/derived/_/index",
    ] {
        let a = RefRecord::first([1; 32], 1, Locality::default()).selected();
        let b = RefRecord::first([2; 32], 1, Locality::default()).selected();
        let a_log = log(a.clone(), None);
        let b_log = log(b.clone(), None);
        let (one, two) = tokio::join!(
            bucket.ref_log_append(name, 1, &a_log),
            other.ref_log_append(name, 1, &b_log)
        );
        assert_eq!(one.unwrap(), RefLogAppendOutcome::Appended);
        assert_eq!(two.unwrap(), RefLogAppendOutcome::Appended);
        let (one, two) = tokio::join!(
            bucket.ref_cas(name, None, &a),
            other.ref_cas(name, None, &b)
        );
        assert_eq!(
            usize::from(matches!(one.unwrap(), RefCasOutcome::Applied))
                + usize::from(matches!(two.unwrap(), RefCasOutcome::Applied)),
            1
        );
        let chosen = bucket.ref_get(name).await.unwrap().unwrap();
        assert_eq!(
            bucket.ref_log_read(name, 1).await.unwrap(),
            vec![if chosen == a { a_log } else { b_log }]
        );
    }
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn selected_candidates_coexist_with_legacy_numbered_files() {
    let bucket = fixture().await;
    let name = "refs/heads/_/legacy";
    let first = RefRecord::first([1; 32], 1, Locality::default()).selected();
    let first_log = log(first.clone(), None);
    bucket.prepared_cas(name, None, &first).await.unwrap();

    // An orphaned legacy file already occupies the next sequence. The selected
    // sibling has a different filename, and never inherits that orphan's body.
    let orphan = first.advance([3; 32], 2).unwrap();
    let mut orphan_log = log(orphan, Some(first.clone()));
    orphan_log.expected_previous = None;
    let guard = bucket.exclusive().await.unwrap();
    let orphan_key = BucketKey::reflog(name, 2).unwrap();
    bucket
        .install(&orphan_key, &orphan_log.encode().unwrap(), false)
        .await
        .unwrap();
    drop(guard);
    assert_eq!(
        bucket.ref_log_read(name, 1).await.unwrap(),
        vec![first_log.clone()]
    );
    assert!(bucket.ref_log_read(name, 2).await.unwrap().is_empty());
    let next = first.advance([2; 32], 2).unwrap().selected();
    bucket
        .prepared_cas(name, Some(&first), &next)
        .await
        .unwrap();
    let selected_log = log(next.clone(), Some(first));
    assert_eq!(
        bucket.ref_log_read(name, 1).await.unwrap(),
        vec![first_log.clone(), selected_log.clone()]
    );
    assert!(
        bucket
            .root()
            .join(BucketKey::reflog(name, 2).unwrap().as_str())
            .is_file()
    );
    assert!(
        bucket
            .root()
            .join(
                BucketKey::reflog_candidate(name, 2, &next.candidate_id.unwrap())
                    .unwrap()
                    .as_str()
            )
            .is_file()
    );
    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.ref_log_read(name, 1).await.unwrap(),
        vec![first_log, selected_log]
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn complete_ref_inventory_survives_reopen_index_publication_and_ref_removal() {
    use crate::store::{ContentStore, ContentUpload, MetaUpload};
    use terrane_core::identity::IdentityKind;
    let bucket = fixture().await;
    assert_eq!(bucket.ref_names().await.unwrap(), Vec::<String>::new());
    let name = "refs/heads/_/main";
    let record = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket.prepared_cas(name, None, &record).await.unwrap();
    let tag = "refs/tags/_/release";
    let tag_record = RefRecord::first([2; 32], 1, Locality::default());
    bucket.ref_cas(tag, None, &tag_record).await.unwrap();
    assert_eq!(
        bucket.ref_names().await.unwrap(),
        vec![name.to_string(), tag.to_string()]
    );

    let sealed = crate::pack::PackWriter::new(
        crate::pack::PackId::from_random_bytes([7; 16]),
        crate::pack::PackClass::Data,
        false,
    )
    .seal()
    .unwrap();
    let empty_index = sealed.index_object();
    bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Index, empty_index).unwrap(),
        ))
        .await
        .unwrap();
    let guard = bucket.exclusive().await.unwrap();
    let selected = bucket.selected_publication_locked().await.unwrap();
    bucket
        .publish_raw_locked(
            &selected,
            vec![terrane_core::gc::publication::LogicalChange {
                key: BucketKey::ref_record(name).unwrap().as_str().into(),
                expected: Some(record.encode().unwrap()),
                new: None,
            }],
        )
        .await
        .unwrap();
    drop(guard);
    let reopened = FileBucket::open(
        config(bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.ref_names().await.unwrap(),
        vec![name.to_string(), tag.to_string()]
    );
    assert_eq!(reopened.ref_get(name).await.unwrap(), None);
    let replacement = record.advance([3; 32], 2).unwrap().selected();
    let mut candidate = log(replacement.clone(), None);
    candidate.previous_commit = Some(record.commit);
    candidate.committed_previous = Some(record);
    reopened
        .ref_log_append(name, replacement.seq, &candidate)
        .await
        .unwrap();
    assert_eq!(
        reopened.ref_cas(name, None, &replacement).await.unwrap(),
        RefCasOutcome::Applied
    );
    assert_eq!(
        reopened.ref_names().await.unwrap(),
        vec![name.to_string(), tag.to_string()]
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn legacy_unknown_inventory_refuses_unregistered_existing_and_new_advances() {
    let bucket = fixture().await;
    let name = "refs/heads/_/legacy";
    let first = RefRecord::first([1; 32], 1, Locality::default());
    let mut first_log = log(first.clone(), None);
    first_log.expected_previous = None;
    let key = BucketKey::ref_record(name).unwrap();
    let guard = bucket.exclusive().await.unwrap();
    // Fixture setup authors migrated bytes; ordinary append cannot migrate.
    let first_log_key = BucketKey::reflog(name, 1).unwrap();
    bucket
        .install(&first_log_key, &first_log.encode().unwrap(), false)
        .await
        .unwrap();
    bucket
        .install(&key, &first.encode().unwrap(), false)
        .await
        .unwrap();
    let cap_key = BucketKey::parse("CAPABILITIES").unwrap();
    let mut capabilities =
        BucketCapabilities::decode(&bucket.read_optional(&cap_key).await.unwrap().unwrap())
            .unwrap();
    capabilities.ref_names = None;
    bucket
        .install(&cap_key, &capabilities.encode().unwrap(), true)
        .await
        .unwrap();
    drop(guard);

    tokio::fs::remove_dir_all(super::tests::control_path(bucket.root()))
        .await
        .unwrap();
    assert!(matches!(
        FileBucket::open(
            config(bucket.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator
        )
        .await
        .err()
        .unwrap()
        .kind(),
        StoreErrorKind::Unsupported
    ));

    let next = first.advance([2; 32], 2).unwrap().selected();
    assert!(
        bucket
            .prepared_cas(name, Some(&first), &next)
            .await
            .is_err()
    );
    let another = RefRecord::first([3; 32], 2, Locality::default()).selected();
    assert!(
        bucket
            .prepared_cas("refs/heads/_/new", None, &another)
            .await
            .is_err()
    );
    assert_eq!(
        tokio::fs::read(bucket.root().join(key.as_str()))
            .await
            .unwrap(),
        first.encode().unwrap()
    );
    assert!(
        !bucket
            .root()
            .join(BucketKey::ref_record("refs/heads/_/new").unwrap().as_str())
            .exists()
    );
    let persisted = BucketCapabilities::decode(
        &tokio::fs::read(bucket.root().join("CAPABILITIES"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(persisted.ref_names, None);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn opening_an_existing_empty_root_is_not_fresh_initialization_authority() {
    let bucket = fixture().await;
    let root = bucket.root().with_extension("existing-empty");
    TokioLocalFs.create_dir_new(&root).await.unwrap();
    let error =
        match FileBucket::open(config(root.clone()), TokioLocalFs, TokioClock, Validator).await {
            Ok(_) => panic!("existing root without CAPABILITIES was accepted"),
            Err(error) => error,
        };
    assert_eq!(error.kind(), &StoreErrorKind::Unsupported);
    assert!(!root.join("CAPABILITIES").exists());
    tokio::fs::remove_dir_all(root).await.unwrap();
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn a_head_missing_from_a_complete_inventory_is_corruption() {
    let bucket = fixture().await;
    let name = "refs/heads/_/hidden";
    let record = RefRecord::first([1; 32], 1, Locality::default()).selected();
    bucket.prepared_cas(name, None, &record).await.unwrap();
    super::tests::corrupt_selected_capabilities(&bucket, |capabilities| {
        capabilities.ref_names = Some(Vec::new())
    })
    .await;
    assert!(matches!(
        bucket.ref_get(name).await.unwrap_err().kind(),
        StoreErrorKind::Corrupt(_)
    ));
    let next = record.advance([2; 32], 2).unwrap().selected();
    assert!(matches!(
        bucket
            .ref_cas(name, Some(&record), &next)
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert_eq!(
        tokio::fs::read(
            bucket
                .root()
                .join(BucketKey::ref_record(name).unwrap().as_str())
        )
        .await
        .unwrap(),
        record.encode().unwrap()
    );
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

#[tokio::test]
async fn nested_ref_names_coexist_without_changing_refname_grammar() {
    for names in [
        ["refs/heads/_/a", "refs/heads/_/a/b"],
        ["refs/heads/_/a/b", "refs/heads/_/a"],
    ] {
        let bucket = fixture().await;
        let mut expected = Vec::new();

        for (position, name) in names.iter().enumerate() {
            assert!(terrane_core::refs::RefName::parse(name).is_ok());
            let digest = if position == 0 { [1; 32] } else { [2; 32] };
            let first = RefRecord::first(digest, 1, Locality::default()).selected();
            let first_log = log(first.clone(), None);
            assert_eq!(
                bucket.ref_log_append(name, 1, &first_log).await.unwrap(),
                RefLogAppendOutcome::Appended
            );
            assert_eq!(
                bucket.ref_cas(name, None, &first).await.unwrap(),
                RefCasOutcome::Applied
            );
            expected.push((first, first_log));
        }

        let reopened = FileBucket::open(
            config(bucket.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await
        .unwrap();
        for (position, name) in names.iter().enumerate() {
            let (first, first_log) = &expected[position];
            assert_eq!(reopened.ref_get(name).await.unwrap(), Some(first.clone()));
            assert_eq!(
                reopened.ref_log_read(name, 1).await.unwrap(),
                vec![first_log.clone()]
            );

            let digest = if position == 0 { [3; 32] } else { [4; 32] };
            let second = first.advance(digest, 2).unwrap().selected();
            let second_log = log(second.clone(), Some(first.clone()));
            reopened.ref_log_append(name, 2, &second_log).await.unwrap();
            assert_eq!(
                reopened.ref_cas(name, Some(first), &second).await.unwrap(),
                RefCasOutcome::Applied
            );
            assert_eq!(reopened.ref_get(name).await.unwrap(), Some(second.clone()));
            assert_eq!(
                reopened.ref_log_read(name, 1).await.unwrap(),
                vec![first_log.clone(), second_log]
            );
            expected[position].0 = second;
        }

        let reopened_again = FileBucket::open(
            config(bucket.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await
        .unwrap();
        for (name, (record, _)) in names.iter().zip(&expected) {
            assert_eq!(
                reopened_again.ref_get(name).await.unwrap(),
                Some(record.clone())
            );
            assert_eq!(reopened_again.ref_log_read(name, 1).await.unwrap().len(), 2);
        }

        tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    }
}
