//! Exercises the complete portable-copy activation crash and retained recovery matrix.

use super::*;

/// Exercises actual activation failures and retained Pending recovery handoffs.
///
/// # Panics
/// Panics if a fixture operation, consumed hook, or recovery assertion fails.
pub(super) async fn run() {
    let (native, head) = source().await;
    let authority = native.guard().configured_original_authority().unwrap();
    crate::gc::lease::Collector::new(native.guard(), &authority)
        .acquire("copy recovery source".into(), 60)
        .await
        .unwrap();
    for boundary in [
        CopyBoundary::Snapshot,
        CopyBoundary::Transaction,
        CopyBoundary::Activation,
        CopyBoundary::Pending,
        CopyBoundary::Pointer,
        CopyBoundary::Slot,
        CopyBoundary::History,
        CopyBoundary::Capabilities,
        CopyBoundary::RefCache,
        CopyBoundary::Lease,
        CopyBoundary::Active,
    ] {
        for after in [false, true] {
            let configuration = destination(native.store()).await;
            stale_caches(&configuration).await;
            let control = control(&configuration);
            let old_pointer = tokio::fs::read(configuration.root.join("publication/PORTABLE"))
                .await
                .unwrap();
            boundaries::fault(control.clone(), configuration.root.clone(), boundary, after);
            assert!(
                initialize(configuration.clone()).await.is_err(),
                "{boundary:?}, after={after}"
            );
            boundaries::assert_consumed(&control);
            let registered = tokio::fs::read(control.join("backend-registration.cbor"))
                .await
                .ok();
            let Some(registered) = registered else {
                assert!(
                    reopen(configuration.clone()).await.is_err(),
                    "{boundary:?}, after={after}"
                );
                assert!(
                    initialize(configuration.clone()).await.is_err(),
                    "orphan staging granted registration"
                );
                assert!(!control.join("publication/commits/0").exists());
                assert_eq!(
                    tokio::fs::read(configuration.root.join("publication/PORTABLE"))
                        .await
                        .unwrap(),
                    old_pointer
                );
                remove(&configuration).await;
                continue;
            };
            let pending = BackendRegistration::decode(&registered).unwrap();
            let activation_bytes = tokio::fs::read(control.join("publication/ACTIVATION"))
                .await
                .unwrap();
            assert_eq!(
                pending.genesis,
                Some(*blake3::hash(&activation_bytes).as_bytes())
            );
            let commit =
                terrane_format::gc::publication::PublicationCommit::decode(&activation_bytes)
                    .unwrap();
            let transaction_bytes = tokio::fs::read(control.join(&commit.transaction_key))
                .await
                .unwrap();
            let transaction =
                terrane_format::gc::publication::PublicationTransaction::decode(&transaction_bytes)
                    .unwrap();
            assert_eq!(transaction.new.binding, pending.binding);
            assert!(transaction.new.sources.is_empty());
            assert!(transaction.new.guard.is_none());
            assert_eq!(transaction.new.loss_generation, 0);
            if matches!(boundary, CopyBoundary::Pending) {
                assert_eq!(
                    tokio::fs::read(configuration.root.join("publication/PORTABLE"))
                        .await
                        .unwrap(),
                    old_pointer
                );
                assert!(!control.join("publication/commits/0").exists());
            }
            if matches!(boundary, CopyBoundary::Slot) && !after {
                assert_ne!(
                    tokio::fs::read(configuration.root.join("publication/PORTABLE"))
                        .await
                        .unwrap(),
                    old_pointer
                );
                assert!(!control.join("publication/commits/0").exists());
            }
            let copied = reopen(configuration.clone()).await.unwrap();
            assert_eq!(copied.ref_get(NAME).await.unwrap(), Some(head.clone()));
            assert_eq!(
                tokio::fs::read(control.join("publication/ACTIVATION"))
                    .await
                    .unwrap(),
                activation_bytes
            );
            assert_eq!(
                tokio::fs::read(control.join(&commit.transaction_key))
                    .await
                    .unwrap(),
                transaction_bytes
            );
            assert_eq!(
                tokio::fs::read(control.join("publication/commits/0"))
                    .await
                    .unwrap(),
                activation_bytes
            );
            let active = BackendRegistration::decode(
                &tokio::fs::read(control.join("backend-registration.cbor"))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(active.activation, Activation::Active);
            assert_eq!(active.binding, pending.binding);
            assert_eq!(active.genesis, pending.genesis);
            let history = SelectedHistory::decode(
                &tokio::fs::read(configuration.root.join("publication/SELECTED-HISTORY"))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(history.origin, active.binding);
            assert_eq!(history.branches, transaction.new.branches);
            assert!(!configuration.root.join("gc/lease").exists());
            remove(&configuration).await;
        }
    }
    for case in [
        "activation absent",
        "activation corrupt",
        "activation wrong digest",
        "transaction absent",
        "transaction corrupt",
        "snapshot absent",
        "slot conflict",
        "activation unavailable",
        "transaction unavailable",
        "snapshot unavailable",
        "pending wrong genesis digest",
    ] {
        let configuration = destination(native.store()).await;
        let control = control(&configuration);
        boundaries::fault(
            control.clone(),
            configuration.root.clone(),
            CopyBoundary::Pointer,
            false,
        );
        assert!(initialize(configuration.clone()).await.is_err());
        boundaries::assert_consumed(&control);
        let mut pending_bytes = tokio::fs::read(control.join("backend-registration.cbor"))
            .await
            .unwrap();
        let activation = terrane_format::gc::publication::PublicationCommit::decode(
            &tokio::fs::read(control.join("publication/ACTIVATION"))
                .await
                .unwrap(),
        )
        .unwrap();
        let transaction = terrane_format::gc::publication::PublicationTransaction::decode(
            &tokio::fs::read(control.join(&activation.transaction_key))
                .await
                .unwrap(),
        )
        .unwrap();
        match case {
            "activation absent" => tokio::fs::remove_file(control.join("publication/ACTIVATION"))
                .await
                .unwrap(),
            "activation corrupt" => {
                tokio::fs::write(control.join("publication/ACTIVATION"), b"corrupt")
                    .await
                    .unwrap()
            }
            "activation wrong digest" => {
                let mut altered = activation.clone();
                altered.transaction_digest[0] ^= 1;
                tokio::fs::write(
                    control.join("publication/ACTIVATION"),
                    altered.encode().unwrap(),
                )
                .await
                .unwrap();
            }
            "transaction absent" => {
                tokio::fs::remove_file(control.join(&activation.transaction_key))
                    .await
                    .unwrap()
            }
            "transaction corrupt" => {
                tokio::fs::write(control.join(&activation.transaction_key), b"corrupt")
                    .await
                    .unwrap()
            }
            "snapshot absent" => {
                tokio::fs::remove_file(configuration.root.join(&transaction.snapshot.key))
                    .await
                    .unwrap()
            }
            "slot conflict" => {
                TokioLocalFs
                    .create_dir_new(&control.join("publication/commits"))
                    .await
                    .unwrap();
                TokioLocalFs
                    .write_new(&control.join("publication/commits/0"), b"conflicting slot")
                    .await
                    .unwrap();
            }
            "activation unavailable" | "transaction unavailable" | "snapshot unavailable" => {}
            "pending wrong genesis digest" => {
                let mut pending = BackendRegistration::decode(&pending_bytes).unwrap();
                pending.genesis.as_mut().unwrap()[0] ^= 1;
                pending_bytes = pending.encode().unwrap();
                tokio::fs::write(control.join("backend-registration.cbor"), &pending_bytes)
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        if case.ends_with("unavailable") {
            let fs = ReadFs::default();
            fs.unavailable(match case {
                "activation unavailable" => control.join("publication/ACTIVATION"),
                "transaction unavailable" => control.join(&activation.transaction_key),
                "snapshot unavailable" => configuration.root.join(&transaction.snapshot.key),
                _ => unreachable!(),
            });
            let error = FileBucket::open(configuration.clone(), fs.clone(), TokioClock, Validator)
                .await
                .err()
                .unwrap();
            assert!(
                matches!(error.kind(), StoreErrorKind::Unavailable { .. }),
                "{case}: {error:?}"
            );
            assert!(std::error::Error::source(&error).is_some(), "{case}");
            assert_eq!(fs.effects(), 0, "{case}");
        } else {
            let error = reopen(configuration.clone()).await.err().unwrap();
            if case == "pending wrong genesis digest" {
                assert!(
                    matches!(error.kind(), StoreErrorKind::Corrupt(_)),
                    "{case}: {error:?}"
                );
            }
        }
        assert_eq!(
            tokio::fs::read(control.join("backend-registration.cbor"))
                .await
                .unwrap(),
            pending_bytes,
            "{case}"
        );
        remove(&configuration).await;
    }
    sync_failures(native.store(), &head).await;
    replaced_staging(native.store()).await;
}

/// Makes each otherwise redundant cache projection an actual fixed command.
async fn stale_caches(configuration: &super::super::FileBucketConfig) {
    tokio::fs::write(
        configuration.root.join("CAPABILITIES"),
        b"stale capability cache",
    )
    .await
    .unwrap();
    tokio::fs::write(
        configuration.root.join(format!("{NAME}:record")),
        b"stale ref cache",
    )
    .await
    .unwrap();
}

async fn sync_failures(source: &Bucket, head: &terrane_format::refs::RefRecord) {
    for boundary in [
        CopyBoundary::Snapshot,
        CopyBoundary::Transaction,
        CopyBoundary::Activation,
        CopyBoundary::Pending,
        CopyBoundary::Pointer,
        CopyBoundary::Slot,
        CopyBoundary::Capabilities,
        CopyBoundary::History,
        CopyBoundary::RefCache,
        CopyBoundary::Active,
    ] {
        let configuration = destination(source).await;
        stale_caches(&configuration).await;
        let control = control(&configuration);
        boundaries::file_sync(control.clone(), configuration.root.clone(), boundary);
        assert!(
            initialize(configuration.clone()).await.is_err(),
            "file sync {boundary:?}"
        );
        boundaries::assert_consumed(&control);
        if control.join("backend-registration.cbor").exists() {
            let pending = tokio::fs::read(control.join("backend-registration.cbor"))
                .await
                .unwrap();
            let before = BackendRegistration::decode(&pending).unwrap();
            assert_eq!(before.activation, Activation::Pending);
            let copied = reopen(configuration.clone()).await.unwrap();
            assert_eq!(copied.ref_get(NAME).await.unwrap(), Some(head.clone()));
            let active = BackendRegistration::decode(
                &tokio::fs::read(control.join("backend-registration.cbor"))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(active.binding, before.binding);
            assert_eq!(active.genesis, before.genesis);
        } else {
            assert!(!control.join("publication/commits/0").exists());
            assert!(reopen(configuration.clone()).await.is_err());
            assert!(initialize(configuration.clone()).await.is_err());
        }
        remove(&configuration).await;
    }

    // This observer enumerates real explicit SyncDirectory commands on a
    // successful native path. Every position is then failed on a fresh copy;
    // rename/remove parent-sync boundaries are covered by the before/after matrix.
    let configuration = destination(source).await;
    stale_caches(&configuration).await;
    let trace_control = control(&configuration);
    let trace = boundaries::trace_directories(trace_control.clone(), configuration.root.clone());
    initialize(configuration.clone()).await.unwrap();
    boundaries::finish_trace(&trace_control);
    let paths = trace.into_iter().collect::<Vec<_>>();
    assert!(paths.contains(&trace_control));
    assert!(paths.contains(&trace_control.parent().unwrap().to_owned()));
    assert!(
        paths
            .iter()
            .all(|path| path.starts_with(&configuration.root)
                || path.starts_with(&trace_control)
                || path == trace_control.parent().unwrap())
    );
    assert!(!paths.is_empty());
    eprintln!("portable-copy explicit directory-sync trace: {paths:?}");
    remove(&configuration).await;

    for ordinal in 1..=paths.len() {
        let configuration = destination(source).await;
        stale_caches(&configuration).await;
        let control = control(&configuration);
        boundaries::directory_sync(control.clone(), configuration.root.clone(), ordinal);
        assert!(
            initialize(configuration.clone()).await.is_err(),
            "directory sync {ordinal}"
        );
        boundaries::assert_consumed(&control);
        if control.join("backend-registration.cbor").exists() {
            let before = BackendRegistration::decode(
                &tokio::fs::read(control.join("backend-registration.cbor"))
                    .await
                    .unwrap(),
            )
            .unwrap();
            let copied = reopen(configuration.clone()).await.unwrap();
            assert_eq!(copied.ref_get(NAME).await.unwrap(), Some(head.clone()));
            let active = BackendRegistration::decode(
                &tokio::fs::read(control.join("backend-registration.cbor"))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(active.binding, before.binding);
            assert_eq!(active.genesis, before.genesis);
        } else {
            assert!(reopen(configuration.clone()).await.is_err());
            assert!(initialize(configuration.clone()).await.is_err());
        }
        remove(&configuration).await;
    }
}

async fn replaced_staging(source: &Bucket) {
    use std::time::Duration;
    for record in ["activation", "transaction", "snapshot"] {
        let configuration = destination(source).await;
        let control = control(&configuration);
        boundaries::fault(
            control.clone(),
            configuration.root.clone(),
            CopyBoundary::Pointer,
            false,
        );
        assert!(initialize(configuration.clone()).await.is_err());
        let pending = tokio::fs::read(control.join("backend-registration.cbor"))
            .await
            .unwrap();
        boundaries::assert_consumed(&control);
        let pointer = tokio::fs::read(configuration.root.join("publication/PORTABLE"))
            .await
            .unwrap();
        let commit = terrane_format::gc::publication::PublicationCommit::decode(
            &tokio::fs::read(control.join("publication/ACTIVATION"))
                .await
                .unwrap(),
        )
        .unwrap();
        let transaction = terrane_format::gc::publication::PublicationTransaction::decode(
            &tokio::fs::read(control.join(&commit.transaction_key))
                .await
                .unwrap(),
        )
        .unwrap();
        let victim = match record {
            "activation" => control.join("publication/ACTIVATION"),
            "transaction" => control.join(&commit.transaction_key),
            "snapshot" => configuration.root.join(&transaction.snapshot.key),
            _ => unreachable!(),
        };
        let bytes = tokio::fs::read(&victim).await.unwrap();
        let original = tokio::fs::symlink_metadata(&victim).await.unwrap();
        let (arrived, arrivals) = std::sync::mpsc::channel();
        let (release, releases) = std::sync::mpsc::channel();
        let observations = boundaries::gate(
            control.clone(),
            configuration.root.clone(),
            CopyBoundary::RecoveryHandoff,
            arrived,
            releases,
        );
        let fs = ReadFs::default();
        let opened_fs = fs.clone();
        let opened_configuration = configuration.clone();
        let recovery = tokio::spawn(async move {
            FileBucket::open(opened_configuration, opened_fs, TokioClock, Validator).await
        });
        tokio::time::timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || arrivals.recv().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        let retained = observations.recv().unwrap();
        assert!(retained.retained());
        let temporary = victim.with_extension("same-bytes-replacement");
        tokio::fs::copy(&victim, &temporary).await.unwrap();
        TokioLocalFs.sync_file(&temporary).await.unwrap();
        TokioLocalFs.rename(&temporary, &victim).await.unwrap();
        TokioLocalFs
            .sync_directory(victim.parent().unwrap())
            .await
            .unwrap();
        let replacement = tokio::fs::symlink_metadata(&victim).await.unwrap();
        assert_ne!(
            (original.dev(), original.ino()),
            (replacement.dev(), replacement.ino())
        );
        assert_eq!(tokio::fs::read(&victim).await.unwrap(), bytes);
        release.send(()).unwrap();
        let error = recovery.await.unwrap().err().unwrap();
        assert!(
            matches!(error.kind(), StoreErrorKind::Unavailable { .. }),
            "{record}: {error:?}"
        );
        eprintln!("portable-copy same-byte {record} replacement refused: {error:?}");
        boundaries::assert_consumed(&control);
        assert!(!retained.retained());
        // Only the queued nonmutating durability handoff was submitted. The
        // captured immutable incarnation fails before any subsequent selected write.
        assert_eq!(fs.effects(), 1, "{record}");
        assert_eq!(
            tokio::fs::read(control.join("backend-registration.cbor"))
                .await
                .unwrap(),
            pending
        );
        assert_eq!(
            tokio::fs::read(configuration.root.join("publication/PORTABLE"))
                .await
                .unwrap(),
            pointer
        );
        assert!(!control.join("publication/commits/0").exists());
        remove(&configuration).await;
    }
}
