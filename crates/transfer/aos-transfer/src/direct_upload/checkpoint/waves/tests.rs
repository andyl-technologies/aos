//! Group durability, failed-wave isolation, custody failure and cancellation.

use std::os::unix::fs::PermissionsExt as _;

use super::*;
use crate::direct_upload::checkpoint::{sqlite, SqliteDirectCheckpoints};

async fn store() -> (tempfile::TempDir, SqliteDirectCheckpoints) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = SqliteDirectCheckpoints::open(
        &directory.path().join("direct.sqlite"),
        &"ab".repeat(32),
        true,
    )
    .await
    .unwrap();
    (directory, store)
}

fn pending(
    state: &State,
    work: impl FnOnce(&Transaction<'_>) -> Result<(), DirectClientError> + Send + 'static,
) -> (Pending, oneshot::Receiver<Result<(), DirectClientError>>) {
    let (send, receive) = oneshot::channel();
    let pending = Pending {
        work: Box::new(move |transaction| {
            let result = work(transaction);
            Outcome {
                successful: result.is_ok(),
                complete: Box::new(move |committed| {
                    let _ = send.send(committed.and(result));
                }),
            }
        }),
        _reservation: state.budget.clone().try_acquire_owned().unwrap(),
    };
    (pending, receive)
}

#[tokio::test]
async fn group_commit_is_durable_before_success_and_rolls_back_only_refused_wave() {
    let (directory, store) = store().await;
    let path = directory.path().join("direct.sqlite");
    let (entered_send, entered_receive) = oneshot::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let (first, mut first_result) = pending(&store.state, move |transaction| {
        sqlite::write(transaction, "intent", "first", 0, 0, &"first")?;
        entered_send.send(()).unwrap();
        release_receive.recv().unwrap();
        Ok(())
    });
    let (refused, refused_result) = pending(&store.state, |transaction| {
        sqlite::write(transaction, "intent", "refused", 0, 0, &"refused")?;
        Err(DirectClientError::Invalid)
    });
    let (last, last_result) = pending(&store.state, |transaction| {
        assert_eq!(
            sqlite::read::<String>(transaction, "intent", "first", 0, 0)?,
            Some("first".into())
        );
        assert_eq!(
            sqlite::read::<String>(transaction, "intent", "refused", 0, 0)?,
            None
        );
        sqlite::write(transaction, "intent", "last", 0, 0, &"last")
    });
    let state = store.state.clone();
    let writer =
        tokio::task::spawn_blocking(move || execute_group(&state, vec![first, refused, last]));

    entered_receive.await.unwrap();
    assert!(matches!(
        first_result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let reader = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        sqlite::read::<String>(&reader, "intent", "first", 0, 0).unwrap(),
        None
    );
    release_send.send(()).unwrap();

    assert_eq!(first_result.await.unwrap(), Ok(()));
    assert_eq!(
        refused_result.await.unwrap(),
        Err(DirectClientError::Invalid)
    );
    assert_eq!(last_result.await.unwrap(), Ok(()));
    writer.await.unwrap();
    assert_eq!(
        sqlite::read::<String>(&reader, "intent", "first", 0, 0).unwrap(),
        Some("first".into())
    );
    assert_eq!(
        sqlite::read::<String>(&reader, "intent", "refused", 0, 0).unwrap(),
        None
    );
    assert_eq!(
        sqlite::read::<String>(&reader, "intent", "last", 0, 0).unwrap(),
        Some("last".into())
    );
    drop(reader);
    drop(store);

    let reopened = SqliteDirectCheckpoints::open(&path, &"ab".repeat(32), false)
        .await
        .unwrap();
    let connection = reopened.state.connection.lock().unwrap();
    assert_eq!(
        sqlite::read::<String>(&connection, "intent", "last", 0, 0).unwrap(),
        Some("last".into())
    );
}

#[tokio::test]
async fn failed_group_custody_rolls_back_every_successful_wave() {
    let (directory, store) = store().await;
    let original = directory.path().join("direct.sqlite");
    let moved = directory.path().join("moved.sqlite");
    let moved_original = original.clone();
    let moved_destination = moved.clone();
    let (first, first_result) = pending(&store.state, |transaction| {
        sqlite::write(transaction, "intent", "first", 0, 0, &"first")
    });
    let (last, last_result) = pending(&store.state, move |transaction| {
        sqlite::write(transaction, "intent", "last", 0, 0, &"last")?;
        std::fs::rename(moved_original, moved_destination).unwrap();
        Ok(())
    });
    let state = store.state.clone();
    tokio::task::spawn_blocking(move || execute_group(&state, vec![first, last]))
        .await
        .unwrap();

    assert_eq!(
        first_result.await.unwrap(),
        Err(DirectClientError::Checkpoint)
    );
    assert_eq!(
        last_result.await.unwrap(),
        Err(DirectClientError::Checkpoint)
    );
    let connection = store.state.connection.lock().unwrap();
    assert_eq!(
        sqlite::read::<String>(&connection, "intent", "first", 0, 0).unwrap(),
        None
    );
    assert_eq!(
        sqlite::read::<String>(&connection, "intent", "last", 0, 0).unwrap(),
        None
    );
    drop(connection);
    std::fs::rename(moved, original).unwrap();
}

#[tokio::test]
async fn sqlite_commit_failure_refuses_every_wave_and_leaves_no_partial_records() {
    let (directory, store) = store().await;
    let (first, first_result) = pending(&store.state, |transaction| {
        sqlite::write(transaction, "intent", "first", 0, 0, &"first")
    });
    let (last, last_result) = pending(&store.state, |transaction| {
        // The deferred violation succeeds locally and fails the actual COMMIT.
        transaction
            .execute_batch(
                "CREATE TABLE test_parent (id INTEGER PRIMARY KEY);
             CREATE TABLE test_child (parent INTEGER REFERENCES test_parent(id)
               DEFERRABLE INITIALLY DEFERRED);
             INSERT INTO test_child VALUES (1);",
            )
            .map_err(|_| DirectClientError::Checkpoint)?;
        sqlite::write(transaction, "intent", "last", 0, 0, &"last")
    });
    let state = store.state.clone();
    tokio::task::spawn_blocking(move || execute_group(&state, vec![first, last]))
        .await
        .unwrap();

    assert_eq!(
        first_result.await.unwrap(),
        Err(DirectClientError::Checkpoint)
    );
    assert_eq!(
        last_result.await.unwrap(),
        Err(DirectClientError::Checkpoint)
    );
    drop(store);
    let reopened = SqliteDirectCheckpoints::open(
        &directory.path().join("direct.sqlite"),
        &"ab".repeat(32),
        false,
    )
    .await
    .unwrap();
    let connection = reopened.state.connection.lock().unwrap();
    assert_eq!(
        sqlite::read::<String>(&connection, "intent", "first", 0, 0).unwrap(),
        None
    );
    assert_eq!(
        sqlite::read::<String>(&connection, "intent", "last", 0, 0).unwrap(),
        None
    );
}

#[tokio::test]
async fn cancelled_waiter_keeps_durable_work_and_does_not_stall_bounded_queue() {
    let (_directory, store) = store().await;
    let (entered_send, entered_receive) = oneshot::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let first_store = store.clone();
    let first = tokio::spawn(async move {
        let reservation = first_store.reserve().await?;
        first_store
            .wave(reservation, move |transaction| {
                sqlite::write(transaction, "intent", "cancelled", 0, 0, &"retained")?;
                entered_send.send(()).unwrap();
                release_receive.recv().unwrap();
                Ok(())
            })
            .await
    });
    entered_receive.await.unwrap();
    let mut neighbors = Vec::new();
    for index in 1..MAX_PENDING_WAVES {
        let store = store.clone();
        neighbors.push(tokio::spawn(async move {
            let reservation = store.reserve().await?;
            store
                .wave(reservation, move |transaction| {
                    sqlite::write(transaction, "intent", &index.to_string(), 0, 0, &index)
                })
                .await
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if store.state.waves.lock().unwrap().pending.len() == MAX_PENDING_WAVES - 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(store.state.budget.clone().try_acquire_owned().is_err());
    first.abort();
    release_send.send(()).unwrap();

    for neighbor in neighbors {
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), neighbor)
                .await
                .unwrap()
                .unwrap(),
            Ok(())
        );
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if store.state.budget.available_permits() == MAX_PENDING_WAVES
                && !store.state.waves.lock().unwrap().running
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let reservation = store.reserve().await.unwrap();
    store
        .wave(reservation, |transaction| {
            assert_eq!(
                sqlite::read::<String>(transaction, "intent", "cancelled", 0, 0)?,
                Some("retained".into())
            );
            sqlite::write(transaction, "intent", "later", 0, 0, &"later")
        })
        .await
        .unwrap();
}
