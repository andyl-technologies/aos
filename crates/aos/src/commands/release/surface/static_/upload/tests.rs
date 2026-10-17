//! Scheduler overlap and barriers using held, completed and failed upload futures.
//!
//! These callbacks exercise the production scheduling function without provider
//! transport. They establish no multipart, resume or throughput qualification.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use anyhow::bail;
use tokio::sync::Semaphore;

use super::*;

fn objects(immutable: usize) -> Vec<RegistryPublicationObjectInput> {
    let mut objects: Vec<_> = (0..immutable)
        .map(|number| RegistryPublicationObjectInput {
            path: format!("objects/{number:03}"),
            kind: "immutable".into(),
            ..Default::default()
        })
        .collect();
    for path in ["HEAD", "info/refs", "objects/info/packs"] {
        objects.push(RegistryPublicationObjectInput {
            path: path.into(),
            kind: "mutable_pointer".into(),
            ..Default::default()
        });
    }
    objects
}

#[tokio::test]
async fn immutable_puts_overlap_with_eight_owned_futures_then_visibility_is_serial() {
    let objects = objects(20);
    let selected: Vec<_> = objects.iter().collect();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut completed = 0;

    ordered(
        &selected,
        |object| {
            let active = active.clone();
            let maximum = maximum.clone();
            let events = events.clone();
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(count, Ordering::SeqCst);
                if upload_rank(object) != 0 {
                    assert_eq!(count, 1);
                }
                events.lock().unwrap().push((object.path.clone(), "start"));
                tokio::task::yield_now().await;
                events.lock().unwrap().push((object.path.clone(), "finish"));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        },
        |count| completed = count,
    )
    .await
    .unwrap();

    assert_eq!(maximum.load(Ordering::SeqCst), IMMUTABLE_UPLOAD_CONCURRENCY);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(completed, objects.len());
    let events = events.lock().unwrap();
    let first_pointer = events
        .iter()
        .position(|event| event == &("objects/info/packs".into(), "start"))
        .unwrap();
    assert_eq!(
        events[..first_pointer]
            .iter()
            .filter(|(_, event)| *event == "finish")
            .count(),
        20
    );
    let pointers: Vec<_> = events[first_pointer..]
        .iter()
        .map(|(path, event)| (path.as_str(), *event))
        .collect();
    assert_eq!(
        pointers,
        [
            ("objects/info/packs", "start"),
            ("objects/info/packs", "finish"),
            ("info/refs", "start"),
            ("info/refs", "finish"),
            ("HEAD", "start"),
            ("HEAD", "finish"),
        ]
    );
}

#[tokio::test]
async fn held_immutable_prevents_pointers_head_and_following_timestamp_cas() {
    let objects = objects(10);
    let selected: Vec<_> = objects.iter().collect();
    let release = Arc::new(Semaphore::new(0));
    let other_completed = Arc::new(Semaphore::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let operation = async {
        ordered(
            &selected,
            |object| {
                let release = release.clone();
                let other_completed = other_completed.clone();
                let events = events.clone();
                async move {
                    if object.path == "objects/000" {
                        release.acquire().await.unwrap().forget();
                    } else if upload_rank(object) == 0 {
                        other_completed.add_permits(1);
                    }
                    events.lock().unwrap().push(object.path.clone());
                    Ok(())
                }
            },
            |_| {},
        )
        .await?;
        events.lock().unwrap().push("timestamp-CAS".into());
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(operation);

    tokio::select! {
        result = &mut operation => panic!("held prerequisite crossed barrier: {result:?}"),
        done = other_completed.acquire_many(9) => done.unwrap().forget(),
    }
    assert_eq!(events.lock().unwrap().len(), 9);
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .all(|path| path.starts_with("objects/0"))
    );
    release.add_permits(1);
    operation.await.unwrap();

    let events = events.lock().unwrap();
    assert_eq!(
        &events[10..],
        ["objects/info/packs", "info/refs", "HEAD", "timestamp-CAS"]
    );
}

#[tokio::test]
async fn first_failure_stops_new_dispatch_and_awaits_every_admitted_neighbor() {
    let objects = objects(20);
    let selected: Vec<_> = objects.iter().collect();
    let release = Arc::new(Semaphore::new(0));
    let started = Arc::new(Semaphore::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let finished = Arc::new(AtomicUsize::new(0));
    let operation = async {
        ordered(
            &selected,
            |object| {
                let release = release.clone();
                let started = started.clone();
                let events = events.clone();
                let finished = finished.clone();
                async move {
                    events.lock().unwrap().push(object.path.clone());
                    started.add_permits(1);
                    if object.path == "objects/000" {
                        finished.fetch_add(1, Ordering::SeqCst);
                        bail!("retained immutable PUT failure");
                    }
                    if object.path == "objects/001" {
                        release.acquire().await.unwrap().forget();
                    }
                    tokio::task::yield_now().await;
                    finished.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            |_| {},
        )
        .await?;
        events.lock().unwrap().push("timestamp-CAS".into());
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(operation);

    tokio::select! {
        result = &mut operation => panic!("returned before active PUT settled: {result:?}"),
        starts = started.acquire_many(8) => starts.unwrap().forget(),
    }
    assert_eq!(events.lock().unwrap().len(), 8);
    release.add_permits(1);
    let error = operation.await.unwrap_err();

    assert!(error.to_string().contains("retained immutable PUT failure"));
    assert_eq!(finished.load(Ordering::SeqCst), 8);
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .all(|path| path.as_str() <= "objects/007")
    );
}

#[tokio::test]
async fn pointer_failure_preserves_head_and_timestamp_barriers() {
    let objects = objects(2);
    let selected: Vec<_> = objects.iter().collect();
    let events = Mutex::new(Vec::new());
    let operation = async {
        ordered(
            &selected,
            |object| {
                let events = &events;
                async move {
                    events.lock().unwrap().push(object.path.clone());
                    if object.path == "info/refs" {
                        bail!("ref publication refused");
                    }
                    Ok(())
                }
            },
            |_| {},
        )
        .await?;
        events.lock().unwrap().push("timestamp-CAS".into());
        Ok::<(), anyhow::Error>(())
    };

    assert!(operation.await.is_err());

    let events = events.lock().unwrap();
    assert_eq!(events.len(), 4);
    assert_eq!(&events[2..], ["objects/info/packs", "info/refs"]);
}
