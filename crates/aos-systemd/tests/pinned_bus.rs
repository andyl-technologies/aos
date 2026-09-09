//! Real-broker tests for manager incarnation pinning.
//!
//! The ordinary client tests use a peer-to-peer socket and cannot exercise
//! `GetId`, `GetNameOwner`, or signal sender filtering across well-known-name
//! replacement. The hermetic Nix check starts the AOS-built D-Bus broker and
//! supplies its address through `AOS_TEST_DBUS_ADDRESS`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use aos_systemd::{Error, JobResult, PinnedSystemdManager};
use common::{MANAGER_PATH, fake_systemd};

const SYSTEMD_NAME: &str = "org.freedesktop.systemd1";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the hermetic AOS D-Bus broker"]
async fn replacement_owner_cannot_complete_reused_job_path()
-> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::var("AOS_TEST_DBUS_ADDRESS")?;
    let (first_fake, first_state) = fake_systemd();
    first_state
        .suppress_emit
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let first_manager = zbus::connection::Builder::address(address.as_str())?
        .serve_at(MANAGER_PATH, first_fake)?
        .build()
        .await?;
    first_manager.request_name(SYSTEMD_NAME).await?;

    let client_connection = zbus::connection::Builder::address(address.as_str())?
        .build()
        .await?;
    let pinned = Arc::new(PinnedSystemdManager::from_connection(client_connection).await?);
    let first_incarnation = pinned.incarnation().clone();

    let old_call = {
        let pinned = Arc::clone(&pinned);
        tokio::spawn(async move { pinned.restart_unit("example.service").await })
    };
    wait_for_call(&first_state, "restart_unit").await;

    assert!(first_manager.release_name(SYSTEMD_NAME).await?);
    let (second_fake, second_state) = fake_systemd();
    let second_manager = zbus::connection::Builder::address(address.as_str())?
        .serve_at(MANAGER_PATH, second_fake)?
        .build()
        .await?;
    second_manager.request_name(SYSTEMD_NAME).await?;

    let second_client_connection = zbus::connection::Builder::address(address.as_str())?
        .build()
        .await?;
    let second_client = PinnedSystemdManager::from_connection(second_client_connection).await?;
    let reused = second_client.restart_unit("example.service").await?;
    assert_eq!(reused.job_path.as_str(), "/org/freedesktop/systemd1/job/1");
    assert_eq!(reused.result, JobResult::Done);
    wait_for_call(&second_state, "restart_unit").await;

    let mut old_call = old_call;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut old_call)
            .await
            .is_err(),
        "the replacement owner's reused path completed the old pinned call"
    );
    old_call.abort();

    let changed = pinned.is_active("example.service").await;
    assert!(matches!(changed, Err(Error::ManagerIncarnationChanged)));
    let second_incarnation = second_client.incarnation();
    assert_eq!(first_incarnation.bus_id(), second_incarnation.bus_id());
    assert_ne!(first_incarnation.owner(), second_incarnation.owner());
    Ok(())
}

async fn wait_for_call(state: &common::FakeState, expected: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        if state
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|call| call == expected)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("manager never received {expected}");
}
