//! Exercises inactive-unit retention through the pinned manager connection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aos_systemd_client::{Error, PinnedSystemdManager};

use super::common::{MANAGER_PATH, UNIT_PATH, fake_systemd};
use super::{FakeUnit, SYSTEMD_NAME};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the hermetic AOS D-Bus broker"]
async fn inactive_unit_survives_property_reads_only_while_referenced()
-> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::var("AOS_TEST_DBUS_ADDRESS")?;
    let (fake, state) = fake_systemd();
    state
        .collect_unreferenced_units
        .store(true, Ordering::SeqCst);
    let manager = zbus::connection::Builder::address(address.as_str())?
        .serve_at(MANAGER_PATH, fake)?
        .serve_at(
            UNIT_PATH,
            FakeUnit {
                needs_reload: Arc::new(AtomicBool::new(false)),
            },
        )?
        .build()
        .await?;
    manager.request_name(SYSTEMD_NAME).await?;

    let connection = zbus::connection::Builder::address(address.as_str())?
        .build()
        .await?;
    let pinned = PinnedSystemdManager::from_connection(connection).await?;

    // A successful load does not retain the otherwise idle object. This is
    // the production mount handler's former load-then-query failure.
    pinned.load_unit("example.service").await?;
    let missing = pinned.unit_identity("example.service").await.unwrap_err();
    assert!(missing.is_no_such_unit(), "{missing}");
    state.calls.lock().unwrap().clear();

    let identity = pinned.load_referenced_unit("example.service").await?;
    assert_eq!(identity, UNIT_PATH);
    assert_eq!(pinned.unit_identity("example.service").await?, identity);
    assert_eq!(state.reference_balance.load(Ordering::SeqCst), 1);
    assert_eq!(
        state.calls.lock().unwrap().as_slice(),
        ["ref_unit", "get_unit", "get_unit"]
    );

    // Retention is liveness, not acceptance of a substituted canonical name.
    assert!(matches!(
        pinned.load_referenced_unit("alias.service").await,
        Err(Error::UnitAlias { .. })
    ));
    Ok(())
}
