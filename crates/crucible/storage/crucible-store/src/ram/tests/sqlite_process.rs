//! Gives SQLite-backed RAM cases their unchanged process-native heap scope.
//!
//! Case-local storage/codec banks do not partition SQLite's global hard heap.
//! Exact self-execution keeps those cases parallel without making one case's
//! connection caches consume another case's authored 8 MiB native entitlement.

use std::process::{Command, ExitStatus};

const ISOLATED_CASE: &str = "CRUCIBLE_RAM_SQLITE_CASE";
const PRESSURE_CHILD: &str = "CRUCIBLE_RAM_SQLITE_PRESSURE_CHILD";

pub(super) fn isolated() -> bool {
    let thread = std::thread::current();
    let name = thread.name().expect("named libtest RAM case");
    assert!(name.starts_with("ram::tests::"));
    if std::env::var_os(ISOLATED_CASE).as_deref() == Some(std::ffi::OsStr::new(name)) {
        return false;
    }

    let status = child_command(name)
        .status()
        .expect("isolated native SQLite RAM case");
    assert_child_success(status);
    true
}

fn child_command(name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("RAM test executable"));
    command
        .args(["--exact", name, "--nocapture"])
        .env(ISOLATED_CASE, name);
    command
}

fn assert_child_success(status: ExitStatus) {
    assert!(
        status.success(),
        "isolated SQLite RAM case failed: {status}"
    );
}

#[test]
fn native_pressure_stays_in_its_original_process_and_child_failure_propagates() {
    if isolated() {
        return;
    }

    const BYTES: usize = 4 << 20;
    const NATIVE_LIMIT: u64 = 8 << 20;
    let heap = crate::content_store::fixture_sqlite_heap().expect("original native fixture heap");
    assert_eq!(heap.maximum_heap_bytes(), NATIVE_LIMIT);
    let baseline = crucible_sqlite_heap::memory_used();
    let held = heap
        .open_connection(":memory:", rusqlite::OpenFlags::default())
        .expect("held native connection");
    let competing = heap
        .open_connection(":memory:", rusqlite::OpenFlags::default())
        .expect("independent native connection");
    let limit: u64 = held
        .query_row("PRAGMA hard_heap_limit", [], |row| row.get(0))
        .expect("actual unchanged native ceiling");
    assert_eq!(limit, NATIVE_LIMIT);

    held.query_row("SELECT zeroblob(?1)", [BYTES as i64], |row| {
        // get_ref materializes a native SQLite buffer, rather than returning
        // an owned Rust Vec that would cease to pressure SQLite's allocator.
        let rusqlite::types::ValueRef::Blob(bytes) = row.get_ref(0)? else {
            panic!("actual native BLOB");
        };
        assert_eq!(bytes.len(), BYTES);
        assert!(crucible_sqlite_heap::memory_used() >= baseline + BYTES as i64);

        if let Some(mode) = std::env::var_os(PRESSURE_CHILD) {
            assert!(mode == "healthy" || mode == "refuse");
            assert_eq!((bytes[0], bytes[BYTES - 1]), (0, 0));
            if mode == "refuse" {
                // A real nonzero child exit must reach the parent assertion.
                std::process::exit(23);
            }
            return Ok(());
        }

        // These two live results would exceed one unchanged process heap.
        // The actual native error distinguishes this from Rust quota refusal.
        let error = competing
            .query_row("SELECT length(randomblob(?1))", [BYTES as i64], |row| {
                row.get::<_, i64>(0)
            })
            .expect_err("another native allocation exceeds the shared hard heap");
        let crate::content_store::StoreError::StreamIo { source, .. } = error else {
            panic!("actual managed native failure");
        };
        let native = source
            .get_ref()
            .and_then(|source| source.downcast_ref::<rusqlite::Error>())
            .expect("original SQLite allocation failure");
        assert_eq!(
            native.sqlite_error_code(),
            Some(rusqlite::ErrorCode::OutOfMemory)
        );
        drop(source);

        let thread = std::thread::current();
        let name = thread.name().expect("exact pressure case");
        let status = child_command(name)
            .env(PRESSURE_CHILD, "healthy")
            .status()
            .expect("concurrent independently bounded native child");
        assert_child_success(status);

        let status = child_command(name)
            .env(PRESSURE_CHILD, "refuse")
            .status()
            .expect("actual refusing child");
        assert_eq!(status.code(), Some(23));
        assert!(std::panic::catch_unwind(|| assert_child_success(status)).is_err());

        // Parent native memory stayed live throughout both child executions.
        assert!(crucible_sqlite_heap::memory_used() >= baseline + BYTES as i64);
        assert_eq!((bytes[0], bytes[BYTES - 1]), (0, 0));
        Ok(())
    })
    .expect("retained parent native result");

    drop(competing);
    drop(held);
    assert_eq!(crucible_sqlite_heap::memory_used(), baseline);
    assert_eq!(heap.maximum_heap_bytes(), NATIVE_LIMIT);
}
