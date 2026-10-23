//! Rejects unfunded reports, foreign journals and premature accounting return.

use super::Fixture;

#[test]
fn shutdown_report_contracts_require_the_same_prepaid_immutable_cells()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::load(0)?;

    for (path, before, after, reason) in [
        (
            "launch_cleanup.rs",
            "reserve_controls(0, bytes)",
            "reserve_controls(0, 0)",
            "original Source report allocation is unfunded",
        ),
        (
            "retained_record.rs",
            ".checked_add(ShutdownJournal::peak_bytes()?)",
            "",
            "complete prebirth peak omits shutdown cells",
        ),
        (
            "launch_cleanup.rs",
            "self.inner.shutdown_storage.try_lock().ok()?.take()",
            "self.inner.shutdown_storage.try_lock().ok()?.clone()",
            "native shutdown journal can be claimed twice",
        ),
        (
            "shutdown_journal.rs",
            "drop(Arc::into_inner(journal));",
            "drop(journal);",
            "shared header outlives financial return",
        ),
        (
            "shutdown_journal.rs",
            "mask: failures,",
            "mask: u8::MAX,",
            "old receipts observe later failures",
        ),
        (
            "shutdown_journal.rs",
            "self.failures()[index].set(output)",
            "self.failures()[index].set(output.clone())",
            "publication copies the original owned diagnostic",
        ),
        (
            "src/node.rs",
            "shutdown_continuation::ChildShutdown::for_launch(launch_cleanup.as_ref())",
            "shutdown_continuation::ChildShutdown::for_launch(foreign_cleanup.as_ref())",
            "Node claims another launch's report cells",
        ),
        (
            "shutdown/continuation.rs",
            "return Some(QemuShutdownError::StorageUnavailable);",
            "return None;",
            "missing prepaid storage permits effects",
        ),
    ] {
        fixture.rejects(path, before, after, reason);
    }

    Ok(())
}
