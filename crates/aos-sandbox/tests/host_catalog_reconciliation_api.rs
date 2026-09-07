//! Verifies that downstream controllers can name Host catalog reconciliation results.

#![cfg(target_os = "linux")]

use aos_sandbox::{
    DurableCurrentHostCatalogV1, DurablePendingHostCatalogV1, HostCatalogReconciliationV1,
};

#[test]
fn downstream_code_can_inspect_host_catalog_reconciliation_results() {
    fn inspect_result(result: HostCatalogReconciliationV1) -> u64 {
        match result {
            HostCatalogReconciliationV1::Current(current) => current.generation(),
            HostCatalogReconciliationV1::Publish(pending) => pending.generation(),
        }
    }

    fn inspect_pending(pending: &DurablePendingHostCatalogV1) {
        let _ = pending.generation();
        let _ = pending.catalog_digest();
        let _ = pending.canonical_catalog();
        let _ = pending.catalog();
    }

    fn inspect_current(current: &DurableCurrentHostCatalogV1) {
        let _ = current.generation();
        let _ = current.catalog_digest();
        let _ = current.canonical_catalog();
        let _ = current.catalog();
    }

    let _ = (inspect_result, inspect_pending, inspect_current);
}
