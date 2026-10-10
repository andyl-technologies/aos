//! Opens the fixed genuine graph under its already retained catalog owner.
//!
//! Physical binding and native heap installation precede this call. The graph
//! keeps its own controls external to the ordinary repository/admin handles.

use super::*;
use crucible_cas::content_store::{
    OriginalDirectoryRefOwner, OriginalSqliteGraphConfig, OriginalSqliteGraphOwner,
};

pub(crate) fn prepare_original_directory_refs(
    catalog: &crate::private_measurement_runtime::catalog::OriginalActorCatalogOwner,
) -> Result<OriginalDirectoryRefOwner, StoreError> {
    OriginalDirectoryRefOwner::open(
        Path::new("/var/lib/crucible/measurement/catalog/refs"),
        catalog.physical_quota()?,
    )
}

pub(crate) fn prepare_original_sqlite_graph(
    catalog: &crate::private_measurement_runtime::catalog::OriginalActorCatalogOwner,
    heap: &crucible_cas::content_store::SqliteProcessHeap,
) -> Result<OriginalSqliteGraphOwner, StoreError> {
    let quota = catalog.physical_quota()?;
    let supervisor = catalog.supervisor()?;
    OriginalSqliteGraphOwner::open(
        OriginalSqliteGraphConfig {
            name: "campaign-primary",
            root: Path::new("/var/lib/crucible/measurement/catalog/objects"),
            admitted_kinds: &CAMPAIGN_REPOSITORY_OBJECT_KINDS,
            maximum_sqlite_heap_bytes: heap.maximum_heap_bytes(),
        },
        quota,
        supervisor,
        heap,
    )
}
