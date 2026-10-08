//! Finite original operation and admitted scratch storage for GC components.
//!
//! The scratch catalog owns a portable resource account and a real finite host
//! supervision scope. Its fixture quota guard does not certify an installed
//! filesystem quota or native paging admission.

use std::sync::Arc;
use std::time::Duration;

use crucible_cas::content_store::{
    ImmutableBlobBackend, SqliteBlobBackend, SqliteCatalogOperation, SqliteCatalogOperationKind,
    SqliteCatalogSupervisor, StoreError, StorePhysicalQuotaGuard,
};
use crucible_linux_resource::host_supervision::{
    HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets, HostOperationClass,
    HostOperationGuard, HostOperationSupervisor,
};

use crate::campaign_gc::CampaignGcOperationContext;
use crucible_cas::owned_decode::DecodeBudget;

/// Owns one finite component maintenance scope across planning and apply.
pub(crate) struct ComponentGcOperation {
    marks: Arc<dyn ImmutableBlobBackend>,
    resources: Arc<dyn StorePhysicalQuotaGuard>,
    decoding: DecodeBudget,
    boundary: Box<dyn FnMut() -> Result<(), StoreError>>,
    _scratch: tempfile::TempDir,
}

impl ComponentGcOperation {
    /// Opens isolated scratch with explicit resident, descriptor and time bounds.
    pub(crate) fn new() -> Self {
        let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
            .unwrap_or_else(|error| panic!("finite component GC resources: {error}"));
        Self::with_resources(resources)
    }

    pub(super) fn with_resources(resources: Arc<dyn StorePhysicalQuotaGuard>) -> Self {
        let decoding = DecodeBudget::for_store(Arc::clone(&resources))
            .unwrap_or_else(|error| panic!("original component GC decoding authority: {error}"));
        let scratch = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("component GC scratch directory: {error}"));
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(Duration::from_secs(300));
                    HOST_OPERATION_CLASS_COUNT],
            },
            Some(Duration::from_secs(300)),
        )
        .unwrap_or_else(|error| panic!("finite component GC supervision: {error}"));
        let original = supervisor
            .begin(HostOperationClass::Transfer)
            .unwrap_or_else(|error| panic!("original component GC boundary: {error}"));
        let sqlite = Arc::new(ComponentSqliteSupervisor {
            resources: Arc::clone(&resources),
            supervisor,
        });
        let marks = SqliteBlobBackend::open_with_physical_quota(
            "component-gc-marks",
            scratch.path(),
            Arc::clone(&resources),
            8 * 1024 * 1024,
            sqlite,
            &crucible_cas::content_store::fixture_sqlite_heap()
                .expect("authored SQLite fixture process"),
        )
        .unwrap_or_else(|error| panic!("admitted component GC mark catalog: {error}"));

        Self {
            marks,
            resources,
            decoding,
            boundary: Box::new(move || {
                original.wait_slice().map(|_| ()).map_err(supervision_error)
            }),
            _scratch: scratch,
        }
    }

    /// Borrows the finite fixture account for lifetime assertions.
    pub(super) fn resources(&self) -> Arc<dyn StorePhysicalQuotaGuard> {
        Arc::clone(&self.resources)
    }

    /// Borrows the same original scope and scratch authority for all GC calls.
    pub(crate) fn context(&mut self) -> CampaignGcOperationContext<'_> {
        CampaignGcOperationContext::new(
            Arc::clone(&self.marks),
            &self.decoding,
            self.boundary.as_mut(),
        )
        .unwrap_or_else(|error| panic!("component GC operation context: {error}"))
    }
}

struct ComponentSqliteSupervisor {
    resources: Arc<dyn StorePhysicalQuotaGuard>,
    supervisor: HostOperationSupervisor,
}

impl SqliteCatalogSupervisor for ComponentSqliteSupervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.resources.reserve_resources(0, bytes)
    }

    fn begin(
        &self,
        kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        let class = match kind {
            SqliteCatalogOperationKind::Read => HostOperationClass::PageIn,
            SqliteCatalogOperationKind::Write => HostOperationClass::Writeback,
        };
        self.supervisor
            .begin(class)
            .map(|operation| Box::new(ComponentSqliteOperation(operation)) as Box<_>)
            .map_err(supervision_error)
    }
}

struct ComponentSqliteOperation(HostOperationGuard);

impl SqliteCatalogOperation for ComponentSqliteOperation {
    fn check(&self) -> Result<(), StoreError> {
        self.0.wait_slice().map(|_| ()).map_err(supervision_error)
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        self.0.complete().map(|_| ()).map_err(supervision_error)
    }
}

fn supervision_error(
    source: crucible_linux_resource::host_supervision::HostSupervisionError,
) -> StoreError {
    StoreError::Supervision {
        source: Box::new(source),
    }
}
