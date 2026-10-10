//! Checks actual repository controls with a real original guard and SQLite graph.
//!
//! Finite fixture banks and the process fixture heap do not certify an actor,
//! native initialization, filesystem quota or deployed service.

// crucible-lint: allow panic-shortcut -- failed control assertions stop these fixture tests.
#![allow(clippy::unwrap_used)]

use crucible::owned_decode::{DecodeAdmissionError, DecodeResourceAuthority, ResourceLoan};
use crucible_cas::content_store::{
    ObjectKind, OriginalSqliteGraphConfig, SqliteCatalogOperation, SqliteCatalogOperationKind,
    SqliteCatalogSupervisor, StorePhysicalQuotaGuard,
};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};

use super::*;

struct Fixture {
    original: HostOperationGuard,
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
}

struct Credit {
    _pair: HostServiceLeasePair,
}

impl DecodeResourceAuthority for Fixture {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        DecodeResourceAuthority::verify_live(self)?;
        let extent = bytes
            + ResourceLoan::allocation_bytes::<Credit>()
            + 2 * crucible_linux_resource::host_services::HostServiceLease::metadata_bytes();
        let (first, second) = self
            .resident
            .reserve_paired_bytes(&self.metadata, extent)
            .map_err(DecodeAdmissionError::new)?;
        Ok(ResourceLoan::new(Credit {
            _pair: HostServiceLeasePair::new(first, second),
        }))
    }
}

impl StorePhysicalQuotaGuard for Fixture {
    fn verify(&self) -> Result<(), StoreError> {
        DecodeResourceAuthority::verify_live(self).map_err(decode_error)
    }

    fn reserve_resources(&self, _descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        // This fixture covers the metadata/control lane only. Production
        // descriptor and physical quota admission use the real catalog owner.
        DecodeResourceAuthority::reserve(self, bytes).map_err(decode_error)
    }
}

struct Operation;

impl SqliteCatalogOperation for Operation {
    fn check(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        Ok(())
    }
}

impl SqliteCatalogSupervisor for Fixture {
    fn reserve_resident_bytes(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        DecodeResourceAuthority::reserve(self, bytes).map_err(decode_error)
    }

    fn begin(
        &self,
        _kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        StorePhysicalQuotaGuard::verify(self)?;
        Ok(Box::new(Operation))
    }
}

fn decode_error(source: DecodeAdmissionError) -> StoreError {
    StoreError::DecodeAdmission {
        source,
        custody: None,
    }
}

fn fixture() -> (HostOperationSupervisor, Arc<Fixture>, DecodeBudget) {
    let root = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let fixture = Arc::new(Fixture {
        original: root.begin(HostOperationClass::Preparation).unwrap(),
        resident: HostServiceAllocator::new(1, 128, 16 << 20).unwrap(),
        metadata: HostServiceAllocator::new(1, 128, 16 << 20).unwrap(),
    });
    let budget = DecodeBudget::new(fixture.clone(), 4 << 20).unwrap();
    (root, fixture, budget)
}

fn stores(
    root: &Path,
    fixture: &Arc<Fixture>,
) -> (OriginalSqliteGraphOwner, OriginalDirectoryRefOwner) {
    let heap = crucible_cas::content_store::fixture_sqlite_heap().unwrap();
    let graph = OriginalSqliteGraphOwner::open(
        OriginalSqliteGraphConfig {
            name: "campaign-primary",
            root,
            admitted_kinds: &[ObjectKind::CampaignFact],
            maximum_sqlite_heap_bytes: heap.maximum_heap_bytes(),
        },
        fixture.clone(),
        fixture.clone(),
        &heap,
    )
    .unwrap();
    let refs = OriginalDirectoryRefOwner::open(&root.join("refs"), fixture.clone()).unwrap();
    (graph, refs)
}

#[test]
fn genuine_repository_weak_control_blocks_before_backend_reuse() {
    let (_root, fixture, budget) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let (mut graph, mut refs) = stores(directory.path(), &fixture);
    let mut repository =
        OriginalCampaignRepositoryBootstrap::prepare(&mut graph, &refs, &budget).unwrap();
    let weak = Arc::downgrade(repository.repository.as_ref().unwrap());

    assert!(repository.try_close().is_err());
    assert!(repository.control.is_some());
    assert!(graph.try_close().is_err());
    assert!(refs.try_close().is_err());
    drop(weak);

    repository.try_close().unwrap();
    assert!(repository.control.is_none());
    refs.try_close().unwrap();
    graph.try_close().unwrap();
    budget.check().unwrap();
}

#[test]
fn canceled_same_original_refuses_before_repository_control_transfer() {
    let (root, fixture, budget) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let (mut graph, refs) = stores(directory.path(), &fixture);
    root.cancel().unwrap();

    assert!(OriginalCampaignRepositoryBootstrap::prepare(&mut graph, &refs, &budget).is_err());
    assert!(graph.graph().is_ok());
    assert!(budget.verify_live().is_err());
}
