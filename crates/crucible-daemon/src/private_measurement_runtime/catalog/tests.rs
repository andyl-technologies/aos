//! Exercises same-roster catalog scopes and actual external control custody.
//!
//! These local banks are mechanism fixtures, not certified parent evidence.

// crucible-lint: allow panic-shortcut -- failed ownership assertions stop these mechanism tests.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible::owned_decode::DecodeResourceAuthority;
use crucible_linux_resource::host_services::HostServiceAllocator;
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationState,
    HostOperationSupervisor,
};

pub(super) struct FixtureAccounts {
    pub(super) original: Arc<HostOperationGuard>,
    pub(super) supervisor: HostOperationSupervisor,
}

struct FixtureDecode {
    original: Arc<HostOperationGuard>,
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
}

impl DecodeResourceAuthority for FixtureDecode {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        type Credit = (Option<HostServiceLease>, HostServiceLeasePair);
        let bytes = bytes
            + ResourceLoan::allocation_bytes::<Credit>()
            + 2 * HostServiceLease::metadata_bytes();
        let (resident, metadata) = self
            .resident
            .reserve_paired_bytes(&self.metadata, bytes)
            .map_err(DecodeAdmissionError::new)?;
        Ok(ResourceLoan::new((
            None::<HostServiceLease>,
            HostServiceLeasePair::new(resident, metadata),
        )))
    }

    fn reserve_descriptors(&self, descriptors: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        type Credit = (HostServiceLease, HostServiceLeasePair);
        let bytes =
            ResourceLoan::allocation_bytes::<Credit>() + 3 * HostServiceLease::metadata_bytes();
        let (first, second) = self
            .resident
            .reserve_paired_bytes(&self.metadata, bytes)
            .map_err(DecodeAdmissionError::new)?;
        let descriptor = self
            .resident
            .reserve_resources(0, descriptors, 0)
            .map_err(DecodeAdmissionError::new)?;
        Ok(ResourceLoan::new((
            descriptor,
            HostServiceLeasePair::new(first, second),
        )))
    }
}

pub(crate) struct FixtureDecoder {
    budget: Option<DecodeBudget>,
    authority: Arc<FixtureDecode>,
}

impl FixtureDecoder {
    pub(crate) fn budget(&self) -> Result<&DecodeBudget, DecodeAdmissionError> {
        let budget = self
            .budget
            .as_ref()
            .ok_or_else(|| DecodeAdmissionError::new(OriginalActorAccountError::Unavailable))?;
        budget.check()?;
        Ok(budget)
    }

    pub(crate) fn try_close(mut self) -> Result<(), Self> {
        if self.budget().and_then(DecodeBudget::verify_live).is_err() {
            return Err(self);
        }
        drop(self.budget.take());
        if Arc::get_mut(&mut self.authority).is_none() {
            return Err(self);
        }
        Ok(())
    }
}

pub(crate) struct GraphQuotaFixture(pub(crate) DecodeBudget);

impl crucible_cas::content_store::StorePhysicalQuotaGuard for GraphQuotaFixture {
    fn verify(&self) -> Result<(), StoreError> {
        self.0
            .verify_live()
            .map_err(|source| StoreError::DecodeAdmission {
                source,
                custody: Some(self.0.custody()),
            })
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        let decode_error = |source| StoreError::DecodeAdmission {
            source,
            custody: Some(self.0.custody()),
        };
        let descriptors = if descriptors == 0 {
            None
        } else {
            Some(
                self.0
                    .reserve_descriptors(descriptors)
                    .map_err(decode_error)?,
            )
        };
        type Credit = (
            Option<crucible::owned_decode::DecodeDescriptorLoan>,
            DecodeScratch,
        );
        let extent = bytes
            .checked_add(ResourceLoan::allocation_bytes::<Credit>())
            .ok_or(StoreError::Quota)?;
        let bytes = self.0.reserve_scratch_bytes(extent).map_err(decode_error)?;
        Ok(ResourceLoan::new((descriptors, bytes)))
    }
}

pub(crate) fn fixture_original(owner: &OriginalActorCatalogOwner) -> Arc<HostOperationGuard> {
    let accounts = &owner.authority.as_ref().unwrap().accounts;
    match accounts {
        CatalogAccounts::Fixture(accounts) => Arc::clone(&accounts.original),
        CatalogAccounts::Original(_) => {
            panic!("fixture original requires the local mechanism owner")
        }
    }
}

pub(crate) fn fixture() -> (
    HostOperationSupervisor,
    FixtureDecoder,
    OriginalActorCatalogOwner,
) {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let resident = HostServiceAllocator::new(1, 32, 4 << 20).unwrap();
    let metadata = HostServiceAllocator::new(1, 32, 4 << 20).unwrap();
    let authority = Arc::new(FixtureDecode {
        original: Arc::clone(&original),
        resident: resident.clone(),
        metadata: metadata.clone(),
    });
    let decoder = FixtureDecoder {
        budget: Some(DecodeBudget::new(authority.clone(), 4 << 20).unwrap()),
        authority,
    };
    let bytes = shared_extent::<CatalogAuthority>().unwrap()
        + shared_extent::<CatalogSupervisor>().unwrap()
        + shared_extent::<CatalogCause>().unwrap()
        + 2 * HostServiceLease::metadata_bytes();
    let (first, second) = resident.reserve_paired_bytes(&metadata, bytes).unwrap();
    let authority = Arc::new(CatalogAuthority {
        physical: Mutex::new(None),
        accounts: CatalogAccounts::Fixture(FixtureAccounts {
            original,
            supervisor: supervisor.clone(),
        }),
        budget: decoder.budget().unwrap().clone(),
        failure: Mutex::new(None),
    });
    let owner = OriginalActorCatalogOwner {
        supervisor: Some(Arc::new(CatalogSupervisor(Arc::clone(&authority)))),
        authority: Some(authority),
        controls: Some(HostServiceLeasePair::new(first, second)),
        close_failure: None,
    };
    (supervisor, decoder, owner)
}

/// Constructs the closed production-class catalog profile for creation controls.
///
/// The concrete values match original_actor/workflow.rs CATALOG exactly.
/// This method accepts no amount, issues no production evidence and changes no
/// existing fixture. The owner and original pair precede all tested operations.
pub(crate) fn campaign_creation_fixture() -> (
    HostOperationSupervisor,
    FixtureDecoder,
    OriginalActorCatalogOwner,
    HostServiceLeasePair,
) {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let resident = HostServiceAllocator::new(1, 128, 512 << 20).unwrap();
    let metadata = HostServiceAllocator::new(1, 128, 256 << 20).unwrap();
    // This fixed test profile follows the actual CATALOG resident/metadata/FD
    // vector. Existing small controls keep their independent 4 MiB profile.
    // Prepay the same decode authority Arc before its actual allocation; this
    // external loan stays with the caller until that authority is freed.
    let decode_bytes =
        shared_extent::<FixtureDecode>().unwrap() + 2 * HostServiceLease::metadata_bytes();
    let (decode_first, decode_second) = resident
        .reserve_paired_bytes(&metadata, decode_bytes)
        .unwrap();
    let decode_controls = HostServiceLeasePair::new(decode_first, decode_second);
    let authority = Arc::new(FixtureDecode {
        original: Arc::clone(&original),
        resident: resident.clone(),
        metadata: metadata.clone(),
    });
    let decoder = FixtureDecoder {
        budget: Some(DecodeBudget::new(authority.clone(), 256 << 20).unwrap()),
        authority,
    };
    let bytes = shared_extent::<CatalogAuthority>().unwrap()
        + shared_extent::<CatalogSupervisor>().unwrap()
        + shared_extent::<CatalogCause>().unwrap()
        + 2 * HostServiceLease::metadata_bytes();
    let (first, second) = resident.reserve_paired_bytes(&metadata, bytes).unwrap();
    let authority = Arc::new(CatalogAuthority {
        physical: Mutex::new(None),
        accounts: CatalogAccounts::Fixture(FixtureAccounts {
            original,
            supervisor: supervisor.clone(),
        }),
        budget: decoder.budget().unwrap().clone(),
        failure: Mutex::new(None),
    });
    let owner = OriginalActorCatalogOwner {
        supervisor: Some(Arc::new(CatalogSupervisor(Arc::clone(&authority)))),
        authority: Some(authority),
        controls: Some(HostServiceLeasePair::new(first, second)),
        close_failure: None,
    };
    (supervisor, decoder, owner, decode_controls)
}

#[test]
fn catalog_operation_completes_only_its_same_root_scope() {
    let (root, decoder, owner) = fixture();
    let supervisor = owner.supervisor().unwrap();
    let operation = supervisor.begin(SqliteCatalogOperationKind::Read).unwrap();

    operation.check().unwrap();
    let during = root.operation_statuses().unwrap();
    assert!(
        during
            .iter()
            .any(|status| status.class == HostOperationClass::PageIn)
    );
    operation.complete().unwrap();

    let after = root.operation_statuses().unwrap();
    assert!(
        after
            .iter()
            .any(|status| status.class == HostOperationClass::Preparation
                && status.state == HostOperationState::Running)
    );
    drop(supervisor);
    owner.try_close().unwrap();
    assert!(decoder.try_close().is_ok());
}

#[test]
fn actual_graph_alias_refusal_completes_same_catalog_scope_before_alias_release() {
    use crucible_cas::content_store::{
        ObjectKind, OriginalSqliteGraphConfig, OriginalSqliteGraphOwner,
    };

    let (root, decoder, owner) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let heap = crucible_cas::content_store::fixture_sqlite_heap().unwrap();
    let quota = Arc::new(GraphQuotaFixture(decoder.budget().unwrap().clone()));
    let mut graph_owner = OriginalSqliteGraphOwner::open(
        OriginalSqliteGraphConfig {
            name: "campaign-primary",
            root: directory.path(),
            admitted_kinds: &[ObjectKind::CampaignFact],
            maximum_sqlite_heap_bytes: heap.maximum_heap_bytes(),
        },
        quota.clone(),
        owner.supervisor().unwrap(),
        &heap,
    )
    .unwrap();
    let graph = graph_owner.graph().unwrap();
    let weak = Arc::downgrade(&graph);
    drop(graph);

    assert!(graph_owner.try_close().is_err());
    assert!(
        owner
            .authority
            .as_ref()
            .unwrap()
            .failure
            .lock()
            .unwrap()
            .is_none()
    );
    assert!(root.operation_statuses().unwrap().iter().all(|status| {
        status.class != HostOperationClass::Writeback
            || status.state == HostOperationState::Completed
    }));
    drop(weak);

    graph_owner.try_close().unwrap();
    drop(graph_owner);
    drop(quota);
    owner.try_close().unwrap();
    assert!(decoder.try_close().is_ok());
}

#[test]
fn catalog_weak_control_alias_blocks_close_until_actual_release() {
    let (_root, decoder, owner) = fixture();
    let supervisor = owner.supervisor().unwrap();
    let weak = Arc::downgrade(&supervisor);
    drop(supervisor);

    let retained = owner.try_close().err().unwrap();
    assert!(weak.upgrade().is_some());
    drop(weak);

    retained.try_close().unwrap();
    assert!(decoder.try_close().is_ok());
}

#[test]
fn catalog_backend_loan_pins_authority_after_facade_control_closes() {
    let (_root, decoder, owner) = fixture();
    let supervisor = owner.supervisor().unwrap();
    let loan = supervisor.reserve_resident_bytes(1 << 20).unwrap();
    drop(supervisor);

    let retained = owner.try_close().err().unwrap();
    assert!(retained.supervisor.is_none());
    assert!(retained.authority.is_some());
    drop(loan);

    retained.try_close().unwrap();
    assert!(decoder.try_close().is_ok());
}

#[test]
fn catalog_abandoned_real_scope_retains_first_failure_after_alias_drop() {
    let (_root, decoder, owner) = fixture();
    let supervisor = owner.supervisor().unwrap();
    let operation = supervisor.begin(SqliteCatalogOperationKind::Write).unwrap();

    drop(operation);
    let first = supervisor
        .begin(SqliteCatalogOperationKind::Read)
        .err()
        .unwrap();
    assert!(matches!(first, StoreError::DecodeAdmission { .. }));
    drop(supervisor);
    let retained = owner.try_close().err().unwrap();
    assert!(retained.close_failure.is_some());
    assert!(retained.try_close().is_err());
    assert!(decoder.try_close().is_err());
}
