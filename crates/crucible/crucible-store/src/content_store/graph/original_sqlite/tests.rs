//! Exercises real SQLite graph identity and external control retirement.
//!
//! The finite fixture loans test allocation lifetimes, not installed project
//! quotas, native initialization peaks or an authenticated actor entitlement.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;

struct Fixture {
    resources: FixtureResourceBudget,
    live: AtomicBool,
}

struct Operation;

impl SqliteCatalogSupervisor for Fixture {
    fn reserve_resident_bytes(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        self.resources.reserve_with_control(bytes)
    }

    fn begin(
        &self,
        _kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        self.verify()?;
        Ok(Box::new(Operation))
    }
}

impl SqliteCatalogOperation for Operation {
    fn check(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        Ok(())
    }
}

impl StorePhysicalQuotaGuard for Fixture {
    fn verify(&self) -> Result<(), StoreError> {
        if self.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Unauthorized)
        }
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        self.resources.reserve(descriptors, bytes)
    }
}

fn fixture(bytes: u64) -> Arc<Fixture> {
    Arc::new(Fixture {
        resources: FixtureResourceBudget::new(128, bytes),
        live: AtomicBool::new(true),
    })
}

fn open(
    root: &Path,
    fixture: &Arc<Fixture>,
) -> Result<OriginalSqliteGraphOwner, Box<dyn std::error::Error>> {
    let heap = crate::content_store::fixture_sqlite_heap()?;
    Ok(OriginalSqliteGraphOwner::open(
        OriginalSqliteGraphConfig {
            name: "campaign-primary",
            root,
            admitted_kinds: &[ObjectKind::CampaignFact],
            maximum_sqlite_heap_bytes: heap.maximum_heap_bytes(),
        },
        fixture.clone(),
        fixture.clone(),
        &heap,
    )?)
}

#[test]
fn original_single_sqlite_identity_matches_existing_canonical_graph()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let resources = fixture(1 << 20);
    let mut owner = open(directory.path(), &resources)?;
    let node = StoreNodeId::new("campaign-primary")?;
    let expected = StoreGraphConfigurationId::for_config(&StoreGraphConfig {
        gc_mark_root: None,
        root: node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
        nodes: BTreeMap::from([(
            node,
            StoreNodeSpec::Sqlite {
                root: directory.path().to_owned(),
            },
        )]),
    })?;
    let graph = owner.graph()?;
    assert_eq!(graph.configuration_id(), expected);
    assert_eq!(graph.describe().len(), 1);
    drop(graph);

    owner.try_close()?;
    assert_eq!(resources.resources.usage()?, (0, 0));
    Ok(())
}

#[test]
fn original_graph_weak_alias_holds_actual_control_credit() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::TempDir::new()?;
    let resources = fixture(1 << 20);
    let mut owner = open(directory.path(), &resources)?;
    let graph = owner.graph()?;
    let weak = Arc::downgrade(&graph);
    drop(graph);

    assert!(owner.try_close().is_err());
    assert!(resources.resources.usage()?.1 > 0);
    drop(weak);

    owner.try_close()?;
    assert_eq!(resources.resources.usage()?, (0, 0));
    Ok(())
}

#[test]
fn moved_admin_keeps_identity_credit_after_graph_body_close()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let resources = fixture(1 << 20);
    let mut owner = open(directory.path(), &resources)?;
    let admin = owner.take_admin()?;

    assert!(owner.try_close().is_err());
    assert!(owner.graph.is_none());
    assert!(resources.resources.usage()?.1 > 0);
    drop(admin);

    owner.try_close()?;
    assert_eq!(resources.resources.usage()?, (0, 0));
    Ok(())
}

#[test]
fn first_graph_credit_refusal_precedes_sqlite_directory_birth()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let root = directory.path().join("objects");
    let resources = fixture(1);

    assert!(open(&root, &resources).is_err());
    assert!(!root.exists());
    assert_eq!(resources.resources.usage()?, (0, 0));
    Ok(())
}
