//! Real Packed publication readback, authority refusal and terminal custody.
//!
//! The descriptor counter observes actual original reservations, not a mock
//! lookup count. The same small canonical records use the real Packed index,
//! Graph admission and physical facade; these fixtures confer no host quota.

use super::*;
use crate::content_envelope::ContentEnvelope;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{
    BlobHandle, DurabilityRequirement, ObjectKind, PutBatchReceipt, StorePhysicalQuotaGuard,
};
use crate::owned_decode::{DecodeBudget, ResourceLoan};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Account {
    bank: Arc<FixtureResourceBudget>,
    observing: AtomicBool,
    requested_fds: AtomicU64,
}

impl StorePhysicalQuotaGuard for Account {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 << 20)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let loan = self.bank.reserve(descriptors, bytes)?;
        if self.observing.load(Ordering::SeqCst) {
            self.requested_fds.fetch_add(descriptors, Ordering::SeqCst);
        }
        Ok(loan)
    }
}

struct Physical {
    closed: AtomicBool,
    bank: Arc<FixtureResourceBudget>,
}

impl StorePhysicalQuotaGuard for Physical {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 << 20)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.bank.reserve(descriptors, bytes)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::SeqCst) {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

struct Binder(Arc<Physical>);

impl crate::content_store::StorePhysicalQuotaBinder for Binder {
    fn bind(
        &self,
        _root: &std::path::Path,
        _project: u32,
        _bytes: u64,
        _inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Ok(self.0.clone())
    }
}

fn storage_cause(error: &RamStoreError) -> &StoreError {
    match error {
        RamStoreError::Store(StoreError::RamValidation { source }) => {
            storage_cause(source.storage_failure())
        }
        RamStoreError::Store(error) => error,
        _ => panic!("expected retained typed storage cause: {error:?}"),
    }
}

fn graph_at_leaf(
    root: &std::path::Path,
    physical: Arc<Physical>,
    admitted: BTreeSet<ObjectKind>,
    directory_leaf: bool,
) -> crate::content_store::StoreGraph {
    use crate::content_store::{
        StoreGraph, StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers,
        StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients,
        StoreNodeId, StoreNodeSpec, StorePhysicalQuotaBinderHandle, StorePhysicalQuotaPolicyId,
    };
    let parent = StoreNodeId::new("physical").expect("fixed parent");
    let child = StoreNodeId::new("packed").expect("fixed child");
    let policy =
        StorePhysicalQuotaPolicyId::new("model/publication-readback").expect("fixed policy");
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(
            policy.clone(),
            StorePhysicalQuotaBinderHandle::new(Binder(physical)),
        )
        .expect("one physical policy");
    StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            gc_mark_root: None,
            root: parent.clone(),
            admitted_kinds: admitted,
            nodes: std::collections::BTreeMap::from([
                (
                    parent,
                    StoreNodeSpec::PhysicalQuota {
                        child: child.clone(),
                        policy,
                        project_id: 47,
                        maximum_physical_bytes: 4 << 30,
                        maximum_inodes: 1 << 20,
                    },
                ),
                (
                    child,
                    if directory_leaf {
                        StoreNodeSpec::Directory {
                            root: root.join("objects"),
                        }
                    } else {
                        StoreNodeSpec::Packed {
                            root: root.join("objects"),
                            target_pack_bytes: 64 << 10,
                        }
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
        &StoreGraphS3Clients::new(),
        None,
    )
    .expect("real Graph and Packed fixture")
    .0
}

fn graph_at(
    root: &std::path::Path,
    physical: Arc<Physical>,
    admitted: BTreeSet<ObjectKind>,
) -> crate::content_store::StoreGraph {
    graph_at_leaf(root, physical, admitted, false)
}

struct Fixture {
    directory: tempfile::TempDir,
    bank: Arc<FixtureResourceBudget>,
    account: Arc<Account>,
    physical: Arc<Physical>,
    original: DecodeBudget,
    store: crate::ram::RamStore,
    expected: [Option<(ContentId, u64)>; MAX_PUBLICATION_BATCH_OBJECTS],
    bodies: Vec<Vec<u8>>,
    receipt: Option<PutBatchReceipt>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_directory_leaf(false)
    }

    fn with_directory_leaf(directory_leaf: bool) -> Self {
        let directory = tempfile::tempdir().expect("fixture directory");
        let bank = Arc::new(FixtureResourceBudget::new(128, 256 << 20));
        let account = Arc::new(Account {
            bank: bank.clone(),
            observing: AtomicBool::new(false),
            requested_fds: AtomicU64::new(0),
        });
        let original =
            DecodeBudget::for_store(account.clone()).expect("same finite original account");
        let physical = Arc::new(Physical {
            closed: AtomicBool::new(false),
            bank: bank.clone(),
        });
        let graph = graph_at_leaf(
            directory.path(),
            physical.clone(),
            BTreeSet::from([ObjectKind::RamExtent]),
            directory_leaf,
        );
        let store = crate::ram::RamStore::new(
            Arc::new(graph),
            DurabilityRequirement::new(1, false).expect("durable placement"),
            crate::ram::RamStoreLimits::default(),
        )
        .expect("RAM store");
        let mut expected = [None; MAX_PUBLICATION_BATCH_OBJECTS];
        let mut bodies = Vec::new();
        let mut objects = Vec::new();
        for (index, value) in [7u8, 13, 29].into_iter().enumerate() {
            let page = vec![value; 32];
            let mut body = crucible_ram::PageDigest::hash(&page)
                .expect("page digest")
                .as_bytes()
                .to_vec();
            body.extend_from_slice(&(page.len() as u32).to_be_bytes());
            body.extend_from_slice(&page);
            let envelope =
                ContentEnvelope::new(crate::ram::codec::PAGE_SCHEMA, 1, BTreeSet::new(), body)
                    .expect("canonical page envelope");
            let bytes = envelope.canonical_bytes();
            let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
            expected[index] = Some((id, bytes.len() as u64));
            bodies.push(bytes.clone());
            objects.push((id, BlobHandle::from_bytes(bytes)));
        }
        let receipt = store
            .backend
            .put_many_if_absent_with_boundary(&original, &objects, &mut || Ok(()))
            .expect("real batch publication");
        account.observing.store(true, Ordering::SeqCst);
        Self {
            directory,
            bank,
            account,
            physical,
            original,
            store,
            expected,
            bodies,
            receipt: Some(receipt),
        }
    }

    fn requests(&self) -> u64 {
        self.account.requested_fds.load(Ordering::SeqCst)
    }

    fn index(&self) -> Vec<u8> {
        std::fs::read(self.directory.path().join("objects/.packed-admin/index-v1"))
            .expect("committed index")
    }

    fn finish_receipt(&mut self) {
        drop(
            self.receipt
                .take()
                .expect("held actual receipt")
                .accept_with_boundary(&mut || Ok(()))
                .expect("explicit acceptance"),
        );
    }
}

#[test]
fn real_graph_publication_reads_three_objects_through_one_closed_packed_view() {
    let mut fixture = Fixture::new();
    let baseline = fixture.bank.usage().expect("baseline");
    let committed = fixture.index();
    {
        let mut boundary = || Ok(());
        let mut work = Work::new(
            crate::ram::RamStoreLimits::default(),
            &fixture.original,
            &mut boundary,
        )
        .expect("same Work");
        read_publication(
            &fixture.store,
            &fixture.expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect("all three authenticated bodies");
        assert_eq!(work.visits, 3);
        assert_eq!(
            work.io_bytes,
            fixture
                .bodies
                .iter()
                .map(|body| body.len() as u64)
                .sum::<u64>()
        );
        // Two retained lock files, one transient root-index file and one
        // retained pack file. Reopening the view per object would request 12.
        assert_eq!(fixture.requests(), 4);
    }
    assert_eq!(
        fixture.bank.usage().expect("closed view and Work"),
        baseline
    );
    assert_eq!(fixture.index(), committed);
    fixture.finish_receipt();
}

#[test]
fn receipt_mismatch_and_empty_batch_open_no_packed_view() {
    let mut fixture = Fixture::new();
    let baseline = fixture.bank.usage().expect("baseline");
    {
        let mut boundary = || Ok(());
        let mut work = Work::new(
            crate::ram::RamStoreLimits::default(),
            &fixture.original,
            &mut boundary,
        )
        .expect("same Work");
        let empty = [None; MAX_PUBLICATION_BATCH_OBJECTS];
        read_publication(&fixture.store, &empty, &[], &mut work).expect("empty has no effect");
        let mismatch = read_publication(
            &fixture.store,
            &empty,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("count mismatch");
        assert!(matches!(
            mismatch,
            RamStoreError::Invalid("RAM publication batch receipt count")
        ));
        let mut expected = fixture.expected;
        expected[0] = expected[1];
        let error = read_publication(
            &fixture.store,
            &expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("wrong first receipt");
        assert!(
            matches!(error, RamStoreError::Store(StoreError::Corrupt { id }) if Some(id) == expected[0].map(|entry| entry.0)),
            "{error:?}"
        );
        assert_eq!(fixture.requests(), 0);
        assert_eq!(work.visits, 0);
    }
    assert_eq!(fixture.bank.usage().expect("no leaked controls"), baseline);
    fixture.finish_receipt();
}

#[test]
fn graph_admission_refuses_first_object_before_view_creation() {
    let mut fixture = Fixture::new();
    let baseline = fixture.bank.usage().expect("baseline");
    let restricted = crate::ram::RamStore::new(
        Arc::new(graph_at(
            fixture.directory.path(),
            fixture.physical.clone(),
            BTreeSet::from([ObjectKind::RamTree]),
        )),
        DurabilityRequirement::new(1, false).expect("durable"),
        crate::ram::RamStoreLimits::default(),
    )
    .expect("restricted Graph");
    {
        let mut boundary = || Ok(());
        let mut work = Work::new(
            crate::ram::RamStoreLimits::default(),
            &fixture.original,
            &mut boundary,
        )
        .expect("same Work");
        let error = read_publication(
            &restricted,
            &fixture.expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("denied kind");
        assert!(
            matches!(
                storage_cause(&error),
                StoreError::InvalidGraph {
                    violation: crate::content_store::GraphViolation::RouteCoverage,
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(fixture.requests(), 0);
        assert_eq!(work.visits, 0);
    }
    drop(restricted);
    assert_eq!(
        fixture.bank.usage().expect("failed view controls close"),
        baseline
    );
    fixture.finish_receipt();
}

#[test]
fn physical_refusal_after_pack_descriptor_reservation_is_sticky_and_closes_view_pins() {
    let mut fixture = Fixture::new();
    let baseline = fixture.bank.usage().expect("baseline");
    let committed = fixture.index();
    {
        let mut boundary = || {
            if fixture.requests() >= 4 {
                fixture.physical.closed.store(true, Ordering::SeqCst);
            }
            Ok(())
        };
        let mut work = Work::new(
            crate::ram::RamStoreLimits::default(),
            &fixture.original,
            &mut boundary,
        )
        .expect("same Work");
        let first = read_publication(
            &fixture.store,
            &fixture.expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("physical refusal after actual pack descriptor reservation");
        let requested = fixture.requests();
        let retry = read_publication(
            &fixture.store,
            &fixture.expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("same Work remains failed");
        assert!(
            matches!(storage_cause(&first), StoreError::Unauthorized),
            "{first:?}"
        );
        assert!(
            matches!(storage_cause(&retry), StoreError::Unauthorized),
            "{retry:?}"
        );
        let mut bad_expected = fixture.expected;
        bad_expected[0] = bad_expected[1];
        let malformed_retry = read_publication(
            &fixture.store,
            &bad_expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("new malformed input cannot replace the retained refusal");
        assert!(
            matches!(storage_cause(&malformed_retry), StoreError::Unauthorized),
            "{malformed_retry:?}"
        );
        drop(malformed_retry);
        assert_eq!(requested, 4);
        assert_eq!(fixture.requests(), requested);
        drop(first);
        drop(retry);
    }
    assert_eq!(
        fixture
            .bank
            .usage()
            .expect("pins close before original credit"),
        baseline
    );
    assert_eq!(fixture.index(), committed);
    fixture.physical.closed.store(false, Ordering::SeqCst);
    fixture.finish_receipt();
}

#[test]
fn corrupted_second_body_preserves_real_content_id_cause_and_sticky_failure() {
    let mut fixture = Fixture::new();
    let baseline = fixture.bank.usage().expect("baseline");
    let committed = fixture.index();
    let pack = std::fs::read_dir(fixture.directory.path().join("objects/packs"))
        .expect("packs directory")
        .map(|entry| entry.expect("pack entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "pack")
        })
        .expect("actual pack");
    let mut bytes = std::fs::read(&pack).expect("bounded fixture pack");
    let body = &fixture.bodies[1];
    let position = bytes
        .windows(body.len())
        .position(|bytes| bytes == body)
        .expect("exact second canonical body");
    bytes[position + body.len() - 1] ^= 1;
    std::fs::write(&pack, bytes).expect("actual on-disk corruption");
    {
        let mut boundary = || Ok(());
        let mut work = Work::new(
            crate::ram::RamStoreLimits::default(),
            &fixture.original,
            &mut boundary,
        )
        .expect("same Work");
        let error = read_publication(
            &fixture.store,
            &fixture.expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("full ContentId authentication");
        assert!(
            matches!(storage_cause(&error), StoreError::Corrupt { id } if *id == fixture.expected[1].expect("second ID").0),
            "{error:?}"
        );
        let requests = fixture.requests();
        let retry = read_publication(
            &fixture.store,
            &fixture.expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("sticky same Work");
        assert_eq!(fixture.requests(), requests);
        drop(error);
        drop(retry);
    }
    assert_eq!(
        fixture
            .bank
            .usage()
            .expect("failure ownership drops before credit"),
        baseline
    );
    assert_eq!(fixture.index(), committed);
    fixture.finish_receipt();
}

#[test]
fn original_expiry_after_view_close_refuses_publication_acceptance() {
    use crucible_linux_resource::host_supervision::{
        HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets, HostOperationClass,
        HostOperationSupervisor, HostSupervisionError,
    };
    use std::time::Duration;

    let mut fixture = Fixture::new();
    let baseline = fixture.bank.usage().expect("baseline");
    let committed = fixture.index();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets {
            classes: [HostOperationBudget::finite(Duration::from_secs(300));
                HOST_OPERATION_CLASS_COUNT],
        },
        Some(Duration::from_secs(300)),
    )
    .expect("unchanged finite original");
    let operation = supervisor
        .begin(HostOperationClass::Transfer)
        .expect("original operation");
    let operation_id = operation.status().expect("original identity").operation_id;
    let mut observed = false;
    {
        let mut boundary = || {
            if fixture.requests() >= 4
                && fixture.bank.usage().expect("current descriptors").0 == baseline.0
            {
                supervisor
                    .amend_outer_cap(0, Some(Duration::from_nanos(1)))
                    .expect("test expiry at closed-view cut");
                observed = true;
            }
            operation.wait_slice().map(|_| ()).map_err(|source| {
                RamStoreError::Store(StoreError::Supervision {
                    source: Box::new(source),
                })
            })
        };
        let mut work = Work::new(
            crate::ram::RamStoreLimits::default(),
            &fixture.original,
            &mut boundary,
        )
        .expect("same Work");
        let error = read_publication(
            &fixture.store,
            &fixture.expected,
            fixture.receipt.as_ref().expect("receipt"),
            &mut work,
        )
        .expect_err("final original cut");
        let RamStoreError::Store(StoreError::RamReadBoundary { source }) = &error else {
            panic!("{error:?}")
        };
        assert!(
            matches!(source.first_boundary(), Some(RamStoreError::Store(StoreError::Supervision { source })) if matches!(source.downcast_ref::<HostSupervisionError>(), Some(HostSupervisionError::DeadlineExpired { operation_id: actual, class: HostOperationClass::Transfer }) if *actual == operation_id)),
            "{error:?}"
        );
        assert_eq!(work.visits, 3);
        drop(error);
    }
    assert!(
        observed,
        "all real view descriptors closed before the final cut"
    );
    assert_eq!(fixture.bank.usage().expect("closed outcome"), baseline);
    assert_eq!(fixture.index(), committed);
    fixture.finish_receipt();
}

#[test]
fn directory_fallback_retains_the_actual_outer_graph_admission() {
    let mut fixture = Fixture::with_directory_leaf(true);
    let baseline = fixture.bank.usage().expect("Directory receipt baseline");
    let restricted = crate::ram::RamStore::new(
        Arc::new(graph_at_leaf(
            fixture.directory.path(),
            fixture.physical.clone(),
            BTreeSet::from([ObjectKind::RamTree]),
            true,
        )),
        DurabilityRequirement::new(1, false).expect("durable"),
        crate::ram::RamStoreLimits::default(),
    )
    .expect("Directory-backed restricted Graph");
    {
        let mut boundary = || Ok(());
        let mut work = Work::new(
            crate::ram::RamStoreLimits::default(),
            &fixture.original,
            &mut boundary,
        )
        .expect("same Work");
        let error = read_publication(
            &restricted,
            &fixture.expected,
            fixture.receipt.as_ref().expect("actual Directory receipt"),
            &mut work,
        )
        .expect_err("outer Graph cannot be replaced by its Directory child");
        assert!(
            matches!(
                storage_cause(&error),
                StoreError::InvalidGraph {
                    violation: crate::content_store::GraphViolation::RouteCoverage,
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(fixture.requests(), 0);
        assert_eq!(work.visits, 0);
    }
    drop(restricted);
    assert_eq!(
        fixture.bank.usage().expect("refusal controls close"),
        baseline
    );
    // A separate ordinary original Work can still read all actual published
    // Directory objects through its admitted facade; no optimized view used.
    {
        let mut boundary = || Ok(());
        let mut work = Work::new(
            crate::ram::RamStoreLimits::default(),
            &fixture.original,
            &mut boundary,
        )
        .expect("independent Work, same authority");
        read_publication(
            &fixture.store,
            &fixture.expected,
            fixture.receipt.as_ref().expect("Directory receipt"),
            &mut work,
        )
        .expect("ordinary fallback retains real bodies");
        assert_eq!(work.visits, 3);
    }
    assert_eq!(
        fixture.bank.usage().expect("ordinary sources close"),
        baseline
    );
    fixture.finish_receipt();
}
