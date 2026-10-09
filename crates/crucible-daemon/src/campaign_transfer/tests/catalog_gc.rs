//! Durable partial Catalog transfer, real namespace exclusion and GC restart.

mod fixture;

use std::fs::{self, File};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crucible_cas::content_envelope::{ContentChild, ContentEnvelope};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ObjectKind, PutReceipt, StoreError,
    StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::DecodeBudget;
use crucible_cas::ram::{RamStore, RamStoreError, RamStoreLimits};
use crucible_linux_resource::host_supervision::{
    HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets, HostOperationClass,
    HostOperationGuard, HostOperationSupervisor,
};
use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};
use rustix::fs::{FlockOperation, flock};

use super::*;
use crate::{
    CampaignGcMaintenance, CampaignGcOperationContext, DirectoryCampaignGcJournal,
    MemoryAssignmentLedger, apply_single_host_campaign_gc_with_transfers,
    plan_single_host_campaign_gc_with_transfers,
};
use fixture::{OriginalNamespace, RepositoryNamespace};

#[derive(Clone, Copy)]
enum PartialStage {
    MissingChild,
    CorruptChild,
    SurvivingCatalog,
}

/// Names authenticated source coordinates, rather than any newly visible tree.
struct Observation {
    destination: PathBuf,
    original: DecodeBudget,
    root: ContentId,
    parent: ContentId,
    left: ContentId,
    right: ContentId,
    page: ContentId,
    stage: PartialStage,
    armed: AtomicBool,
    reached: AtomicBool,
}

struct ObservedSource {
    child: Arc<dyn ImmutableBlobBackend>,
    observation: Arc<Observation>,
}

impl ImmutableBlobBackend for ObservedSource {
    fn name(&self) -> &str {
        self.child.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.child.metadata_resources()
    }

    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<crucible_cas::content_store::CheckedPublicationMetadata, StoreError> {
        self.child.checked_publication_metadata(kind)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.child.read(id, range)
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        let observation = &self.observation;
        let expected = match observation.stage {
            PartialStage::CorruptChild => observation.right,
            PartialStage::MissingChild | PartialStage::SurvivingCatalog => observation.left,
        };
        if observation.armed.load(Ordering::Acquire) && id == expected {
            let _paths = observation
                .original
                .reserve_scratch_bytes(
                    12 * (observation.destination.as_os_str().len() as u64 + 256),
                )
                .expect("original finite observation paths");
            // Source validation can read the same coordinate before copying.
            // Only a child lookup with its destination parent already stored
            // establishes the receiver's completed parent publication seam.
            if object_path(&observation.destination, observation.parent).exists() {
                assert!(!object_path(&observation.destination, observation.right).exists());
                assert!(!object_path(&observation.destination, observation.root).exists());
                if matches!(observation.stage, PartialStage::CorruptChild) {
                    assert!(object_path(&observation.destination, observation.left).exists());
                    assert!(object_path(&observation.destination, observation.page).exists());
                }
                observation.reached.store(true, Ordering::Release);
            }
        }
        // The default bounded method executes this checked method once. Direct
        // forwarding of an opaque bounded request would bypass the observation.
        self.child.read_with_boundary(original, id, range, boundary)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.child.put_if_absent(id, source)
    }
}

fn object_path(root: &Path, id: ContentId) -> PathBuf {
    id.with_encoded_text(|encoded| {
        let encoded = std::str::from_utf8(encoded).expect("canonical ASCII identity");
        let digest = encoded.rsplit_once('.').expect("content digest").1;
        root.join("objects").join(&digest[..2]).join(encoded)
    })
}

fn envelope(namespace: &RepositoryNamespace, id: ContentId) -> ContentEnvelope {
    let _scope = namespace.original.enter();
    let handle = namespace
        .graph
        .read_with_boundary(&namespace.original, id, None, &mut || Ok(()))
        .expect("actual authenticated source handle");
    let bytes = handle
        .read_all_with_boundary(&namespace.original, 4 * 1024 * 1024, &mut || Ok(()))
        .expect("actual authenticated source bytes");
    assert!(id.authenticates(&bytes));
    ContentEnvelope::from_canonical_bytes(&bytes).expect("canonical source envelope")
}

fn assert_direct_journal(journal: &DirectoryCampaignTransferJournal, plan: &CampaignArchivePlan) {
    let expected = plan.transfer_objects().into_iter().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    journal
        .acquire_campaign_transfer_retention_fence()
        .expect("real durable journal fence")
        .visit_roots(&mut |root| {
            assert!(actual.insert((root.id(), root.logical_length())));
            assert!(!matches!(
                root.id().kind(),
                ObjectKind::RamTree | ObjectKind::RamExtent
            ));
            Ok(())
        })
        .expect("actual direct journal inventory");
    assert_eq!(
        actual, expected,
        "no flattened RAM descendants or fabricated roots"
    );
}

fn assert_no_destination_refs(namespace: &RepositoryNamespace) {
    let mut count = 0;
    namespace
        .refs_admin
        .acquire_ref_inventory_fence()
        .expect("actual post-fence ref inventory")
        .visit_refs(&mut |_| {
            count += 1;
            Ok(())
        })
        .expect("actual destination ref inventory");
    assert_eq!(count, 0, "no partial root claim or archive ref");
}

fn has_cancellation(error: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(CampaignArchiveTransferError::Repository(source)) = error.downcast_ref() {
        return has_cancellation(source);
    }
    if let Some(CampaignRepositoryError::Ram(source)) = error.downcast_ref() {
        return has_cancellation(source);
    }
    match error.downcast_ref::<RamStoreError>() {
        Some(RamStoreError::Canceled) => true,
        Some(RamStoreError::Boundary(cause)) => cause
            .first_boundary()
            .is_some_and(|first| has_cancellation(first)),
        _ => error.source().is_some_and(has_cancellation),
    }
}

fn has_corruption(error: &(dyn std::error::Error + 'static), id: ContentId) -> bool {
    // Transparent Error::source forwarding can skip the inline enum itself.
    // Inspect the actual owning variants before following external IO causes.
    if let Some(CampaignArchiveTransferError::Repository(source)) = error.downcast_ref() {
        return has_corruption(source, id);
    }
    if let Some(repository) = error.downcast_ref::<CampaignRepositoryError>() {
        match repository {
            CampaignRepositoryError::Ram(source) => return has_corruption(source, id),
            CampaignRepositoryError::Store(source) => return has_corruption(source, id),
            _ => {}
        }
    }
    if let Some(ram) = error.downcast_ref::<RamStoreError>() {
        match ram {
            RamStoreError::Store(source) => return has_corruption(source, id),
            RamStoreError::Boundary(cause) => return has_corruption(cause.storage_failure(), id),
            _ => {}
        }
    }
    if matches!(error.downcast_ref::<StoreError>(), Some(StoreError::Corrupt { id: actual }) if *actual == id)
    {
        return true;
    }
    error
        .source()
        .is_some_and(|source| has_corruption(source, id))
}

fn run_partial_transfer(stage: PartialStage) {
    let temporary = tempfile::tempdir().expect("partial archive storage");
    let source_root = temporary.path().join("source");
    let destination_root = temporary.path().join("destination");
    let source_refs = temporary.path().join("source-refs");
    let destination_refs = temporary.path().join("destination-refs");
    let source_owner = OriginalNamespace::new(&source_root);
    let destination_owner = OriginalNamespace::new(&destination_root);
    {
        let source = source_owner.open(&source_refs);
        let destination = destination_owner.open(&destination_refs);
        // This external purpose survives all test-only observer aliases and
        // journal/path/ID collector storage. It supplies no native entitlement.
        let _fixture_resources = source
            .original
            .reserve_scratch_bytes(
                2 * (std::mem::size_of::<Observation>()
                    + std::mem::size_of::<ObservedSource>()
                    + 4 * std::mem::size_of::<usize>()) as u64
                    + 8 * temporary.path().as_os_str().len() as u64
                    + 65_536,
            )
            .expect("finite observer and journal fixture purpose before construction");
        let _scope = source.original.enter();
        let metadata = plan_in_repository(&source.repository);
        let ram = RamStore::new(
            source.graph.clone(),
            DurabilityRequirement::new(1, false).expect("RAM durability"),
            RamStoreLimits::default(),
        )
        .expect("source RAM store");
        let retention = source
            .repository
            .ram_retention_authority()
            .acquire()
            .expect("real source publication fence");
        let capture = source.original.child().expect("original source capture");
        let root = ram
            .capture(
                Topology::new(
                    vec![
                        RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 8192)
                            .expect("two-page region"),
                    ],
                    Limits::default(),
                )
                .expect("finite topology"),
                Scope::Exact,
                &mut |_, index, output| {
                    output.fill((index + 1) as u8);
                    Ok(())
                },
                &retention,
                &capture,
                &mut || Ok(()),
            )
            .expect("actual nonzero RAM tree");
        drop(capture);
        drop(retention);
        let ram_root = root.object_id();
        let parent = envelope(&source, ram_root)
            .children()
            .iter()
            .next()
            .expect("one region Catalog")
            .id();
        let parent_envelope = envelope(&source, parent);
        let mut children = parent_envelope.children().iter();
        let left_child = children.next().expect("left Catalog");
        let right_child = children.next().expect("right Catalog");
        assert_eq!(left_child.role(), "left");
        assert_eq!(right_child.role(), "right");
        let left = left_child.id();
        let right = right_child.id();
        assert!(children.next().is_none());
        let leaf = envelope(&source, left);
        let page_child = leaf.children().iter().next().expect("page zero");
        assert_eq!(page_child.role(), "page");
        let page = page_child.id();
        assert_eq!(page.kind(), ObjectKind::RamExtent);
        let world = ContentEnvelope::new(
            "crucible.executor.exact-checkpoint-root",
            6,
            BTreeSet::from(
                [ContentChild::new("ram-root-00000000", ram_root).expect("RAM binding")],
            ),
            b"storage fixture; no execution authority".to_vec(),
        )
        .expect("world binding");
        let world_id = world.content_id(ObjectKind::ExactManifest);
        source
            .graph
            .put_if_absent(world_id, &BlobHandle::from_bytes(world.canonical_bytes()))
            .expect("actual world object");

        let observation = Arc::new(Observation {
            destination: destination_root.clone(),
            original: destination.original.clone(),
            root: ram_root,
            parent,
            left,
            right,
            page,
            stage,
            armed: AtomicBool::new(false),
            reached: AtomicBool::new(false),
        });
        let observed = Arc::new(ObservedSource {
            child: source.graph.clone(),
            observation: observation.clone(),
        });
        let repository = CampaignRepository::new(
            observed,
            source.refs.clone(),
            crucible_campaign::CampaignRamAdmission::Available(source.original.clone()),
        );
        let plan = repository
            .plan_campaign_archive(
                metadata.manifest().source_snapshot(),
                CampaignArchivePolicy::Mirror,
                [world_id],
                None,
            )
            .expect("real compact archive plan");
        assert_eq!(plan.ram_roots(), &[ram_root]);
        assert!(plan.selected().iter().all(|entry| !matches!(
            entry.id().kind(),
            ObjectKind::RamTree | ObjectKind::RamExtent
        )));
        let source_journal_root = temporary.path().join("source-journal");
        let destination_journal_root = temporary.path().join("destination-journal");
        let mut source_journal = DirectoryCampaignTransferJournal::open(&source_journal_root)
            .expect("real source journal");
        let mut destination_journal =
            DirectoryCampaignTransferJournal::open(&destination_journal_root)
                .expect("real destination journal");
        let durability = DurabilityRequirement::new(1, false).expect("durability");
        let operation = CampaignTransferOperationId::for_archive(
            plan.manifest_id(),
            "destination",
            "partial",
            None,
            durability,
        )
        .expect("fixed archive operation");
        let source_journal_observer = source_journal.clone();
        let destination_journal_observer = destination_journal.clone();
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(Duration::from_secs(300));
                    HOST_OPERATION_CLASS_COUNT],
            },
            Some(Duration::from_secs(300)),
        )
        .expect("existing finite operation ceiling");
        let original = supervisor
            .begin(HostOperationClass::Transfer)
            .expect("one original boundary");
        observation.armed.store(true, Ordering::Release);
        let mut stopped = false;
        let result = transfer_campaign_archive_durably_with_boundary(
            &mut CampaignArchiveTransferEndpoint::new(
                &repository,
                &mut source_journal,
                "source",
                true,
            ),
            &mut CampaignArchiveTransferEndpoint::new(
                &destination.repository,
                &mut destination_journal,
                "destination",
                true,
            ),
            &plan,
            "partial",
            None,
            durability,
            &mut || {
                original
                    .wait_slice()
                    .expect("same original transfer deadline");
                if observation.reached.load(Ordering::Acquire) {
                    let _descriptor = destination
                        .graph
                        .metadata_resources()
                        .expect("same destination resources")
                        .reserve_resources(1, 0)
                        .expect("probe descriptor before open");
                    let file = File::open(destination_refs.join(".ref-admin/publication-lock"))
                        .expect("actual publication lock");
                    assert_eq!(
                        flock(&file, FlockOperation::NonBlockingLockExclusive),
                        Err(rustix::io::Errno::WOULDBLOCK)
                    );
                    assert!(
                        source_journal_observer
                            .contains(operation)
                            .expect("source ownership")
                    );
                    assert!(
                        destination_journal_observer
                            .contains(operation)
                            .expect("destination ownership")
                    );
                    stopped = true;
                    return Err(RamStoreError::Canceled);
                }
                Ok(())
            },
        );
        assert!(
            stopped && observation.reached.load(Ordering::Acquire),
            "exact child stage reached"
        );
        assert!(has_cancellation(
            &result.expect_err("no closure/durability receipt on cancellation")
        ));
        observation.armed.store(false, Ordering::Release);
        assert_no_destination_refs(&destination);
        assert_direct_journal(&source_journal, &plan);
        assert_direct_journal(&destination_journal, &plan);
        let post_probe_descriptor = destination
            .graph
            .metadata_resources()
            .expect("same original post-fence resources")
            .reserve_resources(1, 0)
            .expect("post-fence descriptor before open");
        let file = File::open(destination_refs.join(".ref-admin/publication-lock"))
            .expect("post-fence publication lock");
        flock(&file, FlockOperation::NonBlockingLockExclusive).expect("transfer exclusion closed");
        drop(file);
        drop(post_probe_descriptor);
        // Journal clones own the same writer lock. All observation aliases
        // close before the restart path opens a fresh durable journal owner.
        drop(source_journal_observer);
        drop(destination_journal_observer);

        RestartCase {
            stage,
            temporary: &temporary,
            destination_owner: &destination_owner,
            source: &repository,
            destination,
            plan: &plan,
            operation,
            durability,
            source_journal,
            destination_journal,
            source_journal_root: &source_journal_root,
            destination_journal_root: &destination_journal_root,
            parent,
            page,
            source_original: &source.original,
            original: &original,
        }
        .finish();
        drop(root);
    }
    source_owner.assert_idle();
    destination_owner.assert_idle();
}

struct RestartCase<'a> {
    stage: PartialStage,
    temporary: &'a tempfile::TempDir,
    destination_owner: &'a OriginalNamespace,
    source: &'a CampaignRepository,
    destination: RepositoryNamespace,
    plan: &'a CampaignArchivePlan,
    operation: CampaignTransferOperationId,
    durability: DurabilityRequirement,
    source_journal: DirectoryCampaignTransferJournal,
    destination_journal: DirectoryCampaignTransferJournal,
    source_journal_root: &'a Path,
    destination_journal_root: &'a Path,
    parent: ContentId,
    page: ContentId,
    source_original: &'a DecodeBudget,
    original: &'a HostOperationGuard,
}

impl RestartCase<'_> {
    fn finish(self) {
        let destination_root = self.temporary.path().join("destination");
        let refs_root = self.temporary.path().join("destination-refs");
        let saved_original = self.destination.original.clone();
        let _scope = saved_original.enter();
        let _paths = saved_original
            .reserve_scratch_bytes(16 * (self.temporary.path().as_os_str().len() as u64 + 256))
            .expect("same original restart and fault paths");
        let target = match self.stage {
            PartialStage::CorruptChild => self.page,
            PartialStage::MissingChild | PartialStage::SurvivingCatalog => self.parent,
        };
        let target_path = object_path(&destination_root, target);
        let _fault = saved_original
            .reserve_scratch_bytes(
                2 * fs::metadata(&target_path)
                    .expect("reached actual target")
                    .len(),
            )
            .expect("fault buffers before allocation");
        let _fault_descriptor = self
            .destination
            .graph
            .metadata_resources()
            .expect("same original fault resources")
            .reserve_resources(1, 0)
            .expect("fault descriptor before open");
        let saved_bytes = fs::read(&target_path).expect("save actual target bytes");
        if matches!(
            self.stage,
            PartialStage::CorruptChild | PartialStage::SurvivingCatalog
        ) {
            let mut corrupt = saved_bytes.clone();
            corrupt[0] ^= 0xff;
            fs::write(&target_path, &corrupt)
                .expect("in-place same-length fault after fence closes");
            let result = self
                .destination
                .graph
                .read_with_boundary(&saved_original, target, None, &mut || Ok(()))
                .and_then(|handle| {
                    handle.read_all_with_boundary(&saved_original, 4 * 1024 * 1024, &mut || Ok(()))
                });
            let failure = result.expect_err("actual target authentication rejects the fault");
            assert!(
                has_corruption(&failure, target),
                "exact target corruption, not unrelated refusal: {failure:?}"
            );
        }

        if !matches!(self.stage, PartialStage::SurvivingCatalog) {
            let marks = self
                .destination
                .admin
                .gc_mark_backend("primary", "catalog-orphan-integration")
                .expect("same original real Directory mark namespace");
            let mut check = || {
                self.original
                    .wait_slice()
                    .map(|_| ())
                    .map_err(|source| StoreError::Supervision {
                        source: Box::new(source),
                    })
            };
            let operation = CampaignGcOperationContext::new(marks, &saved_original, &mut check)
                .expect("same original operation for real GC");
            let maintenance = CampaignGcMaintenance::new(&self.destination.admin, &operation);
            let mut ledger = MemoryAssignmentLedger::default();
            let prepared = plan_single_host_campaign_gc_with_transfers(
                &self.destination.repository,
                self.destination.refs_admin.as_ref(),
                &mut ledger,
                None,
                &self.destination_journal,
                None,
                maintenance,
            )
            .expect("orphan links are not traversed by actual GC");
            assert!(
                prepared
                    .candidates()
                    .iter()
                    .any(|candidate| candidate.id() == self.parent)
            );
            if matches!(self.stage, PartialStage::CorruptChild) {
                assert!(
                    prepared
                        .candidates()
                        .iter()
                        .any(|candidate| candidate.id() == self.page)
                );
            }
            let (mut journal, _) = DirectoryCampaignGcJournal::create(
                self.temporary.path().join("actual-gc-journal"),
                &prepared,
                &operation,
            )
            .expect("durable actual GC plan");
            let report = apply_single_host_campaign_gc_with_transfers(
                &mut journal,
                &self.destination.repository,
                self.destination.refs_admin.as_ref(),
                &mut ledger,
                None,
                &self.destination_journal,
                None,
                maintenance,
            )
            .expect("real unrooted Catalog deletion despite absent/corrupt child");
            assert_eq!(report.status(), crate::CampaignGcApplyStatus::Applied);
            assert!(!object_path(&destination_root, self.parent).exists());
        }
        drop(self.destination);
        drop(self.source_journal);
        drop(self.destination_journal);

        let restarted = self.destination_owner.reopen(&refs_root, &saved_original);
        let mut source_journal = DirectoryCampaignTransferJournal::open(self.source_journal_root)
            .expect("actual reopened source journal");
        let mut destination_journal =
            DirectoryCampaignTransferJournal::open(self.destination_journal_root)
                .expect("actual reopened destination journal");
        assert_direct_journal(&source_journal, self.plan);
        assert_direct_journal(&destination_journal, self.plan);
        assert_no_destination_refs(&restarted);
        let mut retry = || {
            transfer_campaign_archive_durably_with_boundary(
                &mut CampaignArchiveTransferEndpoint::new(
                    self.source,
                    &mut source_journal,
                    "source",
                    true,
                ),
                &mut CampaignArchiveTransferEndpoint::new(
                    &restarted.repository,
                    &mut destination_journal,
                    "destination",
                    true,
                ),
                self.plan,
                "partial",
                None,
                self.durability,
                &mut || {
                    self.original
                        .wait_slice()
                        .expect("same original restart boundary");
                    Ok(())
                },
            )
        };
        if matches!(self.stage, PartialStage::SurvivingCatalog) {
            let failure =
                retry().expect_err("surviving Catalog is authenticated, never trusted by name");
            assert!(
                has_corruption(&failure, self.parent),
                "same Catalog corruption remains primary: {failure:?}"
            );
            assert!(!object_path(&destination_root, self.plan.ram_roots()[0]).exists());
            fs::write(&target_path, &saved_bytes).expect("restore exact original Catalog bytes");
        }
        let receipt =
            retry().expect("restart authenticates surviving or recopies collected Catalog");
        assert_eq!(receipt.operation(), self.operation);
        assert!(object_path(&destination_root, self.parent).exists());
        let destination_bytes =
            fs::read(object_path(&destination_root, self.parent)).expect("actual Catalog bytes");
        if target == self.parent {
            assert_eq!(destination_bytes.as_slice(), saved_bytes.as_slice());
        } else {
            let source_bytes = self
                .source
                .blob_backend()
                .read_with_boundary(self.source_original, self.parent, None, &mut || Ok(()))
                .expect("source Catalog")
                .read_all_with_boundary(self.source_original, 4 * 1024 * 1024, &mut || Ok(()))
                .expect("complete source Catalog");
            assert_eq!(destination_bytes.as_slice(), &*source_bytes);
        }
        assert_eq!(
            restarted
                .repository
                .inspect_campaign_archive_ref_with_boundary("partial", &mut || {
                    self.original
                        .wait_slice()
                        .expect("same original final authentication boundary");
                    Ok(())
                })
                .expect("complete authenticated archive after restart")
                .manifest_id(),
            self.plan.manifest_id()
        );
        assert!(
            !source_journal
                .contains(self.operation)
                .expect("source ownership retired")
        );
        assert!(
            !destination_journal
                .contains(self.operation)
                .expect("destination ownership retired")
        );
    }
}

#[test]
fn catalog_with_missing_child_is_collected_then_recopied_after_restart() {
    run_partial_transfer(PartialStage::MissingChild);
}

#[test]
fn catalog_with_corrupt_child_is_collected_without_following_orphan_links() {
    run_partial_transfer(PartialStage::CorruptChild);
}

#[test]
fn surviving_catalog_is_authenticated_before_restart_completion() {
    run_partial_transfer(PartialStage::SurvivingCatalog);
}
