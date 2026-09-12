//! Physical-quota revalidation at the global campaign-GC boundary.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_campaign::CampaignRepository;
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryRefBackend, ImmutableBlobBackend, ObjectKind, StoreError,
    StoreGraph, StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers,
    StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreNodeId,
    StoreNodeSpec, StorePhysicalQuotaBinder, StorePhysicalQuotaGuard, StorePhysicalQuotaPolicyId,
};

use super::*;

struct ToggleQuotaGuard {
    allowed: AtomicBool,
}

impl ToggleQuotaGuard {
    fn new() -> Self {
        Self {
            allowed: AtomicBool::new(true),
        }
    }

    fn set_allowed(&self, allowed: bool) {
        self.allowed.store(allowed, Ordering::Release);
    }
}

impl StorePhysicalQuotaGuard for ToggleQuotaGuard {
    fn verify(&self) -> Result<(), StoreError> {
        if self.allowed.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(StoreError::Quota)
        }
    }
}

struct ToggleQuotaBinder {
    guard: Arc<ToggleQuotaGuard>,
}

impl StorePhysicalQuotaBinder for ToggleQuotaBinder {
    fn bind(
        &self,
        _root: &Path,
        _project_id: u32,
        _maximum_physical_bytes: u64,
        _maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Ok(self.guard.clone())
    }
}

#[test]
fn physical_quota_drift_stops_global_gc_before_deletion() {
    let temp = tempfile::TempDir::new().expect("temporary physical-quota GC root");
    let physical = StoreNodeId::new("quota-primary").expect("physical-quota node");
    let directory = StoreNodeId::new("directory-child").expect("directory child");
    let policy = StorePhysicalQuotaPolicyId::new("host/ext4/gc").expect("quota policy");
    let guard = Arc::new(ToggleQuotaGuard::new());
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(
            policy.clone(),
            Arc::new(ToggleQuotaBinder {
                guard: guard.clone(),
            }),
        )
        .expect("quota binder");
    let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            root: physical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: directory.clone(),
                        policy,
                        project_id: 47,
                        maximum_physical_bytes: 128 * 1024,
                        maximum_inodes: 64,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("objects"),
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
        &StoreGraphS3Clients::new(),
    )
    .expect("physical-quota graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(temp.path().join("refs")));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());

    let orphan_bytes = b"physical quota orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store orphan");
    let mut ledger = MemoryAssignmentLedger::default();
    let prepared = super::super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        graph.as_ref(),
        None,
        &admin,
    )
    .expect("plan physical-quota GC");
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &prepared)
            .expect("create physical-quota GC journal");

    guard.set_allowed(false);
    let quota_error = super::super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        graph.as_ref(),
        None,
        &admin,
    )
    .expect_err("physical-quota drift must stop GC");
    assert!(
        matches!(
            &quota_error,
            CampaignGcApplyError::Blob { backend, source: StoreError::Quota }
                if backend == "quota-primary"
        ),
        "unexpected quota error: {quota_error:?}"
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);

    guard.set_allowed(true);
    assert!(graph.contains(orphan).expect("orphan retained"));
    let report = super::super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        graph.as_ref(),
        None,
        &admin,
    )
    .expect("apply physical-quota GC after restoring quota");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert!(!graph.contains(orphan).expect("orphan deleted"));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}
