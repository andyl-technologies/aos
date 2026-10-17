//! Closed archive metadata proofs and refusal before typed RAM dispatch.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::CampaignArchiveManifestId;
use crucible_cas::content_store::{
    BackendCapabilities, ByteRange, ImmutableBlobBackend, PutReceipt, StoreError,
    StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::DecodeBudget;

use super::*;

struct NoRamDispatch {
    child: Arc<dyn ImmutableBlobBackend>,
    ram_calls: AtomicUsize,
}

impl NoRamDispatch {
    fn repository(source: &CampaignRepository) -> (CampaignRepository, Arc<Self>) {
        let observed = Arc::new(Self {
            child: source.blobs.clone(),
            ram_calls: AtomicUsize::new(0),
        });
        let repository = CampaignRepository::new(
            observed.clone(),
            source.refs.clone(),
            crate::CampaignRamAdmission::Unavailable,
        );
        (repository, observed)
    }
}

impl ImmutableBlobBackend for NoRamDispatch {
    fn name(&self) -> &str {
        self.child.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.child.contains(id)
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.ram_calls.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::Unsupported {
            capability: "unexpected-archive-resource-recapture",
        })
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        if matches!(id.kind(), ObjectKind::RamTree | ObjectKind::RamExtent) {
            self.ram_calls.fetch_add(1, Ordering::SeqCst);
            return Err(StoreError::Unsupported {
                capability: "unexpected-archive-ram-read",
            });
        }
        self.child.read(id, range)
    }

    fn read_with_boundary(
        &self,
        _original: &DecodeBudget,
        _id: ContentId,
        _range: Option<ByteRange>,
        _boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        self.ram_calls.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::Unsupported {
            capability: "unexpected-archive-ram-dispatch",
        })
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        Err(StoreError::Unsupported {
            capability: "read-only-no-ram-archive-proof",
        })
    }
}

fn publish_declared_roots(
    source: &CampaignRepository,
    plan: &crate::CampaignArchivePlan,
    roots: Vec<ContentId>,
) -> CampaignArchiveManifestId {
    let manifest = CampaignArchiveManifest::new(crate::archive::CampaignArchiveManifestBasis {
        source_snapshot: plan.manifest().source_snapshot(),
        policy: plan.manifest().policy(),
        checkpoint_selections: plan.manifest().checkpoint_selections().to_vec(),
        retained_roots: plan.manifest().retained_roots().to_vec(),
        ram_roots: roots,
        selected_pages: plan.manifest().selected_pages().to_vec(),
        omitted_pages: plan.manifest().omitted_pages().to_vec(),
        selected: plan.selected(),
        omitted: plan.omitted(),
    })
    .expect("valid framing for deliberately inconsistent RAM declaration");
    let id = manifest.id().expect("forged manifest identity");
    source
        .put_envelope(ObjectEnvelope::for_archive_manifest(&manifest).expect("manifest envelope"))
        .expect("store manifest without certifying its closure");
    id
}

pub(super) fn assert_hidden_ram_refuses_before_dispatch(
    source: &CampaignRepository,
    plan: &crate::CampaignArchivePlan,
) {
    assert!(!plan.ram_roots().is_empty());
    let hidden = publish_declared_roots(source, plan, Vec::new());
    let (unavailable, observed) = NoRamDispatch::repository(source);

    assert!(matches!(
        unavailable.inspect_campaign_archive(plan.manifest_id()),
        Err(CampaignRepositoryError::Store(StoreError::Unsupported {
            capability: "campaign-ram-admission"
        }))
    ));
    assert_eq!(observed.ram_calls.load(Ordering::SeqCst), 0);

    assert!(matches!(
        unavailable.inspect_campaign_archive(hidden),
        Err(CampaignRepositoryError::Store(StoreError::Unsupported {
            capability: "campaign-ram-admission"
        }))
    ));
    assert_eq!(observed.ram_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn empty_archive_closure_is_authenticated_without_ram_dispatch() {
    let (source, lineage, policy) = fixture();
    let head = source
        .create("no-ram-proof", &lineage, &policy, &BTreeMap::new())
        .expect("metadata-only source");
    let plan = source
        .plan_campaign_archive(head.snapshot_id(), CampaignArchivePolicy::Mirror, [], None)
        .expect("complete metadata closure");
    assert!(plan.ram_roots().is_empty());
    source
        .stage_campaign_archive_metadata(&plan)
        .expect("archive metadata");
    let (unavailable, observed) = NoRamDispatch::repository(&source);

    let inspection = unavailable
        .inspect_campaign_archive(plan.manifest_id())
        .expect("closed no-RAM archive");
    assert!(inspection.manifest().ram_roots().is_empty());
    assert_eq!(observed.ram_calls.load(Ordering::SeqCst), 0);

    let undeclared = ContentId::for_bytes(ObjectKind::ExactManifest, 1, b"undeclared RAM root");
    let mismatch = publish_declared_roots(&source, &plan, vec![undeclared]);
    assert!(matches!(
        unavailable.inspect_campaign_archive(mismatch),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-archive-ram-root-is-not-selected"
        })
    ));
    assert_eq!(observed.ram_calls.load(Ordering::SeqCst), 0);
}
