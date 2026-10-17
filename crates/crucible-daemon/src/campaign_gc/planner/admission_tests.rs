//! Preserves first root-inventory failures against repeated and failing visitors.
//!
//! The metadata-only fixture supplies the same finite original purpose to the
//! real GC operation context. It performs no storage I/O or native admission.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ImmutableBlobBackend, PutReceipt,
    StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::ResourceLoan;

use super::*;
use crate::campaign_gc::roots::admission_tests::Original;
use crate::{
    HotCheckpointFallbackRecord, HotCheckpointFallbackRetentionFence,
    HotCheckpointFallbackRetentionSummary, HotCheckpointFallbackSlot,
};

struct MetadataOnlyMarks {
    resources: Arc<dyn StorePhysicalQuotaGuard>,
}

impl ImmutableBlobBackend for MetadataOnlyMarks {
    fn name(&self) -> &str {
        "root-inventory-metadata-only"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Ok(self.resources.clone())
    }

    fn contains(&self, _id: ContentId) -> Result<bool, StoreError> {
        Err(StoreError::Unsupported {
            capability: "root-inventory-fixture-has-no-object-storage",
        })
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        Err(StoreError::Unsupported {
            capability: "root-inventory-fixture-has-no-object-storage",
        })
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        Err(StoreError::Unsupported {
            capability: "root-inventory-fixture-has-no-object-storage",
        })
    }
}

struct RepeatedHotInventory {
    keys: [ContentId; 2],
    calls: AtomicUsize,
    // Every borrowed fence closes before this external original purpose.
    _fence_credit: ResourceLoan,
}

impl RepeatedHotInventory {
    fn new(original: &Original) -> Self {
        let credit = original
            .resources()
            .reserve_resources(0, std::mem::size_of::<RepeatedHotFence<'_>>() as u64)
            .expect("original fence Box purpose before creation");
        Self {
            keys: [
                ContentId::for_bytes(crucible_cas::content_store::ObjectKind::Trace, 1, b"first"),
                ContentId::for_bytes(crucible_cas::content_store::ObjectKind::Trace, 1, b"later"),
            ],
            calls: AtomicUsize::new(0),
            _fence_credit: credit,
        }
    }
}

impl HotCheckpointFallbackRetentionAdmin for RepeatedHotInventory {
    fn acquire_hot_checkpoint_retention_fence(
        &self,
    ) -> Result<
        Box<dyn HotCheckpointFallbackRetentionFence + '_>,
        HotCheckpointFallbackRetentionError,
    > {
        Ok(Box::new(RepeatedHotFence { owner: self }))
    }
}

struct RepeatedHotFence<'a> {
    owner: &'a RepeatedHotInventory,
}

impl HotCheckpointFallbackRetentionFence for RepeatedHotFence<'_> {
    fn visit_fallbacks(
        &mut self,
        _visitor: &mut dyn FnMut(
            HotCheckpointFallbackSlot,
            HotCheckpointFallbackRecord,
        ) -> Result<(), HotCheckpointFallbackRetentionError>,
    ) -> Result<HotCheckpointFallbackRetentionSummary, HotCheckpointFallbackRetentionError> {
        Err(HotCheckpointFallbackRetentionError::Corrupt {
            reason: "fixture requires root visitation",
        })
    }

    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(ContentId) -> Result<(), HotCheckpointFallbackRetentionError>,
    ) -> Result<HotCheckpointFallbackRetentionSummary, HotCheckpointFallbackRetentionError> {
        // A faulty producer calls again after the first rejection, then also
        // returns its own failure. Neither may replace the first caller cause.
        for key in self.owner.keys {
            self.owner.calls.fetch_add(1, Ordering::SeqCst);
            assert!(matches!(
                visitor(key),
                Err(HotCheckpointFallbackRetentionError::Visitor)
            ));
        }
        Err(HotCheckpointFallbackRetentionError::Corrupt {
            reason: "later producer failure",
        })
    }
}

#[test]
fn repeated_hot_visitor_cannot_replace_the_first_operation_failure() {
    let original = Original::new();
    let resources = original.resources();
    let _mark_credit = resources
        .reserve_resources(0, ResourceLoan::allocation_bytes::<MetadataOnlyMarks>())
        .expect("original mark control purpose before allocation");
    let marks = Arc::new(MetadataOnlyMarks { resources });
    let inventory = RepeatedHotInventory::new(&original);
    let mut polls = 0;
    let mut boundary = || {
        polls += 1;
        match polls {
            1 => Ok(()),
            2 => Err(StoreError::InvalidComposition {
                reason: "first caller failure",
            }),
            _ => Err(StoreError::InvalidComposition {
                reason: "later caller failure",
            }),
        }
    };
    let operation = CampaignGcOperationContext::new(marks, &original.budget, &mut boundary)
        .expect("same original GC context");
    let mut roots = RootAccumulator::new(&original.budget);

    assert!(matches!(
        inventory_hot_fallbacks::<std::io::Error>(Some(&inventory), &mut roots, &operation),
        Err(CampaignGcPlanningError::Reachability(
            StoreError::InvalidComposition {
                reason: "first caller failure"
            }
        ))
    ));
    assert_eq!(inventory.calls.load(Ordering::SeqCst), 2);
    assert!(roots.unique.is_empty());
    drop(roots);
    drop(operation);
    assert_eq!(polls, 2);
}

#[test]
fn repeated_hot_visitor_preserves_actual_root_admission_before_outer_failure() {
    let original = Original::new();
    let resources = original.resources();
    let _mark_credit = resources
        .reserve_resources(0, ResourceLoan::allocation_bytes::<MetadataOnlyMarks>())
        .expect("original mark control purpose before allocation");
    let marks = Arc::new(MetadataOnlyMarks { resources });
    let inventory = RepeatedHotInventory::new(&original);
    let mut boundary = || Ok(());
    let operation = CampaignGcOperationContext::new(marks, &original.budget, &mut boundary)
        .expect("same original GC context");
    let _occupied = original
        .bank
        .reserve_resources(0, 0, 4 * 1024 * 1024 - 100_000)
        .expect("different original purpose occupies capacity before roots");
    let mut roots = RootAccumulator::new(&original.budget);

    let failure =
        inventory_hot_fallbacks::<std::io::Error>(Some(&inventory), &mut roots, &operation)
            .expect_err("first actual root grant refuses");
    let CampaignGcPlanningError::Reachability(StoreError::DecodeAdmission { source, custody }) =
        failure
    else {
        panic!("preserved original root admission category");
    };
    assert!(custody.is_some());
    assert_eq!(
        std::error::Error::source(&source)
            .expect("original typed source")
            .downcast_ref::<crucible_linux_resource::host_services::HostServiceError>(),
        Some(&crucible_linux_resource::host_services::HostServiceError::CapacityExhausted)
    );
    assert_eq!(inventory.calls.load(Ordering::SeqCst), 2);
    assert!(roots.unique.is_empty());
    drop(roots);
    drop(operation);
    drop(custody);
}
