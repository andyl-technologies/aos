//! Original-authority dispatch and actual leaf custody through graph adapters.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::DecodeBudget;
use std::sync::atomic::{AtomicBool, AtomicUsize};

struct Quota {
    budget: FixtureResourceBudget,
    revoked: AtomicBool,
}

impl Quota {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            budget: FixtureResourceBudget::new(128, 256 << 20),
            revoked: AtomicBool::new(false),
        })
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(256 << 20)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        self.budget.reserve(descriptors, bytes)
    }
}

struct ObservedLeaf {
    child: Arc<dyn ImmutableBlobBackend>,
    expected: DecodeBudget,
    reads: AtomicUsize,
    metadata_queries: AtomicUsize,
    puts: AtomicUsize,
    receipt_address: AtomicUsize,
}

impl ImmutableBlobBackend for ObservedLeaf {
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
    ) -> Result<CheckedPublicationMetadata, StoreError> {
        self.metadata_queries.fetch_add(1, Ordering::SeqCst);
        self.child.checked_publication_metadata(kind)
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        assert!(original.same_account(&self.expected));
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.child.read_with_boundary(original, id, range, boundary)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        assert!(original.same_account(&self.expected));
        self.puts.fetch_add(1, Ordering::SeqCst);
        let receipt = self
            .child
            .put_many_if_absent_with_boundary(original, objects, boundary)?;
        self.receipt_address
            .store(receipt.as_ptr() as usize, Ordering::SeqCst);
        Ok(receipt)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.child.contains(id)
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        panic!("checked adapter used an ordinary lookup")
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        panic!("checked adapter used an ordinary put")
    }
}

struct OpaqueLeaf(Arc<dyn ImmutableBlobBackend>);

impl ImmutableBlobBackend for OpaqueLeaf {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.0.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.0.metadata_resources()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.0.contains(id)
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        panic!("opaque checked dispatch fell back to ordinary lookup")
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        panic!("opaque checked dispatch fell back to ordinary put")
    }
}

fn observed_leaf(
    path: &std::path::Path,
    quota: &Arc<Quota>,
    original: &DecodeBudget,
) -> Result<Arc<ObservedLeaf>, StoreError> {
    let child = DirectoryBlobBackend::new_with_physical_quota("directory", path, quota.clone())?;
    Ok(Arc::new(ObservedLeaf {
        child,
        expected: original.clone(),
        reads: AtomicUsize::new(0),
        metadata_queries: AtomicUsize::new(0),
        puts: AtomicUsize::new(0),
        receipt_address: AtomicUsize::new(0),
    }))
}

fn objects() -> Vec<(ContentId, BlobHandle)> {
    [
        ObjectKind::RamExtent,
        ObjectKind::RamTree,
        ObjectKind::ExactManifest,
    ]
    .into_iter()
    .map(|kind| {
        let bytes = b"checked routed payload";
        (
            ContentId::for_bytes(kind, 1, bytes),
            BlobHandle::from_bytes(bytes),
        )
    })
    .collect()
}

fn assert_metrics_oversized_batch_has_no_effects(count: usize) -> Result<(), StoreError> {
    let directory = tempfile::tempdir().unwrap();
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let leaf = observed_leaf(directory.path(), &quota, &original)?;
    let (metrics, state) = MetricsStore::new("bounded", leaf.clone());
    let bytes = b"oversized batch must not reach its child";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    let source = BlobHandle::from_bytes(bytes);
    let input = vec![(id, source); count];
    let mut callbacks = 0;

    let error = metrics
        .put_many_if_absent_with_boundary(&original, &input, &mut || {
            callbacks += 1;
            Ok(())
        })
        .err()
        .unwrap();

    assert!(matches!(error, StoreError::Quota));
    assert_eq!(
        (
            callbacks,
            leaf.metadata_queries.load(Ordering::SeqCst),
            leaf.puts.load(Ordering::SeqCst),
            state.snapshot().put_calls,
        ),
        (0, 0, 0, 0),
    );
    assert_eq!(state.snapshot(), MetricsSnapshot::default());
    assert!(!leaf.child.contains(id)?);
    Ok(())
}

#[test]
fn metrics_rejects_65_inputs_before_preflight_or_effects() -> Result<(), StoreError> {
    assert_metrics_oversized_batch_has_no_effects(65)
}

#[test]
fn metrics_rejects_4096_inputs_before_preflight_or_effects() -> Result<(), StoreError> {
    assert_metrics_oversized_batch_has_no_effects(4096)
}

#[test]
fn metrics_oversized_batch_preserves_closed_original_under_unrelated_ambient()
-> Result<(), StoreError> {
    let directory = tempfile::tempdir().unwrap();
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let leaf = observed_leaf(directory.path(), &quota, &original)?;
    let (metrics, state) = MetricsStore::new("closed", leaf.clone());
    let unrelated = DecodeBudget::for_store(Quota::new()).unwrap();
    let _ambient = unrelated.enter();
    let bytes = b"closed original must take precedence over batch quota";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    let input = vec![(id, BlobHandle::from_bytes(bytes)); 65];
    quota.revoked.store(true, Ordering::SeqCst);
    let mut callbacks = 0;

    let error = metrics
        .put_many_if_absent_with_boundary(&original, &input, &mut || {
            callbacks += 1;
            Ok(())
        })
        .err()
        .unwrap();

    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(callbacks, 0);
    assert_eq!(leaf.metadata_queries.load(Ordering::SeqCst), 0);
    assert_eq!(leaf.puts.load(Ordering::SeqCst), 0);
    assert_eq!(state.snapshot(), MetricsSnapshot::default());
    unrelated.verify_live().unwrap();
    Ok(())
}

#[test]
fn routed_metrics_preserve_same_original_leaf_receipt_and_deferred_source() -> Result<(), StoreError>
{
    let directory = tempfile::tempdir().unwrap();
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let leaf = observed_leaf(directory.path(), &quota, &original)?;
    let input = objects();
    let routed = RoutedStore::new(
        "routed",
        input
            .iter()
            .map(|(id, _)| (id.kind(), leaf.clone() as Arc<dyn ImmutableBlobBackend>))
            .collect(),
    )?;
    let (metrics, state) = MetricsStore::new("metrics", Arc::new(routed));
    assert!(Arc::ptr_eq(
        &metrics.metadata_resources()?,
        &(quota.clone() as Arc<dyn StorePhysicalQuotaGuard>)
    ));

    let receipt = metrics.put_many_if_absent_with_boundary(&original, &input, &mut || Ok(()))?;
    assert_eq!(leaf.puts.load(Ordering::SeqCst), 1);
    assert_eq!(
        receipt.as_ptr() as usize,
        leaf.receipt_address.load(Ordering::SeqCst)
    );
    assert_eq!(
        receipt.iter().map(|value| value.id).collect::<Vec<_>>(),
        input.iter().map(|(id, _)| *id).collect::<Vec<_>>()
    );
    let source = metrics.read_with_boundary(&original, input[0].0, None, &mut || Ok(()))?;
    let range = metrics.read_with_boundary(
        &original,
        input[0].0,
        Some(ByteRange {
            offset: 2,
            length: 5,
        }),
        &mut || Ok(()),
    )?;
    assert_eq!(leaf.reads.load(Ordering::SeqCst), 2);
    assert_eq!(state.snapshot().put_calls, input.len() as u64);
    assert_eq!(state.snapshot().read_calls, 2);

    drop(metrics);
    drop(leaf);
    assert_eq!(
        &*source.read_all_with_boundary(&original, 1024, &mut || Ok(()))?,
        b"checked routed payload"
    );
    assert_eq!(
        &*range.read_all_with_boundary(&original, 1024, &mut || Ok(()))?,
        b"ecked"
    );
    assert_eq!(state.snapshot().read_stream_opens, 0);
    assert_eq!(state.snapshot().read_stream_bytes, 0);
    assert_eq!(state.snapshot().read_stream_completions, 0);
    drop(source);
    drop(range);
    drop(original);

    assert!(quota.budget.usage()?.1 > 0);
    assert_eq!(receipt[0].id, input[0].0);
    drop(receipt);
    assert_eq!(quota.budget.usage()?, (0, 0));
    Ok(())
}

#[test]
fn closed_original_and_callback_poison_refuse_before_route_child_or_metrics()
-> Result<(), StoreError> {
    let directory = tempfile::tempdir().unwrap();
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let leaf = observed_leaf(directory.path(), &quota, &original)?;
    let input = objects();
    let routed = Arc::new(RoutedStore::new(
        "routed",
        BTreeMap::from([(
            input[0].0.kind(),
            leaf.clone() as Arc<dyn ImmutableBlobBackend>,
        )]),
    )?);
    let (metrics, state) = MetricsStore::new("metrics", routed.clone());
    let unrelated = DecodeBudget::for_store(Quota::new()).unwrap();
    let _ambient = unrelated.enter();
    quota.revoked.store(true, Ordering::SeqCst);
    let mut calls = 0;
    for backend in [routed.as_ref() as &dyn ImmutableBlobBackend, &metrics] {
        let error = backend
            .read_with_boundary(&original, input[1].0, None, &mut || {
                calls += 1;
                Ok(())
            })
            .err()
            .unwrap();
        assert!(matches!(error.original_failure(), StoreError::Unauthorized));
        let error = backend
            .put_many_if_absent_with_boundary(&original, &input, &mut || {
                calls += 1;
                Ok(())
            })
            .err()
            .unwrap();
        assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    }
    assert_eq!(calls, 0);
    assert_eq!(leaf.reads.load(Ordering::SeqCst), 0);
    assert_eq!(leaf.puts.load(Ordering::SeqCst), 0);
    assert_eq!(state.snapshot().read_calls, 0);
    assert_eq!(state.snapshot().put_calls, 0);

    // A separate fixture tests callback poisoning without renewing closed A.
    let callback_quota = Quota::new();
    let poisoned = DecodeBudget::for_store(callback_quota.clone()).unwrap();
    let callback_leaf = observed_leaf(directory.path(), &callback_quota, &poisoned)?;
    let (callback_metrics, callback_state) = MetricsStore::new("callback", callback_leaf.clone());
    let error = callback_metrics
        .read_with_boundary(&poisoned, input[0].0, None, &mut || {
            calls += 1;
            callback_quota.revoked.store(true, Ordering::SeqCst);
            Ok(())
        })
        .err()
        .unwrap();
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(calls, 1);
    assert_eq!(callback_leaf.reads.load(Ordering::SeqCst), 0);
    assert_eq!(callback_state.snapshot().read_calls, 0);
    unrelated.verify_live().unwrap();
    Ok(())
}

#[test]
fn missing_mixed_and_opaque_routes_refuse_before_any_publication() -> Result<(), StoreError> {
    let directory = tempfile::tempdir().unwrap();
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let leaf = observed_leaf(directory.path(), &quota, &original)?;
    let input = objects();
    let routed = RoutedStore::new(
        "missing",
        BTreeMap::from([(
            input[0].0.kind(),
            leaf.clone() as Arc<dyn ImmutableBlobBackend>,
        )]),
    )?;
    assert!(matches!(
        routed.put_many_if_absent_with_boundary(&original, &input, &mut || Ok(())),
        Err(StoreError::InvalidComposition { .. })
    ));
    let opaque = Arc::new(OpaqueLeaf(leaf.child.clone()));
    let routed = RoutedStore::new(
        "mixed",
        BTreeMap::from([
            (
                input[0].0.kind(),
                leaf.clone() as Arc<dyn ImmutableBlobBackend>,
            ),
            (
                input[1].0.kind(),
                opaque.clone() as Arc<dyn ImmutableBlobBackend>,
            ),
            (
                input[2].0.kind(),
                leaf.clone() as Arc<dyn ImmutableBlobBackend>,
            ),
        ]),
    )?;
    assert!(Arc::ptr_eq(
        &routed.metadata_resources()?,
        &(quota as Arc<dyn StorePhysicalQuotaGuard>)
    ));
    assert!(matches!(
        routed.put_many_if_absent_with_boundary(&original, &input, &mut || Ok(())),
        Err(StoreError::Unsupported {
            capability: "checked-mixed-routed-batch"
        })
    ));
    assert!(matches!(
        routed.read_with_boundary(&original, input[1].0, None, &mut || Ok(())),
        Err(StoreError::Unsupported {
            capability: "checked-blob-metadata"
        })
    ));
    let (metrics, state) = MetricsStore::new("opaque", opaque);
    assert!(matches!(
        metrics.put_many_if_absent_with_boundary(&original, &input, &mut || Ok(())),
        Err(StoreError::Unsupported {
            capability: "checked-publication-metadata-bound"
        })
    ));
    assert_eq!(state.snapshot().put_calls, 0);
    assert_eq!(leaf.puts.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn routed_checked_publication_authenticates_corrupt_source_before_calling_leaf()
-> Result<(), StoreError> {
    let directory = tempfile::tempdir().unwrap();
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let leaf = observed_leaf(directory.path(), &quota, &original)?;
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"expected routed bytes");
    let routed = RoutedStore::new(
        "routed",
        BTreeMap::from([(id.kind(), leaf.clone() as Arc<dyn ImmutableBlobBackend>)]),
    )?;
    let baseline = quota.budget.usage()?;

    let error = routed
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(b"corrupt routed bytes"))],
            &mut || Ok(()),
        )
        .err()
        .unwrap();

    assert!(
        matches!(error.original_failure(), StoreError::Corrupt { id: actual } if *actual == id)
    );
    assert_eq!(leaf.puts.load(Ordering::SeqCst), 0);
    assert!(!leaf.child.contains(id)?);
    drop(error);
    assert_eq!(quota.budget.usage()?, baseline);
    Ok(())
}

struct RoutedSwallowingSource(Arc<AtomicBool>);

impl BlobSource for RoutedSwallowingSource {
    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Owning
    }

    fn logical_length(&self) -> u64 {
        b"routed swallowed callback".len() as u64
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        panic!("checked routed verification must not open an ordinary source")
    }

    fn open_with_boundary(
        &self,
        original: &DecodeBudget,
        _boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        CheckedReader::new_prepaid(
            RoutedSwallowingReader {
                original: original.clone(),
                reading: self.0.clone(),
                bytes: b"routed swallowed callback",
            },
            original,
        )
    }
}

struct RoutedSwallowingReader {
    original: DecodeBudget,
    reading: Arc<AtomicBool>,
    bytes: &'static [u8],
}

impl CheckedBlobReader for RoutedSwallowingReader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        self.reading.store(true, Ordering::SeqCst);
        let _swallowed = boundary();
        std::io::Read::read(&mut self.bytes, output).map_err(|source| StoreError::StreamIo {
            operation: "routed-swallowing-fixture",
            source,
        })
    }
}

#[test]
fn routed_checked_authentication_keeps_swallowed_first_refusal_before_leaf()
-> Result<(), StoreError> {
    let directory = tempfile::tempdir().unwrap();
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let leaf = observed_leaf(directory.path(), &quota, &original)?;
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"routed swallowed callback");
    let routed = RoutedStore::new(
        "routed",
        BTreeMap::from([(id.kind(), leaf.clone() as Arc<dyn ImmutableBlobBackend>)]),
    )?;
    let baseline = quota.budget.usage()?;
    let reading = Arc::new(AtomicBool::new(false));
    let input = BlobHandle::new(RoutedSwallowingSource(reading.clone()));
    let mut refused = false;
    let mut calls_after_refusal = 0;

    let error = routed
        .put_many_if_absent_with_boundary(&original, &[(id, input)], &mut || {
            if refused {
                calls_after_refusal += 1;
            } else if reading.load(Ordering::SeqCst) {
                refused = true;
                return Err(StoreError::Unauthorized);
            }
            Ok(())
        })
        .err()
        .unwrap();

    assert!(refused);
    assert_eq!(calls_after_refusal, 0);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(leaf.puts.load(Ordering::SeqCst), 0);
    assert!(!leaf.child.contains(id)?);
    drop(error);
    assert_eq!(quota.budget.usage()?, baseline);
    Ok(())
}
