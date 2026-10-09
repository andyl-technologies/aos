//! Closed-record allocation and original-callback provenance regressions.
#![cfg(test)]

use super::*;
use crate::ram::codec::{PAGE_SCHEMA, TreeNode};
use crate::ram::record_account::{RecordAccount, RecordAllocationPlan};

#[test]
fn prepaid_codec_refusal_is_local_and_preserves_original_poisoning() {
    let quota = ObservedQuota::new();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.used();
    let competing = quota
        .resources
        .reserve(0, METADATA_BYTES - baseline)
        .unwrap();
    let error = RecordAccount::new(&parent, RecordAllocationPlan::read(4179, 0).unwrap())
        .err()
        .unwrap();
    assert!(contains_original_quota(&error));
    parent.check().unwrap();
    drop(error);
    drop(competing);
    assert_eq!(quota.used(), baseline);

    let record = RecordAccount::new(&parent, RecordAllocationPlan::read(4179, 0).unwrap()).unwrap();
    // A hostile allocation within one partition remains sticky and monotone.
    assert!(record.codec.charge_bytes(METADATA_BYTES).is_err());
    assert!(record.codec.charge_bytes(1).is_err());
    parent.check().unwrap();
    drop(record);
    assert_eq!(quota.used(), baseline);

    parent.charge_bytes(METADATA_BYTES).unwrap_err();
    let poisoned = parent.failure().unwrap().unwrap();
    let refusal = RecordAccount::new(&parent, RecordAllocationPlan::read(4179, 0).unwrap())
        .err()
        .unwrap();
    let RamStoreError::Store(StoreError::DecodeAdmission { source, .. }) = refusal else {
        panic!("expected original admission")
    };
    assert_eq!(source, poisoned);
    drop(parent);
    assert_eq!(quota.used(), 0);
}

#[test]
fn tree_decoder_uses_fewer_real_original_bank_reservations() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let retention = Retention::default();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &parent, &mut boundary).unwrap();
    let (page, digest) = store.put_page(&[3; 4096], &retention, &mut work).unwrap();
    let left = store
        .put_tree(
            &TreeNode::Leaf { page, digest },
            0,
            1,
            &retention,
            &mut work,
        )
        .unwrap();
    let branch = store
        .put_tree(
            &TreeNode::Branch { left, right: left },
            1,
            2,
            &retention,
            &mut work,
        )
        .unwrap();
    let baseline = quota.used();

    let before = quota.reservations.load(Ordering::SeqCst);
    let before_verifications = quota.verifications.load(Ordering::SeqCst);
    let child = parent.child().unwrap();
    let old_scope = child.enter();
    let source = store.backend.read(branch.id, None).unwrap();
    let bytes = source.read_all(4096).unwrap();
    let decoded = ContentEnvelope::from_canonical_bytes_with_child_limit(&bytes, 2).unwrap();
    assert_eq!(decoded.children().len(), 2);
    drop(decoded);
    drop(bytes);
    drop(source);
    drop(old_scope);
    drop(child);
    let original_calls = quota.reservations.load(Ordering::SeqCst) - before;
    let original_verifications = quota.verifications.load(Ordering::SeqCst) - before_verifications;
    assert_eq!(quota.used(), baseline);

    let before = quota.reservations.load(Ordering::SeqCst);
    let before_verifications = quota.verifications.load(Ordering::SeqCst);
    let decoded = store.read_envelope(branch.id, &mut work).unwrap();
    assert_eq!(decoded.children().len(), 2);
    drop(decoded);
    let prepaid_calls = quota.reservations.load(Ordering::SeqCst) - before;
    let prepaid_verifications = quota.verifications.load(Ordering::SeqCst) - before_verifications;
    assert!(
        prepaid_calls < original_calls,
        "original={original_calls} prepaid={prepaid_calls}"
    );
    assert_eq!(quota.used(), baseline);
    // crucible-lint: allow direct-diagnostic -- this component reports genuine finite-bank reservation counts, without a native latency claim.
    eprintln!(
        "tree_original_reservations={original_calls} tree_prepaid_reservations={prepaid_calls} tree_original_verifications={original_verifications} tree_prepaid_verifications={prepaid_verifications}"
    );
    drop(scope);
    drop(parent);
}

#[test]
fn deferred_publication_readers_use_original_bank_after_partition_closes() {
    let quota = ObservedQuota::new();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.used();
    let record =
        RecordAccount::new(&parent, RecordAllocationPlan::canonical(4179).unwrap()).unwrap();
    let scope = record.codec.enter();
    record.codec.charge_array::<u8>(4179).unwrap();
    let source =
        crate::ram::codec_ownership::encoded_source(vec![7; 4179], &record.codec, &record.original)
            .unwrap();
    let clone = source.clone();
    // Poisoning this codec's remaining partition must not redirect a deferred
    // reader's control allocation into that failed local partition.
    record.codec.charge_bytes(METADATA_BYTES).unwrap_err();
    let first = source.open().unwrap();
    drop(scope);
    drop(record);
    let mut second = clone.open().unwrap();
    let competing = quota
        .resources
        .reserve(0, METADATA_BYTES - quota.used())
        .unwrap();
    let error = clone.open().err().unwrap();
    assert!(contains_original_quota(&error));
    drop(error);
    drop(competing);
    let third = clone.open().unwrap();
    drop(source);
    drop(clone);
    drop(first);
    drop(third);
    assert!(quota.used() > baseline + 4179);
    let mut bytes = [0; 4179];
    second.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [7; 4179]);
    drop(second);
    assert_eq!(quota.used(), baseline);
    parent.check().unwrap();
    drop(parent);
    assert_eq!(quota.used(), 0);
}

struct OriginalRetention;

impl RamRetention for OriginalRetention {
    fn retain_object(&self, _id: ContentId) -> Result<(), RamStoreError> {
        // This request deliberately exceeds either codec partition, but fits
        // the original finite bank. Retention must never see transient TLS.
        let original = crate::owned_decode::current_budget().unwrap();
        let _credit = original
            .reserve_scratch_bytes(128 * 1024)
            .map_err(crate::ram::codec_ownership::admission)?;
        Ok(())
    }

    fn retain_root(&self, id: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        self.retain_object(id)?;
        Ok(Arc::new(Lease(id)))
    }
}

#[test]
fn sixty_four_pending_pages_overlap_only_independent_actual_cache_copy_loans() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let cache = MemoryBlobBackend::new("prepaid-copy", 1024 * 1024);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let baseline = quota.used();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &parent, &mut boundary).unwrap();
    store.begin_capture_batch(&mut work).unwrap();
    for index in 0_u64..64 {
        let mut page = [0; 4096];
        page[..8].copy_from_slice(&index.to_be_bytes());
        store
            .put_page(&page, &OriginalRetention, &mut work)
            .unwrap();
    }
    assert_eq!(work.pending.as_ref().unwrap().len(), 64);
    let pending_peak = quota.used();
    for object in work.pending.as_ref().unwrap() {
        cache.put_if_absent(object.id, &object.source).unwrap();
    }
    assert!(quota.used() > pending_peak);
    assert!(quota.used() < METADATA_BYTES);
    store.flush_capture_batch(&mut work).unwrap();
    assert_eq!(cache.object_count().unwrap(), 64);
    let copies_only = quota.used();
    assert!(
        copies_only < baseline + 512 * 1024,
        "copies retained codec pools: {copies_only}"
    );
    drop(work);
    drop(cache);
    assert_eq!(quota.used(), baseline);
    drop(scope);
    drop(parent);
}

#[test]
fn closed_record_bounds_refuse_before_codec_owner_reservation() {
    let quota = ObservedQuota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let before = quota.reservations.load(Ordering::SeqCst);
    assert!(RecordAllocationPlan::read(8193, 0).is_err());
    assert!(RecordAllocationPlan::read(4096, 3).is_err());
    assert!(RecordAllocationPlan::input(usize::MAX, PAGE_SCHEMA, &[]).is_err());
    assert_eq!(quota.reservations.load(Ordering::SeqCst), before);
    original.check().unwrap();
}

#[derive(Debug, thiserror::Error)]
#[error("original late read callback failed")]
struct LateReadFailure;

struct CallbackBackend {
    backend: Arc<dyn ImmutableBlobBackend>,
    observations: Arc<AtomicU64>,
    fail_at_eof: Arc<std::sync::atomic::AtomicBool>,
    revoke_at_eof: Option<Arc<ObservedQuota>>,
    corrupt_first_read: bool,
    revoke_after_eof_verifications: u64,
}

impl ImmutableBlobBackend for CallbackBackend {
    fn name(&self) -> &str {
        self.backend.name()
    }
    fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities()
    }
    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.backend.metadata_resources()
    }
    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.backend.contains(id)
    }
    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.backend.put_if_absent(id, source)
    }
    fn read(&self, _: ContentId, _: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        Err(StoreError::Unsupported {
            capability: "checked adversarial callback fixture",
        })
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        let source = self
            .backend
            .read_with_boundary(original, id, range, boundary)?;
        let credit = original
            .reserve_scratch_bytes(BlobHandle::source_allocation_bytes::<CallbackSource>())
            .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
        let observed = CallbackSource {
            source: source.clone(),
            observations: self.observations.clone(),
            fail_at_eof: self.fail_at_eof.clone(),
            revoke_at_eof: self.revoke_at_eof.clone(),
            corrupt_first_read: self.corrupt_first_read,
            revoke_after_eof_verifications: self.revoke_after_eof_verifications,
            _credit: credit,
        };
        Ok(source.with_untrusted_source(observed))
    }
}

struct CallbackSource {
    source: BlobHandle,
    observations: Arc<AtomicU64>,
    fail_at_eof: Arc<std::sync::atomic::AtomicBool>,
    revoke_at_eof: Option<Arc<ObservedQuota>>,
    corrupt_first_read: bool,
    revoke_after_eof_verifications: u64,
    _credit: crate::owned_decode::DecodeScratch,
}

fn observe_original_callback(
    original: &DecodeBudget,
    counter: &AtomicU64,
) -> Result<(), StoreError> {
    let _scratch = original
        .reserve_scratch_bytes(128 * 1024)
        .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
    counter.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

impl crate::content_store::BlobSource for CallbackSource {
    fn checked_read_access(&self) -> crate::content_store::CheckedReadAccess {
        crate::content_store::CheckedReadAccess::Owning
    }

    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }
    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "checked adversarial callback fixture",
        })
    }

    fn open_with_boundary(
        &self,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crate::content_store::CheckedReader, StoreError> {
        fixture_boundary(original, boundary)?;
        observe_original_callback(original, &self.observations)?;
        let credit = original
            .reserve_scratch_array::<CallbackReader>(1)
            .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
        let reader =
            crate::content_store::BlobSource::open_with_boundary(&self.source, original, boundary)?;
        Ok(crate::content_store::CheckedReader::funded(
            Box::new(CallbackReader {
                reader,
                original: original.clone(),
                observations: self.observations.clone(),
                fail_at_eof: self.fail_at_eof.clone(),
                revoke_at_eof: self.revoke_at_eof.clone(),
                corrupt_first_read: self.corrupt_first_read,
                revoke_after_eof_verifications: self.revoke_after_eof_verifications,
                failed: false,
            }),
            credit,
        ))
    }
}

struct CallbackReader {
    reader: crate::content_store::CheckedReader,
    original: DecodeBudget,
    observations: Arc<AtomicU64>,
    fail_at_eof: Arc<std::sync::atomic::AtomicBool>,
    revoke_at_eof: Option<Arc<ObservedQuota>>,
    corrupt_first_read: bool,
    revoke_after_eof_verifications: u64,
    failed: bool,
}

impl crate::content_store::CheckedBlobReader for CallbackReader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        bytes: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(StoreError::Unsupported {
                capability: "failed adversarial callback reader",
            });
        }
        let result = self.read_inner(bytes, boundary);
        self.failed = result.is_err();
        result
    }
}

impl CallbackReader {
    fn read_inner(
        &mut self,
        bytes: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        observe_original_callback(&self.original, &self.observations)?;
        let read = self.reader.read_with_boundary(bytes, boundary)?;
        if read != 0 && self.corrupt_first_read {
            bytes[0] ^= 1;
            self.corrupt_first_read = false;
        }
        if read == 0
            && let Some(quota) = &self.revoke_at_eof
        {
            if self.revoke_after_eof_verifications == 0 {
                quota.revoked.store(true, Ordering::SeqCst);
            } else {
                quota
                    .revoke_after_verifications
                    .store(self.revoke_after_eof_verifications, Ordering::SeqCst);
            }
        }
        if read == 0 && self.fail_at_eof.load(Ordering::SeqCst) {
            return Err(StoreError::StreamIo {
                operation: "verify-blob-source-length",
                source: std::io::Error::other(LateReadFailure),
            });
        }
        Ok(read)
    }
}

#[test]
fn source_open_read_and_late_auth_callbacks_run_outside_prepaid_tls() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let source_store = directory_store(directory.path(), &quota);
    let page = page_object(&source_store);
    let observations = Arc::new(AtomicU64::new(0));
    let fail_at_eof = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backend = Arc::new(CallbackBackend {
        backend: source_store.backend.clone(),
        observations: observations.clone(),
        fail_at_eof: fail_at_eof.clone(),
        revoke_at_eof: None,
        corrupt_first_read: false,
        revoke_after_eof_verifications: 0,
    });
    let store = RamStore::new(
        backend,
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = original.enter();
    let baseline = quota.used();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let prepared = quota.used();
    let envelope = store.read_envelope(page, &mut work).unwrap();
    assert_eq!(envelope.schema_name(), PAGE_SCHEMA);
    assert!(observations.load(Ordering::SeqCst) >= 3);
    drop(envelope);
    assert_eq!(quota.used(), prepared);

    fail_at_eof.store(true, Ordering::SeqCst);
    let error = store.read_envelope(page, &mut work).err().unwrap();
    let RamStoreError::Store(StoreError::StreamIo { operation, source }) = &error else {
        panic!("expected original stream failure: {error:?}")
    };
    assert_eq!(*operation, "verify-blob-source-length");
    assert!(
        source
            .get_ref()
            .unwrap()
            .downcast_ref::<LateReadFailure>()
            .is_some()
    );
    drop(error);
    assert_eq!(quota.used(), prepared);
    original.check().unwrap();
    drop(work);
    assert_eq!(quota.used(), baseline);
    drop(scope);
    drop(original);
}

#[test]
fn original_authority_revoked_at_eof_refuses_decoded_owner_and_releases_both_loans() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let source_store = directory_store(directory.path(), &quota);
    let page = page_object(&source_store);
    let backend = Arc::new(CallbackBackend {
        backend: source_store.backend.clone(),
        observations: Arc::new(AtomicU64::new(0)),
        fail_at_eof: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        revoke_at_eof: Some(quota.clone()),
        corrupt_first_read: false,
        revoke_after_eof_verifications: 0,
    });
    let store = RamStore::new(
        backend,
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let baseline = quota.used();
    let mut boundary = || quota.verify().map_err(RamStoreError::from);
    let mut work = Work::new(store.limits, &parent, &mut boundary).unwrap();
    let prepared = quota.used();
    let error = store.read_envelope(page, &mut work).err().unwrap();
    assert!(quota.revoked.load(Ordering::SeqCst));
    assert_eq!(decoder_failure(&error), DecoderFailure::OriginalRevocation);
    assert_eq!(
        quota.used(),
        prepared,
        "raw and retained decoder loans must both close on refusal"
    );
    // Partition failure must not poison the original ambient decoder account;
    // actual authority remains revoked and refuses a new genuine child.
    parent.check().unwrap();
    assert!(parent.child().is_err());
    drop(error);
    drop(work);
    assert_eq!(quota.used(), baseline);
    drop(scope);
    drop(parent);
}

#[derive(Debug, PartialEq, Eq)]
enum DecoderFailure {
    OriginalRevocation,
    Envelope(crate::content_envelope::ContentEnvelopeError),
    Digest,
}

fn decoder_failure(error: &RamStoreError) -> DecoderFailure {
    let mut cause: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(current) = cause {
        if current.downcast_ref::<RevokedOriginalAuthority>().is_some() {
            return DecoderFailure::OriginalRevocation;
        }
        cause = current.source();
    }
    match error {
        RamStoreError::Envelope(error) => DecoderFailure::Envelope(error.clone()),
        RamStoreError::Store(StoreError::Corrupt { .. }) => DecoderFailure::Digest,
        _ => panic!("unexpected causal decoder refusal: {error:?}"),
    }
}

fn revoked_decoder_comparison(
    bytes: &[u8],
    corrupt_first_read: bool,
    revoke_after_eof_verifications: u64,
) -> [DecoderFailure; 2] {
    decoder_stage_comparison(
        bytes,
        corrupt_first_read,
        Some(revoke_after_eof_verifications),
    )
}

fn decoder_stage_comparison(
    bytes: &[u8],
    corrupt_first_read: bool,
    revoke_at_eof: Option<u64>,
) -> [DecoderFailure; 2] {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let source_store = directory_store(directory.path(), &quota);
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, bytes);
    source_store
        .backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let backend = Arc::new(CallbackBackend {
        backend: source_store.backend.clone(),
        observations: Arc::new(AtomicU64::new(0)),
        fail_at_eof: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        revoke_at_eof: revoke_at_eof.map(|_| quota.clone()),
        corrupt_first_read,
        revoke_after_eof_verifications: revoke_at_eof.unwrap_or(0),
    });
    let store = RamStore::new(
        backend,
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = original.enter();
    let baseline = quota.used();

    let failures = [false, true].map(|prepaid| {
        quota.revoked.store(false, Ordering::SeqCst);
        let mut boundary = || quota.verify().map_err(RamStoreError::from);
        let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
        let error = if prepaid {
            store.read_envelope(id, &mut work)
        } else {
            store.read_envelope_without_prepayment(id, &mut work)
        }
        .err()
        .unwrap();
        assert_eq!(
            quota.revoked.load(Ordering::SeqCst),
            revoke_at_eof.is_some()
        );
        let failure = decoder_failure(&error);
        drop(error);
        drop(work);
        assert_eq!(quota.used(), baseline, "all refused owner loans must close");
        original.check().unwrap();
        failure
    });
    drop(scope);
    drop(original);
    drop(store);
    drop(source_store);
    assert_eq!(quota.used(), 0);
    failures
}

fn borrowed_valid_schema_prefix() -> Vec<u8> {
    let schema = crate::ram::codec::TREE_SCHEMA.as_bytes();
    let mut bytes = b"CRUCOBJE".to_vec();
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&(schema.len() as u16).to_be_bytes());
    bytes.extend_from_slice(schema);
    bytes
}

#[test]
fn eof_revocation_preserves_original_first_allocation_error_priority() {
    let mut excessive_children = borrowed_valid_schema_prefix();
    excessive_children.extend_from_slice(&1_u32.to_be_bytes());
    excessive_children.extend_from_slice(&3_u32.to_be_bytes());
    assert_eq!(
        revoked_decoder_comparison(&excessive_children, false, 0),
        [
            DecoderFailure::OriginalRevocation,
            DecoderFailure::OriginalRevocation,
        ],
        "original schema admission precedes child count"
    );

    assert_eq!(
        revoked_decoder_comparison(&borrowed_valid_schema_prefix(), false, 0),
        [
            DecoderFailure::OriginalRevocation,
            DecoderFailure::OriginalRevocation,
        ],
        "original schema admission precedes schema version"
    );
}

#[test]
fn checked_eof_refusal_precedes_framing_while_live_reads_preserve_framing_errors() {
    use crate::content_envelope::ContentEnvelopeError;

    let mut invalid_utf8 = b"CRUCOBJE".to_vec();
    invalid_utf8.extend_from_slice(&1_u32.to_be_bytes());
    invalid_utf8.extend_from_slice(&1_u16.to_be_bytes());
    invalid_utf8.push(0xff);
    let cases: &[(&[u8], ContentEnvelopeError)] = &[
        (b"CRUCOBJF\0\0\0\x01", ContentEnvelopeError::Incompatible),
        (b"CRU", ContentEnvelopeError::Truncated),
        (&invalid_utf8, ContentEnvelopeError::InvalidIdentifier),
    ];

    for (bytes, framing) in cases {
        assert_eq!(
            revoked_decoder_comparison(bytes, false, 0),
            [
                DecoderFailure::OriginalRevocation,
                DecoderFailure::OriginalRevocation
            ],
            "an observed checked EOF refusal never exposes bytes to the codec"
        );
        assert_eq!(
            decoder_stage_comparison(bytes, false, None),
            [
                DecoderFailure::Envelope(framing.clone()),
                DecoderFailure::Envelope(framing.clone())
            ],
            "successful live checked reads retain pure framing errors"
        );
    }
    assert_eq!(
        revoked_decoder_comparison(&borrowed_valid_schema_prefix(), true, 0),
        [DecoderFailure::Digest, DecoderFailure::Digest],
        "already-computed object digest failure precedes final EOF authority verification"
    );
}

#[test]
fn successful_checked_read_allows_pure_framing_before_later_codec_admission() {
    use crate::content_envelope::ContentEnvelopeError;

    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.used();
    let mut invalid_utf8 = b"CRUCOBJE".to_vec();
    invalid_utf8.extend_from_slice(&1_u32.to_be_bytes());
    invalid_utf8.extend_from_slice(&1_u16.to_be_bytes());
    invalid_utf8.push(0xff);
    let cases: &[(&[u8], Option<ContentEnvelopeError>)] = &[
        (
            b"CRUCOBJF\0\0\0\x01",
            Some(ContentEnvelopeError::Incompatible),
        ),
        (b"CRU", Some(ContentEnvelopeError::Truncated)),
        (&invalid_utf8, Some(ContentEnvelopeError::InvalidIdentifier)),
        (&borrowed_valid_schema_prefix(), None),
    ];

    for (bytes, framing) in cases {
        quota.revoked.store(false, Ordering::SeqCst);
        let id = ContentId::for_bytes(ObjectKind::RamTree, 1, bytes);
        store
            .backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .unwrap();
        let account = original.child().unwrap();
        let source = store
            .backend
            .read_with_boundary(&account, id, None, &mut || Ok(()))
            .unwrap();
        let read = source
            .read_all_with_boundary(&account, 4096, &mut || Ok(()))
            .unwrap();
        assert_eq!(&*read, *bytes);
        assert!(id.authenticates(&read));

        // Only after a genuine successful checked read does the later codec
        // stage lose original authority. Pure framing does not allocate.
        quota.revoked.store(true, Ordering::SeqCst);
        let before = quota.reservations.load(Ordering::SeqCst);
        let scope = account.enter();
        let error = ContentEnvelope::from_canonical_bytes_with_child_limit(&read, 2).unwrap_err();
        if let Some(framing) = framing {
            assert_eq!(&error, framing);
        } else {
            assert!(matches!(error, ContentEnvelopeError::DecodeAdmission(_)));
            assert_eq!(
                decoder_failure(&RamStoreError::Envelope(error)),
                DecoderFailure::OriginalRevocation
            );
        }
        assert_eq!(quota.reservations.load(Ordering::SeqCst), before);
        drop(scope);
        drop(read);
        drop(source);
        drop(account);
        assert_eq!(quota.used(), baseline);
    }
}

#[test]
fn later_original_admission_revocation_precedes_malformed_child_utf8() {
    let mut bytes = borrowed_valid_schema_prefix();
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(0xff);

    // This delay still expires within the checked EOF stage. No malformed
    // child bytes become visible after its actual original refusal.
    assert_eq!(
        revoked_decoder_comparison(&bytes, false, 2),
        [
            DecoderFailure::OriginalRevocation,
            DecoderFailure::OriginalRevocation
        ]
    );
}

#[test]
fn optimized_scalar_refusal_preserves_original_cancellation_and_partial_counts() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let source_store = directory_store(directory.path(), &quota);
    let page = page_object(&source_store);
    let observations = Arc::new(AtomicU64::new(0));
    let store = callback_store(&source_store, observations.clone());
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let _scope = original.enter();
    let baseline = quota.used();

    let cases = [
        (u64::MAX, 0),
        (0, u64::MAX),
        (store.limits.maximum_object_visits, 0),
        (0, store.limits.maximum_io_bytes),
    ];
    for counts in cases {
        for canceled in [false, true] {
            let outcomes = [false, true].map(|prepaid| {
                let polls = std::cell::Cell::new(0);
                let mut boundary = || {
                    polls.set(polls.get() + 1);
                    if canceled && polls.get() == 2 {
                        Err(RamStoreError::Canceled)
                    } else {
                        Ok(())
                    }
                };
                let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
                (work.visits, work.io_bytes) = counts;
                let reservations = quota.reservations.load(Ordering::SeqCst);
                let error = if prepaid {
                    store.read_envelope(page, &mut work)
                } else {
                    store.read_envelope_without_prepayment(page, &mut work)
                }
                .err()
                .unwrap();
                let refusal = match &error {
                    RamStoreError::Canceled => "canceled",
                    RamStoreError::Limit(limit) => *limit,
                    RamStoreError::Store(StoreError::RamReadBoundary { source }) => {
                        assert!(matches!(
                            source.first_boundary(),
                            Some(RamStoreError::Canceled)
                        ));
                        assert!(matches!(
                            source.storage_failure(),
                            RamStoreError::Store(StoreError::RamBoundary { .. })
                        ));
                        "canceled"
                    }
                    _ => panic!("unexpected scalar refusal: {error:?}"),
                };
                let observed = (
                    refusal,
                    work.visits,
                    work.io_bytes,
                    polls.get(),
                    quota.reservations.load(Ordering::SeqCst) - reservations,
                );
                assert_eq!(
                    observations.load(Ordering::SeqCst),
                    0,
                    "guaranteed refusal performs no metadata lookup or stream callback"
                );
                assert_eq!(observed.4, 0, "already-prepared Work acquires no new loan");
                drop(error);
                drop(work);
                assert_eq!(quota.used(), baseline);
                observed
            });
            assert_eq!(outcomes[0], outcomes[1]);
            assert_eq!(outcomes[0].3, 2);
            if canceled {
                assert_eq!(outcomes[0].0, "canceled");
                assert_eq!((outcomes[0].1, outcomes[0].2), counts);
            }
        }
    }
    original.check().unwrap();
}

fn callback_store(source: &RamStore, observations: Arc<AtomicU64>) -> RamStore {
    RamStore::new(
        Arc::new(CallbackBackend {
            backend: source.backend.clone(),
            observations,
            fail_at_eof: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            revoke_at_eof: None,
            corrupt_first_read: false,
            revoke_after_eof_verifications: 0,
        }),
        DurabilityRequirement::new(1, false).unwrap(),
        source.limits,
    )
    .unwrap()
}

#[test]
fn exhausted_scalar_preflight_keeps_original_refusal_before_callback_under_foreign_tls() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let source_store = directory_store(directory.path(), &quota);
    let page = page_object(&source_store);
    let observations = Arc::new(AtomicU64::new(0));
    let store = callback_store(&source_store, observations.clone());
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let unrelated_quota = ObservedQuota::new();
    let unrelated = DecodeBudget::for_store(unrelated_quota).unwrap();
    let polls = std::cell::Cell::new(0);
    let mut boundary = || {
        polls.set(polls.get() + 1);
        Ok(())
    };
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    work.io_bytes = store.limits.maximum_io_bytes;
    let before = quota.reservations.load(Ordering::SeqCst);
    quota.revoked.store(true, Ordering::SeqCst);
    let scope = unrelated.enter();

    let error = store.read_envelope(page, &mut work).err().unwrap();
    assert_eq!(decoder_failure(&error), DecoderFailure::OriginalRevocation);
    assert_eq!(polls.get(), 0);
    assert_eq!(observations.load(Ordering::SeqCst), 0);
    assert_eq!(quota.reservations.load(Ordering::SeqCst), before);
    assert_eq!(work.visits, 0);
    assert_eq!(work.io_bytes, store.limits.maximum_io_bytes);
    unrelated.verify_live().unwrap();
    drop(scope);
}

#[test]
fn scalar_preflight_inspects_only_when_capacity_does_not_guarantee_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let source_store = directory_store(directory.path(), &quota);
    let page = page_object(&source_store);
    let empty = ContentId::for_bytes(ObjectKind::RamTree, 1, b"");
    source_store
        .backend
        .put_if_absent(empty, &BlobHandle::from_bytes(Vec::new()))
        .unwrap();
    let observations = Arc::new(AtomicU64::new(0));
    let store = callback_store(&source_store, observations.clone());
    let original = DecodeBudget::for_store(quota.clone()).unwrap();

    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let error = store.read_envelope(empty, &mut work).err().unwrap();
    assert_eq!(
        decoder_failure(&error),
        DecoderFailure::Envelope(crate::content_envelope::ContentEnvelopeError::Truncated)
    );
    assert!(observations.load(Ordering::SeqCst) > 0);
    drop(work);

    observations.store(0, Ordering::SeqCst);
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    work.io_bytes = store.limits.maximum_io_bytes - 1;
    assert!(matches!(
        store.read_envelope(page, &mut work),
        Err(RamStoreError::Limit("I/O bytes"))
    ));
    assert_eq!(
        observations.load(Ordering::SeqCst),
        1,
        "remaining capacity requires the actual metadata length; no stream opens after scalar accounting refusal"
    );
    drop(work);

    observations.store(0, Ordering::SeqCst);
    let polls = std::cell::Cell::new(0);
    let mut boundary = || {
        polls.set(polls.get() + 1);
        Ok(())
    };
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    work.io_bytes = store.limits.maximum_io_bytes;
    assert!(matches!(
        store.read_envelope(empty, &mut work),
        Err(RamStoreError::Limit("I/O bytes"))
    ));
    assert_eq!(
        work.io_bytes, store.limits.maximum_io_bytes,
        "no unread length is invented"
    );
    assert_eq!(observations.load(Ordering::SeqCst), 0);
    assert_eq!(polls.get(), 2);
}

#[test]
fn canonical_readers_do_not_retain_the_shared_input_phase() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let store_baseline = quota.used();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let baseline = quota.used();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &parent, &mut boundary).unwrap();
    store.begin_capture_batch(&mut work).unwrap();
    store
        .put_page(&[7; 4096], &OriginalRetention, &mut work)
        .unwrap();

    let object = &work.pending.as_ref().unwrap()[0];
    let input = match &object.envelope {
        crate::ram::codec_ownership::PendingEnvelope::OwnedSmall(input) => Arc::clone(input),
        crate::ram::codec_ownership::PendingEnvelope::OriginalCopy(_) => {
            panic!("typed page copied")
        }
    };
    let input_clone = Arc::clone(&input);
    let source = object.source.clone();
    let mut reader =
        crate::content_store::BlobSource::open_with_boundary(&source, &parent, &mut || Ok(()))
            .unwrap();
    drop(work.pending.take());
    let both_phases = quota.used();
    drop(input);
    assert_eq!(quota.used(), both_phases);
    drop(input_clone);
    let canonical_only = quota.used();
    assert!(canonical_only + 4132 < both_phases);
    drop(source);
    assert_eq!(quota.used(), canonical_only);
    let mut bytes = [0; 4179];
    assert_eq!(
        reader
            .read_with_boundary(&mut bytes, &mut || Ok(()))
            .unwrap(),
        bytes.len()
    );
    assert!(bytes.ends_with(&[7; 4096]));
    assert_eq!(
        reader.read_with_boundary(&mut [0], &mut || Ok(())).unwrap(),
        0
    );
    drop(reader);
    drop(work);
    assert_eq!(quota.used(), baseline);
    drop(scope);
    drop(parent);
    assert_eq!(quota.used(), store_baseline);
    drop(store);
    assert_eq!(quota.used(), 0);
}

#[test]
fn batch_array_refusal_keeps_the_namespace_healthy_and_the_failed_operation_sticky() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let store_baseline = quota.used();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.used();
    let operation = parent.child().unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
    let prepared = quota.used();
    let competitor = quota
        .resources
        .reserve(0, METADATA_BYTES - prepared - 4096)
        .unwrap();

    let error = store.begin_capture_batch(&mut work).unwrap_err();
    assert!(contains_original_quota(&error));
    assert!(work.pending.is_none());
    let first = operation.failure().unwrap().unwrap();
    drop(competitor);
    let reservations = quota.reservations.load(Ordering::SeqCst);
    let repeated_refusal = store.begin_capture_batch(&mut work).unwrap_err();
    let RamStoreError::Store(StoreError::DecodeAdmission { source, .. }) = &repeated_refusal else {
        panic!("expected the same original admission failure: {repeated_refusal:?}")
    };
    assert_eq!(source, &first);
    assert_eq!(operation.failure().unwrap(), Some(first.clone()));
    assert_eq!(quota.reservations.load(Ordering::SeqCst), reservations);
    assert!(work.pending.is_none());
    assert_eq!((work.visits, work.io_bytes), (0, 0));
    assert_eq!(quota.used(), prepared);

    // The failed operation never renews its allowance. Close all of its
    // borrowers before reusing the same namespace in a separate operation.
    drop(error);
    drop(repeated_refusal);
    drop(first);
    drop(work);
    drop(operation);
    assert_eq!(quota.used(), baseline);
    parent.verify_live().unwrap();

    let operation = parent.child().unwrap();
    let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
    store.begin_capture_batch(&mut work).unwrap();
    let array_used = quota.used();
    assert!(
        array_used >= baseline + 64 * std::mem::size_of::<crate::ram::PendingPublication>() as u64
    );
    let error = store.begin_capture_batch(&mut work).unwrap_err();
    assert!(matches!(
        error,
        RamStoreError::Invalid("capture batch already present")
    ));
    assert_eq!(quota.used(), array_used);
    drop(error);
    drop(work);
    drop(operation);
    assert_eq!(quota.used(), baseline);
    drop(parent);
    assert_eq!(quota.used(), store_baseline);
    drop(store);
    assert_eq!(quota.used(), 0);
}
