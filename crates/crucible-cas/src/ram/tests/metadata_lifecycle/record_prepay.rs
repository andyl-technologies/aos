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
    let RamStoreError::Store(StoreError::Supervision { source }) = refusal else {
        panic!("expected original admission")
    };
    assert_eq!(
        source.downcast_ref::<crate::owned_decode::DecodeAdmissionError>(),
        Some(&poisoned)
    );
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
    let mut work = Work::new(store.limits, &mut boundary);
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
    let mut work = Work::new(store.limits, &mut boundary);
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
    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let source = self.backend.read(id, range)?;
        let account = crate::owned_decode::current_child_budget()
            .unwrap()
            .unwrap();
        let credit = account
            .reserve_scratch_bytes(
                (std::mem::size_of::<CallbackSource>() + 2 * std::mem::size_of::<usize>()) as u64,
            )
            .map_err(|source| StoreError::Supervision {
                source: Box::new(source),
            })?;
        let observed = Arc::new(CallbackSource {
            source: source.clone(),
            observations: self.observations.clone(),
            fail_at_eof: self.fail_at_eof.clone(),
            revoke_at_eof: self.revoke_at_eof.clone(),
            corrupt_first_read: self.corrupt_first_read,
            revoke_after_eof_verifications: self.revoke_after_eof_verifications,
            _credit: credit,
        });
        Ok(source.with_observed_source(observed))
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

fn observe_original_callback(counter: &AtomicU64) -> Result<(), StoreError> {
    let original = crate::owned_decode::current_child_budget()
        .map_err(|source| StoreError::Supervision {
            source: Box::new(source),
        })?
        .ok_or(StoreError::Unsupported {
            capability: "original callback scope",
        })?;
    let _scratch = original
        .reserve_scratch_bytes(128 * 1024)
        .map_err(|source| StoreError::Supervision {
            source: Box::new(source),
        })?;
    counter.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

impl crate::content_store::BlobSource for CallbackSource {
    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }
    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        observe_original_callback(&self.observations)?;
        let original = crate::owned_decode::current_child_budget()
            .unwrap()
            .unwrap();
        let credit = original
            .reserve_scratch_bytes(std::mem::size_of::<CallbackReader>() as u64)
            .map_err(|source| StoreError::Supervision {
                source: Box::new(source),
            })?;
        Ok(Box::new(CallbackReader {
            reader: self.source.open()?,
            observations: self.observations.clone(),
            fail_at_eof: self.fail_at_eof.clone(),
            revoke_at_eof: self.revoke_at_eof.clone(),
            corrupt_first_read: self.corrupt_first_read,
            revoke_after_eof_verifications: self.revoke_after_eof_verifications,
            _credit: credit,
        }))
    }
}

struct CallbackReader {
    reader: Box<dyn std::io::Read + Send>,
    observations: Arc<AtomicU64>,
    fail_at_eof: Arc<std::sync::atomic::AtomicBool>,
    revoke_at_eof: Option<Arc<ObservedQuota>>,
    corrupt_first_read: bool,
    revoke_after_eof_verifications: u64,
    _credit: crate::owned_decode::DecodeScratch,
}

impl std::io::Read for CallbackReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        observe_original_callback(&self.observations).map_err(std::io::Error::other)?;
        let read = self.reader.read(bytes)?;
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
            return Err(std::io::Error::other(LateReadFailure));
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
    let mut work = Work::new(store.limits, &mut boundary);
    let envelope = store.read_envelope(page, &mut work).unwrap();
    assert_eq!(envelope.schema_name(), PAGE_SCHEMA);
    assert!(observations.load(Ordering::SeqCst) >= 3);
    drop(envelope);
    assert_eq!(quota.used(), baseline);

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
    assert_eq!(quota.used(), baseline);
    original.check().unwrap();
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
    let mut work = Work::new(store.limits, &mut boundary);
    let error = store.read_envelope(page, &mut work).err().unwrap();
    assert!(quota.revoked.load(Ordering::SeqCst));
    assert_eq!(decoder_failure(&error), DecoderFailure::OriginalRevocation);
    assert_eq!(
        quota.used(),
        baseline,
        "raw and retained decoder loans must both close on refusal"
    );
    // Partition failure must not poison the original ambient decoder account;
    // actual authority remains revoked and refuses a new genuine child.
    parent.check().unwrap();
    assert!(parent.child().is_err());
    drop(error);
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
        revoke_at_eof: Some(quota.clone()),
        corrupt_first_read,
        revoke_after_eof_verifications,
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
        let mut work = Work::new(store.limits, &mut boundary);
        let error = if prepaid {
            store.read_envelope(id, &mut work)
        } else {
            store.read_envelope_without_prepayment(id, &mut work)
        }
        .err()
        .unwrap();
        assert!(quota.revoked.load(Ordering::SeqCst));
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
fn eof_revocation_preserves_digest_and_preallocation_framing_error_priority() {
    use crate::content_envelope::ContentEnvelopeError;

    let incompatible = b"CRUCOBJF\0\0\0\x01";
    assert_eq!(
        revoked_decoder_comparison(incompatible, false, 0),
        [
            DecoderFailure::Envelope(ContentEnvelopeError::Incompatible),
            DecoderFailure::Envelope(ContentEnvelopeError::Incompatible),
        ]
    );
    assert_eq!(
        revoked_decoder_comparison(b"CRU", false, 0),
        [
            DecoderFailure::Envelope(ContentEnvelopeError::Truncated),
            DecoderFailure::Envelope(ContentEnvelopeError::Truncated),
        ]
    );
    let mut invalid_utf8 = b"CRUCOBJE".to_vec();
    invalid_utf8.extend_from_slice(&1_u32.to_be_bytes());
    invalid_utf8.extend_from_slice(&1_u16.to_be_bytes());
    invalid_utf8.push(0xff);
    assert_eq!(
        revoked_decoder_comparison(&invalid_utf8, false, 0),
        [
            DecoderFailure::Envelope(ContentEnvelopeError::InvalidIdentifier),
            DecoderFailure::Envelope(ContentEnvelopeError::InvalidIdentifier),
        ]
    );
    assert_eq!(
        revoked_decoder_comparison(&borrowed_valid_schema_prefix(), true, 0),
        [DecoderFailure::Digest, DecoderFailure::Digest],
        "a failed object digest must precede any decoder authority check"
    );
}

#[test]
fn later_original_admission_revocation_precedes_malformed_child_utf8() {
    let mut bytes = borrowed_valid_schema_prefix();
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(0xff);

    // Schema admission succeeds; revocation occurs at the second original
    // verification, the child-node admission before malformed role decoding.
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
    let store = directory_store(directory.path(), &quota);
    let page = page_object(&store);
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
                let mut work = Work::new(store.limits, &mut boundary);
                (work.visits, work.io_bytes) = counts;
                let reservations = quota.reservations.load(Ordering::SeqCst);
                let error = if prepaid {
                    store.read_envelope(page, &mut work)
                } else {
                    store.read_envelope_without_prepayment(page, &mut work)
                }
                .err()
                .unwrap();
                let refusal = match error {
                    RamStoreError::Canceled => "canceled",
                    RamStoreError::Limit(limit) => limit,
                    _ => panic!("unexpected scalar refusal: {error:?}"),
                };
                let observed = (
                    refusal,
                    work.visits,
                    work.io_bytes,
                    polls.get(),
                    quota.reservations.load(Ordering::SeqCst) - reservations,
                );
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
    let mut work = Work::new(store.limits, &mut boundary);
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
    let mut reader = source.open().unwrap();
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
    reader.read_exact(&mut bytes).unwrap();
    assert!(bytes.ends_with(&[7; 4096]));
    assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    drop(reader);
    assert_eq!(quota.used(), baseline);
    drop(scope);
    drop(parent);
    assert_eq!(quota.used(), store_baseline);
    drop(store);
    assert_eq!(quota.used(), 0);
}

#[test]
fn batch_array_refusal_keeps_the_original_parent_healthy_and_reusable() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let store_baseline = quota.used();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let baseline = quota.used();
    let competitor = quota
        .resources
        .reserve(0, METADATA_BYTES - baseline - 4096)
        .unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &mut boundary);
    let error = store.begin_capture_batch(&mut work).unwrap_err();
    assert!(contains_original_quota(&error));
    assert!(work.pending.is_none());
    parent.check().unwrap();
    drop(error);
    drop(competitor);
    assert_eq!(quota.used(), baseline);

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
    drop(work);
    assert_eq!(quota.used(), baseline);
    drop(scope);
    drop(parent);
    assert_eq!(quota.used(), store_baseline);
    drop(store);
    assert_eq!(quota.used(), 0);
}
