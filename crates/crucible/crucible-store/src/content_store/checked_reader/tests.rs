//! Whole-ID EOF contracts across generic verified and ranged checked sources.

use super::*;
use crate::content_store::composition::VerifiedStore;
use crate::content_store::test_resources::FixtureResourceBudget;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Quota(FixtureResourceBudget);

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.reserve(descriptors, bytes)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

fn account() -> (Arc<Quota>, DecodeBudget) {
    let quota = Arc::new(Quota(FixtureResourceBudget::new(8, 4 * 1024 * 1024)));
    let account = DecodeBudget::for_store(quota.clone()).expect("explicit finite original fixture");
    (quota, account)
}

struct ClaimedIdentitySource {
    bytes: Arc<[u8]>,
    claimed: ContentId,
    queries: Arc<AtomicUsize>,
}

impl BlobSource for ClaimedIdentitySource {
    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Owning
    }

    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(Cursor::new(self.bytes.clone())))
    }

    fn open_with_boundary(
        &self,
        caller: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        let reader = memory(self.bytes.clone(), caller, boundary)?;
        Ok(CheckedReader::new(Box::new(ClaimedIdentityReader {
            reader,
            claimed: self.claimed,
            queries: self.queries.clone(),
        })))
    }
}

struct ClaimedIdentityReader {
    reader: CheckedReader,
    claimed: ContentId,
    queries: Arc<AtomicUsize>,
}

impl CheckedBlobReader for ClaimedIdentityReader {
    fn original_account(&self) -> &DecodeBudget {
        self.reader.original_account()
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        self.reader.read_with_boundary(output, boundary)
    }

    fn full_eof_identity(&self) -> Option<ContentId> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        Some(self.claimed)
    }
}

#[test]
fn custom_reader_identity_claim_never_suppresses_actual_eof_hashing() {
    let (quota, account) = account();
    let wrong = ContentId::for_bytes(ObjectKind::Trace, 1, b"different bytes");
    let queries = Arc::new(AtomicUsize::new(0));
    let source = ClaimedIdentitySource {
        bytes: Arc::from(b"actual returned bytes".as_slice()),
        claimed: wrong,
        queries: queries.clone(),
    };
    let custom = source
        .open_with_boundary(&account, &mut || Ok(()))
        .expect("custom checked reader");

    assert_eq!(custom.full_eof_identity(), None);
    assert_eq!(queries.load(Ordering::SeqCst), 0);
    drop(custom);

    let mut handle = BlobHandle::new(source);
    handle.integrity_id = Some(wrong);
    let error = handle
        .read_all_with_boundary(&account, handle.logical_length(), &mut || Ok(()))
        .expect_err("custom claim cannot replace actual whole-object hashing");

    assert!(matches!(error, StoreError::Corrupt { id } if id == wrong));
    assert_eq!(queries.load(Ordering::SeqCst), 0);
    drop(handle);
    drop(account);
    assert_eq!(quota.0.usage().expect("remaining original loans"), (0, 0));
}

#[test]
fn audited_range_forwards_the_existing_full_identity_without_accepting_eof_early() {
    let (quota, account) = account();
    let bytes = vec![0x37; 128 * 1024 + 13];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let full = BlobHandle::from_bytes(bytes.clone())
        .verified_as(id)
        .expect("full identity");
    let mut reader = range(
        &full,
        ByteRange {
            offset: 64 * 1024 + 3,
            length: 11,
        },
        &account,
        &mut || Ok(()),
    )
    .expect("audited proper range");

    assert_eq!(reader.full_eof_identity(), Some(id));
    let output = read_owned(&mut reader, &account, 11, 11, &mut || Ok(()))
        .expect("underlying full stream reaches authenticating EOF");
    assert_eq!(&*output, &bytes[64 * 1024 + 3..64 * 1024 + 14]);

    drop(output);
    drop(reader);
    drop(full);
    drop(account);
    assert_eq!(quota.0.usage().expect("remaining original loans"), (0, 0));
}

#[test]
fn generic_verified_bytes_proper_slice_checks_full_identity_at_eof() {
    let (quota, account) = account();
    let scope = account.enter();
    let bytes = vec![0x37; 128 * 1024 + 13];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let full = BlobHandle::from_bytes(bytes.clone())
        .verified_as(id)
        .expect("full identity");
    assert!(
        !full.self_authenticating,
        "generic source does not claim backend authentication"
    );
    let range = full
        .slice(Some(ByteRange {
            offset: 64 * 1024 + 3,
            length: 11,
        }))
        .expect("proper subrange");
    let result = range
        .read_all_with_boundary(&account, 11, &mut || Ok(()))
        .expect("full stream authenticated, not range-as-full digest");
    assert_eq!(&*result, &bytes[64 * 1024 + 3..64 * 1024 + 14]);
    drop(result);
    drop(range);
    drop(full);
    drop(scope);
    drop(account);
    assert_eq!(quota.0.usage().expect("remaining original loans"), (0, 0));
}

#[derive(Clone)]
pub(super) struct GenericSource {
    pub(super) bytes: Arc<Mutex<Arc<[u8]>>>,
    length: u64,
    opens: Arc<AtomicUsize>,
}

impl BlobSource for GenericSource {
    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Owning
    }

    fn logical_length(&self) -> u64 {
        self.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(Cursor::new(
            self.bytes.lock().map_err(|_| StoreError::Quota)?.clone(),
        )))
    }

    fn open_with_boundary(
        &self,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let bytes = self.bytes.lock().map_err(|_| StoreError::Quota)?.clone();
        memory(bytes, original, boundary)
    }
}

struct GenericCheckedChild {
    id: ContentId,
    source: GenericSource,
}

impl ImmutableBlobBackend for GenericCheckedChild {
    fn name(&self) -> &str {
        "generic-checked-component"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        Ok(id == self.id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        if id != self.id {
            return Err(StoreError::NotFound { id });
        }
        BlobHandle::new(self.source.clone()).slice(range)
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        check(original, boundary)?;
        if range.is_some() {
            return Err(StoreError::Unsupported {
                capability: "generic-child-range",
            });
        }
        self.read(id, None)
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        Err(StoreError::Unsupported {
            capability: "read-only-component-source",
        })
    }
}

pub(super) fn generic(bytes: &[u8]) -> (ContentId, GenericSource, VerifiedStore) {
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    let source = GenericSource {
        bytes: Arc::new(Mutex::new(Arc::from(bytes))),
        length: bytes.len() as u64,
        opens: Arc::new(AtomicUsize::new(0)),
    };
    let child = Arc::new(GenericCheckedChild {
        id,
        source: source.clone(),
    });
    (id, source, VerifiedStore::new("verified-checked", child))
}

#[test]
fn verified_checked_generic_child_accepts_proper_range_without_range_digest() {
    let (quota, account) = account();
    let scope = account.enter();
    let bytes = vec![0x5d; 128 * 1024 + 19];
    let (id, source, verified) = generic(&bytes);
    let range = verified
        .read_with_boundary(
            &account,
            id,
            Some(ByteRange {
                offset: 64 * 1024 + 5,
                length: 7,
            }),
            &mut || Ok(()),
        )
        .expect("actual generic checked child and full verifier");
    assert!(
        !range.self_authenticating,
        "no generic authentication flag is fabricated"
    );
    let output = range
        .read_all_with_boundary(&account, 7, &mut || Ok(()))
        .expect("actual full EOF contract is forwarded");
    assert_eq!(&*output, &bytes[64 * 1024 + 5..64 * 1024 + 12]);
    assert_eq!(
        source.opens.load(Ordering::SeqCst),
        2,
        "one initial verification and one complete ranged stream, no third materialization"
    );
    drop(output);
    drop(range);
    drop(scope);
    drop(account);
    assert_eq!(quota.0.usage().expect("last reader credit"), (0, 0));
}

#[test]
fn verified_generic_range_rejects_corrupted_hidden_suffix_and_stays_failed() {
    let (_, account) = account();
    let _scope = account.enter();
    let mut bytes = vec![9; 128 * 1024 + 19];
    let (id, source, verified) = generic(&bytes);
    let range = verified
        .read_with_boundary(
            &account,
            id,
            Some(ByteRange {
                offset: 13,
                length: 7,
            }),
            &mut || Ok(()),
        )
        .expect("initial full verification");
    // Deliberate fixture corruption after verification emulates a backing
    // integrity violation without granting a different content identity.
    *bytes.last_mut().expect("hidden suffix") = 8;
    *source.bytes.lock().expect("corrupt backing") = Arc::from(bytes);
    let mut reader = range
        .open_with_boundary(&mut || Ok(()))
        .expect("fresh underlying full-ID verifier");
    let mut output = [0; 7];
    assert_eq!(
        reader
            .read_with_boundary(&mut output, &mut || Ok(()))
            .expect("valid visible prefix"),
        7
    );
    assert_eq!(output, [9; 7]);
    let error = reader
        .read_with_boundary(&mut [0; 1], &mut || Ok(()))
        .expect_err("hidden suffix must authenticate against full ID");
    assert!(matches!(error, StoreError::Corrupt { id: rejected } if rejected == id));
    assert!(
        reader
            .read_with_boundary(&mut [0; 1], &mut || Ok(()))
            .is_err(),
        "EOF corruption cannot reset"
    );
}
