//! Source-sized copy scratch, independent payer custody, and refusal ordering.
//!
//! Fixture creation and its physical files are outside this finite portable
//! model. Each source and caller retains a distinct 4 MiB/eight-FD account;
//! controls observe actual loans, stream authentication, and staging bytes.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{CheckedBlobReader, CheckedReader, StorePhysicalQuotaGuard};
use crate::owned_decode::ResourceLoan;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const RESIDENT_BYTES: u64 = 4 * 1024 * 1024;
const DESCRIPTORS: u64 = 8;

struct Quota {
    resources: FixtureResourceBudget,
    refuse_large_scratch: AtomicBool,
    closed: AtomicBool,
    last_scratch_bytes: AtomicUsize,
    before_last_scratch: AtomicUsize,
}

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::SeqCst) {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(RESIDENT_BYTES)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        if self.refuse_large_scratch.load(Ordering::SeqCst)
            && bytes >= checked_io::READ_BYTES as u64
        {
            return Err(StoreError::Quota);
        }
        let before = self.resources.usage()?.1;
        let credit = self.resources.reserve(descriptors, bytes)?;
        self.before_last_scratch
            .store(before as usize, Ordering::SeqCst);
        self.last_scratch_bytes
            .store(bytes as usize, Ordering::SeqCst);
        Ok(credit)
    }
}

fn account() -> (Arc<Quota>, DecodeBudget) {
    let quota = Arc::new(Quota {
        resources: FixtureResourceBudget::new(DESCRIPTORS, RESIDENT_BYTES),
        refuse_large_scratch: AtomicBool::new(false),
        closed: AtomicBool::new(false),
        last_scratch_bytes: AtomicUsize::new(0),
        before_last_scratch: AtomicUsize::new(0),
    });
    let original = DecodeBudget::for_store(quota.clone()).expect("finite fixture original");
    (quota, original)
}

#[derive(Default)]
struct Probe {
    first_capacity: AtomicUsize,
    first_resident: AtomicUsize,
    reads: AtomicUsize,
    eof_reads: AtomicUsize,
    revoke_after_read: AtomicBool,
}

struct Source {
    bytes: Arc<[u8]>,
    declared: u64,
    original: DecodeBudget,
    quota: Arc<Quota>,
    probe: Arc<Probe>,
}

impl BlobSource for Source {
    fn logical_length(&self) -> u64 {
        self.declared
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "source-copy-fixture-needs-original",
        })
    }

    fn open_with_boundary(
        &self,
        caller: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedReader, StoreError> {
        checked_reader::check_pair(caller, &self.original, boundary)?;
        CheckedReader::new_prepaid(
            Reader {
                bytes: self.bytes.clone(),
                offset: 0,
                original: self.original.clone(),
                quota: self.quota.clone(),
                probe: self.probe.clone(),
            },
            &self.original,
        )
    }
}

struct Reader {
    bytes: Arc<[u8]>,
    offset: usize,
    original: DecodeBudget,
    quota: Arc<Quota>,
    probe: Arc<Probe>,
}

impl CheckedBlobReader for Reader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        checked_reader::check(&self.original, boundary)?;
        assert!(!output.is_empty(), "EOF must use a nonempty buffer");
        assert!(output.len() <= checked_io::READ_BYTES);
        if self.probe.reads.fetch_add(1, Ordering::SeqCst) == 0 {
            self.probe
                .first_capacity
                .store(output.len(), Ordering::SeqCst);
            self.probe
                .first_resident
                .store(self.quota.resources.usage()?.1 as usize, Ordering::SeqCst);
        }
        let read = output.len().min(self.bytes.len() - self.offset);
        output[..read].copy_from_slice(&self.bytes[self.offset..self.offset + read]);
        self.offset += read;
        if read == 0 {
            self.probe.eof_reads.fetch_add(1, Ordering::SeqCst);
        }
        if self.probe.revoke_after_read.load(Ordering::SeqCst) {
            self.quota.closed.store(true, Ordering::SeqCst);
        }
        checked_reader::check(&self.original, boundary)?;
        Ok(read)
    }
}

fn source(
    bytes: &[u8],
    declared: u64,
    original: &DecodeBudget,
    quota: &Arc<Quota>,
    probe: &Arc<Probe>,
) -> BlobHandle {
    BlobHandle::new(Source {
        bytes: Arc::from(bytes),
        declared,
        original: original.clone(),
        quota: quota.clone(),
        probe: probe.clone(),
    })
}

#[test]
fn short_copy_retains_length_plus_one_on_the_source_account() {
    let (caller_quota, caller) = account();
    let (source_quota, source_original) = account();
    assert!(!caller.same_account(&source_original));
    let caller_baseline = caller_quota.resources.usage().expect("caller baseline");
    let source_baseline = source_quota.resources.usage().expect("source baseline");
    let probe = Arc::new(Probe::default());
    let bytes = b"small canonical source";
    let input = source(
        bytes,
        bytes.len() as u64,
        &source_original,
        &source_quota,
        &probe,
    );
    source_quota
        .refuse_large_scratch
        .store(true, Ordering::SeqCst);
    let output = tempfile::tempfile().expect("fixture output outside original model");
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);

    copy(&caller, id, &input, Some((Ok(&output), 0)), &mut || Ok(()))
        .expect("short source needs fewer actual scratch bytes");

    assert_eq!(probe.first_capacity.load(Ordering::SeqCst), bytes.len() + 1);
    assert_eq!(
        probe.first_resident.load(Ordering::SeqCst) as u64,
        source_quota.before_last_scratch.load(Ordering::SeqCst) as u64 + bytes.len() as u64 + 1,
    );
    assert_eq!(
        source_quota.last_scratch_bytes.load(Ordering::SeqCst),
        bytes.len() + 1
    );
    assert!(
        source_quota.before_last_scratch.load(Ordering::SeqCst) as u64 > source_baseline.1,
        "both actual reader controls precede the scratch loan"
    );
    assert_eq!(probe.eof_reads.load(Ordering::SeqCst), 1);
    let mut published = vec![0; bytes.len()];
    output
        .read_exact_at(&mut published, 0)
        .expect("actual copied bytes");
    assert_eq!(published, bytes);
    assert_eq!(
        caller_quota.resources.usage().expect("caller credit"),
        caller_baseline
    );
    assert_eq!(
        source_quota
            .resources
            .usage()
            .expect("closed source scratch"),
        source_baseline
    );
}

#[test]
fn scratch_bound_covers_empty_short_and_large_sources_with_actual_eof() {
    for length in [
        0,
        1,
        checked_io::READ_BYTES - 2,
        checked_io::READ_BYTES - 1,
        checked_io::READ_BYTES,
        checked_io::READ_BYTES + 1,
    ] {
        let (caller_quota, caller) = account();
        let (source_quota, original) = account();
        let baseline = source_quota.resources.usage().expect("source baseline");
        let caller_baseline = caller_quota.resources.usage().expect("caller baseline");
        let probe = Arc::new(Probe::default());
        let bytes = vec![0x39; length];
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
        let input = source(&bytes, length as u64, &original, &source_quota, &probe);

        copy(&caller, id, &input, None, &mut || Ok(())).expect("complete checked source");

        assert_eq!(
            probe.first_capacity.load(Ordering::SeqCst),
            (length + 1).min(checked_io::READ_BYTES)
        );
        assert_eq!(probe.eof_reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            source_quota.resources.usage().expect("source close"),
            baseline
        );
        assert_eq!(
            caller_quota.resources.usage().expect("caller close"),
            caller_baseline
        );
    }
}

#[test]
fn surplus_byte_refuses_before_any_declared_prefix_is_written() {
    for declared in [0_u64, 2] {
        let (_, caller) = account();
        let (quota, original) = account();
        let baseline = quota.resources.usage().expect("source baseline");
        let probe = Arc::new(Probe::default());
        let bytes = b"abc";
        let input = source(bytes, declared, &original, &quota, &probe);
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes[..declared as usize]);
        let output = tempfile::tempfile().expect("fixture staging");
        output
            .write_all_at(b"sentinel", 0)
            .expect("staging predecessor");

        let error = copy(&caller, id, &input, Some((Ok(&output), 0)), &mut || Ok(()))
            .expect_err("surplus first read must refuse before write");

        assert!(matches!(
            error,
            StoreError::InvalidSourceLength { declared: actual, observed }
                if actual == declared && observed == declared + 1
        ));
        let mut unchanged = [0_u8; 8];
        output
            .read_exact_at(&mut unchanged, 0)
            .expect("staging observation");
        assert_eq!(&unchanged, b"sentinel");
        assert_eq!(probe.reads.load(Ordering::SeqCst), 1);
        assert_eq!(probe.eof_reads.load(Ordering::SeqCst), 0);
        assert_eq!(quota.resources.usage().expect("scratch closed"), baseline);
    }
}

#[test]
fn fullhash_failure_and_postread_source_refusal_keep_the_actual_cause() {
    let (_, caller) = account();
    let (quota, original) = account();
    let baseline = quota.resources.usage().expect("source baseline");
    let probe = Arc::new(Probe::default());
    let input = source(b"wrong", 5, &original, &quota, &probe);
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"right");
    let error = copy(&caller, id, &input, None, &mut || Ok(()))
        .expect_err("unaudited reader must authenticate the whole hash");
    assert!(matches!(error, StoreError::Corrupt { id: actual } if actual == id));
    assert_eq!(probe.eof_reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        quota.resources.usage().expect("hash failure scratch close"),
        baseline
    );

    let probe = Arc::new(Probe::default());
    probe.revoke_after_read.store(true, Ordering::SeqCst);
    let input = source(b"right", 5, &original, &quota, &probe);
    let output = tempfile::tempfile().expect("fixture staging");
    let error = copy(&caller, id, &input, Some((Ok(&output), 0)), &mut || Ok(()))
        .expect_err("the source original postcut precedes output");
    let StoreError::DecodeAdmission { source: cause, .. } = &error else {
        panic!("retain source original refusal: {error:?}");
    };
    assert!(matches!(
        std::error::Error::source(cause).and_then(|cause| cause.downcast_ref::<StoreError>()),
        Some(StoreError::Unauthorized)
    ));
    assert_eq!(output.metadata().expect("staging metadata").len(), 0);
    assert_eq!(
        quota.resources.usage().expect("refusal scratch close"),
        baseline
    );
    caller
        .verify_live()
        .expect("independent caller remains live");
}

#[test]
fn large_source_scratch_refusal_closes_reader_before_any_read_or_write() {
    let (caller_quota, caller) = account();
    let (quota, original) = account();
    let baseline = quota.resources.usage().expect("source baseline");
    let caller_baseline = caller_quota.resources.usage().expect("caller baseline");
    let probe = Arc::new(Probe::default());
    let bytes = vec![0x73; checked_io::READ_BYTES];
    let input = source(&bytes, bytes.len() as u64, &original, &quota, &probe);
    quota.refuse_large_scratch.store(true, Ordering::SeqCst);
    let output = tempfile::tempfile().expect("fixture staging");
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);

    let error = copy(&caller, id, &input, Some((Ok(&output), 0)), &mut || Ok(()))
        .expect_err("actual source scratch quota refuses before reading");

    let StoreError::DecodeAdmission { source: cause, .. } = &error else {
        panic!("retain source scratch admission: {error:?}");
    };
    assert!(matches!(
        std::error::Error::source(cause).and_then(|cause| cause.downcast_ref::<StoreError>()),
        Some(StoreError::Quota)
    ));
    assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
    assert_eq!(output.metadata().expect("staging metadata").len(), 0);
    assert_eq!(quota.resources.usage().expect("reader close"), baseline);
    assert_eq!(
        caller_quota.resources.usage().expect("caller credit"),
        caller_baseline
    );
    caller
        .verify_live()
        .expect("independent caller remains live");
}

#[test]
fn initiating_boundary_cause_precedes_later_length_and_hash_refusal() {
    let (_, caller) = account();
    let (quota, original) = account();
    let baseline = quota.resources.usage().expect("source baseline");
    let probe = Arc::new(Probe::default());
    let input = source(b"surplus", 2, &original, &quota, &probe);
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"ok");
    let initiating_id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"boundary cause");
    let output = tempfile::tempfile().expect("fixture staging");

    let error = copy(&caller, id, &input, Some((Ok(&output), 0)), &mut || {
        if probe.reads.load(Ordering::SeqCst) != 0 {
            Err(StoreError::Corrupt { id: initiating_id })
        } else {
            Ok(())
        }
    })
    .expect_err("actual first boundary cause must precede later stream failure");

    assert!(matches!(error, StoreError::Corrupt { id: actual } if actual == initiating_id));
    assert_eq!(output.metadata().expect("staging metadata").len(), 0);
    assert_eq!(probe.reads.load(Ordering::SeqCst), 1);
    assert_eq!(probe.eof_reads.load(Ordering::SeqCst), 0);
    assert_eq!(quota.resources.usage().expect("scratch close"), baseline);
}
