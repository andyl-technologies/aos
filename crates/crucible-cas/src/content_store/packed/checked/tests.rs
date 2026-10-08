//! Checked pack authentication, original refusal, and pinned alias controls.
//!
//! Fixture construction is outside the finite original model. These tests
//! observe descriptor counters and checked behavior, not native quota install
//! or allocation closure of the surrounding fixture and allocator controls.

use super::*;
use crate::content_store::StorePhysicalQuotaGuard;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::{DecodeAdmissionError, ResourceLoan};
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::TempDir;

const RESIDENT_BYTES: u64 = 4 * 1024 * 1024;
const DESCRIPTORS: u64 = 8;

struct Quota {
    resources: FixtureResourceBudget,
    closed: AtomicBool,
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
        self.resources.reserve(descriptors, bytes)
    }
}

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Decode(#[from] DecodeAdmissionError),
}

struct Fixture {
    _root: TempDir,
    backend: PackedBlobBackend,
    quota: Arc<Quota>,
    original: DecodeBudget,
    id: ContentId,
}

impl Fixture {
    fn new(bytes: &[u8]) -> Result<Self, FixtureError> {
        let root = TempDir::new()?;
        let backend =
            PackedBlobBackend::open("checked-packed", root.path(), MIN_TARGET_PACK_BYTES)?;
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
        backend.put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))?;
        let quota = Arc::new(Quota {
            resources: FixtureResourceBudget::new(DESCRIPTORS, RESIDENT_BYTES),
            closed: AtomicBool::new(false),
        });
        let original = DecodeBudget::for_store(quota.clone())?;
        Ok(Self {
            _root: root,
            backend,
            quota,
            original,
            id,
        })
    }
}

#[test]
fn checked_pack_chunks_and_ranges_authenticate_and_keep_old_inodes_after_repack() {
    let bytes = vec![0x47; 192 * 1024];
    let fixture = Fixture::new(&bytes).unwrap();
    let baseline = fixture.quota.resources.usage().unwrap();
    let handle = lookup(
        &fixture.backend,
        &fixture.original,
        fixture.id,
        None,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(fixture.quota.resources.usage().unwrap().0, 1);
    let alias = handle.clone();
    let mut reader =
        BlobSource::open_with_boundary(&handle, &fixture.original, &mut || Ok(())).unwrap();
    let mut output = vec![0; READ_BYTES * 2];
    assert_eq!(
        reader
            .read_with_boundary(&mut output, &mut || Ok(()))
            .unwrap(),
        READ_BYTES
    );
    assert_eq!(&output[..READ_BYTES], &bytes[..READ_BYTES]);
    drop(handle);
    let plan = fixture.backend.plan_repack().unwrap();
    fixture.backend.apply_repack(&plan).unwrap();
    assert_eq!(
        &*alias
            .read_all_with_boundary(&fixture.original, bytes.len() as u64, &mut || Ok(()))
            .unwrap(),
        &bytes
    );
    drop(reader);
    drop(alias);
    assert_eq!(fixture.quota.resources.usage().unwrap(), baseline);

    let range = ByteRange::new(73, 4097).unwrap();
    let ranged = lookup(
        &fixture.backend,
        &fixture.original,
        fixture.id,
        Some(range),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        &*ranged
            .read_all_with_boundary(&fixture.original, bytes.len() as u64, &mut || Ok(()))
            .unwrap(),
        &bytes[73..73 + 4097]
    );
}

#[test]
fn poisoned_original_refuses_before_callbacks_or_descriptor_effects() {
    let fixture = Fixture::new(b"first refusal remains original").unwrap();
    let baseline = fixture.quota.resources.usage().unwrap();
    let refusal = DecodeAdmissionError::new(StoreError::Quota);
    fixture.original.record_failure(refusal.clone());
    let mut callbacks = 0;
    let result = lookup(
        &fixture.backend,
        &fixture.original,
        fixture.id,
        None,
        &mut || {
            callbacks += 1;
            Ok(())
        },
    );
    let Err(StoreError::DecodeAdmission { source, .. }) = result else {
        panic!("retain the poisoned original refusal")
    };
    assert_eq!(source, refusal);
    assert_eq!(callbacks, 0);
    assert_eq!(fixture.quota.resources.usage().unwrap(), baseline);
}

#[test]
fn contended_state_lock_polls_original_and_closes_both_descriptor_loans_on_refusal() {
    let fixture = Fixture::new(b"lock contention").unwrap();
    let baseline = fixture.quota.resources.usage().unwrap();
    let held = fixture.backend.lock_state().unwrap();
    let mut polls = 0;
    let result = lookup(
        &fixture.backend,
        &fixture.original,
        fixture.id,
        None,
        &mut || {
            if fixture.quota.resources.usage().unwrap().0 == 2 {
                polls += 1;
                if polls == 5 {
                    return Err(StoreError::Unauthorized);
                }
            }
            Ok(())
        },
    );
    assert!(matches!(result, Err(StoreError::Unauthorized)));
    assert_eq!(polls, 5);
    assert_eq!(fixture.quota.resources.usage().unwrap(), baseline);
    drop(held);
    fixture.original.verify_live().unwrap();
}

#[test]
fn distinct_caller_cannot_hide_source_poison_before_actual_read() {
    let fixture = Fixture::new(b"source stays authoritative").unwrap();
    let handle = lookup(
        &fixture.backend,
        &fixture.original,
        fixture.id,
        None,
        &mut || Ok(()),
    )
    .unwrap();
    let caller_quota = Arc::new(Quota {
        resources: FixtureResourceBudget::new(DESCRIPTORS, RESIDENT_BYTES),
        closed: AtomicBool::new(false),
    });
    let caller = DecodeBudget::for_store(caller_quota).unwrap();
    let mut reader = BlobSource::open_with_boundary(&handle, &caller, &mut || Ok(())).unwrap();
    let refusal = DecodeAdmissionError::new(StoreError::Quota);
    let mut callbacks = 0;
    let mut output = [0xa5; 64];
    let result = reader.read_with_boundary(&mut output, &mut || {
        callbacks += 1;
        if callbacks == 2 {
            fixture.original.record_failure(refusal.clone());
        }
        Ok(())
    });
    let Err(StoreError::DecodeAdmission { source, .. }) = result else {
        panic!("retain actual source refusal during inner preflight")
    };
    assert_eq!(source, refusal);
    assert_eq!(output, [0xa5; 64]);
    assert!(
        reader
            .read_with_boundary(&mut output, &mut || Ok(()))
            .is_err()
    );
    caller.verify_live().unwrap();
}

#[test]
fn checksum_failure_keeps_existing_manifest_error_order() {
    let fixture = Fixture::new(b"manifest failure before logical byte authentication").unwrap();
    let index = fixture.backend.load_index().unwrap();
    let entry = index.entries.get(&fixture.id).unwrap();
    let path = fixture.backend.pack_path(entry.pack);
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.write_at(&[0xff], (PACK_MAGIC.len() + 32 + 4 + 4) as u64)
        .unwrap();
    assert!(matches!(
        fixture.backend.read(fixture.id, None),
        Err(StoreError::Incompatible)
    ));
    assert!(matches!(
        lookup(
            &fixture.backend,
            &fixture.original,
            fixture.id,
            None,
            &mut || Ok(())
        ),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn checked_publication_restarts_retries_and_keeps_exact_v1_index_bytes() {
    let fixture = Fixture::new(b"prior durable object").unwrap();
    let baseline = fixture.quota.resources.usage().unwrap();
    let bytes = vec![0x63; 192 * 1024];
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
    let old = fixture.backend.load_index().unwrap();
    let snapshot =
        index_snapshot::IndexSnapshot::load(&fixture.backend, &fixture.original, &mut || Ok(()))
            .unwrap();
    let entry = IndexEntry {
        pack: PackId([7; 32]),
        offset: pack_fixed_header_length() + 2 + id.encode().len() as u64 + 16,
        length: bytes.len() as u64,
    };
    let encoded = snapshot
        .inserted(&fixture.backend, id, entry, &fixture.original, &mut || {
            Ok(())
        })
        .unwrap();
    let mut expected = old;
    expected.entries.insert(id, entry);
    expected.generation += 1;
    expected.last_repack_plan = None;
    assert_eq!(
        encoded.bytes(),
        encode_index(&expected, fixture.backend.configuration).unwrap()
    );
    drop(encoded);
    drop(snapshot);

    let source = BlobHandle::from_bytes(bytes.clone());
    let receipt = fixture
        .backend
        .put_many_if_absent_with_boundary(
            &fixture.original,
            &[(id, source.clone())],
            &mut || Ok(()),
        )
        .unwrap()
        .accept_with_boundary(&mut || Ok(()))
        .unwrap();
    assert_eq!(receipt.len(), 1);
    assert_eq!(receipt[0].id, id);
    assert!(receipt[0].placements[0].durable);
    assert_eq!(fixture.quota.resources.usage().unwrap().0, 0);
    drop(receipt);
    assert_eq!(fixture.quota.resources.usage().unwrap(), baseline);
    let restarted = PackedBlobBackend::open(
        "checked-packed",
        fixture._root.path(),
        MIN_TARGET_PACK_BYTES,
    )
    .unwrap();
    let handle = restarted
        .read_with_boundary(&fixture.original, id, None, &mut || Ok(()))
        .unwrap();
    assert_eq!(
        &*handle
            .read_all_with_boundary(&fixture.original, bytes.len() as u64, &mut || Ok(()))
            .unwrap(),
        &bytes
    );
    drop(handle);
    let generation = restarted.load_index().unwrap().generation;
    let retry = restarted
        .put_many_if_absent_with_boundary(&fixture.original, &[(id, source)], &mut || Ok(()))
        .unwrap();
    assert_eq!(retry.len(), 1);
    assert_eq!(restarted.load_index().unwrap().generation, generation);
}

#[test]
fn checked_publication_rejects_corrupt_source_and_closes_staging_before_credit_refund() {
    let fixture = Fixture::new(b"prior object").unwrap();
    let old_index = fs::read(fixture.backend.index_path()).unwrap();
    let baseline = fixture.quota.resources.usage().unwrap();
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"expected source");
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(
            &fixture.original,
            &[(id, BlobHandle::from_bytes(b"incorrect source".to_vec()))],
            &mut || Ok(()),
        )
        .err()
        .unwrap();
    let StoreError::PackedScope { source } = &error else {
        panic!("own Packed scope")
    };
    assert!(
        matches!(source.work_failure(), Some(StoreError::Corrupt { id: actual }) if *actual == id)
    );
    assert_eq!(source.outcome(), PackedPublicationOutcome::default());
    assert_eq!(source.cleanup_failures().count(), 0);
    assert_eq!(fs::read(fixture.backend.index_path()).unwrap(), old_index);
    assert_eq!(fs::read_dir(&fixture.backend.packs).unwrap().count(), 1);
    assert_eq!(fixture.quota.resources.usage().unwrap().0, 0);
    drop(error);
    assert_eq!(fixture.quota.resources.usage().unwrap(), baseline);
}

#[test]
fn checked_publication_retains_pack_visibility_and_exact_callback_refusal_before_index() {
    let fixture = Fixture::new(b"prior object").unwrap();
    let old_index = fs::read(fixture.backend.index_path()).unwrap();
    let bytes = b"new complete pack before index publication";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    let input = BlobHandle::from_bytes(bytes.to_vec());
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(&fixture.original, &[(id, input.clone())], &mut || {
            let complete = fs::read_dir(&fixture.backend.packs)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "pack")
                })
                .count();
            if complete == 2 {
                Err(StoreError::Unauthorized)
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    let StoreError::PackedScope { source } = &error else {
        panic!("own physical Packed outcome")
    };
    assert!(matches!(
        source.first_boundary(),
        Some(StoreError::Unauthorized)
    ));
    assert_eq!(source.outcome().published_packs, 1);
    assert!(source.outcome().pack_visibility_uncertain);
    assert!(!source.outcome().index_visibility_uncertain);
    assert_eq!(source.outcome().durable_objects, 0);
    assert_eq!(fs::read(fixture.backend.index_path()).unwrap(), old_index);
    assert_eq!(fixture.quota.resources.usage().unwrap().0, 0);
    drop(error);
    fixture.original.verify_live().unwrap();
    let retry = fixture
        .backend
        .put_many_if_absent_with_boundary(&fixture.original, &[(id, input)], &mut || Ok(()))
        .unwrap();
    assert_eq!(retry.len(), 1);
    assert_eq!(fixture.backend.load_index().unwrap().entries.len(), 2);
}

#[test]
fn checked_publication_keeps_original_poison_and_index_uncertainty_after_rename() {
    let fixture = Fixture::new(b"prior object").unwrap();
    let bytes = b"index transition with an expired original";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(
            &fixture.original,
            &[(id, BlobHandle::from_bytes(bytes.to_vec()))],
            &mut || {
                let bytes = fs::read(fixture.backend.index_path()).unwrap();
                if decode_index(&bytes, fixture.backend.configuration)
                    .unwrap()
                    .entries
                    .contains_key(&id)
                {
                    fixture.quota.closed.store(true, Ordering::SeqCst);
                    // Preserve the actual same-guard refusal as the original's
                    // sticky first cause, rather than assume verify_live caches it.
                    let refusal = fixture.original.verify_live().err().unwrap();
                    fixture.original.record_failure(refusal);
                }
                Ok(())
            },
        )
        .err()
        .unwrap();
    let first = fixture.original.check().err().unwrap();
    let StoreError::PackedScope { source } = &error else {
        panic!("retain index uncertainty")
    };
    let Some(StoreError::DecodeAdmission { source: actual, .. }) = source.work_failure() else {
        panic!("retain actual original refusal")
    };
    assert_eq!(*actual, first);
    assert_eq!(source.outcome().published_packs, 1);
    assert!(source.outcome().index_visibility_uncertain);
    assert_eq!(source.outcome().durable_objects, 0);
    assert_eq!(fixture.quota.resources.usage().unwrap().0, 0);
    let mut callbacks = 0;
    let refused = fixture.backend.put_many_if_absent_with_boundary(
        &fixture.original,
        &[(id, BlobHandle::from_bytes(bytes.to_vec()))],
        &mut || {
            callbacks += 1;
            Ok(())
        },
    );
    let Err(StoreError::DecodeAdmission { source, .. }) = refused else {
        panic!("same original stays poisoned")
    };
    assert_eq!(source, first);
    assert_eq!(callbacks, 0);
}

#[test]
fn checked_publication_does_not_open_an_opaque_raw_source() {
    struct Opaque(Arc<std::sync::atomic::AtomicUsize>);
    impl BlobSource for Opaque {
        fn logical_length(&self) -> u64 {
            3
        }
        fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(std::io::Cursor::new(b"raw")))
        }
    }
    let fixture = Fixture::new(b"prior object").unwrap();
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"raw");
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(
            &fixture.original,
            &[(id, BlobHandle::new(Opaque(opens.clone())))],
            &mut || Ok(()),
        )
        .err()
        .unwrap();
    assert!(matches!(
        error.original_failure(),
        StoreError::Unsupported { .. }
    ));
    assert_eq!(opens.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.backend.load_index().unwrap().entries.len(), 1);
    assert_eq!(fs::read_dir(&fixture.backend.packs).unwrap().count(), 1);
    assert_eq!(fixture.quota.resources.usage().unwrap().0, 0);
}

struct SwallowingSource {
    reading: Arc<AtomicBool>,
    return_distinct_error: bool,
}

impl BlobSource for SwallowingSource {
    fn logical_length(&self) -> u64 {
        b"one-shot callback".len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "swallowing-fixture-needs-original",
        })
    }

    fn open_with_boundary(
        &self,
        original: &DecodeBudget,
        _boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crate::content_store::CheckedReader, StoreError> {
        crate::content_store::CheckedReader::new_prepaid(
            SwallowingReader {
                original: original.clone(),
                reading: self.reading.clone(),
                bytes: b"one-shot callback",
                return_distinct_error: self.return_distinct_error,
            },
            original,
        )
    }
}

struct SwallowingReader {
    original: DecodeBudget,
    reading: Arc<AtomicBool>,
    bytes: &'static [u8],
    return_distinct_error: bool,
}

impl crate::content_store::CheckedBlobReader for SwallowingReader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        self.reading.store(true, Ordering::SeqCst);
        let _swallowed_refusal = boundary();
        if self.return_distinct_error {
            return Err(StoreError::StreamIo {
                operation: "distinct-swallowing-source-failure",
                source: std::io::Error::from_raw_os_error(5),
            });
        }
        self.bytes
            .read(output)
            .map_err(|source| StoreError::StreamIo {
                operation: "swallowing-fixture-read",
                source,
            })
    }
}

#[test]
fn checked_publication_keeps_one_shot_refusal_even_when_reader_swallows_it() {
    for return_distinct_error in [false, true] {
        let fixture = Fixture::new(b"prior object").unwrap();
        let baseline = fixture.quota.resources.usage().unwrap();
        let old_index = fs::read(fixture.backend.index_path()).unwrap();
        let reading = Arc::new(AtomicBool::new(false));
        let input = BlobHandle::new(SwallowingSource {
            reading: reading.clone(),
            return_distinct_error,
        });
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"one-shot callback");
        let mut refused = false;
        let mut calls_after_refusal = 0;

        let error = fixture
            .backend
            .put_many_if_absent_with_boundary(&fixture.original, &[(id, input)], &mut || {
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
        let StoreError::PackedScope { source } = &error else {
            panic!("retain callback and distinct source together")
        };
        assert!(matches!(
            source.first_boundary(),
            Some(StoreError::Unauthorized)
        ));
        if return_distinct_error {
            let Some(StoreError::StreamIo { operation, source }) = source.work_failure() else {
                panic!("retain actual distinct source error")
            };
            assert_eq!(*operation, "distinct-swallowing-source-failure");
            assert_eq!(source.raw_os_error(), Some(5));
        } else {
            assert!(source.work_failure().is_none());
        }
        assert_eq!(source.outcome(), PackedPublicationOutcome::default());
        assert_eq!(source.cleanup_failures().count(), 0);
        assert_eq!(fs::read(fixture.backend.index_path()).unwrap(), old_index);
        assert_eq!(fs::read_dir(&fixture.backend.packs).unwrap().count(), 1);
        assert_eq!(fixture.quota.resources.usage().unwrap().0, 0);
        drop(error);
        assert_eq!(fixture.quota.resources.usage().unwrap(), baseline);
    }
}

#[test]
fn checked_publication_projects_actual_cleanup_when_completed_work_has_no_failure() {
    let fixture = Fixture::new(b"prior object").unwrap();
    let baseline = fixture.quota.resources.usage().unwrap();
    let bytes = b"durable object with failed staging cleanup";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    let mut replaced = None;

    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(
            &fixture.original,
            &[(id, BlobHandle::from_bytes(bytes.to_vec()))],
            &mut || {
                if replaced.is_none()
                    && fs::read_dir(&fixture.backend.packs)
                        .unwrap()
                        .filter_map(Result::ok)
                        .filter(|entry| {
                            entry
                                .path()
                                .extension()
                                .is_some_and(|value| value == "pack")
                        })
                        .count()
                        == 2
                {
                    // The test actor replaces only the already linked pack's
                    // exclusive temporary name, forcing real remove_file failure.
                    let path = fs::read_dir(&fixture.backend.packs)
                        .unwrap()
                        .filter_map(Result::ok)
                        .find(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".pack.tmp-")
                        })
                        .unwrap()
                        .path();
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                    replaced = Some(path);
                }
                Ok(())
            },
        )
        .err()
        .unwrap();

    let StoreError::PackedScope { source } = &error else {
        panic!("retain real cleanup-only failure")
    };
    assert!(source.first_boundary().is_none());
    assert!(source.work_failure().is_none());
    assert_eq!(source.cleanup_failures().count(), 1);
    let StoreError::StreamIo {
        operation,
        source: cleanup,
    } = error.original_failure()
    else {
        panic!("actual cleanup is the first typed failure")
    };
    assert_eq!(*operation, "remove-packed-checked-staging");
    assert_eq!(cleanup.kind(), std::io::ErrorKind::IsADirectory);
    assert_eq!(source.outcome().durable_objects, 1);
    assert!(source.outcome().staging_cleanup_pending);
    assert!(!source.outcome().index_visibility_uncertain);
    assert!(
        fixture
            .backend
            .load_index()
            .unwrap()
            .entries
            .contains_key(&id)
    );
    assert_eq!(fixture.quota.resources.usage().unwrap().0, 0);
    drop(error);
    assert_eq!(fixture.quota.resources.usage().unwrap(), baseline);
    fs::remove_dir(replaced.unwrap()).unwrap();
}

#[derive(Default)]
struct DescriptorCloseProbe {
    armed: AtomicBool,
    path: std::sync::Mutex<Option<PathBuf>>,
    charged_at_refund: std::sync::atomic::AtomicU64,
    physically_closed: AtomicBool,
}

struct CloseObservedQuota {
    resources: Arc<FixtureResourceBudget>,
    probe: Arc<DescriptorCloseProbe>,
}

impl StorePhysicalQuotaGuard for CloseObservedQuota {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(RESIDENT_BYTES)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let loan = self.resources.reserve(descriptors, bytes)?;
        if descriptors == 0 {
            return Ok(loan);
        }
        Ok(ResourceLoan::new(CloseObservedLoan {
            _loan: loan,
            resources: self.resources.clone(),
            probe: self.probe.clone(),
        }))
    }
}

struct CloseObservedLoan {
    _loan: ResourceLoan,
    resources: Arc<FixtureResourceBudget>,
    probe: Arc<DescriptorCloseProbe>,
}

impl Drop for CloseObservedLoan {
    fn drop(&mut self) {
        if !self.probe.armed.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Ok((charged, _)) = self.resources.usage() {
            self.probe
                .charged_at_refund
                .store(charged, Ordering::SeqCst);
        }
        if let Ok(path) = self.probe.path.lock()
            && let Some(path) = path.as_deref()
        {
            self.probe.physically_closed.store(
                matches!(fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                Ordering::SeqCst,
            );
        }
    }
}

#[test]
fn final_pin_boundary_refusal_closes_real_file_before_same_original_descriptor_refund() {
    // This observer's controls and proc-directory scan are test infrastructure,
    // outside the original model. It observes a real fd and the same finite
    // charged loan; it does not establish native project quota or System-free.
    let fixture = Fixture::new(b"physical pin close witness").unwrap();
    let index = fixture.backend.load_index().unwrap();
    let entry = *index.entries.get(&fixture.id).unwrap();
    let target = fixture.backend.pack_path(entry.pack);
    let resources = Arc::new(FixtureResourceBudget::new(DESCRIPTORS, RESIDENT_BYTES));
    let probe = Arc::new(DescriptorCloseProbe::default());
    let original = DecodeBudget::for_store(Arc::new(CloseObservedQuota {
        resources: resources.clone(),
        probe: probe.clone(),
    }))
    .unwrap();
    let baseline = resources.usage().unwrap();
    let mut callbacks = 0;
    let handle = open_entry(
        &fixture.backend,
        &original,
        fixture.id,
        entry,
        None,
        &mut || {
            callbacks += 1;
            Ok(())
        },
    )
    .unwrap();
    drop(handle);
    assert_eq!(resources.usage().unwrap(), baseline);
    assert!(callbacks >= 2);
    let handoff_boundary = callbacks - 1;

    for unwind in [false, true] {
        probe.charged_at_refund.store(0, Ordering::SeqCst);
        probe.physically_closed.store(false, Ordering::SeqCst);
        let mut at = 0;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            open_entry(
                &fixture.backend,
                &original,
                fixture.id,
                entry,
                None,
                &mut || {
                    at += 1;
                    if at == handoff_boundary {
                        let descriptor_path = fs::read_dir("/proc/self/fd")
                            .unwrap()
                            .filter_map(Result::ok)
                            .map(|entry| entry.path())
                            .find(|path| fs::read_link(path).is_ok_and(|link| link == target))
                            .unwrap();
                        assert!(fs::symlink_metadata(&descriptor_path).is_ok());
                        assert_eq!(resources.usage().unwrap().0, 1);
                        *probe.path.lock().unwrap() = Some(descriptor_path);
                        probe.armed.store(true, Ordering::SeqCst);
                        if unwind {
                            panic!("intentional exact pre-pin boundary unwind");
                        }
                        return Err(StoreError::Unauthorized);
                    }
                    Ok(())
                },
            )
        }));

        assert_eq!(at, handoff_boundary);
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(Err(StoreError::Unauthorized))));
        }
        assert_eq!(probe.charged_at_refund.load(Ordering::SeqCst), 1);
        assert!(probe.physically_closed.load(Ordering::SeqCst));
        assert!(!probe.armed.load(Ordering::SeqCst));
        assert_eq!(resources.usage().unwrap(), baseline);
        original.verify_live().unwrap();
    }
}
