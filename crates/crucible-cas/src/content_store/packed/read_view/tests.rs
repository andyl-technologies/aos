//! Real Packed pin, EOF, corruption and original-account read-view controls.

use super::*;
use crate::content_store::StorePhysicalQuotaGuard;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::ResourceLoan;
use std::os::unix::fs::FileExt;

const BYTES: u64 = 4 << 20;
const FDS: u64 = 8;

struct Quota(FixtureResourceBudget);

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(BYTES)
    }

    fn reserve_resources(&self, fds: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.reserve(fds, bytes)
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    backend: PackedBlobBackend,
    original: DecodeBudget,
    quota: Arc<Quota>,
    objects: Vec<(ContentId, BlobHandle)>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let backend =
            PackedBlobBackend::open("view", directory.path(), MIN_TARGET_PACK_BYTES).unwrap();
        let quota = Arc::new(Quota(FixtureResourceBudget::new(FDS, BYTES)));
        let original = DecodeBudget::for_store(quota.clone()).unwrap();
        let objects = (0_u64..128)
            .map(|index| {
                let bytes = index.to_be_bytes().repeat(3);
                (
                    ContentId::for_bytes(ObjectKind::Trace, 1, &bytes),
                    BlobHandle::from_bytes(bytes),
                )
            })
            .collect::<Vec<_>>();
        for batch in objects.chunks(64) {
            let receipt = backend
                .put_many_if_absent_with_boundary(&original, batch, &mut || Ok(()))
                .unwrap();
            drop(receipt.accept_with_boundary(&mut || Ok(())).unwrap());
        }
        Self {
            _directory: directory,
            backend,
            original,
            quota,
            objects,
        }
    }
}

#[test]
fn pinned_view_reuses_one_pack_and_keeps_actual_sources_after_view_close() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    assert!(view.snapshot.header.arena.is_some());
    let mut saved = None;
    for (id, expected) in &fixture.objects {
        let handle = reader
            .lookup(&fixture.backend, &fixture.original, *id, &mut || Ok(()))
            .unwrap();
        let bytes = handle
            .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
            .unwrap();
        assert_eq!(&*bytes, &*expected.read_all(24).unwrap());
        assert_eq!(fixture.quota.0.usage().unwrap().0, 4);
        if fixture.objects.last().map(|object| object.0) == Some(*id) {
            saved = Some(handle);
        }
    }
    drop(reader);
    drop(view);
    assert_eq!(fixture.quota.0.usage().unwrap().0, 1);
    let handle = saved.unwrap();
    assert_eq!(
        handle
            .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
            .unwrap()
            .len(),
        24
    );
    drop(handle);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn actual_pack_mutation_refuses_cached_metadata_and_old_handle_at_eof() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    let id = fixture.objects[0].0;
    let handle = reader
        .lookup(&fixture.backend, &fixture.original, id, &mut || Ok(()))
        .unwrap();
    let pack = reader.last_pack.as_ref().unwrap();
    let position = pack
        .entries
        .binary_search_by_key(&id, |entry| entry.id)
        .unwrap();
    let entry = &pack.entries[position];
    let name = index_io::pack_name(pack.id);
    let path = fixture
        .backend
        .packs
        .join(std::str::from_utf8(&name).unwrap());
    let writable = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    writable.write_all_at(&[0xee], entry.offset).unwrap();
    drop(writable);
    assert!(
        matches!(reader.lookup(&fixture.backend, &fixture.original, id, &mut || Ok(())), Err(StoreError::Corrupt { id: found }) if found == id)
    );
    assert!(
        matches!(handle.read_all_with_boundary(&fixture.original, 24, &mut || Ok(())), Err(StoreError::Corrupt { id: found }) if found == id)
    );
    drop(handle);
    drop(reader);
    drop(view);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn original_refusal_and_unwind_close_view_fds_and_all_paid_buffers() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
        let mut reader = view
            .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
            .unwrap();
        let id = fixture.objects[0].0;
        let handle = reader
            .lookup(&fixture.backend, &fixture.original, id, &mut || Ok(()))
            .unwrap();
        drop(handle);
        let error = reader
            .lookup(&fixture.backend, &fixture.original, id, &mut || {
                Err(StoreError::Unauthorized)
            })
            .err()
            .unwrap();
        assert!(matches!(error, StoreError::Unauthorized));
        panic!("actual view unwind");
    }));
    assert!(outcome.is_err());
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
    let all = fixture
        .quota
        .0
        .reserve(FDS - baseline.0, BYTES - baseline.1)
        .unwrap();
    drop(all);
}

#[test]
fn corrupt_committed_root_prefix_refuses_before_any_pack_source() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let root = fixture.backend.admin.join(INDEX_FILE);
    let mut bytes = std::fs::read(&root).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&root, bytes).unwrap();
    assert!(matches!(
        View::begin(&fixture.backend, &fixture.original, &mut || Ok(())),
        Err(StoreError::Unsupported {
            capability: "packed-index-version"
        })
    ));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}
