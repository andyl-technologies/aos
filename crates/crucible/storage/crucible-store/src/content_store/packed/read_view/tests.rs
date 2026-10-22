//! Real Packed pin, EOF, corruption and original-account read-view controls.

use super::*;
use crate::content_store::StorePhysicalQuotaGuard;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::ResourceLoan;
use std::os::unix::fs::FileExt;

const BYTES: u64 = 4 << 20;
const FDS: u64 = 8;

struct Quota(
    FixtureResourceBudget,
    super::super::shared_cache::PackedManifestCache<ResourceLoan>,
    u64,
);

impl StorePhysicalQuotaGuard for Quota {
    fn read_packed_manifest(
        &self,
        request: &mut crate::content_store::PackedManifestRead<'_>,
    ) -> Result<(), StoreError> {
        request.retain_in(&self.1, |bytes, check| {
            check()?;
            assert!(
                self.1.reclaim(0)?.is_some(),
                "admission never holds the cache mutex"
            );
            self.0.reserve_with_control(bytes)
        })
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(self.2)
    }

    fn reserve_resources(&self, fds: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        assert!(
            self.1.reclaim(0)?.is_some(),
            "Original admission and copy allocation occur outside the cache mutex"
        );
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
        Self::with_pack_batches(&[64, 64], BYTES, 1 << 20)
    }

    fn with_pack_batches(batches: &[usize], metadata_bytes: u64, cache_bytes: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let backend =
            PackedBlobBackend::open("view", directory.path(), MIN_TARGET_PACK_BYTES).unwrap();
        let quota = Arc::new(Quota(
            FixtureResourceBudget::new(FDS, metadata_bytes),
            super::super::shared_cache::PackedManifestCache::new(
                cache_bytes,
                FixtureResourceBudget::loan_control_bytes(),
            ),
            metadata_bytes,
        ));
        let original = DecodeBudget::for_store(quota.clone()).unwrap();
        let objects = (0..batches.iter().sum::<usize>() as u64)
            .map(|index| {
                let bytes = index.to_be_bytes().repeat(3);
                (
                    ContentId::for_bytes(ObjectKind::Trace, 1, &bytes),
                    BlobHandle::from_bytes(bytes),
                )
            })
            .collect::<Vec<_>>();
        let mut offset = 0;
        for &count in batches {
            let batch = &objects[offset..offset + count];
            let receipt = backend
                .put_many_if_absent_with_boundary(&original, batch, &mut || Ok(()))
                .unwrap();
            drop(receipt.accept_with_boundary(&mut || Ok(())).unwrap());
            offset += count;
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
            .lookup(&fixture.backend, &fixture.original, *id, None, &mut || {
                Ok(())
            })
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
        .lookup(
            &fixture.backend,
            &fixture.original,
            id,
            None,
            &mut || Ok(()),
        )
        .unwrap();
    let pack = reader.last_pack.as_ref().unwrap();
    let position = pack
        .manifest
        .as_ref()
        .unwrap()
        .entries
        .binary_search_by_key(&id, |entry| entry.id)
        .unwrap();
    let entry = &pack.manifest.as_ref().unwrap().entries[position];
    let name = index_io::pack_name(pack.id);
    let path = fixture
        .backend
        .packs
        .join(std::str::from_utf8(&name).unwrap());
    let writable = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    writable.write_all_at(&[0xee], entry.offset).unwrap();
    drop(writable);
    assert!(
        matches!(reader.lookup(&fixture.backend, &fixture.original, id, None, &mut || Ok(())), Err(StoreError::Corrupt { id: found }) if found == id)
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
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap();
        drop(handle);
        let error = reader
            .lookup(&fixture.backend, &fixture.original, id, None, &mut || {
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

#[test]
fn cached_root_still_rereads_and_refuses_a_changed_arena_page() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    let id = fixture.objects[0].0;
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    assert_eq!(reader.root.as_ref().unwrap().identical_reads, 1);

    let reference = index_format::PageReference::decode(view.snapshot.body()).unwrap();
    let name = index_io::arena_name(view.snapshot.header.arena.unwrap());
    let path = fixture
        .backend
        .admin
        .join(std::str::from_utf8(&name).unwrap());
    let writable = fs::OpenOptions::new().write(true).open(path).unwrap();
    writable.write_all_at(&[0xee], reference.offset).unwrap();
    drop(writable);

    let error = reader
        .lookup(
            &fixture.backend,
            &fixture.original,
            id,
            None,
            &mut || Ok(()),
        )
        .err()
        .unwrap();
    assert!(matches!(error, StoreError::Incompatible));
    assert_eq!(
        reader.root.as_ref().unwrap().identical_reads,
        1,
        "changed bytes cannot reuse validation"
    );
    drop(reader);
    drop(view);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn canonical_session_reuses_one_manifest_without_retaining_descriptors_or_locks() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let mut session =
        super::super::canonical_session::Session::new(&fixture.backend, &fixture.original).unwrap();
    assert_eq!(
        fixture.quota.0.usage().unwrap(),
        (
            baseline.0,
            baseline.1 + std::mem::size_of::<super::super::canonical_session::Session>() as u64
        ),
        "session construction prepays its actual inline body before manifest lookup"
    );
    for (id, expected) in &fixture.objects[..2] {
        let handle = session
            .lookup(&fixture.backend, &fixture.original, *id, None, &mut || {
                Ok(())
            })
            .unwrap();
        let bytes = handle
            .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
            .unwrap();
        assert_eq!(&*bytes, &*expected.read_all(24).unwrap());
        drop((bytes, handle));
        assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
        assert_eq!(session.authenticated_manifests, 1);
    }
    // A real same-namespace mutation proves no source lock survives the turn.
    let bytes = b"canonical-session-new-object";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    let receipt = fixture
        .backend
        .put_many_if_absent_with_boundary(
            &fixture.original,
            &[(id, BlobHandle::from_bytes(bytes.to_vec()))],
            &mut || Ok(()),
        )
        .unwrap();
    drop(receipt.accept_with_boundary(&mut || Ok(())).unwrap());
    let handle = session
        .lookup(
            &fixture.backend,
            &fixture.original,
            fixture.objects[0].0,
            None,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        &*handle
            .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
            .unwrap(),
        &*fixture.objects[0].1.read_all(24).unwrap()
    );
    assert_eq!(
        session.authenticated_manifests, 2,
        "changed root generation requires fresh manifest authentication"
    );
    drop((handle, session));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn canonical_session_reopens_replaced_pack_before_reusing_manifest() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let mut session =
        super::super::canonical_session::Session::new(&fixture.backend, &fixture.original).unwrap();
    let id = fixture.objects[0].0;
    drop(
        session
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let retained = fixture.quota.0.usage().unwrap();
    // Select the real pack for this object rather than an unrelated fixture pack.
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let name = index_io::pack_name(reader.last_pack.as_ref().unwrap().id);
    let path = fixture
        .backend
        .packs
        .join(std::str::from_utf8(&name).unwrap());
    drop(reader);
    drop(view);
    let previous = path.with_extension("previous-test-pack");
    std::fs::rename(&path, &previous).unwrap();
    std::fs::write(&path, []).unwrap();
    let error = session
        .lookup(
            &fixture.backend,
            &fixture.original,
            id,
            None,
            &mut || Ok(()),
        )
        .err()
        .unwrap();
    assert!(matches!(error, StoreError::Corrupt { id: found } if found == id));
    assert_eq!(session.authenticated_manifests, 1);
    assert_eq!(fixture.quota.0.usage().unwrap(), retained);
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(previous, path).unwrap();
    drop(session);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn canonical_session_original_refusal_precedes_fresh_path_and_keeps_paid_metadata() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let mut session =
        super::super::canonical_session::Session::new(&fixture.backend, &fixture.original).unwrap();
    let id = fixture.objects[0].0;
    drop(
        session
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let retained = fixture.quota.0.usage().unwrap();
    let mut cuts = 0;
    let error = session
        .lookup(&fixture.backend, &fixture.original, id, None, &mut || {
            cuts += 1;
            Err(StoreError::Unauthorized)
        })
        .err()
        .unwrap();
    assert!(matches!(error, StoreError::Unauthorized));
    assert_eq!(cuts, 1);
    assert_eq!(session.authenticated_manifests, 1);
    assert_eq!(fixture.quota.0.usage().unwrap(), retained);
    drop(session);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn canonical_session_refuses_another_original_without_transferring_cache_credit() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let before = other.quota.0.usage().unwrap();
    let mut session =
        super::super::canonical_session::Session::new(&fixture.backend, &fixture.original).unwrap();
    let id = fixture.objects[0].0;
    drop(
        session
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let retained = fixture.quota.0.usage().unwrap();
    assert!(matches!(
        session.lookup(&fixture.backend, &other.original, id, None, &mut || Ok(())),
        Err(StoreError::Incompatible)
    ));
    assert_eq!(other.quota.0.usage().unwrap(), before);
    assert_eq!(fixture.quota.0.usage().unwrap(), retained);
}

mod shared_cache;

mod costs;
