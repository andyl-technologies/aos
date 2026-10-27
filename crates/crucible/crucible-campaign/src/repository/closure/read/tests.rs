//! Failure-atomic traversal caches and finite checked allocation growth.

// crucible-lint: allow panic-shortcut -- component fixtures localize exact admission and authentication failures.
#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible_store::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, DirectoryBlobBackend, ImmutableBlobBackend,
    ObjectKind, PutReceipt, StorePhysicalQuotaGuard,
};
use crucible_store::owned_decode::ResourceLoan;

use super::*;

struct Resources {
    maximum_bytes: u64,
    usage: Arc<Mutex<(u64, u64)>>,
    reservations: AtomicUsize,
    revoke_at: AtomicUsize,
    revoked: AtomicBool,
}

impl Resources {
    fn new(maximum_bytes: u64) -> Self {
        Self {
            maximum_bytes,
            usage: Arc::new(Mutex::new((0, 0))),
            reservations: AtomicUsize::new(0),
            revoke_at: AtomicUsize::new(usize::MAX),
            revoked: AtomicBool::new(false),
        }
    }

    fn usage(&self) -> (u64, u64) {
        *self.usage.lock().expect("finite traversal usage")
    }
}

impl StorePhysicalQuotaGuard for Resources {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(self.maximum_bytes)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        let mut usage = self.usage.lock().map_err(|_| StoreError::Quota)?;
        let next_descriptors = usage
            .0
            .checked_add(descriptors)
            .filter(|next| *next <= 32)
            .ok_or(StoreError::Quota)?;
        let next_bytes = usage
            .1
            .checked_add(resident_bytes)
            .filter(|next| *next <= self.maximum_bytes)
            .ok_or(StoreError::Quota)?;

        *usage = (next_descriptors, next_bytes);
        let loan = ResourceLoan::new(Loan {
            usage: self.usage.clone(),
            descriptors,
            resident_bytes,
        });
        let ordinal = self.reservations.fetch_add(1, Ordering::SeqCst) + 1;
        if ordinal == self.revoke_at.load(Ordering::SeqCst) {
            self.revoked.store(true, Ordering::SeqCst);
        }
        Ok(loan)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(StoreError::Unavailable)
        } else {
            Ok(())
        }
    }
}

struct Loan {
    usage: Arc<Mutex<(u64, u64)>>,
    descriptors: u64,
    resident_bytes: u64,
}

impl Drop for Loan {
    fn drop(&mut self) {
        let mut usage = self.usage.lock().expect("return traversal credits");
        usage.0 -= self.descriptors;
        usage.1 -= self.resident_bytes;
    }
}

#[test]
fn checked_traversal_small_elements_grow_geometrically_and_release_after_refusal() {
    let repository = CampaignRepository::in_memory("checked-vector-growth", 1024);
    let resources = Arc::new(Resources::new(2 * 1024 * 1024));
    let original = DecodeBudget::for_store(resources.clone()).expect("finite original");
    let baseline = resources.usage();
    let mut accepted = Vec::new();

    for _ in 0..2 {
        let reader = ClosureRead::new(&repository, Some(&original)).expect("same-authority child");
        let mut values = Vec::<u8>::new();
        let mut growths = 0;

        loop {
            let prior = (values.len(), values.capacity());
            let result = reader.push(&mut values, 7);
            if let Err(error) = result {
                assert_eq!((values.len(), values.capacity()), prior);
                assert!(
                    reader
                        .operation()
                        .expect("checked account")
                        .check()
                        .is_err()
                );
                assert!(
                    values.len() >= 4096,
                    "small traversal exhausted credits too early"
                );
                assert!(resources.usage().1 <= resources.maximum_bytes);
                drop(error);
                break;
            }
            if values.capacity() != prior.1 {
                growths += 1;
            }
            assert!(values.len() <= 2 * 1024 * 1024, "finite bank never refused");
        }

        assert!(
            growths <= 20,
            "traversal charged a separate allocation per push"
        );
        assert!(values.iter().all(|value| *value == 7));
        accepted.push(values.len());
        drop(values);
        drop(reader);
        assert_eq!(resources.usage(), baseline);
        original
            .verify_live()
            .expect("child refusal did not renew or revoke original");
    }

    assert_eq!(
        accepted[0], accepted[1],
        "released entitlement was not reacquired"
    );
    drop(original);
    assert_eq!(resources.usage(), (0, 0));
}

struct ObservedBackend {
    inner: Arc<dyn ImmutableBlobBackend>,
    selected: ContentId,
    selected_reads: AtomicUsize,
}

impl ImmutableBlobBackend for ObservedBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.inner.metadata_resources()
    }

    fn contains(&self, _id: ContentId) -> Result<bool, StoreError> {
        panic!("checked closure used ordinary presence")
    }

    fn read(&self, _id: ContentId, _range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        panic!("checked closure used ordinary read")
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        let source = self
            .inner
            .read_with_boundary(original, id, range, boundary)?;
        if id == self.selected {
            self.selected_reads.fetch_add(1, Ordering::SeqCst);
        }
        Ok(source)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

fn find_object(root: &std::path::Path, id: ContentId) -> std::path::PathBuf {
    for entry in std::fs::read_dir(root).expect("directory objects") {
        let path = entry.expect("object entry").path();
        if path.is_dir() {
            let candidate = find_object(&path, id);
            if candidate.exists() {
                return candidate;
            }
        } else if path
            .file_name()
            .is_some_and(|name| name == id.encode().as_str())
        {
            return path;
        }
    }
    root.join("missing-object")
}

#[test]
fn canceled_checked_merkle_closure_does_not_cache_unverified_descendants() {
    let directory = tempfile::tempdir().expect("durable closure directory");
    let resources = Arc::new(Resources::new(16 * 1024 * 1024));
    let original = DecodeBudget::for_store(resources.clone()).expect("finite original");
    let backend = DirectoryBlobBackend::new_with_physical_quota(
        "checked-cache-retry",
        directory.path().to_path_buf(),
        resources.clone(),
    )
    .expect("quota-bound directory");
    let map = MerkleMap::new(backend.clone());
    let bytes = b"authenticated selected leaf";
    let leaf = ContentId::for_bytes(ObjectKind::Observation, 1, bytes);
    backend
        .put_if_absent(leaf, &BlobHandle::from_bytes(bytes.to_vec()))
        .expect("actual leaf publication");
    let mut root = map.empty().expect("empty trie");
    // The two keys share a first nibble, requiring a descendant node rather
    // than leaving both leaves in the root.
    for first_byte in [0x10, 0x11] {
        let mut key = [0; 32];
        key[0] = first_byte;
        root = map
            .insert(root.content_id(), CampaignHash::from_bytes(key), leaf)
            .expect("publish descendant trie");
    }
    drop(map);

    let observed = Arc::new(ObservedBackend {
        inner: backend,
        selected: leaf,
        selected_reads: AtomicUsize::new(0),
    });
    let map = MerkleMap::new(observed.clone());
    let baseline = resources.usage();
    let mut cache = BTreeSet::new();
    let operation = original.child().expect("first child");
    let error = crucible_store::ram::with_store_operation_boundary(
        &operation,
        &mut || {
            if observed.selected_reads.load(Ordering::SeqCst) > 0 {
                Err(crucible_store::ram::RamStoreError::Canceled)
            } else {
                Ok(())
            }
        },
        |checked| {
            map.verify_closure_objects_cached_with_boundary(
                root.content_id(),
                &mut cache,
                &operation,
                checked,
            )
            .map_err(|error| match error {
                crate::CampaignStoreError::Store(source) => source,
                error => panic!("unexpected semantic failure before cancellation: {error}"),
            })
        },
    )
    .err()
    .expect("cancel after opening the actual descendant leaf");
    let crucible_store::ram::RamStoreError::Store(StoreError::RamReadBoundary { source }) = &error
    else {
        panic!("cancellation lost its typed boundary");
    };
    assert!(matches!(
        source.first_boundary(),
        Some(crucible_store::ram::RamStoreError::Canceled)
    ));
    assert!(cache.is_empty(), "failed walk exposed a reusable ancestor");
    assert_eq!(observed.selected_reads.load(Ordering::SeqCst), 1);
    drop(error);
    drop(operation);
    assert_eq!(resources.usage(), baseline);

    let leaf_path = find_object(directory.path(), leaf);
    assert!(leaf_path.exists(), "actual directory leaf");
    std::fs::write(&leaf_path, vec![0; bytes.len()]).expect("corrupt actual leaf bytes");
    let operation = original
        .child()
        .expect("retry under the same finite authority");
    let error = map
        .verify_closure_objects_cached_with_boundary(
            root.content_id(),
            &mut cache,
            &operation,
            &mut || Ok(()),
        )
        .err()
        .expect("same cache must not hide descendant corruption");
    assert!(
        matches!(error, crate::CampaignStoreError::Store(StoreError::Corrupt { id }) if id == leaf)
    );
    assert!(cache.is_empty());
    assert!(observed.selected_reads.load(Ordering::SeqCst) > 1);
    drop(error);
    drop(operation);
    assert_eq!(resources.usage(), baseline);

    std::fs::write(&leaf_path, bytes).expect("restore original leaf bytes");
    let operation = original
        .child()
        .expect("healthy retry under original authority");
    let before_walk = resources.reservations.load(Ordering::SeqCst);
    let closure = map
        .verify_closure_objects_cached_with_boundary(
            root.content_id(),
            &mut cache,
            &operation,
            &mut || Ok(()),
        )
        .expect("authenticate the complete original trie");
    let walk_reservations = resources.reservations.load(Ordering::SeqCst) - before_walk;
    assert_eq!(closure.root.entry_count(), 2);
    assert_eq!(closure.values, BTreeSet::from([leaf]));
    assert!(
        cache.len() >= 2,
        "root and descendant verified only after success"
    );
    drop(closure);
    drop(cache);
    drop(operation);
    assert_eq!(resources.usage(), baseline);

    // Repeat the same cold-cache walk, but let its final successful grant
    // revoke the original. Admission must finish before the last boundary;
    // no verified position may become reusable when that boundary refuses.
    let operation = original.child().expect("final-admission child");
    let before_walk = resources.reservations.load(Ordering::SeqCst);
    resources
        .revoke_at
        .store(before_walk + walk_reservations, Ordering::SeqCst);
    let mut cache = BTreeSet::new();
    let error = map
        .verify_closure_objects_cached_with_boundary(
            root.content_id(),
            &mut cache,
            &operation,
            &mut || Ok(()),
        )
        .err()
        .expect("revocation during final cache admission refuses publication");
    assert!(resources.revoked.load(Ordering::SeqCst));
    assert_eq!(
        resources.reservations.load(Ordering::SeqCst),
        before_walk + walk_reservations
    );
    assert!(
        cache.is_empty(),
        "refused final admission published cache state"
    );
    assert!(original.verify_live().is_err());
    drop(error);
    drop(cache);
    drop(operation);
    assert_eq!(resources.usage(), baseline);

    drop(map);
    drop(observed);
    drop(original);
    assert_eq!(resources.usage(), (0, 0));
}

#[test]
fn checked_mixed_merkle_edits_preserve_exact_roots_without_ordinary_reads_or_writes() {
    let directory = tempfile::tempdir().expect("durable mixed-edit directory");
    let resources = Arc::new(Resources::new(16 * 1024 * 1024));
    let original = DecodeBudget::for_store(resources.clone()).expect("finite original");
    let backend = DirectoryBlobBackend::new_with_physical_quota(
        "checked-mixed-edits",
        directory.path().to_path_buf(),
        resources.clone(),
    )
    .expect("quota-bound directory");
    let ordinary = MerkleMap::new(backend.clone());
    let leaf = ContentId::for_bytes(ObjectKind::Observation, 1, b"first value");
    let replacement = ContentId::for_bytes(ObjectKind::Observation, 1, b"second value");
    for (id, bytes) in [
        (leaf, b"first value".as_slice()),
        (replacement, b"second value".as_slice()),
    ] {
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .expect("publish actual values");
    }
    let key = |first_byte| {
        let mut bytes = [0; 32];
        bytes[0] = first_byte;
        CampaignHash::from_bytes(bytes)
    };
    let mut root = ordinary.empty().expect("empty trie").content_id();
    for first_byte in [0x10, 0x11, 0xf0] {
        root = ordinary
            .insert(root, key(first_byte), leaf)
            .expect("publish shared-prefix trie")
            .content_id();
    }
    let cases = [
        BTreeMap::new(),
        BTreeMap::from([(key(0x22), None)]),
        BTreeMap::from([(key(0x10), None)]),
        BTreeMap::from([
            (key(0x10), None),
            (key(0x11), Some(replacement)),
            (key(0x12), Some(leaf)),
            (key(0x22), None),
        ]),
        BTreeMap::from([(key(0x10), None), (key(0x11), None), (key(0xf0), None)]),
    ];
    let empty = MerkleMap::empty_content_id().expect("canonical empty root");
    let mut cases = cases
        .into_iter()
        .map(|edits| (root, edits))
        .collect::<Vec<_>>();
    cases.extend([
        (empty, BTreeMap::new()),
        (empty, BTreeMap::from([(key(0x10), None)])),
        (empty, BTreeMap::from([(key(0x10), Some(leaf))])),
    ]);
    let expected = cases
        .iter()
        .map(|(prior, edits)| {
            ordinary
                .root_after_edits(*prior, edits)
                .expect("canonical ordinary root")
        })
        .collect::<Vec<_>>();
    drop(ordinary);

    let observed = Arc::new(ObservedBackend {
        inner: backend.clone(),
        selected: leaf,
        selected_reads: AtomicUsize::new(0),
    });
    let checked = MerkleMap::new(observed.clone());
    let baseline = resources.usage();
    let mut mixed_edit_grants = None;
    for ((prior, edits), expected) in cases.iter().zip(expected) {
        let was_present = backend
            .contains(expected)
            .expect("prior virtual-root presence");
        // Presence checks acquire their own descriptor credit. Measure only
        // the edit operation so its final grant can be revoked exactly.
        let before = resources.reservations.load(Ordering::SeqCst);
        let operation = original.child().expect("mixed-edit child");
        let actual = checked
            .root_after_edits_with_boundary(*prior, edits, &operation, &mut || Ok(()))
            .expect("checked exact root");

        assert_eq!(actual, expected);
        if edits.contains_key(&key(0x12)) {
            mixed_edit_grants = Some(resources.reservations.load(Ordering::SeqCst) - before);
        }
        assert_eq!(
            backend.contains(expected).expect("virtual-root presence"),
            was_present
        );
        drop(operation);
        assert_eq!(resources.usage(), baseline);
    }
    let grants = mixed_edit_grants.expect("measured mixed-edit admissions");
    assert!(grants > 1);
    resources.revoke_at.store(
        resources.reservations.load(Ordering::SeqCst) + grants,
        Ordering::SeqCst,
    );
    let (prior, edits) = &cases[3];
    let operation = original.child().expect("final-grant revocation child");
    let refused = checked.root_after_edits_with_boundary(*prior, edits, &operation, &mut || Ok(()));

    assert!(
        resources.revoked.load(Ordering::SeqCst),
        "the measured final grant must revoke the original"
    );
    assert!(refused.is_err(), "revocation must refuse the computed root");
    drop(refused);
    drop(operation);
    assert_eq!(resources.usage(), baseline);
    assert_eq!(observed.selected_reads.load(Ordering::SeqCst), 0);
    drop(checked);
    drop(observed);
    drop(backend);
    drop(original);
    assert_eq!(resources.usage(), (0, 0));
}
