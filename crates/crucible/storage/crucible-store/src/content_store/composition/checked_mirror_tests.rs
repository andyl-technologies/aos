//! Checked mirror ordering, policy validation and first-refusal custody.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::DecodeBudget;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

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
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        self.resources.reserve(descriptors, bytes)
    }
}

fn account() -> (Arc<Quota>, DecodeBudget) {
    let quota = Arc::new(Quota {
        resources: FixtureResourceBudget::new(8, 4 * 1024 * 1024),
        closed: AtomicBool::new(false),
    });
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    (quota, original)
}

#[derive(Clone, Copy)]
enum Reply {
    Found,
    Missing,
    OtherMissing,
    Corrupt,
    SwallowThenMissing,
    SwallowThenCorrupt,
    SwallowThenFound,
}

struct Leaf {
    ordinal: u8,
    calls: Arc<Mutex<Vec<u8>>>,
    original: DecodeBudget,
    reply: Reply,
}

impl ImmutableBlobBackend for Leaf {
    fn name(&self) -> &str {
        "checked mirror witness"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::default()
    }

    fn contains(&self, _: ContentId) -> Result<bool, StoreError> {
        panic!("checked mirror must not use ordinary presence")
    }

    fn read(&self, _: ContentId, _: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        panic!("checked mirror must not use ordinary reads")
    }

    fn put_if_absent(&self, _: ContentId, _: &BlobHandle) -> Result<PutReceipt, StoreError> {
        panic!("checked mirror lookup must not publish")
    }

    fn read_with_boundary(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        _: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        assert!(original.same_account(&self.original));
        self.calls.lock().unwrap().push(self.ordinal);
        if matches!(
            self.reply,
            Reply::SwallowThenMissing | Reply::SwallowThenCorrupt | Reply::SwallowThenFound
        ) {
            let _ignored = boundary();
        } else {
            boundary()?;
        }
        match self.reply {
            Reply::Found | Reply::SwallowThenFound => Ok(BlobHandle::from_bytes(b"mirror")),
            Reply::Missing | Reply::SwallowThenMissing => Err(StoreError::NotFound { id }),
            Reply::OtherMissing => Err(StoreError::NotFound {
                id: ContentId::for_bytes(id.kind(), 1, b"another object"),
            }),
            Reply::Corrupt | Reply::SwallowThenCorrupt => Err(StoreError::Corrupt { id }),
        }
    }
}

fn mirrors(original: &DecodeBudget, replies: &[Reply]) -> (WriteThroughStore, Arc<Mutex<Vec<u8>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let children = replies
        .iter()
        .enumerate()
        .map(|(index, &reply)| {
            Arc::new(Leaf {
                ordinal: index as u8,
                calls: calls.clone(),
                original: original.clone(),
                reply,
            }) as Arc<dyn ImmutableBlobBackend>
        })
        .collect();
    (WriteThroughStore::new("mirrors", children).unwrap(), calls)
}

fn id() -> ContentId {
    ContentId::for_bytes(ObjectKind::RamTree, 1, b"mirror")
}

#[test]
fn checked_mirrors_follow_order_only_after_exact_clean_absence() {
    let (_, original) = account();
    let (store, calls) = mirrors(&original, &[Reply::Missing, Reply::Found, Reply::Corrupt]);
    let handle = store
        .read_with_boundary(&original, id(), None, &mut || Ok(()))
        .unwrap();
    assert_eq!(handle.read_all(64).unwrap(), b"mirror");
    assert_eq!(*calls.lock().unwrap(), [0, 1]);

    for reply in [Reply::OtherMissing, Reply::Corrupt] {
        let (store, calls) = mirrors(&original, &[reply, Reply::Found]);
        assert!(
            store
                .read_with_boundary(&original, id(), None, &mut || Ok(()))
                .is_err()
        );
        assert_eq!(*calls.lock().unwrap(), [0]);
    }
}

#[test]
fn swallowed_callback_refusal_never_selects_another_mirror_or_accepts_success() {
    for reply in [Reply::SwallowThenMissing, Reply::SwallowThenFound] {
        let (_, original) = account();
        let (store, calls) = mirrors(&original, &[reply, Reply::Found]);
        let mut polls = 0;
        let error = store
            .read_with_boundary(&original, id(), None, &mut || {
                polls += 1;
                if polls == 2 {
                    Err(StoreError::Unauthorized)
                } else {
                    Ok(())
                }
            })
            .err()
            .unwrap();
        assert!(matches!(error, StoreError::Unauthorized));
        assert_eq!(polls, 2);
        assert_eq!(*calls.lock().unwrap(), [0]);
    }
}

#[test]
fn first_callback_refusal_retains_the_distinct_child_failure() {
    let (_, original) = account();
    let (store, calls) = mirrors(&original, &[Reply::SwallowThenCorrupt, Reply::Found]);
    let mut polls = 0;
    let error = store
        .read_with_boundary(&original, id(), None, &mut || {
            polls += 1;
            if polls == 2 {
                Err(StoreError::Unauthorized)
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    let StoreError::CompositeScope { source } = error else {
        panic!("retain both real failures")
    };
    assert!(matches!(
        source.first_boundary(),
        Some(StoreError::Unauthorized)
    ));
    assert!(
        matches!(source.work_failure(), Some(StoreError::Corrupt { id: failed }) if *failed == id())
    );
    assert!(source.prior_publications().is_empty());
    assert_eq!(*calls.lock().unwrap(), [0]);
}

#[test]
fn callback_poisoning_and_closed_original_refuse_before_another_child() {
    let (quota, original) = account();
    let (store, calls) = mirrors(&original, &[Reply::Missing, Reply::Found]);
    let mut polls = 0;
    let error = store
        .read_with_boundary(&original, id(), None, &mut || {
            polls += 1;
            if polls == 2 {
                quota.closed.store(true, Ordering::SeqCst);
            }
            Ok(())
        })
        .err()
        .unwrap();
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(*calls.lock().unwrap(), [0]);
    calls.lock().unwrap().clear();
    assert!(
        store
            .read_with_boundary(&original, id(), None, &mut || panic!(
                "closed original must precede callback"
            ))
            .is_err()
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn checked_durability_keeps_per_kind_requirement_before_child_reads() {
    let (_, original) = account();
    let (child, calls) = mirrors(&original, &[Reply::Found]);
    let store = DurabilityPolicyStore::new(
        "policy",
        Arc::new(child),
        BTreeMap::from([(
            ObjectKind::RamTree,
            DurabilityRequirement::new(1, false).unwrap(),
        )]),
    );
    store
        .read_with_boundary(&original, id(), None, &mut || Ok(()))
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), [0]);
    calls.lock().unwrap().clear();
    let unsupported = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"mirror");
    assert!(matches!(
        store.read_with_boundary(&original, unsupported, None, &mut || Ok(())),
        Err(StoreError::InvalidComposition { .. })
    ));
    assert!(calls.lock().unwrap().is_empty());
}
