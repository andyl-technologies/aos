//! Actual canonical control closure before the original child's custody refund.

use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, DurabilityRequirement, StoreError, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{DecodeBudget, DecodeCustody, ResourceLoan};
use crucible_cas::ram::{
    RamObjectCoordinate, RamRetention, RamRootLease, RamStore, RamStoreError, RamStoreLimits,
};
use crucible_linux_resource::test_support::{
    AllocationIdentity, AllocationRosterOutcome, BeforeFreeMarkerOutcome, TestAllocationObserver,
};
use crucible_ram::{RegionClass, RegionDescriptor, Scope, Topology};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const CAPACITY: usize = 64;
const LIMIT: usize = 256 * 1024 * 1024;
static WATCH: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static SIZES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static TARGET: AtomicUsize = AtomicUsize::new(usize::MAX);
static CLOSED: AtomicBool = AtomicBool::new(false);

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

struct Loan {
    usage: Arc<AtomicUsize>,
    bytes: usize,
    observation: Option<usize>,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.observation == Some(TARGET.load(Ordering::SeqCst)) {
            CLOSED.store(true, Ordering::SeqCst);
        }
        self.usage.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

struct Quota(Arc<AtomicUsize>);

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(LIMIT as u64)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn reserve_resources(&self, _descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let requested = usize::try_from(bytes).map_err(|_| StoreError::Quota)?;
        // The finite test issuer pays its concrete loan control before creating
        // it. Kernel namespace enforcement is outside this owner-close proof.
        let bytes = requested
            .checked_add(ResourceLoan::allocation_bytes::<Loan>() as usize)
            .ok_or(StoreError::Quota)?;
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|used| *used <= LIMIT)
            })
            .map_err(|_| StoreError::Quota)?;
        let observation = WATCH.load(Ordering::SeqCst).then(|| {
            let index = COUNT.fetch_add(1, Ordering::SeqCst);
            if index < CAPACITY {
                SIZES[index].store(requested, Ordering::SeqCst);
            }
            index
        });
        Ok(ResourceLoan::new(Loan {
            usage: self.0.clone(),
            bytes,
            observation,
        }))
    }
}

struct Lease(ContentId);

impl RamRootLease for Lease {
    fn root(&self) -> ContentId {
        self.0
    }
}

struct Retention;

impl RamRetention for Retention {
    fn retain_object(&self, _id: ContentId) -> Result<(), RamStoreError> {
        Ok(())
    }

    fn retain_root(&self, id: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        Ok(Arc::new(Lease(id)))
    }
}

#[test]
fn canonical_control_frees_before_child_custody_on_drop_unwind_and_concurrent_final_aliases()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in 0..3 {
        WATCH.store(false, Ordering::SeqCst);
        COUNT.store(0, Ordering::SeqCst);
        TARGET.store(usize::MAX, Ordering::SeqCst);
        CLOSED.store(false, Ordering::SeqCst);
        let directory = tempfile::tempdir()?;
        let usage = Arc::new(AtomicUsize::new(0));
        let guard = Arc::new(Quota(usage.clone()));
        let backend = DirectoryBlobBackend::new_with_physical_quota(
            "canonical-close",
            directory.path(),
            guard.clone(),
        )?;
        let store = RamStore::new(
            backend,
            DurabilityRequirement::new(1, false)?,
            RamStoreLimits::default(),
        )?;
        let original = DecodeBudget::for_store(guard)?;
        let topology = Topology::new(
            vec![RegionDescriptor::new(
                "main",
                RegionClass::MutableMain,
                128,
            )?],
            crucible_ram::Limits::default(),
        )?;
        let root = store.capture(
            topology,
            Scope::Exact,
            &mut |_, _, bytes| {
                bytes.fill(13);
                Ok(())
            },
            &Retention,
            &original,
            &mut || Ok(()),
        )?;

        let record = {
            WATCH.store(true, Ordering::SeqCst);
            let record = store.read_transfer_object(
                &root,
                &RamObjectCoordinate::Page {
                    region_id: "main".to_owned(),
                    page_index: 0,
                },
                &original,
                &mut || Ok(()),
            );
            WATCH.store(false, Ordering::SeqCst);
            record
        };
        let record = record?;
        assert!(COUNT.load(Ordering::SeqCst) <= CAPACITY);

        // The sealed Arc's live data address and pinned repr-C prefix identify
        // this exact control, independently of unrelated decode reallocations.
        let (layout, data_offset) = std::alloc::Layout::new::<[AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<(Vec<u8>, DecodeCustody)>())?;
        let extent = layout.pad_to_align().size();
        let control = AllocationIdentity::from_address(
            std::num::NonZeroUsize::new(
                record
                    .canonical_field_address_for_test()
                    .checked_sub(data_offset)
                    .ok_or("canonical prefix underflow")?,
            )
            .ok_or("zero canonical control identity")?,
        );
        let charged = extent + 4 * std::mem::size_of::<ResourceLoan>();
        let matches: Vec<_> = (0..COUNT.load(Ordering::SeqCst))
            .filter(|&index| SIZES[index].load(Ordering::SeqCst) == charged)
            .collect();
        let target = matches
            .last()
            .copied()
            .ok_or("missing canonical control charge")?;
        assert_eq!(
            target + 1,
            COUNT.load(Ordering::SeqCst),
            "the final reservation immediately precedes the used canonical owner allocation"
        );
        TARGET.store(target, Ordering::SeqCst);
        let other = record.clone();
        drop(root);
        drop(store);
        drop(original);
        assert!(!CLOSED.load(Ordering::SeqCst));

        let ((), outcome) = TestAllocationObserver::observe_close_marker_before_free(
            &CLOSED,
            control,
            || match mode {
                0 => {
                    drop(other);
                    drop(record);
                }
                1 => {
                    drop(other);
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            let _record = record;
                            panic!("intentional canonical owner unwind");
                        }));
                    assert!(result.is_err());
                }
                _ => std::thread::scope(|scope| {
                    scope.spawn(move || drop(record));
                    scope.spawn(move || drop(other));
                }),
            },
        )?;
        assert_eq!(outcome, BeforeFreeMarkerOutcome::Open);
        assert!(CLOSED.load(Ordering::SeqCst));
        assert_eq!(usage.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn returned_frame_payload_frees_before_its_own_credit_after_sender_closes()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_cas::ram::RamTransferSender;
    use crucible_protocol::ram_transfer::{
        RamTransferControl, RamTransferLimits, RamTransferMessage, RamTransferNodeCoordinate,
    };

    for mode in 0..3 {
        WATCH.store(false, Ordering::SeqCst);
        COUNT.store(0, Ordering::SeqCst);
        TARGET.store(usize::MAX, Ordering::SeqCst);
        CLOSED.store(false, Ordering::SeqCst);
        let directory = tempfile::tempdir()?;
        let usage = Arc::new(AtomicUsize::new(0));
        let guard = Arc::new(Quota(usage.clone()));
        let backend = DirectoryBlobBackend::new_with_physical_quota(
            "frame-close",
            directory.path(),
            guard.clone(),
        )?;
        let store = RamStore::new(
            backend,
            DurabilityRequirement::new(1, false)?,
            RamStoreLimits::default(),
        )?;
        let original = DecodeBudget::for_store(guard)?;
        let topology = Topology::new(
            vec![RegionDescriptor::new(
                "main",
                RegionClass::MutableMain,
                128,
            )?],
            crucible_ram::Limits::default(),
        )?;
        let root = store.capture(
            topology,
            Scope::Exact,
            &mut |_, _, bytes| {
                bytes.fill(17);
                Ok(())
            },
            &Retention,
            &original,
            &mut || Ok(()),
        )?;
        let operation = [37; 32];
        let mut sender = RamTransferSender::new(
            store.clone(),
            root.clone(),
            operation,
            ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::ExactManifest,
                6,
                b"frame owner",
            ),
            "destination",
            1,
            RamTransferLimits {
                objects: 100_000,
                bytes: 64 * 1024 * 1024,
                chunk_bytes: 64,
            },
            &original,
        )?;
        let want = || RamTransferMessage {
            operation,
            control: RamTransferControl::WantNode {
                coordinate: RamTransferNodeCoordinate::Root,
                object: root.object_id().to_string(),
            },
        };
        // These are two independent linear responses, not invented aliases.
        // The second uses the sender's actual authenticated retained root.
        let other = sender.respond(want(), &mut || Ok(()))?;
        let request = want();
        let (frame, roster) = TestAllocationObserver::capture_allocation_roster(|| {
            WATCH.store(true, Ordering::SeqCst);
            let frame = sender.respond(request, &mut || Ok(()));
            WATCH.store(false, Ordering::SeqCst);
            frame
        })?;
        let frame = frame?;
        assert_eq!(roster.outcome, AllocationRosterOutcome::Complete);
        assert!(!roster.overflow);
        let RamTransferControl::ObjectChunk { bytes, .. } = &frame.message().control else {
            return Err("expected actual owning chunk response".into());
        };
        let payload = roster
            .entries()
            .find(|entry| entry.contains_address(bytes.as_ptr().addr()))
            .ok_or("missing actual response byte allocation")?;
        assert_eq!(payload.bytes(), bytes.len());
        let encoded_length = frame.message().encode()?.len();
        let peak = encoded_length
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .ok_or("frame peak overflow")?;
        let count = COUNT.load(Ordering::SeqCst);
        assert!(count > 0 && count <= CAPACITY);
        let target = count - 1;
        assert_eq!(SIZES[target].load(Ordering::SeqCst), peak);
        TARGET.store(target, Ordering::SeqCst);
        drop(sender);
        drop(root);
        drop(store);
        drop(original);
        assert!(!CLOSED.load(Ordering::SeqCst));

        let ((), outcome) = TestAllocationObserver::observe_close_marker_before_free(
            &CLOSED,
            payload.identity(),
            || match mode {
                0 => {
                    drop(other);
                    drop(frame);
                }
                1 => {
                    drop(other);
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            let _frame = frame;
                            panic!("intentional returned frame unwind");
                        }));
                    assert!(result.is_err());
                }
                _ => std::thread::scope(|scope| {
                    scope.spawn(move || drop(other));
                    scope.spawn(move || drop(frame));
                }),
            },
        )?;
        assert_eq!(outcome, BeforeFreeMarkerOutcome::Open);
        assert!(CLOSED.load(Ordering::SeqCst));
        assert_eq!(usage.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
