//! Actual native-worker success and unwind retain prepaid inventory controls.

use std::num::NonZeroUsize;
use std::sync::Barrier;
use std::time::Duration;

use super::*;
use crate::qmp::checkpoint_paged_source_support::ImmutableBacking;
use crate::ram_source::{QemuRamBacking, QemuRamReadBoundaryError, QemuRamSourceService};
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_qemu_protocol::ram_page::RamPageBinding;
use crucible_ram::RootRecord;
use std::os::unix::net::UnixStream;

#[test]
fn incomplete_worker_journal_admission_preserves_actual_input_without_allocation() {
    let _serial = TEST_LOCK.lock().unwrap();
    let backing = Arc::new(ImmutableBacking::new(2).unwrap());
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    // Admit the actual other controls and exactly one journal. This independent
    // allowance must refuse the production preparation's two real journals.
    let single_journal = QemuRamWorkerFailure::allocation_bytes().unwrap()
        + HostServiceLease::metadata_bytes()
        - std::mem::size_of::<HostServiceLease>() as u64
        + shared_allocation_bytes::<AtomicBool>().unwrap()
        + crate::ram_source::worker_outcome::WorkerOutcome::allocation_peak_bytes().unwrap();
    let peak = crate::ram_source::SOURCE_STACK_BYTES as u64
        + 3 * crucible_qemu_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
        + single_journal;
    let account = HostServiceAllocator::new(1, 2, peak).unwrap();
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut input = Some(crate::ram_source::SourceInput::new(
        socket, backing, binding,
    ));

    let (result, counts) = TestAllocationObserver::count(|| {
        QemuRamSourceService::prepare(&mut input, supervisor, account)
    });

    assert!(matches!(
        result,
        Err(QemuRamSourceError::Services(
            HostServiceError::CapacityExhausted
        ))
    ));
    assert!(input.is_some());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
}

struct ExitGate {
    entered: Barrier,
    released: Barrier,
}

struct GatedBacking {
    backing: ImmutableBacking,
    gate: Arc<ExitGate>,
    panic_after_close: bool,
}

impl QemuRamBacking for GatedBacking {
    fn root_object_id(&self) -> &str {
        self.backing.root_object_id()
    }

    fn root_record(&self) -> &RootRecord {
        self.backing.root_record()
    }

    fn with_page_response(
        &self,
        region: &str,
        page: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamReadBoundaryError>,
        consumer: &mut crate::ram_source::QemuRamResponseConsumer<'_>,
    ) -> Result<(), QemuRamSourceError> {
        self.backing
            .with_page_response(region, page, boundary, consumer)
    }
}

impl Drop for GatedBacking {
    fn drop(&mut self) {
        self.gate.entered.wait();
        self.gate.released.wait();
        if self.panic_after_close {
            panic!("intentional detached worker unwind before completion");
        }
    }
}

fn detached_close(panic_after_close: bool) {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let gate = Arc::new(ExitGate {
        entered: Barrier::new(2),
        released: Barrier::new(2),
    });
    let backing = Arc::new(GatedBacking {
        backing: ImmutableBacking::new(2).unwrap(),
        gate: Arc::clone(&gate),
        panic_after_close,
    });
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let peak = crate::ram_source::SOURCE_STACK_BYTES as u64
        + 3 * crucible_qemu_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
        + QemuRamWorkerFailure::startup_metadata_bytes().unwrap();
    let account = HostServiceAllocator::new(1, 2, peak).unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut source = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        supervisor,
        account.clone(),
        None,
    )
    .unwrap();

    // This is the actual startup inventory Arc; the checked header offset
    // locates its allocation without reading control storage or creating aliases.
    let offset = crate::ram_source::worker_outcome::WorkerOutcome::allocation_header_offset();
    let target = source
        .failure
        .allocation_address()
        .unwrap()
        .checked_sub(offset)
        .and_then(NonZeroUsize::new)
        .unwrap();
    let target = AllocationIdentity::from_address(target);
    let mut worker = source.worker.take().unwrap();

    // Retain only the real join handle, without cloning any loan. Source Drop
    // does not join; the watch owns the same original account until actual join,
    // including a panicking worker, before any registry teardown can begin.
    let ((gated_probe, joined), report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || {
            drop(source);
            gate.entered.wait();
            let gated_probe = account.reserve_resources(0, 0, 1);
            gate.released.wait();

            let until = std::time::Instant::now() + Duration::from_secs(5);
            while worker.native.poll().unwrap()
                != crate::ram_source::NativeJoinObservation::Returned
            {
                assert!(std::time::Instant::now() < until);
                std::thread::yield_now();
            }
            let snapshot = worker.outcome.snapshot();
            assert!(snapshot.delivered && !snapshot.uncertain);
            let joined = snapshot.panic.map_or(Ok(()), Err);
            let panicked = joined.is_err();
            // Both actual outcome aliases close before the observed control
            // allocation can free and return its original loan.
            drop(joined);
            drop(worker);
            (gated_probe, panicked)
        })
        .unwrap();

    assert!(matches!(
        gated_probe,
        Err(HostServiceError::CapacityExhausted)
    ));
    assert_eq!(joined, panic_after_close);
    verify_original_refusal(report);
    verify_closed(&account);
}

#[test]
fn detached_canceled_worker_closes_inventory_before_original_refund() {
    detached_close(false);
}

#[test]
fn detached_unwinding_worker_closes_inventory_before_original_refund() {
    detached_close(true);
}

struct NativeTlsGate {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
    finished: std::sync::mpsc::SyncSender<bool>,
}

impl Drop for NativeTlsGate {
    fn drop(&mut self) {
        let _entered = self.entered.send(());
        let released = self.release.recv_timeout(Duration::from_secs(5)).is_ok();
        let _finished = self.finished.send(released);
    }
}

thread_local! {
    static NATIVE_TLS_GATE: std::cell::RefCell<Option<NativeTlsGate>> = const {
        std::cell::RefCell::new(None)
    };
}

struct TlsGatedBacking {
    backing: ImmutableBacking,
    gate: Mutex<Option<NativeTlsGate>>,
    request_entered: std::sync::mpsc::SyncSender<()>,
    request_release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl QemuRamBacking for TlsGatedBacking {
    fn root_object_id(&self) -> &str {
        self.backing.root_object_id()
    }

    fn root_record(&self) -> &RootRecord {
        self.backing.root_record()
    }

    fn with_page_response(
        &self,
        region: &str,
        page: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamReadBoundaryError>,
        consumer: &mut crate::ram_source::QemuRamResponseConsumer<'_>,
    ) -> Result<(), QemuRamSourceError> {
        assert_eq!(std::thread::current().name(), Some("crucible-ram-source"));
        // Install the destructor on the actual serving worker, then hold its
        // callback until the facade closes. Final backing Drop can race between
        // the caller and worker and cannot identify which thread owns TLS.
        NATIVE_TLS_GATE.with(|cell| *cell.borrow_mut() = self.gate.lock().unwrap().take());
        self.request_entered.send(()).unwrap();
        self.request_release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        self.backing
            .with_page_response(region, page, boundary, consumer)
    }
}

#[test]
fn abandoned_source_retains_native_join_debt_during_and_after_tls_teardown() {
    use std::io::Write;

    use crucible_qemu_protocol::ram_page::RamPageRequest;

    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (entered, observed) = std::sync::mpsc::sync_channel(1);
    let (release, blocked) = std::sync::mpsc::sync_channel(1);
    let (finished, returned) = std::sync::mpsc::sync_channel(1);
    let (request_entered, request_observed) = std::sync::mpsc::sync_channel(1);
    let (request_release, request_blocked) = std::sync::mpsc::sync_channel(1);
    let backing = Arc::new(TlsGatedBacking {
        backing: ImmutableBacking::new(2).unwrap(),
        gate: Mutex::new(Some(NativeTlsGate {
            entered,
            release: blocked,
            finished,
        })),
        request_entered,
        request_release: Mutex::new(request_blocked),
    });
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let peak = crate::ram_source::SOURCE_STACK_BYTES as u64
        + 3 * crucible_qemu_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
        + QemuRamWorkerFailure::startup_metadata_bytes().unwrap();
    let account = HostServiceAllocator::new(1, 2, peak).unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let (socket, mut peer) = UnixStream::pair().unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let source = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        supervisor,
        account.clone(),
        None,
    )
    .unwrap();

    peer.write_all(
        &RamPageRequest {
            binding,
            sequence: 1,
            region_ordinal: 0,
            page_index: 0,
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    request_observed
        .recv_timeout(Duration::from_secs(5))
        .unwrap();

    // Keep no worker, outcome alias or extra lease: only production Drop can
    // preserve the actual join record and its paid task/control inventory.
    let ((), counts) = TestAllocationObserver::count(|| drop(source));
    request_release.send(()).unwrap();
    observed.recv_timeout(Duration::from_secs(5)).unwrap();
    let during_tls = account.reserve_resources(0, 0, 1);
    release.send(()).unwrap();
    assert!(returned.recv_timeout(Duration::from_secs(5)).unwrap());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);

    assert!(matches!(
        during_tls,
        Err(HostServiceError::CapacityExhausted)
    ));
    assert!(matches!(
        account.reserve_resources(0, 0, 1),
        Err(HostServiceError::CapacityExhausted)
    ));
    // No native join occurred. This abandoned component's same account remains
    // retained until process exit, even after its Rust body and TLS complete.
}

#[test]
fn unreaped_receiver_retains_the_actual_source_and_unqueried_native_owner() {
    use std::io::Write;
    use crucible_qemu_protocol::ram_page::{
        RamPageRequest, RamPageResponse, RamPageStatus, read_ram_page_response,
    };

    let _serial = TEST_LOCK.lock().unwrap();
    let backing = Arc::new(ImmutableBacking::new(2).unwrap());
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let peak = crate::ram_source::SOURCE_STACK_BYTES as u64
        + 3 * crucible_qemu_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
        + QemuRamWorkerFailure::startup_metadata_bytes().unwrap();
    let account = HostServiceAllocator::new(1, 2, peak).unwrap();
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let (socket, mut receiver) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    receiver
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let source = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        supervisor,
        account.clone(),
        None,
    )
    .unwrap();
    let native_identity = source.worker.as_ref().unwrap().native.thread_id();
    let outcome = source.failure.clone();

    let (_, counts) = TestAllocationObserver::count(|| source.retain_for_unreaped_receiver());

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let retained = outcome
        .retained_live_receiver()
        .unwrap_or_else(|| panic!("unreaped receiver must retain its actual Source facade"));
    let native = &retained.worker.as_ref().unwrap().native;
    assert_eq!(native.thread_id(), native_identity);
    assert_eq!(native.last_status(), None);
    assert_eq!(retained.binding, binding);
    assert!(!retained.cancellation.load(Ordering::Acquire));

    // The receiver still gets an authentic page from the same live worker.
    receiver
        .write_all(
            &RamPageRequest {
                binding,
                sequence: 1,
                region_ordinal: 0,
                page_index: 0,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
    let bytes = read_ram_page_response(&mut receiver).unwrap();
    let response = RamPageResponse::decode(&bytes).unwrap();
    assert_eq!(response.binding, binding);
    assert_eq!(response.status, RamPageStatus::Page);
    assert_eq!(response.page.len(), 4096);
    assert!(!response.proof.is_empty());
    drop(receiver);

    for _ in 0..5_000 {
        if outcome.snapshot().delivered {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(outcome.snapshot().delivered);
    let retained = outcome.retained_live_receiver().unwrap();
    assert_eq!(
        retained.worker.as_ref().unwrap().native.thread_id(),
        native_identity
    );
    assert_eq!(retained.worker.as_ref().unwrap().native.last_status(), None);
    assert!(!retained.cancellation.load(Ordering::Acquire));
    drop(outcome);

    // Rust delivery and closing the diagnostic observer do not consume the
    // retained native join authority or refund the actual original account.
    assert!(matches!(
        account.reserve_resources(0, 0, 1),
        Err(HostServiceError::CapacityExhausted)
    ));
}

#[test]
fn unreaped_receiver_retains_the_prepared_source_before_worker_birth() {
    let _serial = TEST_LOCK.lock().unwrap();
    let backing = Arc::new(ImmutableBacking::new(2).unwrap());
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let peak = crate::ram_source::SOURCE_STACK_BYTES as u64
        + 3 * crucible_qemu_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
        + QemuRamWorkerFailure::startup_metadata_bytes().unwrap();
    let account = HostServiceAllocator::new(1, 2, peak).unwrap();
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let (socket, peer) = UnixStream::pair().unwrap();
    let mut input = Some(crate::ram_source::SourceInput::new(
        socket, backing, binding,
    ));
    let source = QemuRamSourceService::prepare(&mut input, supervisor, account.clone()).unwrap();
    let outcome = source.failure.clone();

    let (_, counts) = TestAllocationObserver::count(|| source.retain_for_unreaped_receiver());

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(input.is_none());
    let retained = outcome.retained_live_receiver().unwrap();
    assert!(retained.worker.is_none());
    assert!(retained.startup.is_some());
    assert!(!retained.spawn_attempted);
    assert!(!retained.cancellation.load(Ordering::Acquire));
    assert_eq!(retained.binding, binding);
    drop((peer, outcome));

    assert!(matches!(
        account.reserve_resources(0, 0, 1),
        Err(HostServiceError::CapacityExhausted)
    ));
}
