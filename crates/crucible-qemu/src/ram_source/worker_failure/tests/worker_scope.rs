//! Detached real-worker success and unwind retain prepaid inventory controls.

use std::num::NonZeroUsize;
use std::sync::Barrier;
use std::time::Duration;

use super::*;
use crate::qmp::checkpoint_paged_source_support::ImmutableBacking;
use crate::ram_source::{QemuRamBacking, QemuRamReadBoundaryError, QemuRamSourceService};
use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_protocol::ram_page::RamPageBinding;
use crucible_ram::RootRecord;
use std::os::unix::net::UnixStream;

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
        + 3 * crucible_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
        + QemuRamWorkerFailure::startup_metadata_bytes().unwrap();
    let account = HostServiceAllocator::new(1, 2, peak).unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut source =
        QemuRamSourceService::start(socket, backing, binding, supervisor, account.clone()).unwrap();

    // This is the actual startup inventory Arc; the checked header offset
    // locates its allocation without reading control storage or creating aliases.
    let (_, offset) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<Mutex<Option<QemuRamWorkerFailure>>>())
        .unwrap();
    let target = (Arc::as_ptr(&source.failure) as usize)
        .checked_sub(offset)
        .and_then(NonZeroUsize::new)
        .unwrap();
    let target = AllocationIdentity::from_address(target);
    let worker = source.worker.take().unwrap();

    // Retain only the real join handle, without cloning any loan. Source Drop
    // does not join; the watch owns the same original account until actual join,
    // including a panicking worker, before any registry teardown can begin.
    let ((gated_probe, joined), report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || {
            drop(source);
            gate.entered.wait();
            let gated_probe = account.reserve_resources(0, 0, 1);
            gate.released.wait();

            let joined = worker.join();
            (gated_probe, joined)
        })
        .unwrap();

    assert!(matches!(
        gated_probe,
        Err(HostServiceError::CapacityExhausted)
    ));
    assert_eq!(joined.is_err(), panic_after_close);
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
