//! Detached real-worker success and unwind retain prepaid inventory controls.

use std::sync::Barrier;
use std::time::Duration;

use super::*;
use crate::qmp::checkpoint_paged_source_support::ImmutableBacking;
use crate::ram_source::{QemuRamBacking, QemuRamReadBoundaryError, QemuRamSourceService};
use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_protocol::ram_page::RamPageBinding;
use crucible_ram::{PageProof, RootRecord};
use std::os::unix::net::UnixStream;

static SERIAL: Mutex<()> = Mutex::new(());

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

    fn read_page_with_proof(
        &self,
        region: &str,
        page: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamReadBoundaryError>,
    ) -> Result<(Vec<u8>, PageProof), QemuRamSourceError> {
        self.backing.read_page_with_proof(region, page, boundary)
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
    let _serial = SERIAL
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
    let target = Arc::as_ptr(&source.failure) as usize - offset;
    let worker = source.worker.take().unwrap();
    DETACHED_OBSERVATION.store(0, Ordering::Release);
    DETACHED_ACCOUNT.store(
        (&account as *const HostServiceAllocator).cast_mut(),
        Ordering::Release,
    );
    DETACHED_TARGET.store(target, Ordering::Release);

    // The harness retains only the join handle, without cloning any loan.
    // The source itself closes without joining. Join proves the allocator
    // observer cannot outlive the actual borrowed account, even on test failure.
    drop(source);
    gate.entered.wait();
    let gated_probe = account.reserve_resources(0, 0, 1);
    gate.released.wait();

    let joined = worker.join();
    let observation = DETACHED_OBSERVATION.load(Ordering::Acquire);
    DETACHED_TARGET.store(0, Ordering::Release);
    DETACHED_ACCOUNT.store(std::ptr::null_mut(), Ordering::Release);

    assert!(matches!(
        gated_probe,
        Err(HostServiceError::CapacityExhausted)
    ));
    assert_eq!(joined.is_err(), panic_after_close);
    assert_eq!(
        observation, 1,
        "inventory control outlived its original worker loan"
    );
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
