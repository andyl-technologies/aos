//! Accounts admitted paging metadata and complete interval mapping peaks.

use super::*;

impl PausedPagingOwner {
    /// Bounds live and pre-fork staged pager metadata using actual logical pages.
    ///
    /// # Errors
    /// Returns overflow in the bounded live and staged metadata envelope.
    pub(crate) fn required_metadata_bytes(
        pages: u64,
        regions: u32,
        spill_quota: u64,
    ) -> Result<u64, RamError> {
        let store = spill_quota
            .checked_div(PAGE_BYTES as u64)
            .and_then(|slots| slots.checked_mul(256))
            .and_then(|bytes| bytes.checked_add(1024))
            .ok_or("spill metadata bound overflow")?;
        let page_states = pages.checked_mul(80).ok_or("page state bound overflow")?;
        let arenas = u64::from(regions)
            .checked_mul(128)
            .and_then(|bytes| bytes.checked_add(1024))
            .ok_or("arena metadata bound overflow")?;
        // Prepared authored mutations coexist with the committed and staged
        // owner. Native target collection may contain duplicate coordinates;
        // its hard work cap bounds both exact arrays before allocation.
        let mutation_receipt = pages
            .min(65536)
            .checked_mul(16)
            .and_then(|bytes| bytes.checked_add(PAGE_BYTES as u64 - 1))
            .map(|bytes| bytes & !(PAGE_BYTES as u64 - 1))
            .and_then(|bytes| bytes.checked_add(PAGE_BYTES as u64))
            .ok_or("prepared write receipt bound overflow")?;
        let native_mutation_scratch = 56 * 65536 + 2 * PAGE_BYTES as u64;
        store
            .checked_add(page_states)
            .and_then(|bytes| bytes.checked_add(arenas))
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(mutation_receipt))
            .and_then(|bytes| bytes.checked_add(native_mutation_scratch))
            .ok_or(RamError::Invariant(
                "live and staged paging metadata bound overflow",
            ))
    }

    pub(super) fn check_mapping_peak(&self, service: &FaultService) -> Result<(), RamError> {
        let mappings = service.arenas.iter().try_fold(0_u64, |sum, arena| {
            let start = arena.native.host_address & !(PAGE_BYTES as u64 - 1);
            let end = arena
                .native
                .host_address
                .checked_add(arena.native.logical_length)
                .and_then(|end| end.checked_add(PAGE_BYTES as u64 - 1))
                .map(|end| end & !(PAGE_BYTES as u64 - 1))
                .ok_or("physical mapping peak overflow")?;
            sum.checked_add(end - start)
                .ok_or("physical mapping peak overflow")
        })?;
        let pinned = service
            .arenas
            .iter()
            .filter(|arena| arena.placement != ArenaPlacement::Pageable)
            .try_fold(0_u64, |sum, arena| {
                let start = arena.native.host_address & !(PAGE_BYTES as u64 - 1);
                let end =
                    (arena.native.host_address + arena.native.logical_length + PAGE_BYTES as u64
                        - 1)
                        & !(PAGE_BYTES as u64 - 1);
                sum.checked_add(end - start)
                    .ok_or("permanent resident floor overflow")
            })?;
        self.permanent_resident_bytes
            .store(pinned, Ordering::Release);
        let peak = mappings
            .checked_add(self.resources.metadata_bytes)
            .and_then(|bytes| bytes.checked_add(self.resources.staging_bytes))
            .ok_or("physical mapping peak overflow")?;
        if peak > self.resources.resident_peak_bytes {
            return Err(RamError::MetadataAdmission {
                required: peak,
                admitted: self.resources.resident_peak_bytes,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_protocol::ram_control::{RamControlBudget, RamControlMode, RamControlPolicy};

    struct NoOperationalCalls;

    impl SourceOperationFactory for NoOperationalCalls {
        fn begin(&self, _: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
            Err(io::Error::other(
                "admission cannot perform operational work",
            ))
        }
    }

    #[test]
    fn low_soft_target_cannot_authorize_an_undersized_execution_peak() {
        let resources = PluginRamResources {
            resident_peak_bytes: 8192,
            backing_peak_bytes: 16384,
            metadata_bytes: 4096,
            staging_bytes: 4096,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 3,
        };
        let owner = PausedPagingOwner::new(resources, Arc::new(NoOperationalCalls)).unwrap();
        owner.seal_geometry(1, 8192).unwrap();
        assert!(owner.kernel_probe().is_none());
        let policy = RamControlPolicy {
            mode: RamControlMode::Managed,
            resident_target_bytes: 0,
            eviction_preference: 100,
            writeback_bytes_per_second: 4096,
            maximum_paging_io_in_flight: 1,
            prefetch_on_increase: false,
            budgets: [RamControlBudget {
                poll_ms: 1,
                progress_ms: Some(100),
                total_ms: Some(100),
            }; 14],
        };

        assert!(matches!(
            owner.apply_policy(&policy),
            Err(RamError::MetadataAdmission {
                required: 16384,
                admitted: 8192
            })
        ));
        assert!(owner.policy.lock().unwrap().is_none());
        assert!(owner.active.lock().unwrap().is_none());
    }
}

pub(super) fn prepare_service(
    source: &ValidatedRestoreSource,
    operations: Arc<dyn SourceOperationFactory>,
    native: NativeOperations,
    spill: Arc<Mutex<super::super::PreservedPages>>,
    counters: Arc<PagingCounters>,
) -> Result<Arc<FaultService>, RamError> {
    prepare_service_for_inventory(
        &source.native_regions,
        &source.budget,
        ServiceConfiguration {
            topology_generation: source.topology_generation,
            operations,
            native,
            spill,
            source: Some(source.source.clone()),
            resident: false,
            counters,
        },
    )
}

pub(super) struct ServiceConfiguration {
    pub(super) topology_generation: u64,
    pub(super) operations: Arc<dyn SourceOperationFactory>,
    pub(super) native: NativeOperations,
    pub(super) spill: Arc<Mutex<super::super::PreservedPages>>,
    pub(super) source: Option<Arc<RestorePageSource>>,
    pub(super) resident: bool,
    pub(super) counters: Arc<PagingCounters>,
}

pub(super) fn prepare_service_for_inventory(
    regions: &[crucible_ram::RegionDescriptor],
    budget: &crucible_ram::MetadataBudget,
    configuration: ServiceConfiguration,
) -> Result<Arc<FaultService>, RamError> {
    let ServiceConfiguration {
        topology_generation,
        operations,
        native,
        spill,
        source,
        resident,
        counters,
    } = configuration;
    spill
        .try_lock()
        .map_err(|_| "spill metadata admission unavailable")?
        .admit_metadata(budget)?;
    let arena_bytes = regions
        .len()
        .checked_mul(std::mem::size_of::<Arena>())
        .and_then(|bytes| bytes.checked_add(1024))
        .ok_or("arena metadata size overflow")?;
    let arena_reservation = budget
        .reserve_bytes(arena_bytes as u64)
        .map_err(RamError::from)?;
    let mut arenas = Vec::new();
    arenas
        .try_reserve_exact(regions.len())
        .map_err(RamError::from)?;
    let mut pages = 0_usize;
    for (index, descriptor) in regions.iter().enumerate() {
        let mut arena = NativeArena::default();
        let index = u32::try_from(index).map_err(|_| "arena index overflow")?;
        let status = (native.arena)(topology_generation, index, &mut arena);
        if status != 0 {
            return Err(RamError::Native {
                operation: "native arena authority",
                status,
            });
        }
        let placement = validate_arena(&arena, descriptor, index, topology_generation)?;
        arenas.push(Arena {
            native: arena,
            page_start: pages,
            placement,
        });
        pages = pages
            .checked_add(
                usize::try_from(arena.logical_length.div_ceil(PAGE_BYTES as u64))
                    .map_err(|_| "arena page count exceeds address space")?,
            )
            .ok_or("arena page count overflow")?;
    }
    for (index, arena) in arenas.iter().enumerate() {
        for other in &arenas[..index] {
            if arena.native.host_address < other.native.host_address + other.native.mapping_length
                && other.native.host_address
                    < arena.native.host_address + arena.native.mapping_length
            {
                return Err(RamError::Invariant("stable arena mappings overlap"));
            }
        }
    }
    let metadata = pages
        .checked_mul(std::mem::size_of::<PageState>())
        .ok_or("paging metadata size overflow")?;
    let reservation = budget
        .reserve_bytes(metadata as u64)
        .map_err(RamError::from)?;
    let mut states = Vec::new();
    states.try_reserve_exact(pages).map_err(RamError::from)?;
    states.resize(
        pages,
        PageState {
            version: 1,
            resident,
            writable: false,
            preserved: None,
        },
    );
    for arena in &arenas {
        if arena.placement != ArenaPlacement::Pageable {
            let count = usize::try_from(arena.native.logical_length.div_ceil(PAGE_BYTES as u64))
                .map_err(|_| "pinned logical page count overflow")?;
            for state in &mut states[arena.page_start..arena.page_start + count] {
                state.resident = true;
            }
        }
    }
    let registration = Registration::open().map_err(RamError::from)?;
    let generation = NEXT_WORKER_GENERATION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .map_err(|_| "paging worker generation exhausted")?;
    Ok(Arc::new(FaultService {
        registration: Arc::new(registration),
        counters,
        source,
        spill,
        arenas,
        states: Mutex::new(states),
        worker: Mutex::new(None),
        stop: AtomicBool::new(false),
        activated: AtomicBool::new(false),
        destructive: AtomicBool::new(false),
        failed: AtomicBool::new(false),
        retained_token: AtomicU64::new(0),
        operations,
        worker_generation: generation,
        native,
        _reservation: reservation,
        _arena_reservation: arena_reservation,
    }))
}
