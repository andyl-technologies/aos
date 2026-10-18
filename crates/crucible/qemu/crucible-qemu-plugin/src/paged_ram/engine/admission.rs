//! Accounts admitted paging metadata and complete interval mapping peaks.

use super::*;

impl PausedPagingOwner {
    /// Returns the complete Rust metadata request for one sealed inventory.
    ///
    /// Native metadata and separately issued installer controls retain their own
    /// purposes. This scalar describes the observer and live/staged pager request;
    /// its transport does not grant capacity or renew the installing operation.
    ///
    /// # Errors
    /// Refuses empty geometry or overflow in the complete request.
    pub(crate) fn required_rust_metadata_bytes(
        topology: &crucible_ram::Topology,
        spill_quota: u64,
    ) -> Result<u64, RamError> {
        if topology.total_logical_bytes() == 0 || spill_quota == 0 {
            return Err(RamError::Invariant("empty Rust metadata inventory"));
        }
        let pages = topology.regions().iter().try_fold(0_u64, |total, region| {
            total
                .checked_add(region.geometry().page_count())
                .ok_or(RamError::Invariant("Rust metadata page count overflow"))
        })?;
        let regions = u32::try_from(topology.regions().len())
            .map_err(|_| RamError::Invariant("Rust metadata region count overflow"))?;
        let paging = Self::required_metadata_bytes(pages, regions, spill_quota)?;
        crucible_ram::RamSnapshot::maximum_metadata_bytes(topology, 4)?
            .checked_add(9 * 3 * 1024 * 1024)
            .and_then(|bytes| bytes.checked_add(paging))
            .ok_or(RamError::Invariant(
                "complete Rust metadata request overflow",
            ))
    }

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
        let page_version_controls = u64::try_from(PageStates::control_bytes())
            .ok()
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or("live and staged page vector control overflow")?;
        let fault_work = service::capture_work::FaultWorkOwner::required_metadata_bytes()?
            .checked_mul(2)
            .ok_or("live and staged fault work metadata overflow")?;
        let resident_observations =
            super::physical_observation::ResidentObservationState::required_metadata_bytes()?
                .checked_mul(2)
                .ok_or("live and staged resident observation metadata overflow")?;
        store
            .checked_add(page_states)
            .and_then(|bytes| bytes.checked_add(arenas))
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(fault_work))
            .and_then(|bytes| bytes.checked_add(page_version_controls))
            .and_then(|bytes| bytes.checked_add(resident_observations))
            .and_then(|bytes| bytes.checked_add(mutation_receipt))
            .and_then(|bytes| bytes.checked_add(native_mutation_scratch))
            .and_then(|bytes| bytes.checked_add(2 * (16 * u64::from(regions) + 256)))
            .and_then(|bytes| {
                bytes.checked_add(
                    2 * crucible_qemu_protocol::ram_control::RAM_PERFORMANCE_BANK_RESERVE_BYTES,
                )
            })
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

/// Checks the already declared 1024-byte enclosing control allowance.
///
/// # Errors
/// Refuses a target whose real service header and Arc counters exceed it.
pub(super) fn verify_service_header_extent() -> Result<(), RamError> {
    let bytes = size_of::<FaultService>()
        .checked_add(2 * size_of::<usize>())
        .ok_or("fault service header extent overflow")?;
    if bytes > 1024 {
        return Err(RamError::Invariant("fault service exceeds admitted header"));
    }
    Ok(())
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
    // The existing same-bank arena reservation includes this fixed service
    // header and the actual two Arc counters. Growth must fit, never raise it.
    verify_service_header_extent()?;
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
        .and_then(|bytes| bytes.checked_add(PageStates::control_bytes()))
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
    let capture_work = service::capture_work::FaultWorkOwner::prepare(budget)?;
    // The distinct result body is prepaid under this same inventory account
    // before either body or enclosing service allocation, not by a status poll.
    let resident_observation =
        super::physical_observation::ResidentObservationState::prepare(budget)?;
    let registration = Registration::open().map_err(RamError::from)?;
    let generation = NEXT_WORKER_GENERATION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .map_err(|_| "paging worker generation exhausted")?;
    let service = Arc::new(FaultService {
        registration: Arc::new(registration),
        counters,
        source,
        spill,
        arenas,
        states: Mutex::new(PageStates::new(states)),
        placement_dependency: Mutex::new(None),
        worker: Mutex::new(None),
        capture_work,
        stop: AtomicBool::new(false),
        activated: AtomicBool::new(false),
        destructive: AtomicBool::new(false),
        failed: AtomicBool::new(false),
        lifetime: Mutex::new(service::ActorLifetime::default()),
        retained_token: AtomicU64::new(0),
        resident_observation,
        operations,
        worker_generation: generation,
        native,
        _reservation: reservation,
        _arena_reservation: arena_reservation,
    });
    Ok(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_qemu_protocol::ram_control::{RamControlBudget, RamControlMode, RamControlPolicy};

    struct NoOperationalCalls;

    impl SourceOperationFactory for NoOperationalCalls {
        fn begin(&self, _: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
            Err(io::Error::other(
                "admission cannot perform operational work",
            ))
        }
    }

    #[test]
    fn complete_report_contains_the_actual_live_and_staged_fixed_bodies() {
        use crucible_ram::{Limits, RamSnapshot, RegionClass, RegionDescriptor, Topology};

        let topology = Topology::new(
            vec![
                RegionDescriptor::new("main", RegionClass::MutableMain, PAGE_BYTES as u64).unwrap(),
            ],
            Limits::default(),
        )
        .unwrap();
        let spill_quota = 2 * PAGE_BYTES as u64;
        let observer =
            RamSnapshot::maximum_metadata_bytes(&topology, 4).unwrap() + 9 * 3 * 1024 * 1024;
        let paging = PausedPagingOwner::required_metadata_bytes(1, 1, spill_quota).unwrap();
        let fixed = 2 * (service::capture_work::FaultWorkOwner::required_metadata_bytes().unwrap()
            + PageStates::control_bytes() as u64
            + super::super::physical_observation::ResidentObservationState::required_metadata_bytes().unwrap());
        let complete =
            PausedPagingOwner::required_rust_metadata_bytes(&topology, spill_quota).unwrap();
        let omitting_target_controls = observer + paging - fixed;

        assert_eq!(complete, observer + paging);
        assert_eq!(complete - omitting_target_controls, fixed);
        assert!(fixed >= 2 * PAGE_BYTES as u64);
        let unchanged = crucible_ram::MetadataBudget::new(omitting_target_controls);
        assert!(unchanged.reserve_bytes(complete).is_err());
        assert_eq!(unchanged.used_bytes(), 0);
        let exact = crucible_ram::MetadataBudget::new(complete);
        let retained = exact.reserve_bytes(complete).unwrap();
        assert_eq!(exact.used_bytes(), complete);
        drop(retained);
        assert_eq!(exact.used_bytes(), 0);
        assert!(PausedPagingOwner::required_rust_metadata_bytes(&topology, 0).is_err());
        assert!(PausedPagingOwner::required_metadata_bytes(u64::MAX, 1, spill_quota).is_err());
    }

    #[test]
    fn absent_measurement_observation_does_not_acquire_spill_ownership() {
        use crucible_qemu_protocol::ram_control::RamControlPerformanceAction;

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
        let spill_ownership = owner.spill.lock().unwrap();

        assert_eq!(
            owner
                .performance(RamControlPerformanceAction::Observe)
                .unwrap(),
            None
        );
        assert_eq!(
            owner
                .performance(RamControlPerformanceAction::Stop)
                .unwrap(),
            None
        );
        assert!(!owner.performance_installed.load(Ordering::Acquire));
        drop(spill_ownership);
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
                poll_ns: 1_000_000,
                progress_ns: Some(100_000_000),
                total_ns: Some(100_000_000),
            }; 14],
        };

        assert!(matches!(
            owner.apply_policy(&policy, 1),
            Err(RamError::MetadataAdmission {
                required: 16384,
                admitted: 8192
            })
        ));
        assert!(owner.policy.lock().unwrap().is_none());
        assert!(owner.active.lock().unwrap().is_none());
    }
}
