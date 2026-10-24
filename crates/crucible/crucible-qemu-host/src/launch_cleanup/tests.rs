//! Real descriptor, process-reap, and source-worker custody regressions.

use super::*;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use crucible_host_resources::host_services::{
    HostServiceAllocator, HostServiceLease, HostServiceLeasePair,
};
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_host_resources::ram_policy::{HostRamMode, HostRamPolicy};
use crucible_qemu_protocol::ram_page::{RamPageBinding, RamPageRequest};
use crucible_ram::{
    Limits, MetadataBudget, PageDigest, RegionClass, RegionDescriptor, RegionTree, RootRecord,
    Scope, Topology,
};

use crate::ram_control::RamControlClient;
use crate::ram_source::{QemuRamBacking, QemuRamSourceError, QemuRamSourceService};

pub(crate) mod allocation;

struct Registrar {
    services: HostServiceAllocator,
    descriptors: Arc<Mutex<Vec<DescriptorWitness>>>,
    retired: AtomicUsize,
    normal_retired: Arc<AtomicUsize>,
    prepared: Arc<AtomicBool>,
    quarantined: AtomicUsize,
    refuse_retirement: bool,
    quarantine_notice: Option<mpsc::Sender<()>>,
    _funding: Option<HostServiceLeasePair>,
}

impl RamControlRegistrar for Registrar {
    fn retirement_authority(
        &self,
        _: HostRamTarget,
    ) -> Result<Arc<dyn RamControlRetirementAuthority>, RamControlError> {
        Ok(Arc::new(TestRetirement {
            services: self.services.clone(),
            descriptors: self.descriptors.clone(),
            normal_retired: self.normal_retired.clone(),
            prepared: self.prepared.clone(),
            refuse_retirement: self.refuse_retirement,
        }))
    }

    fn register(
        &self,
        _: HostRamTarget,
        _: HostRamPolicy,
        _: HostResourceVector,
        _: HostOperationSupervisor,
        _: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        Ok(())
    }

    fn retire_unpublished_after_cleanup(
        &self,
        _: HostRamTarget,
        _: HostResourceVector,
    ) -> Result<(), RamControlError> {
        self.verify_closed()?;
        self.retired.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn prepare_retirement_after_cleanup(
        &self,
        _: HostRamTarget,
    ) -> crate::ram_control::RamControlRetirementOutcome {
        crate::ram_control::RamControlRetirementOutcome::from_known({
            self.prepared.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn retire_after_cleanup(&self, _: HostRamTarget) -> Result<(), RamControlError> {
        if !self.prepared.load(Ordering::Acquire) {
            return Err(RamControlError::AuthorityMismatch);
        }
        self.verify_closed()?;
        self.normal_retired.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn quarantine_unpublished(
        &self,
        _: HostRamTarget,
        _: HostResourceVector,
    ) -> Result<(), RamControlError> {
        self.quarantined.fetch_add(1, Ordering::AcqRel);
        if let Some(notice) = &self.quarantine_notice {
            let _ = notice.send(());
        }
        Ok(())
    }
}

impl Registrar {
    fn verify_closed(&self) -> Result<(), RamControlError> {
        verify_resources_closed(&self.services, &self.descriptors, self.refuse_retirement)
    }
}

struct TestRetirement {
    services: HostServiceAllocator,
    descriptors: Arc<Mutex<Vec<DescriptorWitness>>>,
    normal_retired: Arc<AtomicUsize>,
    prepared: Arc<AtomicBool>,
    refuse_retirement: bool,
}

impl RamControlRetirementAuthority for TestRetirement {
    fn retire_after_cleanup(&self) -> Result<(), RamControlError> {
        if !self.prepared.load(Ordering::Acquire) {
            return Err(RamControlError::AuthorityMismatch);
        }
        verify_resources_closed(&self.services, &self.descriptors, self.refuse_retirement)?;
        self.normal_retired.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

fn verify_resources_closed(
    services: &HostServiceAllocator,
    descriptors: &Mutex<Vec<DescriptorWitness>>,
    refuse_retirement: bool,
) -> Result<(), RamControlError> {
    if refuse_retirement {
        return Err(RamControlError::AuthorityMismatch);
    }
    // A real remaining descriptor or worker permit refuses the test's
    // retirement receipt, making premature cleanup observable.
    let _capacity = services
        .reserve_resources(1, 32, 1024 * 1024)
        .map_err(|_| RamControlError::AuthorityMismatch)?;
    let descriptors = descriptors
        .lock()
        .map_err(|_| RamControlError::AuthorityMismatch)?;
    for descriptor in &*descriptors {
        if !descriptor.is_closed()? {
            return Err(RamControlError::AuthorityMismatch);
        }
    }
    Ok(())
}

struct DescriptorWitness {
    path: PathBuf,
    identity: PathBuf,
    _peer: UnixStream,
}

impl DescriptorWitness {
    fn new(descriptor: RawFd, peer: UnixStream) -> Self {
        let path = PathBuf::from(format!("/proc/self/fd/{descriptor}"));
        let identity = std::fs::read_link(&path)
            .unwrap_or_else(|error| panic!("descriptor identity fixture failed: {error:?}"));
        Self {
            path,
            identity,
            _peer: peer,
        }
    }

    fn is_closed(&self) -> std::io::Result<bool> {
        // Parallel pre-exec children can briefly inherit a socket, delaying
        // peer EOF. This witnesses the exact local descriptor instead; actual
        // reap and join proofs independently cover the launch's other owners.
        match std::fs::read_link(&self.path) {
            Ok(identity) => Ok(identity != self.identity),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    }
}

fn registration(
    refuse_retirement: bool,
    notice: Option<mpsc::Sender<()>>,
) -> (RamControlRegistration, Arc<Registrar>) {
    registration_with_funding(refuse_retirement, notice, None)
}

fn registration_with_funding(
    refuse_retirement: bool,
    notice: Option<mpsc::Sender<()>>,
    funding: Option<HostServiceLeasePair>,
) -> (RamControlRegistration, Arc<Registrar>) {
    let services = HostServiceAllocator::new(1, 32, 1024 * 1024)
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let registrar = Arc::new(Registrar {
        services: services.clone(),
        descriptors: Arc::new(Mutex::new(Vec::new())),
        retired: AtomicUsize::new(0),
        normal_retired: Arc::new(AtomicUsize::new(0)),
        prepared: Arc::new(AtomicBool::new(false)),
        quarantined: AtomicUsize::new(0),
        refuse_retirement,
        quarantine_notice: notice,
        _funding: funding,
    });
    (
        RamControlRegistration {
            target: HostRamTarget {
                daemon_epoch: [1; 32],
                owner_id: [2; 32],
                node_id: [3; 32],
                owner_generation: 1,
                arena_generation: 1,
                retained_template: false,
            },
            initial_policy: HostRamPolicy {
                mode: HostRamMode::Managed,
                resident_target_bytes: 4096,
                eviction_preference: 50,
                writeback_bytes_per_second: 4096,
                maximum_paging_io_in_flight: 1,
                prefetch_on_increase: false,
                latency: HostOperationBudgets::default(),
            },
            resources: HostResourceVector {
                resident_peak_bytes: 1024 * 1024,
                backing_peak_bytes: 1024 * 1024,
                metadata_bytes: 4096,
                staging_bytes: 65536,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 2,
                file_descriptors: 32,
            },
            host_services: services,
            spill_quota_bytes: 8192,
            registrar: registrar.clone(),
        },
        registrar,
    )
}

struct DescriptorBorrower {
    _socket: UnixStream,
    _service: HostServiceLease,
    _cleanup: LaunchCleanup,
}

#[test]
fn descriptor_witness_refuses_a_live_local_socket_without_a_service_permit() {
    let (registration, registrar) = registration(false, None);
    let (socket, peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    registrar
        .descriptors
        .lock()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))
        .push(DescriptorWitness::new(socket.as_raw_fd(), peer));

    assert!(registrar.verify_closed().is_err());
    drop(socket);
    assert!(registrar.verify_closed().is_ok());
    drop(registration);
}

#[test]
fn failed_setup_reap_does_not_release_while_real_descriptor_borrower_remains() {
    let (registration, registrar) = registration(false, None);
    let cleanup = LaunchCleanup::new(&registration);
    let (socket, peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    registrar
        .descriptors
        .lock()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))
        .push(DescriptorWitness::new(socket.as_raw_fd(), peer));
    let borrower = DescriptorBorrower {
        _socket: socket,
        _service: registration
            .host_services
            .reserve_resources(0, 1, 0)
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
        _cleanup: cleanup.clone(),
    };
    let config = crucible_qemu_shmem::RegionConfig::new(1, 4);
    let length = crucible_qemu_shmem::RegionLayout::for_config(config)
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))
        .region_size;
    let (mut resources, setup_peer) = crate::spawn::create_test_spawn_resource_pair(length + 4096)
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    crate::spawn::prepare_test_preexec_setup(&mut resources, config)
        .unwrap_or_else(|error| panic!("cleanup fixture setup prequeue failed: {error}"));
    resources.retain_launch_cleanup(cleanup.clone());
    registrar
        .descriptors
        .lock()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))
        .push(DescriptorWitness::new(
            resources.control_socket_fd(),
            setup_peer,
        ));
    let mut child = crate::QemuNodeChild::new(
        Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
    );
    child.retain_launch_cleanup(cleanup.clone());

    let error = match crate::host_setup::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    ) {
        Ok(_) => panic!("invalid setup unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        crate::QemuHostPluginSetupError::RegionLengthMismatch { .. }
    ));
    child
        .force_kill_and_reap_failed_realization()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    assert!(child.reaped());
    drop(child);
    drop(cleanup);
    assert_eq!(registrar.retired.load(Ordering::Acquire), 0);

    drop(borrower);

    assert_eq!(registrar.retired.load(Ordering::Acquire), 1);
    assert_eq!(registrar.quarantined.load(Ordering::Acquire), 0);
}

#[test]
fn missing_reap_or_refused_retirement_quarantines_without_discharge() {
    for refuse_retirement in [false, true] {
        let (registration, registrar) = registration(refuse_retirement, None);
        let cleanup = LaunchCleanup::new(&registration);
        if !refuse_retirement {
            cleanup.child_started();
        }

        drop(cleanup);

        assert_eq!(registrar.retired.load(Ordering::Acquire), 0);
        assert_eq!(registrar.quarantined.load(Ordering::Acquire), 1);
    }
}

#[test]
fn published_retirement_waits_for_final_descriptor_close_after_actual_reap() {
    let (registration, registrar) = registration(false, None);
    let cleanup = LaunchCleanup::new(&registration);
    let (socket, peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    registrar
        .descriptors
        .lock()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))
        .push(DescriptorWitness::new(socket.as_raw_fd(), peer));
    let borrower = DescriptorBorrower {
        _socket: socket,
        _service: registration
            .host_services
            .reserve_resources(0, 1, 0)
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
        _cleanup: cleanup.clone(),
    };
    let mut child = crate::QemuNodeChild::new(
        Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
    );
    child.retain_launch_cleanup(cleanup.clone());
    registrar
        .register(
            registration.target,
            registration.initial_policy,
            registration.resources,
            HostOperationSupervisor::new(HostOperationBudgets::default(), None)
                .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
            None,
        )
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    cleanup
        .published()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    assert!(cleanup.is_published());
    assert!(!cleanup.cleanup_proven());

    child
        .force_kill_and_reap_failed_realization()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    assert!(cleanup.cleanup_proven());
    let outcome = registrar.prepare_retirement_after_cleanup(registration.target);
    assert!(
        outcome.failure.is_none(),
        "cleanup fixture failed: {outcome:?}"
    );
    assert_eq!(
        outcome.disposition,
        crate::ram_control::RamControlRetirementDisposition::Returned
    );
    drop(child);
    drop(cleanup);
    let retired = registrar.normal_retired.clone();
    let scoped_lifetime = Arc::downgrade(&registrar);
    drop(registration);
    drop(registrar);
    assert!(scoped_lifetime.upgrade().is_none());
    assert_eq!(retired.load(Ordering::Acquire), 0);
    drop(borrower);

    assert_eq!(retired.load(Ordering::Acquire), 1);
}

#[test]
fn retained_manifest_metadata_outlives_reap_and_releases_before_outer_retirement() {
    let (registration, registrar) = registration(false, None);
    let cleanup = LaunchCleanup::new(&registration);
    let service = registration
        .host_services
        .reserve_resources(0, 0, 4096)
        .unwrap_or_else(|error| panic!("metadata admission failed: {error:?}"));
    let metadata = QemuFaultManifestMetadataLease::new(service, cleanup.clone());
    let copied_metadata = metadata.clone();
    let mut child = crate::QemuNodeChild::new(
        Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap_or_else(|error| panic!("cleanup child failed: {error:?}")),
    );
    child.retain_launch_cleanup(cleanup.clone());
    cleanup
        .published()
        .unwrap_or_else(|error| panic!("publication failed: {error:?}"));

    child
        .force_kill_and_reap_failed_realization()
        .unwrap_or_else(|error| panic!("reap failed: {error:?}"));
    let outcome = registrar.prepare_retirement_after_cleanup(registration.target);
    assert!(
        outcome.failure.is_none(),
        "retirement preparation failed: {outcome:?}"
    );
    assert_eq!(
        outcome.disposition,
        crate::ram_control::RamControlRetirementDisposition::Returned
    );
    drop(child);
    drop(cleanup);
    drop(metadata);
    assert_eq!(registrar.normal_retired.load(Ordering::Acquire), 0);
    assert!(
        registration
            .host_services
            .reserve_resources(0, 0, 1024 * 1024)
            .is_err()
    );

    drop(copied_metadata);

    assert_eq!(registrar.normal_retired.load(Ordering::Acquire), 1);
    assert_eq!(registrar.quarantined.load(Ordering::Acquire), 0);
    assert!(
        registration
            .host_services
            .reserve_resources(0, 0, 1024 * 1024)
            .is_ok()
    );
}

#[test]
fn publication_breaks_registrar_back_reference_without_inventing_terminal_authority() {
    let (registration, registrar) = registration(false, None);
    let cleanup = LaunchCleanup::new(&registration);
    let registrar_lifetime = Arc::downgrade(&registrar);
    cleanup
        .published()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));

    drop(registration);
    drop(registrar);

    assert!(registrar_lifetime.upgrade().is_none());
    drop(cleanup);
}

struct Backing {
    record: RootRecord,
    tree: RegionTree,
    entered: Option<mpsc::Sender<()>>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
    original: crucible_ram::MetadataBudget,
    finished: Option<mpsc::Sender<()>>,
}

/// Observes Rust/TLS destruction without claiming a native join receipt.
struct SourceBodyReturned(mpsc::Sender<()>);

impl Drop for SourceBodyReturned {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

thread_local! {
    static SOURCE_BODY_RETURNED: std::cell::RefCell<Option<SourceBodyReturned>> = const {
        std::cell::RefCell::new(None)
    };
}

impl Drop for Backing {
    fn drop(&mut self) {
        if let Some(finished) = self.finished.take() {
            SOURCE_BODY_RETURNED.with(|returned| {
                *returned.borrow_mut() = Some(SourceBodyReturned(finished));
            });
        }
    }
}

impl QemuRamBacking for Backing {
    fn root_object_id(&self) -> &str {
        "test-root"
    }
    fn root_record(&self) -> &RootRecord {
        &self.record
    }
    fn with_page_response(
        &self,
        region: &str,
        index: u64,
        boundary: &mut dyn FnMut() -> Result<(), crate::ram_source::QemuRamReadBoundaryError>,
        consumer: &mut crate::ram_source::QemuRamResponseConsumer<'_>,
    ) -> Result<(), QemuRamSourceError> {
        if let Some(entered) = &self.entered {
            let _ = entered.send(());
        }
        if let Some(release) = self
            .release
            .lock()
            .map_err(|_| QemuRamSourceError::Ownership)?
            .take()
        {
            release.recv().map_err(|_| QemuRamSourceError::Ownership)?;
        }
        boundary()?;
        crate::qmp::checkpoint_paged_source_support::fixture_page_response(
            &self.tree,
            region,
            index,
            &self.original,
            &[7; 4096],
            boundary,
            consumer,
        )
    }
}

fn backing(entered: Option<mpsc::Sender<()>>, release: Option<mpsc::Receiver<()>>) -> Arc<Backing> {
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 4096)
                .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
        ],
        Limits::default(),
    )
    .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let budget = MetadataBudget::new(1024 * 1024);
    let original = budget.clone();
    let tree = RegionTree::from_page_digests(
        4096,
        &[PageDigest::hash(&vec![7; 4096])
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))],
        &budget,
    )
    .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let record = RootRecord::new(topology, Scope::Exact, vec![tree.digest()])
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    Arc::new(Backing {
        record,
        tree,
        entered,
        release: Mutex::new(release),
        original,
        finished: None,
    })
}

#[test]
fn actual_source_join_closes_worker_descriptors_and_leases_before_discharge() {
    let (registration, registrar) = registration(false, None);
    let cleanup = LaunchCleanup::new(&registration);
    let (socket, peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    registrar
        .descriptors
        .lock()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))
        .push(DescriptorWitness::new(socket.as_raw_fd(), peer));
    let backing = backing(None, None);
    let binding = RamPageBinding {
        session: [4; 16],
        owner_incarnation: [5; 16],
        source_generation: 1,
        root_digest: *backing.record.digest().as_bytes(),
    };
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let original = supervisor
        .begin(crucible_host_resources::host_supervision::HostOperationClass::Cleanup)
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let mut source = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        supervisor.clone(),
        registration.host_services.clone(),
        Some(cleanup.clone()),
    )
    .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    drop(cleanup);
    assert_eq!(registrar.retired.load(Ordering::Acquire), 0);

    source
        .stop(Some(crate::ram_control::RamCleanupOriginal::direct(
            &original,
            &supervisor,
        )))
        .1
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));

    drop(source);
    assert_eq!(registrar.retired.load(Ordering::Acquire), 1);
    assert_eq!(registrar.quarantined.load(Ordering::Acquire), 0);
}

// crucible-lint: allow clippy-disallowed-method -- this fixture bounds final host cleanup custody only; host time never enters guest or modeled state.
#[allow(clippy::disallowed_methods)]
#[test]
fn abandoned_source_retains_cleanup_and_capacity_after_rust_return() {
    let (notice, quarantined) = mpsc::channel();
    let (registration, registrar) = registration(false, Some(notice));
    let cleanup = LaunchCleanup::new(&registration);
    let (entered, started) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let (finished, body_returned) = mpsc::channel();
    let mut backing = backing(Some(entered), Some(blocked));
    Arc::get_mut(&mut backing)
        .expect("unshared cleanup backing")
        .finished = Some(finished);
    let binding = RamPageBinding {
        session: [4; 16],
        owner_incarnation: [5; 16],
        source_generation: 1,
        root_digest: *backing.record.digest().as_bytes(),
    };
    let (socket, mut peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let source = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        HostOperationSupervisor::new(HostOperationBudgets::default(), None)
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
        registration.host_services.clone(),
        Some(cleanup.clone()),
    )
    .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let request = RamPageRequest {
        binding,
        sequence: 1,
        region_ordinal: 0,
        page_index: 0,
    };
    peer.write_all(
        &request
            .encode()
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    started
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));

    drop(source);
    drop(cleanup);
    assert_eq!(registrar.retired.load(Ordering::Acquire), 0);
    assert!(
        registration
            .host_services
            .reserve_resources(1, 32, 1024 * 1024)
            .is_err()
    );
    release
        .send(())
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    body_returned
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));

    // The real worker has destroyed its Rust body and reached TLS teardown.
    // Its abandoned native join record still retains the containing launch,
    // pending join obligation and original task loan until process exit.
    assert!(
        registration
            .host_services
            .reserve_resources(1, 32, 1024 * 1024)
            .is_err()
    );
    assert_eq!(registrar.retired.load(Ordering::Acquire), 0);
    assert_eq!(registrar.quarantined.load(Ordering::Acquire), 0);
    assert!(matches!(
        quarantined.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}

#[test]
fn uncertain_final_cleanup_retains_actual_unhanded_target_workspace_descriptor()
-> Result<(), Box<dyn std::error::Error>> {
    if crate::test_process::run_isolated(
        module_path!(),
        "uncertain_final_cleanup_retains_actual_unhanded_target_workspace_descriptor",
    )? {
        return Ok(());
    }

    for cause in [
        "unreaped",
        "import",
        "join",
        "registrar",
        "authority-poison",
        "workspace-poison",
        "proven",
    ] {
        let (registration, _) = registration(cause == "registrar", None);
        let cleanup = LaunchCleanup::new(&registration);
        let (socket, mut peer) = UnixStream::pair()?;
        peer.set_nonblocking(true)?;
        // This component body cannot issue Source/Target or native credit. Its
        // real socket makes the generic unhanded destructor's close observable.
        *cleanup.inner.target_workspace.lock().unwrap() = Some(
            crate::spawn::OriginalDeviceDigestWorkspace::descriptor_ownership_mechanism(
                socket.into(),
            ),
        );
        if cause == "unreaped" {
            cleanup.child_started();
        }
        let import = (cause == "import").then(|| cleanup.descriptor_import().unwrap());
        let join = (cause == "join").then(|| cleanup.source_join().unwrap());
        if cause == "authority-poison" {
            let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = cleanup.inner.authority.lock().unwrap();
                panic!("poison actual cleanup authority mechanism");
            }));
            assert!(poisoned.is_err());
        }
        if cause == "workspace-poison" {
            let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = cleanup.inner.target_workspace.lock().unwrap();
                panic!("poison actual workspace keeper mechanism");
            }));
            assert!(poisoned.is_err());
        }

        drop(cleanup);
        // Dropping tickets without reporting physical closure leaves their
        // actual outstanding counters set before the final record destructor.
        drop(import);
        drop(join);

        let mut byte = [0_u8; 1];
        let observed = peer.read(&mut byte);
        if cause == "proven" {
            assert_eq!(observed?, 0, "proven unique body must physically close");
        } else {
            assert!(
                matches!(observed, Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "uncertain {cause} must retain the same actual body descriptor"
            );
        }
    }
    Ok(())
}

#[test]
fn poisoned_publication_keeps_actual_runtime_registration_and_refuses_return()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{QemuHostIoRuntime, QemuLiveHostIoRuntime};
    use std::os::fd::AsFd;
    let (registration, registrar) = registration(false, None);
    let cleanup = LaunchCleanup::new(&registration);
    cleanup.published()?;
    let allocation = crucible_qemu_shmem::RegionAllocation::new_model(
        crucible_qemu_shmem::RegionConfig::new(1, 2),
    )?;
    let layout = allocation.layout();
    let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let (wake, _peer) = UnixStream::pair()?;
    let mut runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(shmem.as_fd(), wake.as_fd(), layout.region_size, 0)?
            .with_ram_control_registration(registration)
            .with_launch_cleanup(Some(cleanup.clone()));
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = cleanup.inner.authority.lock().unwrap();
        panic!("component publication access becomes uncertain");
    }));
    assert!(poisoned.is_err());
    assert!(cleanup.publication().is_err());
    let mut progress = crate::ram_control::RamControlRetirementProgress::new();

    let (returned, first) = runtime.retire_host_ram_after_cleanup(None, &mut progress);
    assert!(!returned);
    let first = first.unwrap_err();
    assert!(first.first.is_some() && first.uncertain);
    assert!(runtime.ram_control_registration().is_some());
    let (returned, repeated) = runtime.retire_host_ram_after_cleanup(None, &mut progress);
    assert!(!returned);
    assert_eq!(repeated.unwrap_err(), first);
    assert!(runtime.ram_control_registration().is_some());
    assert!(!registrar.prepared.load(Ordering::Acquire));
    assert_eq!(registrar.normal_retired.load(Ordering::Acquire), 0);
    Ok(())
}

#[path = "tests/retirement.rs"]
mod retirement;
