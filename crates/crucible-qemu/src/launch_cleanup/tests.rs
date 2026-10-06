//! Real descriptor, process-reap, and source-worker custody regressions.

use super::*;
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_linux_resource::ram_policy::{HostRamMode, HostRamPolicy};
use crucible_protocol::ram_page::{RamPageBinding, RamPageRequest};
use crucible_ram::{
    Limits, MetadataBudget, PageDigest, PageProof, RegionClass, RegionDescriptor, RegionTree,
    RootRecord, Scope, Topology,
};

use crate::ram_control::RamControlClient;
use crate::ram_source::{QemuRamBacking, QemuRamSourceError, QemuRamSourceService};

struct Registrar {
    services: HostServiceAllocator,
    descriptors: Arc<Mutex<Vec<DescriptorWitness>>>,
    retired: AtomicUsize,
    normal_retired: Arc<AtomicUsize>,
    prepared: Arc<AtomicBool>,
    quarantined: AtomicUsize,
    refuse_retirement: bool,
    quarantine_notice: Option<mpsc::Sender<()>>,
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

    fn prepare_retirement_after_cleanup(&self, _: HostRamTarget) -> Result<(), RamControlError> {
        self.prepared.store(true, Ordering::Release);
        Ok(())
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
    let config = crucible_shmem::RegionConfig::new(1, 4);
    let length = crucible_shmem::RegionLayout::for_config(config)
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))
        .region_size;
    let (mut resources, setup_peer) = crate::spawn::create_test_spawn_resource_pair(length + 4096)
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
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
    registrar
        .prepare_retirement_after_cleanup(registration.target)
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
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
    registrar
        .prepare_retirement_after_cleanup(registration.target)
        .unwrap_or_else(|error| panic!("retirement preparation failed: {error:?}"));
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
}

impl QemuRamBacking for Backing {
    fn root_object_id(&self) -> &str {
        "test-root"
    }
    fn root_record(&self) -> &RootRecord {
        &self.record
    }
    fn read_page_with_proof(
        &self,
        region: &str,
        index: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamSourceError>,
    ) -> Result<(Vec<u8>, PageProof), QemuRamSourceError> {
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
        Ok((
            vec![7; 4096],
            self.tree
                .proof(region, index)
                .map_err(|_| QemuRamSourceError::Ownership)?,
        ))
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
    let tree = RegionTree::from_page_digests(
        4096,
        &[PageDigest::hash(&vec![7; 4096])
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"))],
        &MetadataBudget::new(1024 * 1024),
    )
    .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let record = RootRecord::new(topology, Scope::Exact, vec![tree.digest()])
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    Arc::new(Backing {
        record,
        tree,
        entered,
        release: Mutex::new(release),
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
    let source = QemuRamSourceService::start_with_cleanup(
        socket,
        backing,
        binding,
        HostOperationSupervisor::new(HostOperationBudgets::default(), None)
            .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}")),
        registration.host_services.clone(),
        Some(cleanup.clone()),
    )
    .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    drop(cleanup);
    assert_eq!(registrar.retired.load(Ordering::Acquire), 0);

    source
        .stop()
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));

    assert_eq!(registrar.retired.load(Ordering::Acquire), 1);
    assert_eq!(registrar.quarantined.load(Ordering::Acquire), 0);
}

#[test]
fn detached_blocked_source_keeps_capacity_then_quarantines_without_a_join_proof() {
    let (notice, quarantined) = mpsc::channel();
    let (registration, registrar) = registration(false, Some(notice));
    let cleanup = LaunchCleanup::new(&registration);
    let (entered, started) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let backing = backing(Some(entered), Some(blocked));
    let binding = RamPageBinding {
        session: [4; 16],
        owner_incarnation: [5; 16],
        source_generation: 1,
        root_digest: *backing.record.digest().as_bytes(),
    };
    let (socket, mut peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));
    let source = QemuRamSourceService::start_with_cleanup(
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
    quarantined
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("cleanup fixture failed: {error:?}"));

    assert_eq!(registrar.retired.load(Ordering::Acquire), 0);
    assert_eq!(registrar.quarantined.load(Ordering::Acquire), 1);
    assert!(
        registration
            .host_services
            .reserve_resources(1, 32, 1024 * 1024)
            .is_ok()
    );
}
