//! Real-descriptor staging boundaries without native fork qualification.

use super::*;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::ram_control::{RamControlClient, RamControlRegistrar};
use crucible_linux_resource::host_services::HostServiceAllocator;
use crucible_linux_resource::host_supervision::HostOperationBudgets;
use crucible_linux_resource::ram_policy::{
    HostRamMode, HostRamPolicy, HostRamTarget, HostResourceVector,
};
use crucible_protocol::ram_control::RamControlError;

#[derive(Default)]
struct Registrar {
    retired: AtomicUsize,
    quarantined: AtomicUsize,
}

impl RamControlRegistrar for Registrar {
    fn register(
        &self,
        _: HostRamTarget,
        _: HostRamPolicy,
        _: HostResourceVector,
        _: HostOperationSupervisor,
        _: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }
    fn retire_unpublished_after_cleanup(
        &self,
        _: HostRamTarget,
        _: HostResourceVector,
    ) -> Result<(), RamControlError> {
        self.retired.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn quarantine_unpublished(
        &self,
        _: HostRamTarget,
        _: HostResourceVector,
    ) -> Result<(), RamControlError> {
        self.quarantined.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

fn registration() -> Result<(RamControlRegistration, Arc<Registrar>), Box<dyn Error>> {
    let registrar = Arc::new(Registrar::default());
    Ok((
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
                resident_peak_bytes: 32 << 20,
                backing_peak_bytes: 32 << 20,
                metadata_bytes: 1 << 20,
                staging_bytes: 16 << 20,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 2,
                file_descriptors: 32,
            },
            spill_quota_bytes: 8192,
            host_services: HostServiceAllocator::new(2, 32, 32 << 20)?,
            registrar: registrar.clone(),
        },
        registrar,
    ))
}

fn directory() -> Result<(tempfile::TempDir, crate::QemuPreparedRunDirectory), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    File::create(root.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let cgroup = File::open(root.path())?.into();
    let procs = File::create(root.path().join("cgroup.procs"))?.into();
    let cancellation = super::super::hot_fork_plugin_endpoints::create_nonblocking_eventfd()?;
    let contract = crate::QemuChildProcessContract::from_unvalidated_hot_fork_test_descriptors(
        cgroup,
        procs,
        cancellation,
        1,
        1 << 30,
        1 << 30,
    );
    let directory = crate::QemuPreparedRunDirectory::open_for_test_requirements(
        crate::QemuLaunchResourceRequirements::from_vm_shape(1, 1, false),
        root.path(),
        &contract,
    )?;
    Ok((root, directory))
}

fn supervisor() -> Result<HostOperationSupervisor, Box<dyn Error>> {
    Ok(HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        None,
    )?)
}

#[test]
fn stages_use_independent_sealed_plans_namespaces_and_anonymous_disk_files()
-> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::FileExt;
    let (_root, directory) = directory()?;
    let (first_registration, first_owner) = registration()?;
    let (second_registration, second_owner) = registration()?;
    let mut first = QemuHotForkRamStage::prepare(
        first_registration.clone(),
        supervisor()?,
        &directory,
        None,
        LaunchCleanup::new(&first_registration),
    )?;
    let mut second = QemuHotForkRamStage::prepare(
        second_registration.clone(),
        supervisor()?,
        &directory,
        None,
        LaunchCleanup::new(&second_registration),
    )?;
    first.seal(7, 11)?;
    second.seal(7, 12)?;

    assert_ne!(first.session, second.session);
    assert_ne!(first.names.plan, second.names.plan);
    let first_disk = rustix::fs::fstat(&first.spill)?;
    let second_disk = rustix::fs::fstat(&second.spill)?;
    assert_eq!(first_disk.st_nlink, 0);
    assert_eq!(second_disk.st_nlink, 0);
    assert_ne!(first_disk.st_ino, second_disk.st_ino);
    let file = File::from(first.plan.as_ref().ok_or("plan absent")?.try_clone()?);
    let mut bytes = vec![0; file.metadata()?.len() as usize];
    file.read_exact_at(&mut bytes, 0)?;
    let plan = RamForkPlan::decode(&bytes)?;
    assert_eq!(plan.process_contract_generation, 11);
    assert_eq!(plan.control.session, first.session);
    assert_eq!(plan.source, None);
    match plan.control.message {
        RamControlMessage::Request(RamControlRequest::Apply {
            expected_revision,
            policy_revision,
            reservation_revision,
            resources,
            ..
        }) => {
            assert_eq!(
                (expected_revision, policy_revision, reservation_revision),
                (0, 1, 0)
            );
            assert_eq!(resources, resources_to_wire(first_registration.resources));
        }
        _ => panic!("sealed child plan must carry its actual initial allocation"),
    }
    assert!(file.write_all_at(b"changed", 0).is_err());
    assert!(file.set_len(1).is_err());
    drop(file);
    drop(first);
    drop(second);
    assert_eq!(first_owner.retired.load(Ordering::Acquire), 1);
    assert_eq!(second_owner.retired.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn cancellation_and_insufficient_service_peak_refuse_before_descriptor_staging()
-> Result<(), Box<dyn Error>> {
    let (_root, directory) = directory()?;
    let (mut registration, owner) = registration()?;
    let canceled = supervisor()?;
    canceled.cancel()?;
    assert!(
        QemuHotForkRamStage::prepare(
            registration.clone(),
            canceled,
            &directory,
            None,
            LaunchCleanup::new(&registration)
        )
        .is_err()
    );
    assert_eq!(owner.retired.load(Ordering::Acquire), 1);
    registration.host_services = HostServiceAllocator::new(1, 15, 32 << 20)?;
    assert!(
        QemuHotForkRamStage::prepare(
            registration.clone(),
            supervisor()?,
            &directory,
            None,
            LaunchCleanup::new(&registration)
        )
        .is_err()
    );
    assert_eq!(owner.retired.load(Ordering::Acquire), 2);
    Ok(())
}

#[test]
fn ambiguous_monitor_custody_keeps_reservation_after_local_descriptors_close()
-> Result<(), Box<dyn Error>> {
    let (_root, directory) = directory()?;
    let (registration, owner) = registration()?;
    let services = registration.host_services.clone();
    let mut stage = QemuHotForkRamStage::prepare(
        registration.clone(),
        supervisor()?,
        &directory,
        None,
        LaunchCleanup::new(&registration),
    )?;
    stage.seal(7, 11)?;
    stage.imported = Some(stage.cleanup.descriptor_import()?);
    drop(stage);

    let _all_local_capacity = services.reserve_resources(2, 32, 32 << 20)?;
    assert_eq!(owner.retired.load(Ordering::Acquire), 0);
    assert_eq!(owner.quarantined.load(Ordering::Acquire), 1);
    Ok(())
}

struct Backing {
    record: crucible_ram::RootRecord,
    tree: crucible_ram::RegionTree,
}

impl QemuRamBacking for Backing {
    fn root_object_id(&self) -> &str {
        "fixture-source"
    }
    fn root_record(&self) -> &crucible_ram::RootRecord {
        &self.record
    }
    fn read_page_with_proof(
        &self,
        region: &str,
        index: u64,
        boundary: &mut dyn FnMut() -> Result<(), crate::ram_source::QemuRamSourceError>,
    ) -> Result<(Vec<u8>, crucible_ram::PageProof), crate::ram_source::QemuRamSourceError> {
        boundary()?;
        Ok((
            vec![9; 4096],
            self.tree
                .proof(region, index)
                .map_err(|_| crate::ram_source::QemuRamSourceError::Ownership)?,
        ))
    }
}

#[test]
fn fresh_source_keeps_backing_until_join_and_refuses_another_namespace()
-> Result<(), Box<dyn Error>> {
    use crucible_protocol::ram_page::{
        RamPageRequest, RamPageResponse, RamPageStatus, read_ram_page_response,
    };
    use crucible_ram::{
        Limits, MetadataBudget, PageDigest, RegionClass, RegionDescriptor, RegionTree, RootRecord,
        Scope, Topology,
    };
    use std::time::Duration;
    let (_root, directory) = directory()?;
    let (registration, owner) = registration()?;
    let cleanup = LaunchCleanup::new(&registration);
    let tree = RegionTree::from_page_digests(
        4096,
        &[PageDigest::hash(&vec![9; 4096])?],
        &MetadataBudget::new(1 << 20),
    )?;
    let topology = Topology::new(
        vec![RegionDescriptor::new(
            "machine.ram",
            RegionClass::MutableMain,
            4096,
        )?],
        Limits::default(),
    )?;
    let backing = Arc::new(Backing {
        record: RootRecord::new(topology, Scope::Exact, vec![tree.digest()])?,
        tree,
    });
    let binding = RamPageBinding {
        session: [4; 16],
        owner_incarnation: [5; 16],
        source_generation: 1,
        root_digest: *backing.record.digest().as_bytes(),
    };
    let lifetime = Arc::downgrade(&backing);
    let stage = QemuHotForkRamStage::prepare(
        registration,
        supervisor()?,
        &directory,
        Some((backing, binding)),
        cleanup,
    )?;
    let mut peer = stage
        .source_child
        .as_ref()
        .ok_or("source absent")?
        .try_clone()?;
    peer.set_read_timeout(Some(Duration::from_secs(2)))?;
    peer.set_write_timeout(Some(Duration::from_secs(2)))?;
    assert!(lifetime.upgrade().is_some());

    peer.write_all(
        &RamPageRequest {
            binding,
            sequence: 1,
            region_ordinal: 0,
            page_index: 0,
        }
        .encode()?,
    )?;
    let bytes = read_ram_page_response(&mut peer)?;
    let response = RamPageResponse::decode(&bytes)?;
    assert_eq!(response.status, RamPageStatus::Page);
    assert_eq!(response.page, &vec![9; 4096]);
    let proof = crucible_ram::PageProof::decode(response.proof, Limits::default())?;
    let retained = lifetime.upgrade().ok_or("backing lost during request")?;
    proof.verify(response.page, &retained.record, retained.record.digest())?;
    drop(retained);

    let foreign = RamPageBinding {
        owner_incarnation: [8; 16],
        ..binding
    };
    peer.write_all(
        &RamPageRequest {
            binding: foreign,
            sequence: 2,
            region_ordinal: 0,
            page_index: 0,
        }
        .encode()?,
    )?;
    let bytes = read_ram_page_response(&mut peer)?;
    let response = RamPageResponse::decode(&bytes)?;
    assert_eq!(response.status, RamPageStatus::Rejected);
    assert!(response.page.is_empty());
    assert!(response.proof.is_empty());
    drop(peer);
    drop(stage);
    assert!(lifetime.upgrade().is_none());
    assert_eq!(owner.retired.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn pinned_directory_keeps_no_child_admission_until_final_close_and_refuses_rebinding()
-> Result<(), Box<dyn Error>> {
    let (_root, mut directory) = directory()?;
    let (registration, owner) = registration()?;
    let custody = crate::QemuRamLaunchCustody::new(&registration);
    assert!(custody.validates(&registration));
    directory.retain_ram_launch_custody(custody.clone())?;
    directory.retain_ram_launch_custody(custody.clone())?;
    drop(custody);
    drop(registration);
    assert_eq!(owner.retired.load(Ordering::Acquire), 0);

    let (foreign, foreign_owner) = super::tests::registration()?;
    let foreign_custody = crate::QemuRamLaunchCustody::new(&foreign);
    assert!(
        directory
            .retain_ram_launch_custody(foreign_custody.clone())
            .is_err()
    );
    drop(foreign_custody);
    drop(foreign);
    assert_eq!(foreign_owner.retired.load(Ordering::Acquire), 1);
    assert_eq!(owner.retired.load(Ordering::Acquire), 0);

    drop(directory);
    assert_eq!(owner.retired.load(Ordering::Acquire), 1);
    Ok(())
}
