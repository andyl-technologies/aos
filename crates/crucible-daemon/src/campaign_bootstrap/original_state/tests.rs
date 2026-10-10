//! Exercises real state files and the same retained preparation guard.
//!
//! Local fixture banks pay their controls for these mechanism tests. They do
//! not construct a parent carrier, Source entitlement or production actor.

// crucible-lint: allow panic-shortcut -- failed mechanism assertions stop these tests immediately.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible::owned_decode::{DecodeResourceAuthority, ResourceLoan};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};

struct Fixture {
    original: HostOperationGuard,
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
    cancel_after_root_open: std::sync::Mutex<Option<(u64, u64, HostOperationSupervisor)>>,
}

struct Credit {
    _descriptors: Option<crucible_linux_resource::host_services::HostServiceLease>,
    _pair: HostServiceLeasePair,
}

impl DecodeResourceAuthority for Fixture {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        let mut trigger = self.cancel_after_root_open.lock().unwrap();
        if let Some((device, inode, supervisor)) = trigger.as_ref()
            && root_descriptor_present(*device, *inode)
        {
            supervisor.cancel().unwrap();
            trigger.take();
        }
        drop(trigger);
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        let extent = bytes
            + ResourceLoan::allocation_bytes::<Credit>()
            + 2 * crucible_linux_resource::host_services::HostServiceLease::metadata_bytes();
        let (first, second) = self
            .resident
            .reserve_paired_bytes(&self.metadata, extent)
            .map_err(DecodeAdmissionError::new)?;
        Ok(ResourceLoan::new(Credit {
            _descriptors: None,
            _pair: HostServiceLeasePair::new(first, second),
        }))
    }

    fn reserve_descriptors(&self, count: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        let extent = ResourceLoan::allocation_bytes::<Credit>()
            + 3 * crucible_linux_resource::host_services::HostServiceLease::metadata_bytes();
        let (first, second) = self
            .resident
            .reserve_paired_bytes(&self.metadata, extent)
            .map_err(DecodeAdmissionError::new)?;
        let descriptors = self
            .resident
            .reserve_resources(0, count, 0)
            .map_err(DecodeAdmissionError::new)?;
        Ok(ResourceLoan::new(Credit {
            _descriptors: Some(descriptors),
            _pair: HostServiceLeasePair::new(first, second),
        }))
    }
}

fn fixture(descriptors: u64) -> (HostOperationSupervisor, Arc<Fixture>, DecodeBudget) {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let authority = Arc::new(Fixture {
        original: supervisor.begin(HostOperationClass::Preparation).unwrap(),
        resident: HostServiceAllocator::new(1, descriptors, 1 << 20).unwrap(),
        metadata: HostServiceAllocator::new(1, descriptors, 1 << 20).unwrap(),
        cancel_after_root_open: std::sync::Mutex::new(None),
    });
    let budget = DecodeBudget::new(authority.clone(), 1 << 20).unwrap();
    (supervisor, authority, budget)
}

fn state_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), Permissions::from_mode(0o700)).unwrap();
    root
}

fn prepare(
    root: &Path,
    budget: &DecodeBudget,
) -> Result<OriginalCampaignStateBootstrap, OriginalCampaignStateError> {
    let metadata = fs::metadata(root).unwrap();
    OriginalCampaignStateBootstrap::prepare_at(root, metadata.uid(), metadata.gid(), budget)
}

#[test]
fn state_descriptor_refusal_precedes_lock_or_identity_creation() {
    let root = state_root();
    let (_supervisor, _authority, budget) = fixture(1);

    let refusal = prepare(root.path(), &budget).err().unwrap();

    assert!(matches!(refusal.source, StateCause::Original(_)));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn state_identity_and_exclusive_lock_survive_until_actual_healthy_close() {
    let root = state_root();
    let (_supervisor, authority, budget) = fixture(8);
    let owner = prepare(root.path(), &budget).unwrap();
    let identity_path = root.path().join(STATE_IDENTITY_FILE);
    let identity = fs::read(&identity_path).unwrap();
    assert_eq!(identity.len(), STATE_IDENTITY_BYTES);
    assert_eq!(&identity[..8], STATE_IDENTITY_MAGIC);
    assert!(authority.resident.reserve_resources(0, 8, 0).is_err());

    owner.try_close().unwrap();

    assert!(authority.resident.reserve_resources(0, 8, 0).is_ok());
    let metadata = fs::metadata(root.path()).unwrap();
    let ordinary =
        CampaignStateOwner::open(root.path(), metadata.uid(), metadata.gid(), false).unwrap();
    assert_eq!(fs::read(identity_path).unwrap(), identity);
    assert_eq!(ordinary.transfer_identity().len(), 64);
    drop(ordinary);
}

#[test]
fn state_drop_keeps_actual_lock_and_descriptor_payment_on_uncertainty() {
    let root = state_root();
    let (_supervisor, authority, budget) = fixture(8);
    let owner = prepare(root.path(), &budget).unwrap();

    drop(owner);

    assert!(authority.resident.reserve_resources(0, 8, 0).is_err());
    let metadata = fs::metadata(root.path()).unwrap();
    assert!(matches!(
        CampaignStateOwner::open(root.path(), metadata.uid(), metadata.gid(), false),
        Err(CampaignLocalServiceError::StateInUse)
    ));
}

#[test]
fn state_kernel_first_cause_retains_the_immediate_original_postcut() {
    let (supervisor, _authority, budget) = fixture(8);

    let refusal = effect::<()>(&budget, || {
        supervisor.cancel().unwrap();
        Err(io::Error::from_raw_os_error(5))
    })
    .err()
    .unwrap();

    assert!(
        matches!(refusal, StateCause::Kernel { source, original_after: Some(_) }
        if source.raw_os_error() == Some(5))
    );
}

#[test]
fn state_original_cancellation_refuses_before_any_file_birth() {
    let root = state_root();
    let (supervisor, _authority, budget) = fixture(8);
    supervisor.cancel().unwrap();

    assert!(prepare(root.path(), &budget).is_err());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

fn root_descriptor_present(device: u64, inode: u64) -> bool {
    fs::read_dir("/proc/self/fd").unwrap().any(|entry| {
        entry
            .ok()
            .and_then(|entry| fs::metadata(entry.path()).ok())
            .is_some_and(|metadata| metadata.dev() == device && metadata.ino() == inode)
    })
}

#[test]
fn state_rejects_nonprivate_root_before_file_birth() {
    let root = state_root();
    fs::set_permissions(root.path(), Permissions::from_mode(0o755)).unwrap();
    let (_supervisor, _authority, budget) = fixture(8);

    let refusal = prepare(root.path(), &budget).err().unwrap();

    assert!(matches!(refusal.source, StateCause::Identity));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn state_late_original_refusal_retains_successfully_opened_root_and_credit() {
    let root = state_root();
    let metadata = fs::metadata(root.path()).unwrap();
    let (supervisor, authority, budget) = fixture(8);
    *authority.cancel_after_root_open.lock().unwrap() =
        Some((metadata.dev(), metadata.ino(), supervisor));

    let refusal = prepare(root.path(), &budget).err().unwrap();

    assert!(matches!(refusal.source, StateCause::Original(_)));
    assert!(root_descriptor_present(metadata.dev(), metadata.ino()));
    assert!(authority.resident.reserve_resources(0, 8, 0).is_err());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn state_unwind_retains_actual_lock_and_external_credit() {
    let root = state_root();
    let (_supervisor, authority, budget) = fixture(8);

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _owner = prepare(root.path(), &budget).unwrap();
        std::panic::panic_any("after actual state publication");
    }));

    assert!(unwind.is_err());
    assert!(authority.resident.reserve_resources(0, 8, 0).is_err());
    let metadata = fs::metadata(root.path()).unwrap();
    assert!(matches!(
        CampaignStateOwner::open(root.path(), metadata.uid(), metadata.gid(), false),
        Err(CampaignLocalServiceError::StateInUse)
    ));
}

#[test]
fn actual_service_handle_keeps_same_state_files_and_external_credit_until_close() {
    let root = state_root();
    let (_supervisor, authority, budget) = fixture(8);
    let mut owner = prepare(root.path(), &budget).unwrap();
    let handle = owner.share_for_service().unwrap();
    let expected_identity = handle.transfer_identity().unwrap().to_owned();
    let pins = owner.shared.as_ref().unwrap();
    assert!(Arc::ptr_eq(pins, &handle.pins));
    assert!(owner.root.is_none());
    assert!(owner.lock.is_none());
    assert!(owner.shared_control.is_some());
    assert!(authority.resident.reserve_resources(0, 8, 0).is_err());

    let state: PreparedCampaignStateOwner = handle.into();
    assert_eq!(
        state.debug_session_inventory_path().unwrap(),
        root.path().join("debug-sessions.v1")
    );
    let metadata = fs::metadata(root.path()).unwrap();
    assert!(matches!(
        CampaignStateOwner::open(root.path(), metadata.uid(), metadata.gid(), false),
        Err(CampaignLocalServiceError::StateInUse)
    ));
    drop(state);
    owner.try_close().unwrap();

    assert!(authority.resident.reserve_resources(0, 8, 0).is_ok());
    let reopened =
        CampaignStateOwner::open(root.path(), metadata.uid(), metadata.gid(), false).unwrap();
    assert_eq!(reopened.transfer_identity(), expected_identity);
}

#[test]
fn surviving_state_weak_refuses_actual_close_and_retains_same_lock_and_payment() {
    let root = state_root();
    let (_supervisor, authority, budget) = fixture(8);
    let mut owner = prepare(root.path(), &budget).unwrap();
    let handle = owner.share_for_service().unwrap();
    let weak = Arc::downgrade(&handle.pins);
    drop(handle);

    let error = owner.try_close().unwrap_err();

    assert!(matches!(error.source, StateCause::Aliases));
    assert!(weak.upgrade().is_some());
    assert!(authority.resident.reserve_resources(0, 8, 0).is_err());
    let metadata = fs::metadata(root.path()).unwrap();
    assert!(matches!(
        CampaignStateOwner::open(root.path(), metadata.uid(), metadata.gid(), false),
        Err(CampaignLocalServiceError::StateInUse)
    ));
}

#[test]
fn canceled_shared_state_retains_actual_service_files_and_credit() {
    let root = state_root();
    let (supervisor, authority, budget) = fixture(8);
    let mut owner = prepare(root.path(), &budget).unwrap();
    let handle = owner.share_for_service().unwrap();
    let weak = Arc::downgrade(&handle.pins);
    drop(handle);
    supervisor.cancel().unwrap();

    let error = owner.try_close().unwrap_err();

    assert!(matches!(error.source, StateCause::Original(_)));
    assert!(weak.upgrade().is_some());
    assert!(authority.resident.reserve_resources(0, 8, 0).is_err());
}
