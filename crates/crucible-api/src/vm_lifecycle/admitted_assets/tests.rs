//! Exercises original refusal, copied-body cleanup and final custody ordering.
//!
//! Counter credits are local component controls, not native launch authority.

// crucible-lint: allow panic-shortcut -- ownership witness failures stop these component controls.

use super::*;
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible::owned_decode::{DecodeResourceAuthority, ResourceLoan};
use crucible::{ContentHash, DagStore, DagStoreError, MemoryDagStore};
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};

type AfterCopy = Box<dyn FnOnce(&mut ProductionVmLifecycleConfig)>;

thread_local! {
    static AFTER_COPY: RefCell<Option<AfterCopy>> = RefCell::new(None);
}

pub(super) fn after_copy(configuration: &mut ProductionVmLifecycleConfig) {
    AFTER_COPY.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook(configuration);
        }
    });
}

struct Authority {
    used: Arc<AtomicU64>,
    maximum: u64,
    original: Arc<HostOperationGuard>,
    witness_armed: Arc<AtomicBool>,
    body_freed: Arc<AtomicBool>,
}

struct Credit {
    used: Arc<AtomicU64>,
    bytes: u64,
    witness_armed: Arc<AtomicBool>,
    body_freed: Arc<AtomicBool>,
}

impl Drop for Credit {
    fn drop(&mut self) {
        if self.witness_armed.load(Ordering::SeqCst) {
            assert!(self.body_freed.load(Ordering::SeqCst));
        }
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("component credit exhausted"))
            })?;
        Ok(ResourceLoan::new(Credit {
            used: self.used.clone(),
            bytes,
            witness_armed: self.witness_armed.clone(),
            body_freed: self.body_freed.clone(),
        }))
    }
}

fn fixture(
    maximum: u64,
) -> Result<(HostOperationSupervisor, Arc<Authority>, DecodeBudget), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
    let authority = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum,
        original,
        witness_armed: Arc::new(AtomicBool::new(false)),
        body_freed: Arc::new(AtomicBool::new(false)),
    });
    let budget = DecodeBudget::new(authority.clone(), maximum)?;
    Ok((supervisor, authority, budget))
}

fn paths() -> ProductionVmGuestAssetPaths<'static> {
    ProductionVmGuestAssetPaths {
        executable: Path::new("qemu"),
        plugin: Path::new("plugin"),
        architecture: VmArchitecture::X86_64,
        kernel: Path::new("kernel"),
        root_image: Path::new("root"),
        initrd: Some(Path::new("initrd")),
        root_image_format: RootImageFormat::Raw,
        run_state_root: Path::new("run"),
    }
}

struct BodyFreed(Arc<AtomicBool>);

impl Drop for BodyFreed {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct StoreWitness {
    // The real owned store body dies before the final marker is published.
    body: MemoryDagStore,
    _freed: BodyFreed,
}

impl DagStore for StoreWitness {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, DagStoreError> {
        self.body.put(bytes)
    }
    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, DagStoreError> {
        self.body.get(key)
    }
    fn exists(&self, key: &ContentHash) -> Result<bool, DagStoreError> {
        self.body.exists(key)
    }
    fn delete(&self, key: &ContentHash) -> Result<bool, DagStoreError> {
        self.body.delete(key)
    }
}

fn install_body_witness(
    configuration: &mut ProductionVmLifecycleConfig,
    authority: &Authority,
) -> Result<(), DagStoreError> {
    let body = MemoryDagStore::new();
    body.put(b"actual retained configuration body")?;
    configuration.world_artifacts = Some(Arc::new(StoreWitness {
        body,
        _freed: BodyFreed(authority.body_freed.clone()),
    }));
    authority.witness_armed.store(true, Ordering::SeqCst);
    Ok(())
}

#[test]
fn insufficient_original_budget_refuses_before_path_copy() -> Result<(), Box<dyn std::error::Error>>
{
    let (_supervisor, authority, budget) = fixture(256)?;
    let before = authority.used.load(Ordering::SeqCst);
    let failure =
        ProductionVmLifecycleConfig::try_from_guest_asset_paths_admitted(paths(), &budget)
            .err()
            .ok_or_else(|| std::io::Error::other("small account unexpectedly admitted"))?;
    assert!(matches!(failure.source, AssetAdmissionCause::Admission(_)));
    assert_eq!(authority.used.load(Ordering::SeqCst), before);
    drop(budget);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    drop(failure);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn canceled_original_refuses_before_copy() -> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, authority, budget) = fixture(16 * 1024 * 1024)?;
    let before = authority.used.load(Ordering::SeqCst);
    supervisor.cancel()?;

    let failure =
        ProductionVmLifecycleConfig::try_from_guest_asset_paths_admitted(paths(), &budget)
            .err()
            .ok_or_else(|| std::io::Error::other("canceled account unexpectedly admitted"))?;
    assert!(matches!(failure.source, AssetAdmissionCause::Admission(_)));
    assert_eq!(authority.used.load(Ordering::SeqCst), before);
    drop(budget);
    drop(failure);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn post_copy_cancellation_destroys_body_before_retained_failure_credit()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, authority, budget) = fixture(16 * 1024 * 1024)?;
    let witness = authority.clone();
    AFTER_COPY.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |configuration| {
            install_body_witness(configuration, &witness)
                .unwrap_or_else(|error| panic!("body witness: {error}"));
            supervisor
                .cancel()
                .unwrap_or_else(|error| panic!("original cancellation: {error}"));
        }))
    });

    let failure =
        ProductionVmLifecycleConfig::try_from_guest_asset_paths_admitted(paths(), &budget)
            .err()
            .ok_or_else(|| std::io::Error::other("late cancellation unexpectedly admitted"))?;
    assert!(authority.body_freed.load(Ordering::SeqCst));
    drop(budget);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    drop(failure);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn final_configuration_body_dies_before_original_credit() -> Result<(), Box<dyn std::error::Error>>
{
    let (_supervisor, authority, budget) = fixture(16 * 1024 * 1024)?;
    let witness = authority.clone();
    AFTER_COPY.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |configuration| {
            install_body_witness(configuration, &witness)
                .unwrap_or_else(|error| panic!("body witness: {error}"));
        }))
    });

    let configuration =
        ProductionVmLifecycleConfig::try_from_guest_asset_paths_admitted(paths(), &budget)?;
    assert_eq!(configuration.guest_assets.len(), 1);
    assert_eq!(configuration.initrd.as_deref(), Some(Path::new("initrd")));
    assert!(configuration.kernel_cmdline_prefix.is_none());
    assert!(
        configuration.guest_assets[&VmArchitecture::X86_64]
            .kernel_cmdline_prefix
            .is_none()
    );
    drop(budget);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    assert!(!authority.body_freed.load(Ordering::SeqCst));
    drop(configuration);
    assert!(authority.body_freed.load(Ordering::SeqCst));
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}
