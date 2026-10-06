//! Original-account refusal and retained ownership for configuration copies.

use super::*;
use crucible::owned_decode::{DecodeBudget, DecodeResourceAuthority};
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority {
    used: Arc<AtomicU64>,
    maximum: u64,
}

struct Credit {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("fixture credit exhausted"))
            })?;
        Ok(Arc::new(Credit {
            used: self.used.clone(),
            bytes,
        }))
    }
}

fn authority(maximum: u64) -> Arc<Authority> {
    Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum,
    })
}

pub(super) fn copy_component_configuration(
    source: &ProductionVmLifecycleConfig,
) -> Arc<ProductionVmLifecycleConfig> {
    const COMPONENT_CONFIGURATION_BYTES: u64 = 16 * 1024 * 1024;
    let owner = authority(COMPONENT_CONFIGURATION_BYTES);
    let budget = DecodeBudget::new(owner, COMPONENT_CONFIGURATION_BYTES)
        .unwrap_or_else(|error| panic!("component configuration account: {error}"));
    let _scope = budget.enter();
    source
        .try_clone_shared_admitted()
        .unwrap_or_else(|error| panic!("component configuration copy: {error}"))
}

#[test]
fn missing_original_account_refuses_configuration_copy() {
    let source = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run");
    assert!(matches!(
        source.try_clone_admitted(),
        Err(ProductionVmLifecycleConfigCloneError::MissingAdmission)
    ));
}

#[test]
fn independent_copies_hold_actual_credits_through_last_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let source = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run")
        .with_kernel_cmdline_prefix("quiet 世界")
        .with_fault_replay(ResolvedEffectTrace {
            mode: crucible::model::FaultReplayMode::LockedEffect,
            work_items: Vec::new(),
            cursor: 0,
        });
    let authority = authority(4 * 1024 * 1024);
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let scope = budget.enter();
    let first = source.try_clone_admitted()?;
    let first_used = authority.used.load(Ordering::SeqCst);
    let second = source.try_clone_admitted()?;
    assert!(authority.used.load(Ordering::SeqCst) > first_used);
    assert_eq!(first.executable(), source.executable());
    assert_eq!(first.guest_assets.len(), source.guest_assets.len());
    assert_eq!(second.kernel_cmdline_prefix, source.kernel_cmdline_prefix);
    assert_eq!(second.fault_replay, source.fault_replay);

    drop(scope);
    drop(budget);
    let both_used = authority.used.load(Ordering::SeqCst);
    drop(first);
    assert!(authority.used.load(Ordering::SeqCst) < both_used);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    assert!(second.enter_input_custody().is_some());
    drop(second);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn exhaustion_refuses_copy_and_preserves_source_paths() -> Result<(), Box<dyn std::error::Error>> {
    let executable = "x".repeat(64 * 1024);
    let source = ProductionVmLifecycleConfig::new(&executable, "plugin", "kernel", "root", "run");
    let authority = authority(16 * 1024);
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let _scope = budget.enter();
    let initial_used = authority.used.load(Ordering::SeqCst);
    let error = source
        .try_clone_admitted()
        .err()
        .ok_or_else(|| std::io::Error::other("oversized copy unexpectedly admitted"))?;
    let ProductionVmLifecycleConfigCloneError::Retained { source: cause, .. } = &error else {
        return Err(std::io::Error::other("copy refusal lost admitted diagnostic custody").into());
    };
    assert!(matches!(
        cause.as_ref(),
        ProductionVmLifecycleConfigCloneError::Admission(_)
    ));
    assert!(authority.used.load(Ordering::SeqCst) > initial_used);
    assert_eq!(source.executable(), Path::new(&executable));
    assert!(source.decode_custody.is_none());
    drop(error);
    assert_eq!(authority.used.load(Ordering::SeqCst), initial_used);
    Ok(())
}
