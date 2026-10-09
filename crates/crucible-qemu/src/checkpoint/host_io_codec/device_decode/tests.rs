//! Saved lower-device account controls with modeled reservation counters.

use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible::owned_decode::{
    DecodeAdmissionError, DecodeResourceAuthority, DecodeScope, ResourceLoan,
};
use crucible_device::subnode::IoCore;
use crucible_device::{BaseImage, BlockDevice, BlockLatency, PAGE_SIZE};

use super::*;

struct Credit(Arc<AtomicU64>, u64);

impl Drop for Credit {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Ordering::SeqCst);
    }
}

struct Authority {
    used: Arc<AtomicU64>,
    calls: AtomicU64,
    live_calls: AtomicU64,
    refuse_live_at: AtomicU64,
    refusing: AtomicBool,
    switch: Mutex<Option<DecodeBudget>>,
    failure: DecodeAdmissionError,
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        let call = self.live_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.refuse_live_at.load(Ordering::SeqCst) {
            Err(self.failure.clone())
        } else {
            Ok(())
        }
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.refusing.load(Ordering::SeqCst) {
            return Err(self.failure.clone());
        }
        let other = self.switch.lock().map_err(|_| self.failure.clone())?.take();
        if let Some(other) = other {
            SWITCHED_SCOPE.with(|scope| scope.replace(Some(other.enter())));
            self.refusing.store(true, Ordering::SeqCst);
        }
        self.used.fetch_add(bytes, Ordering::SeqCst);
        Ok(ResourceLoan::new(Credit(self.used.clone(), bytes)))
    }
}

fn original() -> Result<(DecodeBudget, Arc<Authority>), DecodeAdmissionError> {
    let authority = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        calls: AtomicU64::new(0),
        live_calls: AtomicU64::new(0),
        refuse_live_at: AtomicU64::new(u64::MAX),
        refusing: AtomicBool::new(false),
        switch: Mutex::new(None),
        failure: DecodeAdmissionError::new(fmt::Error),
    });
    let budget = DecodeBudget::new(authority.clone(), 16 * 1024 * 1024)?;
    Ok((budget, authority))
}

fn block_bytes() -> Result<(BlockSnapshot, Vec<u8>), Box<dyn Error>> {
    let core = IoCore::new(crucible_shmem::SLOT_BLK_IO as u32, 16, 16)?;
    let device = BlockDevice::new(
        core,
        BaseImage::new(vec![0; PAGE_SIZE]),
        BlockLatency::default(),
    );
    let snapshot = device.snapshot();
    let bytes = snapshot.to_canonical_bytes()?;
    Ok((snapshot, bytes))
}

thread_local! {
    static SWITCHED_SCOPE: RefCell<Option<DecodeScope>> = const { RefCell::new(None) };
}

struct ScopeCleanup;

impl Drop for ScopeCleanup {
    fn drop(&mut self) {
        SWITCHED_SCOPE.with(|scope| drop(scope.borrow_mut().take()));
    }
}

#[test]
fn lower_block_seed_uses_supplied_account_while_other_scope_is_active() -> Result<(), Box<dyn Error>>
{
    let (expected, bytes) = block_bytes()?;
    let (saved, saved_authority) = original()?;
    let (other, other_authority) = original()?;
    let other_calls_before = other_authority.calls.load(Ordering::SeqCst);
    let other_scope = other.enter();

    let actual = decode_block_device(&bytes, MAX_BYTES, Some(&saved))?;
    drop(other_scope);

    assert_eq!(actual, expected);
    assert!(saved_authority.calls.load(Ordering::SeqCst) > 1);
    assert_eq!(
        other_authority.calls.load(Ordering::SeqCst),
        other_calls_before
    );
    assert_eq!(other.failure()?, None);
    Ok(())
}

#[test]
fn lower_table_keeps_saved_refusal_after_scratch_callback_switch() -> Result<(), Box<dyn Error>> {
    let (_, bytes) = block_bytes()?;
    let (saved, saved_authority) = original()?;
    let (other, other_authority) = original()?;
    let other_calls_before = other_authority.calls.load(Ordering::SeqCst);
    *saved_authority.switch.lock().map_err(|_| fmt::Error)? = Some(other.clone());
    let cleanup = ScopeCleanup;

    let result = decode_block_device(&bytes, MAX_BYTES, Some(&saved));
    drop(cleanup);

    assert!(result.is_err());
    assert_eq!(saved.failure()?, Some(saved_authority.failure.clone()));
    assert_eq!(
        other_authority.calls.load(Ordering::SeqCst),
        other_calls_before
    );
    assert_eq!(other.failure()?, None);
    Ok(())
}

#[test]
fn lower_preexisting_original_failure_remains_typed_before_parser_storage()
-> Result<(), Box<dyn Error>> {
    let (_, bytes) = block_bytes()?;
    let (saved, authority) = original()?;
    let calls_before = authority.calls.load(Ordering::SeqCst);
    let used_before = authority.used.load(Ordering::SeqCst);
    saved.record_failure(authority.failure.clone());

    let result = decode_block_device(&bytes, MAX_BYTES, Some(&saved));

    assert!(result.is_err());
    assert_eq!(saved.failure()?, Some(authority.failure.clone()));
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls_before);
    assert_eq!(authority.used.load(Ordering::SeqCst), used_before);
    Ok(())
}

#[test]
fn final_host_acceptance_keeps_first_live_refusal_in_saved_account() -> Result<(), Box<dyn Error>> {
    let expected = QemuHostIoCheckpoint {
        execution_binding: ContentHash::from_bytes(b"actual host continuation boundary"),
        block: None,
        ninep: None,
        #[cfg(target_os = "linux")]
        accelerator: None,
    };
    let bytes = expected.to_canonical_bytes()?;
    let (saved, authority) = original()?;
    let live_before = authority.live_calls.load(Ordering::SeqCst);
    // The parser performs two live cuts; the complete host acceptance is third.
    authority
        .refuse_live_at
        .store(live_before + 3, Ordering::SeqCst);
    let scope = saved.enter();

    let result = QemuHostIoCheckpoint::from_canonical_bytes(&bytes, expected.execution_binding);
    drop(scope);

    assert_eq!(result.err(), Some(QemuHostIoCheckpointCodecError::Nested));
    assert_eq!(authority.live_calls.load(Ordering::SeqCst), live_before + 3);
    assert_eq!(saved.failure()?, Some(authority.failure.clone()));
    assert_eq!(saved.check().err(), Some(authority.failure.clone()));
    Ok(())
}

#[test]
fn collection_hook_keeps_saved_account_while_other_scope_is_current() -> Result<(), Box<dyn Error>>
{
    let (saved, authority) = original()?;
    let (other, other_authority) = original()?;
    let saved_before = authority.calls.load(Ordering::SeqCst);
    let other_before = other_authority.calls.load(Ordering::SeqCst);
    let other_scope = other.enter();

    admit_collection(&saved, crucible_device::DeviceSnapshotAllocation::BlockPage)?;
    admit_collection(
        &saved,
        crucible_device::DeviceSnapshotAllocation::NinepFidTable { entries: 2 },
    )?;
    drop(other_scope);

    assert!(authority.calls.load(Ordering::SeqCst) > saved_before);
    assert_eq!(other_authority.calls.load(Ordering::SeqCst), other_before);
    assert_eq!(saved.failure()?, None);
    assert_eq!(other.failure()?, None);
    Ok(())
}

#[test]
fn nested_fault_parser_uses_saved_original_under_other_scope() -> Result<(), Box<dyn Error>> {
    let (snapshot, _) = block_bytes()?;
    let bytes = snapshot.storage_faults.to_canonical_bytes()?;
    let (saved, authority) = original()?;
    let (other, other_authority) = original()?;
    let saved_before = authority.calls.load(Ordering::SeqCst);
    let other_before = other_authority.calls.load(Ordering::SeqCst);
    let other_scope = other.enter();

    let actual = decode_block_fault(&bytes, snapshot.device_length, MAX_BYTES, &saved)?;
    drop(other_scope);

    assert_eq!(actual, snapshot.storage_faults);
    assert!(authority.calls.load(Ordering::SeqCst) > saved_before);
    assert_eq!(other_authority.calls.load(Ordering::SeqCst), other_before);
    assert_eq!(saved.failure()?, None);
    assert_eq!(other.failure()?, None);
    Ok(())
}

#[test]
fn nested_fault_parser_keeps_original_refusal_after_scope_switch() -> Result<(), Box<dyn Error>> {
    let (snapshot, _) = block_bytes()?;
    let bytes = snapshot.storage_faults.to_canonical_bytes()?;
    let (saved, authority) = original()?;
    let (other, other_authority) = original()?;
    let other_before = other_authority.calls.load(Ordering::SeqCst);
    *authority.switch.lock().map_err(|_| fmt::Error)? = Some(other.clone());
    let cleanup = ScopeCleanup;

    let actual = decode_block_fault(&bytes, snapshot.device_length, MAX_BYTES, &saved);
    drop(cleanup);

    assert!(actual.is_err());
    assert_eq!(saved.failure()?, Some(authority.failure.clone()));
    assert_eq!(other_authority.calls.load(Ordering::SeqCst), other_before);
    assert_eq!(other.failure()?, None);
    Ok(())
}
