//! Component evidence for original paired credit and diagnostic last-close.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures panic to identify failed original-capacity or last-close assertions.
#![allow(clippy::expect_used)]

use super::*;
use crucible_cas::content_store::ProviderDiagnosticStorage;
use crucible_linux_resource::host_services::HostServiceAllocator;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn allocator(bytes: u64) -> HostServiceAllocator {
    HostServiceAllocator::new(1, 1, bytes).expect("explicit finite component account")
}

// A component issuer embeds occupancy in its own already-funded body. The pin
// is optional test custody, not a namespace/quota/service authority factory.
struct PaidStorage {
    occupied: AtomicBool,
    _pin: Option<Arc<dyn Send + Sync>>,
    _resident: HostServiceLease,
    _metadata: HostServiceLease,
}

impl ProviderDiagnosticStorage for PaidStorage {
    fn try_occupy(&self) -> Result<(), StoreError> {
        self.occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| StoreError::Unavailable)
    }

    fn release(&self) {
        self.occupied.store(false, Ordering::Release);
    }
}

impl std::fmt::Debug for PaidStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PaidStorage { original_custody: retained }")
    }
}

fn storage_bytes() -> u64 {
    provider_diagnostic_bytes()
        + arc_allocation_bytes::<PaidStorage>().expect("actual component Arc geometry") as u64
        + 2 * lease_control_bytes().expect("actual shared lease allocation") as u64
}

fn admit_storage_with_pin(
    resident: &HostServiceAllocator,
    metadata: &HostServiceAllocator,
    pin: Option<Arc<dyn Send + Sync>>,
) -> Result<Arc<PaidStorage>, HostServiceError> {
    let (metadata, resident) = metadata.reserve_paired_bytes(resident, storage_bytes())?;
    Ok(Arc::new(PaidStorage {
        occupied: AtomicBool::new(false),
        _pin: pin,
        _resident: resident,
        _metadata: metadata,
    }))
}

fn admit_storage(
    resident: &HostServiceAllocator,
    metadata: &HostServiceAllocator,
) -> Result<Arc<PaidStorage>, HostServiceError> {
    admit_storage_with_pin(resident, metadata, None)
}

fn checkout(storage: &Arc<PaidStorage>) -> Result<ProviderDiagnosticPermit, StoreError> {
    ProviderDiagnosticPermit::checkout(storage.clone())
}

#[test]
fn complete_layout_is_precharged_in_both_original_accounts() {
    assert_eq!(provider_diagnostic_bytes(), 4184);
    assert_eq!(std::mem::size_of::<ProviderDiagnosticPermit>(), 16);
    assert_eq!(std::mem::size_of::<ProviderDiagnosticError>(), 40);
    assert_eq!(lease_control_bytes().expect("exact lease allocation"), 48);
    let resident = allocator(storage_bytes());
    let metadata = allocator(storage_bytes());
    let slot = admit_storage(&resident, &metadata).expect("complete paid slot");

    for account in [&resident, &metadata] {
        assert_eq!(
            account
                .reserve_resources(0, 0, 1)
                .expect_err("no uncharged headroom"),
            HostServiceError::CapacityExhausted
        );
    }
    drop(slot);

    for account in [&resident, &metadata] {
        let complete = account
            .reserve_resources(0, 0, storage_bytes())
            .expect("original full capacity returns after slot close");
        assert_eq!(complete.resident_bytes(), storage_bytes());
    }
}

#[test]
fn either_initial_reservation_refuses_inline_and_restores_the_other_account() {
    for short_metadata in [true, false] {
        let bytes = storage_bytes();
        let resident = allocator(bytes - u64::from(!short_metadata));
        let metadata = allocator(bytes - u64::from(short_metadata));

        assert_eq!(
            admit_storage(&resident, &metadata).expect_err("initial pair refusal"),
            HostServiceError::CapacityExhausted
        );
        for account in [&resident, &metadata] {
            assert!(
                account
                    .reserve_resources(0, 0, account.maximum_resident_bytes())
                    .is_ok()
            );
        }
    }
}

#[test]
fn funded_descriptor_refusal_preserves_original_typed_source_without_new_credit() {
    let bytes = storage_bytes();
    let resident = allocator(bytes);
    let metadata = allocator(bytes);
    let slot = admit_storage(&resident, &metadata).expect("funded refusal storage");
    let descriptors = resident
        .reserve_resources(0, 1, 0)
        .expect("original descriptor owner");
    let permit = checkout(&slot).expect("exclusive paid slot");
    let cause = resident
        .reserve_resources(0, 1, 0)
        .expect_err("actual FD exhaustion");
    let error = retain_provider_cause(permit, cause.into());

    let StoreError::ProviderDiagnostic { source } = &error else {
        panic!("expected owning provider cause");
    };
    assert_eq!(source.kind(), ProviderFailureKind::Resources);
    assert!(matches!(
        source
            .source()
            .and_then(Error::source)
            .and_then(|cause| cause.downcast_ref::<HostServiceError>()),
        Some(HostServiceError::CapacityExhausted)
    ));
    assert!(matches!(checkout(&slot), Err(StoreError::Unavailable)));

    drop(error);
    drop(descriptors);
    assert!(checkout(&slot).is_ok());
}

#[test]
fn physical_quota_cause_keeps_its_owned_path_and_kind() {
    let resident = allocator(storage_bytes());
    let metadata = allocator(storage_bytes());
    let slot = admit_storage(&resident, &metadata).expect("funded physical cause");
    let permit = checkout(&slot).expect("checkout before path ownership");
    let error = retain_provider_cause(
        permit,
        LinuxProjectQuotaError::MissingAuthority {
            path: std::path::PathBuf::from("/component/pinned-root"),
        }
        .into(),
    );

    let StoreError::ProviderDiagnostic { source } = &error else {
        panic!("expected original physical cause");
    };
    assert_eq!(source.kind(), ProviderFailureKind::PhysicalQuota);
    let Some(LinuxProjectQuotaError::MissingAuthority { path }) = source
        .source()
        .and_then(Error::source)
        .and_then(|cause| cause.downcast_ref::<LinuxProjectQuotaError>())
    else {
        panic!("original lower type/path was lost");
    };
    assert_eq!(path, std::path::Path::new("/component/pinned-root"));
}

#[derive(Debug)]
struct CloseProbe {
    slot: Arc<PaidStorage>,
    closed: Arc<AtomicBool>,
}

impl std::fmt::Display for CloseProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("component close probe")
    }
}

impl Error for CloseProbe {}

impl Drop for CloseProbe {
    fn drop(&mut self) {
        assert!(matches!(checkout(&self.slot), Err(StoreError::Unavailable)));
        self.closed.store(true, Ordering::Release);
    }
}

#[test]
fn source_closes_before_slot_reuse_and_last_alias_retains_service_pin() {
    struct ServicePin {
        file: std::fs::File,
        _descriptor: HostServiceLease,
    }
    let alias_bytes = (std::mem::size_of::<StoreError>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::size_of::<ServicePin>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::size_of::<AtomicBool>()
        + 2 * std::mem::size_of::<usize>()) as u64
        + 3 * HostServiceLease::metadata_bytes();
    let resident = allocator(storage_bytes() + alias_bytes);
    let metadata = allocator(storage_bytes() + alias_bytes);
    let alias_metadata = metadata
        .reserve_resources(0, 0, alias_bytes)
        .expect("alias controls first");
    let alias_resident = resident
        .reserve_resources(0, 0, alias_bytes)
        .expect("alias controls first");
    let descriptor = resident
        .reserve_resources(0, 1, 0)
        .expect("actual retained FD admission");
    let service = Arc::new(ServicePin {
        file: tempfile::tempfile().expect("actual component descriptor"),
        _descriptor: descriptor,
    });
    let weak_service = Arc::downgrade(&service);
    let fd = std::os::fd::AsRawFd::as_raw_fd(&service.file);
    let closed = Arc::new(AtomicBool::new(false));
    let slot = admit_storage_with_pin(&resident, &metadata, Some(service.clone()))
        .expect("one paid original issuer");
    let weak_slot = Arc::downgrade(&slot);
    let permit = checkout(&slot).expect("same owner retained");
    assert!(std::mem::size_of::<CloseProbe>() <= std::mem::size_of::<ProviderCause>());
    let error = Arc::new(StoreError::ProviderDiagnostic {
        source: permit.retain(
            ProviderFailureKind::Supervision,
            Box::new(CloseProbe {
                slot: slot.clone(),
                closed: closed.clone(),
            }),
        ),
    });
    let alias = error.clone();

    drop(service);
    drop(error);
    drop(slot);
    assert!(!closed.load(Ordering::Acquire));
    assert!(weak_service.upgrade().is_some());
    assert!(std::path::Path::new(&format!("/proc/self/fd/{fd}")).exists());
    assert!(resident.reserve_resources(0, 1, 0).is_err());

    drop(alias);
    assert!(closed.load(Ordering::Acquire));
    assert!(weak_service.upgrade().is_none());
    assert!(!std::path::Path::new(&format!("/proc/self/fd/{fd}")).exists());
    assert!(weak_slot.upgrade().is_none());
    drop(alias_metadata);
    drop(alias_resident);
    assert!(
        resident
            .reserve_resources(1, 1, resident.maximum_resident_bytes())
            .is_ok()
    );
    assert!(
        metadata
            .reserve_resources(1, 1, metadata.maximum_resident_bytes())
            .is_ok()
    );
}

#[test]
fn path_bound_refuses_before_new_lower_diagnostic_ownership() {
    let bounded = std::path::PathBuf::from("x".repeat(MAXIMUM_PROVIDER_ERROR_PATH_BYTES));
    assert!(check_provider_error_path(&bounded).is_ok());
    let oversized = std::path::PathBuf::from("x".repeat(MAXIMUM_PROVIDER_ERROR_PATH_BYTES + 1));
    assert!(matches!(
        check_provider_error_path(&oversized),
        Err(StoreError::InvalidComposition { .. })
    ));
}

#[test]
fn identical_account_pays_both_shares_and_releases_only_after_last_issuer() {
    let bytes = storage_bytes();
    let account = allocator(2 * bytes);
    let storage = admit_storage(&account, &account).expect("both original shares admitted");
    let permit = checkout(&storage).expect("original issuer retained");
    let weak = Arc::downgrade(&storage);
    drop(storage);
    assert!(account.reserve_resources(0, 0, 1).is_err());
    assert!(weak.upgrade().is_some());
    drop(permit);
    assert!(weak.upgrade().is_none());
    assert!(account.reserve_resources(0, 0, 2 * bytes).is_ok());
}
