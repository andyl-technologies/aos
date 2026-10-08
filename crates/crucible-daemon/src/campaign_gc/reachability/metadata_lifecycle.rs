//! Same-bank transient mark operations and final immutable-reader custody.

#![cfg(test)]

use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible_cas::content_store::{MemoryBlobBackend, ObjectKind, StorePhysicalQuotaGuard};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};

use super::*;

const RESIDENT_BYTES: u64 = 4 * 1024 * 1024;

// This portable component bank models actual aggregate allocator loans. It
// grants no filesystem quota, native Service admission or performance proof.
struct Resources {
    allocator: HostServiceAllocator,
    used: Arc<AtomicU64>,
    closed: AtomicBool,
}

struct Credit {
    _lease: HostServiceLease,
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl StorePhysicalQuotaGuard for Resources {
    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(StoreError::Unsupported {
                capability: "component-original-owner-closed",
            });
        }
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.verify()?;
        Ok(self.allocator.maximum_resident_bytes())
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        let lease = self
            .allocator
            .reserve_resources(0, descriptors, bytes)
            .map_err(|_| StoreError::Quota)?;
        self.used.fetch_add(bytes, Ordering::AcqRel);
        Ok(crucible_cas::owned_decode::ResourceLoan::new(Credit {
            _lease: lease,
            used: Arc::clone(&self.used),
            bytes,
        }))
    }
}

fn resources() -> Arc<Resources> {
    Arc::new(Resources {
        allocator: HostServiceAllocator::new(1, 128, RESIDENT_BYTES)
            .unwrap_or_else(|error| panic!("finite original mark account: {error}")),
        used: Arc::new(AtomicU64::new(0)),
        closed: AtomicBool::new(false),
    })
}

fn backend(resources: &Arc<Resources>) -> Arc<dyn ImmutableBlobBackend> {
    crate::exact_checkpoint_store::test_support::fixture_metadata_backend(
        Arc::new(MemoryBlobBackend::new("component-marks", RESIDENT_BYTES)),
        resources.clone(),
    )
}

fn page(index: u64) -> ContentId {
    ContentId::for_bytes(ObjectKind::RamExtent, 1, &index.to_be_bytes())
}

fn has_store_cause(error: &(dyn Error + 'static), predicate: fn(&StoreError) -> bool) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if error.downcast_ref::<StoreError>().is_some_and(predicate) {
            return true;
        }
        cause = error.source();
    }
    false
}

#[test]
fn completed_mark_operations_reuse_one_bank_without_poisoning_the_parent() {
    let resources = resources();
    let parent = DecodeBudget::for_store(resources.clone())
        .unwrap_or_else(|error| panic!("original parent account: {error}"));
    let _scope = parent.enter();
    let mut marks = Reachability::with_backend(backend(&resources), &parent)
        .unwrap_or_else(|error| panic!("original mark backend: {error}"));
    for index in 0..96 {
        marks
            .insert(page(index))
            .unwrap_or_else(|error| panic!("distinct mark {index}: {error}"));
    }
    let root = marks.root;
    let retained = resources.used.load(Ordering::Acquire);

    for index in 0..768 {
        let id = page(index % 96);
        marks
            .insert(id)
            .unwrap_or_else(|error| panic!("completed duplicate mark {index}: {error}"));
        assert!(
            marks
                .contains(&id)
                .unwrap_or_else(|error| { panic!("completed membership {index}: {error}") })
        );
        assert!(
            !marks
                .contains(&page(1000 + index))
                .unwrap_or_else(|error| { panic!("completed absence {index}: {error}") })
        );
        assert_eq!(resources.used.load(Ordering::Acquire), retained);
    }
    assert_eq!(marks.root, root);
    assert_eq!(marks.len(), 96);

    let remaining = RESIDENT_BYTES - resources.used.load(Ordering::Acquire);
    let competitor = resources
        .reserve_resources(0, remaining)
        .unwrap_or_else(|error| panic!("actual same-bank live competitor: {error}"));
    let error = marks
        .insert(page(2000))
        .err()
        .unwrap_or_else(|| panic!("live owner exhaustion must refuse marking"));
    assert!(has_store_cause(&error, |error| matches!(
        error,
        StoreError::Quota
    )));
    assert_eq!(marks.root, root);
    drop(error);
    drop(competitor);
    parent
        .check()
        .unwrap_or_else(|error| panic!("child refusal leaves original parent healthy: {error}"));
    marks
        .insert(page(2000))
        .unwrap_or_else(|error| panic!("retry after actual competitor release: {error}"));
    assert_eq!(marks.len(), 97);
    drop(marks);
    drop(_scope);
    drop(parent);
    assert_eq!(resources.used.load(Ordering::Acquire), 0);
    resources
        .reserve_resources(128, RESIDENT_BYTES)
        .unwrap_or_else(|error| panic!("complete original bank restored: {error}"));
}

#[test]
fn explicit_marks_keep_the_original_account_and_last_reader_charged() {
    let resources = resources();
    let parent = DecodeBudget::for_store(resources.clone())
        .unwrap_or_else(|error| panic!("original namespace decoder: {error}"));
    let backend = backend(&resources);
    let mut marks = Reachability::with_backend(Arc::clone(&backend), &parent)
        .unwrap_or_else(|error| panic!("unscoped original metadata projection: {error}"));
    marks
        .insert(page(1))
        .unwrap_or_else(|error| panic!("original mark: {error}"));
    assert!(
        marks
            .contains(&page(1))
            .unwrap_or_else(|error| { panic!("original unscoped membership: {error}") })
    );
    let root_id = marks.root.content_id();
    let source = backend
        .read(root_id, None)
        .unwrap_or_else(|error| panic!("actual immutable root source: {error}"));
    let clone = source.clone();
    let mut reader = source
        .open()
        .unwrap_or_else(|error| panic!("actual delayed root reader: {error}"));
    drop(parent);
    drop(marks);
    drop(backend);
    drop(source);
    let mut bytes = [0_u8; 4096];
    let length = reader
        .read(&mut bytes)
        .unwrap_or_else(|error| panic!("actual reader after mark facades close: {error}"));
    assert!(root_id.authenticates(&bytes[..length]));
    assert_eq!(
        reader
            .read(&mut bytes)
            .unwrap_or_else(|error| panic!("authenticated root EOF: {error}")),
        0
    );
    assert!(matches!(
        resources.reserve_resources(0, RESIDENT_BYTES),
        Err(StoreError::Quota)
    ));
    drop(clone);
    assert!(matches!(
        resources.reserve_resources(0, RESIDENT_BYTES),
        Err(StoreError::Quota)
    ));
    drop(reader);
    assert_eq!(resources.used.load(Ordering::Acquire), 0);
    resources
        .reserve_resources(128, RESIDENT_BYTES)
        .unwrap_or_else(|error| panic!("last actual reader releases the full bank: {error}"));
}

#[test]
fn missing_or_closed_metadata_authority_refuses_before_the_mark_root_changes() {
    let resources = resources();
    let parent = DecodeBudget::for_store(resources.clone())
        .unwrap_or_else(|error| panic!("original namespace decoder: {error}"));
    let error =
        Reachability::with_backend(Arc::new(MemoryBlobBackend::new("unowned", 4096)), &parent)
            .err()
            .unwrap_or_else(|| panic!("an unowned mark backend must refuse"));
    assert!(matches!(
        error,
        StoreError::Unsupported {
            capability: "decoded-metadata-resources"
        }
    ));

    let mut marks = Reachability::with_backend(backend(&resources), &parent)
        .unwrap_or_else(|error| panic!("original mark backend: {error}"));
    let root = marks.root;
    resources.closed.store(true, Ordering::Release);
    let error = marks
        .insert(page(1))
        .err()
        .unwrap_or_else(|| panic!("closed original authority must refuse marking"));
    assert!(has_store_cause(&error, |error| matches!(
        error,
        StoreError::Unsupported {
            capability: "component-original-owner-closed"
        }
    )));
    assert!(marks.contains(&page(1)).is_err());
    assert_eq!(marks.root, root);
    drop(error);
    drop(marks);
    drop(parent);
    assert_eq!(resources.used.load(Ordering::Acquire), 0);
}

#[test]
fn poisoned_original_decode_is_not_replaced_by_an_ambient_account() {
    let resources = resources();
    let parent = DecodeBudget::for_store(resources.clone())
        .unwrap_or_else(|error| panic!("original decoder: {error}"));
    let mut marks = Reachability::with_backend(backend(&resources), &parent)
        .unwrap_or_else(|error| panic!("original mark backend: {error}"));
    let root = marks.root;
    let ambient = DecodeBudget::for_store(resources.clone())
        .unwrap_or_else(|error| panic!("other ambient decoder: {error}"));
    let _scope = ambient.enter();

    assert!(parent.charge_bytes(RESIDENT_BYTES).is_err());
    let used = resources.used.load(Ordering::Acquire);
    assert!(marks.insert(page(1)).is_err());
    assert!(marks.contains(&page(1)).is_err());
    assert!(parent.check().is_err());
    assert_eq!(marks.root, root);
    assert_eq!(resources.used.load(Ordering::Acquire), used);

    let error =
        Reachability::with_backend(Arc::new(MemoryBlobBackend::new("unowned", 4096)), &parent)
            .err()
            .unwrap_or_else(|| panic!("ambient authority cannot replace the original refusal"));
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    ambient
        .check()
        .unwrap_or_else(|error| panic!("ambient account stays healthy: {error}"));
    drop(error);
    drop(_scope);
    drop(ambient);
    drop(parent);
    drop(marks);
    assert_eq!(resources.used.load(Ordering::Acquire), 0);
}

#[test]
fn refused_original_gc_account_precedes_boundary_and_ambient_authority() {
    let resources = resources();
    let parent = DecodeBudget::for_store(resources.clone())
        .unwrap_or_else(|error| panic!("original namespace decoder: {error}"));
    let other_resources = self::resources();
    let ambient = DecodeBudget::for_store(other_resources.clone())
        .unwrap_or_else(|error| panic!("other namespace decoder: {error}"));
    let _scope = ambient.enter();
    resources.closed.store(true, Ordering::Release);
    let retained = resources.used.load(Ordering::Acquire);
    let other_retained = other_resources.used.load(Ordering::Acquire);
    let mut calls = 0;
    let mut boundary = || {
        calls += 1;
        Ok(())
    };

    let error = CampaignGcOperationContext::new(backend(&resources), &parent, &mut boundary)
        .err()
        .unwrap_or_else(|| panic!("closed original refuses before any GC callback"));

    assert!(has_store_cause(&error, |error| matches!(
        error,
        StoreError::Unsupported {
            capability: "component-original-owner-closed"
        }
    )));
    assert_eq!(calls, 0);
    assert_eq!(resources.used.load(Ordering::Acquire), retained);
    assert_eq!(other_resources.used.load(Ordering::Acquire), other_retained);
    ambient
        .check()
        .unwrap_or_else(|error| panic!("other account stays healthy: {error}"));
}

#[test]
fn boundary_cannot_replace_or_poison_the_original_before_gc_storage_admission() {
    let resources = resources();
    let parent = DecodeBudget::for_store(resources.clone())
        .unwrap_or_else(|error| panic!("original namespace decoder: {error}"));
    let other_resources = self::resources();
    let ambient = DecodeBudget::for_store(other_resources.clone())
        .unwrap_or_else(|error| panic!("other namespace decoder: {error}"));
    let _scope = ambient.enter();
    let retained = resources.used.load(Ordering::Acquire);
    let other_retained = other_resources.used.load(Ordering::Acquire);
    let mut calls = 0;
    let mut boundary = || {
        calls += 1;
        assert!(parent.charge_bytes(RESIDENT_BYTES).is_err());
        Ok(())
    };

    let error = CampaignGcOperationContext::new(backend(&resources), &parent, &mut boundary)
        .err()
        .unwrap_or_else(|| panic!("callback refusal must precede storage admission"));

    assert!(has_store_cause(&error, |error| matches!(
        error,
        StoreError::Quota
    )));
    assert_eq!(calls, 1);
    assert!(parent.check().is_err());
    assert_eq!(resources.used.load(Ordering::Acquire), retained);
    assert_eq!(other_resources.used.load(Ordering::Acquire), other_retained);
    ambient
        .check()
        .unwrap_or_else(|error| panic!("ambient account stays healthy: {error}"));
}
